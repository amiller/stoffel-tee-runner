use lobby_records::{job_id_for, verify_signature, EvidenceBundle, JobRecord, JobState, JoinRecord, NodeRecord, ResultRecord, Signed, BUNDLE_VERSION};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope { kind: String, record: Value }

#[derive(Default)]
struct Store { nodes: Vec<NodeRecord>, jobs: Vec<JobRecord>, joins: Vec<JoinRecord>, results: Vec<ResultRecord>, path: PathBuf }
type Shared = Arc<Mutex<Store>>;

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock is before Unix epoch").as_secs() }

fn strict<T: DeserializeOwned>(value: Value, keys: &[&str]) -> Result<T, String> {
    let object = value.as_object().ok_or_else(|| "record must be a JSON object".to_string())?;
    let allowed: HashSet<&str> = keys.iter().copied().collect();
    if let Some(key) = object.keys().find(|key| !allowed.contains(key.as_str())) { return Err(format!("unknown field: {key}")); }
    serde_json::from_value(Value::Object(object.clone())).map_err(|e| format!("malformed record: {e}"))
}

const NODE_KEYS: &[&str] = &["node_id","pubkey","endpoint","max_parties","supported_thresholds","operator_label","attestation","announced_at","signature"];
const JOB_KEYS: &[&str] = &["job_id","program_id","program_url","entry","n_parties","threshold","policy","not_before","state","proposer","created_at","signature"];
const JOIN_KEYS: &[&str] = &["job_id","node_id","pubkey","party_id","joined_at","signature"];
const RESULT_KEYS: &[&str] = &["job_id","node_id","pubkey","party_id","value","program_id","completed_at","signature"];

fn load(path: &Path) -> Result<Store, String> {
    let mut store = Store { path: path.to_path_buf(), ..Default::default() };
    if !path.exists() { return Ok(store); }
    for (line_no, line) in BufReader::new(File::open(path).map_err(|e| e.to_string())?).lines().enumerate() {
        let value: Value = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| format!("line {}: malformed JSON: {e}", line_no + 1))?;
        let env: Envelope = serde_json::from_value(value).map_err(|e| format!("line {}: malformed envelope: {e}", line_no + 1))?;
        add_loaded(&mut store, env.kind.as_str(), env.record).map_err(|e| format!("line {}: {e}", line_no + 1))?;
    }
    Ok(store)
}

fn add_loaded(store: &mut Store, kind: &str, value: Value) -> Result<(), String> {
    // Reload runs the same validation as writes for node_id, capabilities and
    // references (issue #9). Job lines keep schema + signature only: job ids are
    // derived at write time, and re-deriving here would refuse every store
    // written before that rule existed.
    match kind {
        "node" => { let r: NodeRecord = strict(value, NODE_KEYS)?; authorized(&r)?; validate_node(store, &r)?; store.nodes.push(r); }
        "join" => { let r: JoinRecord = strict(value, JOIN_KEYS)?; authorized(&r)?; validate_join(store, &r)?; store.joins.push(r); }
        "result" => { let r: ResultRecord = strict(value, RESULT_KEYS)?; authorized(&r)?; validate_result(store, &r)?; store.results.push(r); }
        "job" => { let r: JobRecord = strict(value, JOB_KEYS)?; authorized(&r)?; store.jobs.push(r); }
        _ => return Err(format!("unknown record kind: {kind}")),
    }
    Ok(())
}

fn append(store: &mut Store, kind: &str, record: Value) -> Result<(), String> {
    let mut file = OpenOptions::new().create(true).append(true).open(&store.path).map_err(|e| format!("open store: {e}"))?;
    writeln!(file, "{}", serde_json::to_string(&json!({"kind": kind, "record": record})).map_err(|e| e.to_string())?).map_err(|e| format!("append store: {e}"))?;
    file.sync_data().map_err(|e| format!("sync store: {e}"))
}

fn latest_node<'a>(s: &'a Store, id: &str) -> Option<&'a NodeRecord> { s.nodes.iter().rev().find(|n| n.node_id == id) }
fn job<'a>(s: &'a Store, id: &str) -> Option<&'a JobRecord> { s.jobs.iter().rev().find(|j| j.job_id == id) }
fn bad(msg: impl Into<String>) -> Response { Response::json(400, json!({"error": msg.into()})) }
fn authorized<T: Signed + Clone + serde::Serialize>(r: &T) -> Result<(), String> { verify_signature(r) }

/// Lifecycle a reader filters on, computed from the record stream. The signed
/// `state` field stays as written (the schema is frozen and a record the service
/// rewrote would no longer verify offline), so the state IS the counts: `open`
/// below `n_parties` joins, `forming` at `n_parties` joins, `finished` at
/// `n_parties` results.
fn derived_state(s: &Store, j: &JobRecord) -> JobState {
    let joins = s.joins.iter().filter(|x| x.job_id == j.job_id).count();
    let results = s.results.iter().filter(|x| x.job_id == j.job_id).count();
    if results == j.n_parties { JobState::Finished } else if joins == j.n_parties { JobState::Forming } else { JobState::Open }
}

fn validate_node(s: &Store, r: &NodeRecord) -> Result<(), String> {
    let pk = hex::decode(&r.pubkey).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| "pubkey is not 32-byte hex".to_string())?;
    if lobby_records::node_id_for(&pk) != r.node_id { return Err("node_id does not match pubkey".into()); }
    if r.max_parties == 0 || r.supported_thresholds.iter().any(|t| 3 * t + 1 > r.max_parties) { return Err("invalid node capabilities".into()); }
    if let Some(old) = latest_node(s, &r.node_id) { if old.pubkey != r.pubkey { return Err("node identity is bound to another key".into()); } }
    Ok(())
}

fn validate_job(r: &JobRecord) -> Result<(), String> {
    if r.n_parties < 3 * r.threshold + 1 || r.n_parties == 0 || r.state != JobState::Open { return Err("job must be open and satisfy n >= 3t + 1".into()); }
    match job_id_for(&r.program_id, &r.entry, r.n_parties, r.threshold) {
        Ok(id) if id == r.job_id => Ok(()),
        Ok(_) => Err("job_id does not match blake3(program_id || entry || n_parties || threshold)".into()),
        Err(e) => Err(e),
    }
}

fn validate_join(s: &Store, r: &JoinRecord) -> Result<(), String> {
    let j = job(s, &r.job_id).ok_or("unknown job")?;
    let n = latest_node(s, &r.node_id).ok_or("unknown node")?;
    let state = derived_state(s, j);
    if state != JobState::Open && state != JobState::Forming { return Err("job is not accepting joins".into()); }
    if n.pubkey != r.pubkey || r.party_id >= j.n_parties { return Err("join key or party is invalid".into()); }
    if n.max_parties < j.n_parties || !n.supported_thresholds.contains(&j.threshold) { return Err("node capabilities do not satisfy the job".into()); }
    if s.joins.iter().any(|x| x.job_id == r.job_id && (x.node_id == r.node_id || x.party_id == r.party_id)) { return Err("node or party already joined".into()); }
    Ok(())
}

fn validate_result(s: &Store, r: &ResultRecord) -> Result<(), String> {
    let j = job(s, &r.job_id).ok_or("unknown job")?;
    let n = latest_node(s, &r.node_id).ok_or("unknown node")?;
    if n.pubkey != r.pubkey || r.program_id != j.program_id { return Err("result key or program is invalid".into()); }
    if !s.joins.iter().any(|x| x.job_id == r.job_id && x.node_id == r.node_id && x.party_id == r.party_id) { return Err("result has no matching join".into()); }
    if s.results.iter().any(|x| x.job_id == r.job_id && x.node_id == r.node_id) { return Err("node already posted a result".into()); }
    Ok(())
}

fn post(s: &mut Store, path: &str, body: Value) -> Response {
    match path {
        "/nodes" => {
            let r: NodeRecord = match strict(body, NODE_KEYS).and_then(|r| { authorized(&r)?; Ok(r) }) { Ok(r) => r, Err(e) => return bad(e) };
            if let Err(e) = validate_node(s, &r) { return bad(e); }
            if s.nodes.iter().any(|old| old == &r) { return Response::json(409, json!({"error":"node record already stored"})); }
            let v = serde_json::to_value(&r).unwrap(); if let Err(e) = append(s, "node", v) { return bad(e); } s.nodes.push(r); Response::json(201, json!({"accepted":true}))
        }
        "/jobs" => {
            let r: JobRecord = match strict(body, JOB_KEYS).and_then(|r| { authorized(&r)?; Ok(r) }) { Ok(r) => r, Err(e) => return bad(e) };
            if let Err(e) = validate_job(&r) { return bad(e); }
            if let Some(old) = job(s, &r.job_id) { if old != &r { return bad("job_id already has a different record"); } return bad("job_id already exists"); }
            let v = serde_json::to_value(&r).unwrap(); if let Err(e) = append(s, "job", v) { return bad(e); } s.jobs.push(r); Response::json(201, json!({"accepted":true}))
        }
        p if p.starts_with("/jobs/") && p.ends_with("/join") => {
            let id = &p[6..p.len()-5]; let r: JoinRecord = match strict(body, JOIN_KEYS).and_then(|r| { authorized(&r)?; Ok(r) }) { Ok(r) => r, Err(e) => return bad(e) };
            if r.job_id != id { return bad("path job id does not match record"); }
            if let Err(e) = validate_join(s, &r) { return bad(e); }
            let v = serde_json::to_value(&r).unwrap(); if let Err(e) = append(s, "join", v) { return bad(e); } s.joins.push(r); Response::json(201, json!({"accepted":true}))
        }
        p if p.starts_with("/jobs/") && p.ends_with("/result") => {
            let id = &p[6..p.len()-7]; let r: ResultRecord = match strict(body, RESULT_KEYS).and_then(|r| { authorized(&r)?; Ok(r) }) { Ok(r) => r, Err(e) => return bad(e) };
            if r.job_id != id { return bad("path job id does not match record"); }
            if let Err(e) = validate_result(s, &r) { return bad(e); }
            let v = serde_json::to_value(&r).unwrap(); if let Err(e) = append(s, "result", v) { return bad(e); } s.results.push(r); Response::json(201, json!({"accepted":true}))
        }
        _ => Response::json(404, json!({"error":"not found"})),
    }
}

fn bundle(s: &Store, id: &str) -> Response {
    let j = match job(s, id) { Some(j) => j.clone(), None => return Response::json(404, json!({"error":"unknown job"})) };
    let joins: Vec<_> = s.joins.iter().filter(|x| x.job_id == id).cloned().collect();
    let results: Vec<_> = s.results.iter().filter(|x| x.job_id == id).cloned().collect();
    let nodes: Vec<_> = joins.iter().filter_map(|x| latest_node(s, &x.node_id).cloned()).collect();
    if derived_state(s, &j) != JobState::Finished { return Response::json(409, json!({"error":"job lifecycle is incomplete"})); }
    if results.windows(2).any(|w| w[0].value != w[1].value) { return Response::json(409, json!({"error":"results disagree"})); }
    Response::json(200, serde_json::to_value(EvidenceBundle { version: BUNDLE_VERSION, job: j, nodes, joins, results }).unwrap())
}

struct Response { status: u16, body: Vec<u8>, content_type: &'static str }
impl Response {
    fn json(status: u16, value: Value) -> Self { Self { status, body: serde_json::to_vec(&value).unwrap(), content_type: "application/json" } }
    fn send(self, mut stream: TcpStream) -> std::io::Result<()> {
        let reason = match self.status { 200 => "OK", 201 => "Created", 400 => "Bad Request", 404 => "Not Found", 409 => "Conflict", _ => "Error" };
        write!(stream, "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", self.status, reason, self.content_type, self.body.len())?;
        stream.write_all(&self.body)
    }
}

fn query(path: &str) -> (&str, Vec<(&str, &str)>) {
    let mut parts = path.splitn(2, '?'); let route = parts.next().unwrap_or("");
    let params = parts.next().unwrap_or("").split('&').filter_map(|p| p.split_once('=')).collect(); (route, params)
}
fn param<'a>(params: &'a [(&str, &str)], key: &str) -> Option<&'a str> { params.iter().find(|(k, _)| *k == key).map(|(_, v)| *v) }

fn get(s: &Store, raw_path: &str) -> Response {
    let (path, params) = query(raw_path);
    if let Some(id) = path.strip_prefix("/jobs/").and_then(|x| x.strip_suffix("/bundle")) { return bundle(s, id); }
    match path {
        "/nodes" => {
            let measurement = param(&params, "measurement");
            let freshness = param(&params, "freshness").and_then(|x| x.parse::<u64>().ok());
            let cutoff = freshness.map(|f| now().saturating_sub(f));
            let mut seen = HashSet::new(); let nodes: Vec<_> = s.nodes.iter().rev().filter(|n| seen.insert(n.node_id.clone())).filter(|n| cutoff.map_or(true, |c| n.announced_at >= c)).filter(|n| measurement.map_or(true, |m| n.attestation.event_log.contains(m) || n.attestation.quote_hex.contains(m))).cloned().collect();
            Response::json(200, serde_json::to_value(nodes).unwrap())
        }
        "/jobs" => {
            let state = param(&params, "state");
            let mut seen = HashSet::new(); let jobs: Vec<_> = s.jobs.iter().rev().filter(|j| seen.insert(j.job_id.clone())).filter(|j| state.map_or(true, |x| serde_json::to_string(&derived_state(s, j)).unwrap().trim_matches('"').eq_ignore_ascii_case(x))).cloned().collect();
            Response::json(200, serde_json::to_value(jobs).unwrap())
        }
        _ => Response::json(404, json!({"error":"not found"})),
    }
}

fn handle(mut stream: TcpStream, store: Shared) {
    let mut bytes = Vec::new(); let mut chunk = [0u8; 4096]; let header_end;
    loop {
        let n = match stream.read(&mut chunk) { Ok(n) => n, Err(_) => return };
        if n == 0 { return; }
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") { header_end = end + 4; break; }
        if bytes.len() > 1024 * 1024 { let _ = bad("request headers too large").send(stream); return; }
    }
    let header = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = header.lines().find_map(|line| line.strip_prefix("Content-Length:").or_else(|| line.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
    while bytes.len() < header_end + content_length { let n = match stream.read(&mut chunk) { Ok(n) => n, Err(_) => return }; if n == 0 { return; } bytes.extend_from_slice(&chunk[..n]); }
    let request = String::from_utf8_lossy(&bytes[..header_end + content_length]); let mut lines = request.split("\r\n");
    let first = match lines.next() { Some(x) => x, None => return };
    let mut first_parts = first.split_whitespace(); let method = first_parts.next().unwrap_or(""); let path = first_parts.next().unwrap_or("");
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    let response = match store.lock() { Ok(mut s) => match method { "GET" => get(&s, path), "POST" => match serde_json::from_str(body) { Ok(v) => post(&mut s, query(path).0, v), Err(e) => bad(format!("malformed JSON: {e}")) }, _ => Response::json(400, json!({"error":"method not supported"})) }, Err(_) => Response::json(500, json!({"error":"store lock failed"})) };
    let _ = response.send(stream);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = env::var("LOBBY_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let path = env::var("LOBBY_STORE").unwrap_or_else(|_| "lobby.jsonl".to_string());
    let store = Arc::new(Mutex::new(load(Path::new(&path))?));
    let listener = TcpListener::bind(&addr)?;
    eprintln!("stoffel lobby listening on {addr}, store {path}");
    for stream in listener.incoming() { if let Ok(stream) = stream { let state = Arc::clone(&store); std::thread::spawn(move || handle(stream, state)); } }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use lobby_records::{node_id_for, sign_record, AttestationBlob, JobPolicy};

    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    fn store() -> Store { Store { path: env::temp_dir().join(format!("stoffel-lobby-test-{}-{}-{}.jsonl", std::process::id(), SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst), now())), ..Default::default() } }
    fn node(key: &SigningKey) -> NodeRecord {
        let pk = key.verifying_key().to_bytes();
        NodeRecord { node_id: node_id_for(&pk), pubkey: hex::encode(pk), endpoint: "node:8080".into(), max_parties: 2, supported_thresholds: vec![0], operator_label: "test".into(), attestation: AttestationBlob { quote_hex: "quote".into(), collateral_json: "{}".into(), event_log: "measurement".into() }, announced_at: now(), signature: String::new() }
    }
    fn node_with(key: &SigningKey, max_parties: usize, supported_thresholds: Vec<usize>) -> NodeRecord { let mut n = node(key); n.max_parties = max_parties; n.supported_thresholds = supported_thresholds; n }
    fn job(proposer: &str, n_parties: usize, threshold: usize) -> JobRecord {
        let program_id = "ab".repeat(32);
        JobRecord { job_id: job_id_for(&program_id, "main", n_parties, threshold).unwrap(), program_id, program_url: None, entry: "main".into(), n_parties, threshold, policy: JobPolicy::default(), not_before: None, state: JobState::Open, proposer: proposer.into(), created_at: now(), signature: String::new() }
    }
    fn join(id: &str, n: &NodeRecord, party: usize) -> JoinRecord { JoinRecord { job_id: id.into(), node_id: n.node_id.clone(), pubkey: n.pubkey.clone(), party_id: party, joined_at: now(), signature: String::new() } }
    fn result(id: &str, n: &NodeRecord, party: usize, program_id: &str) -> ResultRecord { ResultRecord { job_id: id.into(), node_id: n.node_id.clone(), pubkey: n.pubkey.clone(), party_id: party, value: "same".into(), program_id: program_id.into(), completed_at: now(), signature: String::new() } }
    fn post_record<T: serde::Serialize>(s: &mut Store, path: &str, record: &T) -> Response { post(s, path, serde_json::to_value(record).unwrap()) }
    fn body(r: &Response) -> String { String::from_utf8_lossy(&r.body).into_owned() }
    fn listed(s: &Store, state: &str) -> String { body(&get(s, &format!("/jobs?state={state}"))) }

    #[test]
    fn a_job_with_a_chosen_job_id_is_rejected() {
        let mut s = store(); let key = SigningKey::from_bytes(&[1; 32]); let mut n = node(&key); sign_record(&mut n, &key).unwrap();
        assert_eq!(post_record(&mut s, "/nodes", &n).status, 201);
        let mut j = job(&n.pubkey, 2, 0); j.job_id = "proposer-chosen".into(); sign_record(&mut j, &key).unwrap();
        let r = post_record(&mut s, "/jobs", &j);
        assert_eq!(r.status, 400);
        assert!(body(&r).contains("job_id does not match"), "{}", body(&r));
        let _ = std::fs::remove_file(s.path);
    }

    #[test]
    fn derived_state_tracks_the_record_counts() {
        let mut s = store(); let keys = [SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32])];
        let mut nodes = [node(&keys[0]), node(&keys[1])];
        for (i, n) in nodes.iter_mut().enumerate() { sign_record(n, &keys[i]).unwrap(); assert_eq!(post_record(&mut s, "/nodes", n).status, 201); }
        let mut j = job(&nodes[0].pubkey, 2, 0); sign_record(&mut j, &keys[0]).unwrap(); let id = j.job_id.clone();
        assert_eq!(post_record(&mut s, "/jobs", &j).status, 201);
        assert_eq!(derived_state(&s, &j), JobState::Open);
        assert!(listed(&s, "open").contains(&id));
        assert!(!listed(&s, "finished").contains(&id));
        for (i, party) in [(0usize, 0usize), (1, 1)] {
            let mut rec = join(&id, &nodes[i], party); sign_record(&mut rec, &keys[i]).unwrap();
            assert_eq!(post_record(&mut s, &format!("/jobs/{id}/join"), &rec).status, 201);
        }
        assert_eq!(derived_state(&s, &j), JobState::Forming);
        assert!(listed(&s, "forming").contains(&id));
        assert!(!listed(&s, "open").contains(&id));
        for (i, party) in [(0usize, 0usize), (1, 1)] {
            let mut rec = result(&id, &nodes[i], party, &j.program_id); sign_record(&mut rec, &keys[i]).unwrap();
            assert_eq!(post_record(&mut s, &format!("/jobs/{id}/result"), &rec).status, 201);
        }
        assert_eq!(derived_state(&s, &j), JobState::Finished);
        assert!(listed(&s, "finished").contains(&id));
        assert!(!listed(&s, "forming").contains(&id));
        let _ = std::fs::remove_file(s.path);
    }

    #[test]
    fn a_byte_identical_node_replay_conflicts_and_appends_nothing() {
        let mut s = store(); let key = SigningKey::from_bytes(&[4; 32]); let mut n = node(&key); sign_record(&mut n, &key).unwrap();
        assert_eq!(post_record(&mut s, "/nodes", &n).status, 201);
        let lines = BufReader::new(File::open(&s.path).unwrap()).lines().count();
        let r = post_record(&mut s, "/nodes", &n);
        assert_eq!(r.status, 409);
        assert_eq!(BufReader::new(File::open(&s.path).unwrap()).lines().count(), lines, "a 409 replay must not append");
        let _ = std::fs::remove_file(s.path);
    }

    #[test]
    fn join_is_gated_by_the_node_capabilities() {
        let mut s = store();
        let proposer = SigningKey::from_bytes(&[6; 32]); let mut p = node(&proposer); sign_record(&mut p, &proposer).unwrap();
        assert_eq!(post_record(&mut s, "/nodes", &p).status, 201);
        let small_key = SigningKey::from_bytes(&[7; 32]); let mut small = node_with(&small_key, 1, vec![0]); sign_record(&mut small, &small_key).unwrap();
        let picky_key = SigningKey::from_bytes(&[8; 32]); let mut picky = node_with(&picky_key, 4, vec![0]); sign_record(&mut picky, &picky_key).unwrap();
        for n in [&small, &picky] { assert_eq!(post_record(&mut s, "/nodes", n).status, 201); }
        let mut j = job(&p.pubkey, 4, 1); sign_record(&mut j, &proposer).unwrap(); let id = j.job_id.clone();
        assert_eq!(post_record(&mut s, "/jobs", &j).status, 201);
        for (key, n) in [(&small_key, &small), (&picky_key, &picky)] {
            let mut rec = join(&id, n, 0); sign_record(&mut rec, key).unwrap();
            let r = post_record(&mut s, &format!("/jobs/{id}/join"), &rec);
            assert_eq!(r.status, 400);
            assert!(body(&r).contains("capabilities"), "{}", body(&r));
        }
        let _ = std::fs::remove_file(s.path);
    }

    #[test]
    fn reload_runs_the_same_validation_as_writes() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut orphan = join(&"00".repeat(32), &node(&key), 0); sign_record(&mut orphan, &key).unwrap();
        let path = env::temp_dir().join(format!("lobby-reload-orphan-{}-{}.jsonl", std::process::id(), now()));
        std::fs::write(&path, serde_json::to_string(&json!({"kind": "join", "record": orphan})).unwrap()).unwrap();
        let err = match load(&path) { Err(e) => e, Ok(_) => panic!("orphan join store loaded") };
        assert!(err.contains("unknown job"), "{err}");
        let _ = std::fs::remove_file(&path);
        let mut impostor = node(&key); impostor.node_id = "00".repeat(32); sign_record(&mut impostor, &key).unwrap();
        let impostor_path = env::temp_dir().join(format!("lobby-reload-impostor-{}-{}.jsonl", std::process::id(), now()));
        std::fs::write(&impostor_path, serde_json::to_string(&json!({"kind": "node", "record": impostor})).unwrap()).unwrap();
        let err = match load(&impostor_path) { Err(e) => e, Ok(_) => panic!("impostor node store loaded") };
        assert!(err.contains("node_id does not match"), "{err}");
        let _ = std::fs::remove_file(&impostor_path);
    }

    #[test]
    fn two_node_lifecycle_returns_a_bundle_and_rejects_a_forgery() {
        let mut s = store(); let keys = [SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32])];
        let mut nodes = [node(&keys[0]), node(&keys[1])];
        for (i, n) in nodes.iter_mut().enumerate() { sign_record(n, &keys[i]).unwrap(); assert_eq!(post_record(&mut s, "/nodes", n).status, 201); }
        let mut j = job(&nodes[0].pubkey, 2, 0); sign_record(&mut j, &keys[0]).unwrap(); let id = j.job_id.clone();
        assert_eq!(post_record(&mut s, "/jobs", &j).status, 201);
        for (i, party) in [(0usize, 0usize), (1, 1)] {
            let mut rec = join(&id, &nodes[i], party); sign_record(&mut rec, &keys[i]).unwrap(); assert_eq!(post_record(&mut s, &format!("/jobs/{id}/join"), &rec).status, 201);
            let mut rec = result(&id, &nodes[i], party, &j.program_id); sign_record(&mut rec, &keys[i]).unwrap(); assert_eq!(post_record(&mut s, &format!("/jobs/{id}/result"), &rec).status, 201);
        }
        assert_eq!(bundle(&s, &id).status, 200);
        let mut forged = nodes[0].clone(); forged.operator_label = "tampered".into(); assert_eq!(post_record(&mut s, "/nodes", &forged).status, 400);
        let _ = std::fs::remove_file(s.path);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut s = store(); let mut value = serde_json::to_value(node(&SigningKey::from_bytes(&[3; 32]))).unwrap(); value.as_object_mut().unwrap().insert("unexpected".into(), json!(true));
        assert_eq!(post(&mut s, "/nodes", value).status, 400);
    }
}
