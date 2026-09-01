use lobby_records::{verify_signature, EvidenceBundle, JobRecord, JobState, JoinRecord, NodeRecord, ResultRecord, Signed, BUNDLE_VERSION};
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
        add_loaded(&mut store, env.kind.as_str(), env.record)?;
    }
    Ok(store)
}

fn add_loaded(store: &mut Store, kind: &str, value: Value) -> Result<(), String> {
    match kind {
        "node" => { let r: NodeRecord = strict(value, NODE_KEYS)?; authorized(&r)?; store.nodes.push(r); }
        "job" => { let r: JobRecord = strict(value, JOB_KEYS)?; authorized(&r)?; store.jobs.push(r); }
        "join" => { let r: JoinRecord = strict(value, JOIN_KEYS)?; authorized(&r)?; store.joins.push(r); }
        "result" => { let r: ResultRecord = strict(value, RESULT_KEYS)?; authorized(&r)?; store.results.push(r); }
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

fn post(s: &mut Store, path: &str, body: Value) -> Response {
    match path {
        "/nodes" => {
            let r: NodeRecord = match strict(body, NODE_KEYS).and_then(|r| { authorized(&r)?; Ok(r) }) { Ok(r) => r, Err(e) => return bad(e) };
            let pk = match hex::decode(&r.pubkey).ok().and_then(|b| <[u8;32]>::try_from(b).ok()) { Some(pk) => pk, None => return bad("pubkey is not 32-byte hex") };
            if lobby_records::node_id_for(&pk) != r.node_id { return bad("node_id does not match pubkey"); }
            if r.max_parties == 0 || r.supported_thresholds.iter().any(|t| 3 * t + 1 > r.max_parties) { return bad("invalid node capabilities"); }
            if let Some(old) = latest_node(s, &r.node_id) { if old.pubkey != r.pubkey { return bad("node identity is bound to another key"); } }
            let v = serde_json::to_value(&r).unwrap(); if let Err(e) = append(s, "node", v) { return bad(e); } s.nodes.push(r); Response::json(201, json!({"accepted":true}))
        }
        "/jobs" => {
            let r: JobRecord = match strict(body, JOB_KEYS).and_then(|r| { authorized(&r)?; Ok(r) }) { Ok(r) => r, Err(e) => return bad(e) };
            if r.n_parties < 3 * r.threshold + 1 || r.n_parties == 0 || r.state != JobState::Open { return bad("job must be open and satisfy n >= 3t + 1"); }
            if let Some(old) = job(s, &r.job_id) { if old != &r { return bad("job_id already has a different record"); } return bad("job_id already exists"); }
            let v = serde_json::to_value(&r).unwrap(); if let Err(e) = append(s, "job", v) { return bad(e); } s.jobs.push(r); Response::json(201, json!({"accepted":true}))
        }
        p if p.starts_with("/jobs/") && p.ends_with("/join") => {
            let id = &p[6..p.len()-5]; let r: JoinRecord = match strict(body, JOIN_KEYS).and_then(|r| { authorized(&r)?; Ok(r) }) { Ok(r) => r, Err(e) => return bad(e) };
            if r.job_id != id { return bad("path job id does not match record"); }
            let j = match job(s, id) { Some(j) => j, None => return bad("unknown job") };
            let n = match latest_node(s, &r.node_id) { Some(n) => n, None => return bad("unknown node") };
            if j.state != JobState::Open && j.state != JobState::Forming { return bad("job is not accepting joins"); }
            if n.pubkey != r.pubkey || r.party_id >= j.n_parties { return bad("join key or party is invalid"); }
            if s.joins.iter().any(|x| x.job_id == id && (x.node_id == r.node_id || x.party_id == r.party_id)) { return bad("node or party already joined"); }
            let v = serde_json::to_value(&r).unwrap(); if let Err(e) = append(s, "join", v) { return bad(e); } s.joins.push(r); Response::json(201, json!({"accepted":true}))
        }
        p if p.starts_with("/jobs/") && p.ends_with("/result") => {
            let id = &p[6..p.len()-7]; let r: ResultRecord = match strict(body, RESULT_KEYS).and_then(|r| { authorized(&r)?; Ok(r) }) { Ok(r) => r, Err(e) => return bad(e) };
            if r.job_id != id { return bad("path job id does not match record"); }
            let j = match job(s, id) { Some(j) => j, None => return bad("unknown job") };
            let n = match latest_node(s, &r.node_id) { Some(n) => n, None => return bad("unknown node") };
            if n.pubkey != r.pubkey || r.program_id != j.program_id { return bad("result key or program is invalid"); }
            if !s.joins.iter().any(|x| x.job_id == id && x.node_id == r.node_id && x.party_id == r.party_id) { return bad("result has no matching join"); }
            if s.results.iter().any(|x| x.job_id == id && x.node_id == r.node_id) { return bad("node already posted a result"); }
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
    if joins.len() != j.n_parties || results.len() != j.n_parties { return Response::json(409, json!({"error":"job lifecycle is incomplete"})); }
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
            let mut seen = HashSet::new(); let jobs: Vec<_> = s.jobs.iter().rev().filter(|j| seen.insert(j.job_id.clone())).filter(|j| state.map_or(true, |x| serde_json::to_string(&j.state).unwrap().trim_matches('"').eq_ignore_ascii_case(x))).cloned().collect();
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

    fn store() -> Store { Store { path: env::temp_dir().join(format!("stoffel-lobby-test-{}-{}.jsonl", std::process::id(), now())), ..Default::default() } }
    fn node(key: &SigningKey) -> NodeRecord {
        let pk = key.verifying_key().to_bytes();
        NodeRecord { node_id: node_id_for(&pk), pubkey: hex::encode(pk), endpoint: "node:8080".into(), max_parties: 2, supported_thresholds: vec![0], operator_label: "test".into(), attestation: AttestationBlob { quote_hex: "quote".into(), collateral_json: "{}".into(), event_log: "measurement".into() }, announced_at: now(), signature: String::new() }
    }
    fn post_record<T: serde::Serialize>(s: &mut Store, path: &str, record: &T) -> Response { post(s, path, serde_json::to_value(record).unwrap()) }

    #[test]
    fn two_node_lifecycle_returns_a_bundle_and_rejects_a_forgery() {
        let mut s = store(); let keys = [SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32])];
        let mut nodes = [node(&keys[0]), node(&keys[1])];
        for (i, n) in nodes.iter_mut().enumerate() { sign_record(n, &keys[i]).unwrap(); assert_eq!(post_record(&mut s, "/nodes", n).status, 201); }
        let mut job = JobRecord { job_id: "job".into(), program_id: "program".into(), program_url: None, entry: "main".into(), n_parties: 2, threshold: 0, policy: JobPolicy::default(), not_before: None, state: JobState::Open, proposer: nodes[0].pubkey.clone(), created_at: now(), signature: String::new() };
        sign_record(&mut job, &keys[0]).unwrap(); assert_eq!(post_record(&mut s, "/jobs", &job).status, 201);
        for (i, n) in nodes.iter().enumerate() {
            let mut join = JoinRecord { job_id: "job".into(), node_id: n.node_id.clone(), pubkey: n.pubkey.clone(), party_id: i, joined_at: now(), signature: String::new() }; sign_record(&mut join, &keys[i]).unwrap(); assert_eq!(post_record(&mut s, "/jobs/job/join", &join).status, 201);
            let mut result = ResultRecord { job_id: "job".into(), node_id: n.node_id.clone(), pubkey: n.pubkey.clone(), party_id: i, value: "same".into(), program_id: "program".into(), completed_at: now(), signature: String::new() }; sign_record(&mut result, &keys[i]).unwrap(); assert_eq!(post_record(&mut s, "/jobs/job/result", &result).status, 201);
        }
        assert_eq!(bundle(&s, "job").status, 200);
        let mut forged = nodes[0].clone(); forged.operator_label = "tampered".into(); assert_eq!(post_record(&mut s, "/nodes", &forged).status, 400);
        let _ = std::fs::remove_file(s.path);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut s = store(); let mut value = serde_json::to_value(node(&SigningKey::from_bytes(&[3; 32]))).unwrap(); value.as_object_mut().unwrap().insert("unexpected".into(), json!(true));
        assert_eq!(post(&mut s, "/nodes", value).status, 400);
    }
}
