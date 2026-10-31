//! Socket-level evidence for issue #2: drives the real `stoffel-lobby` binary
//! over HTTP from a separate process, then re-verifies the returned bundle with
//! `lobby_records` alone — the reader re-verifies, the service is never asked
//! for a verdict. This repo has no staging deployment, so this run captured
//! with `-- --nocapture` is the Tier 1 transcript.

use ed25519_dalek::SigningKey;
use lobby_records::{
    job_id_for, node_id_for, sign_record, verify_signature, AttestationBlob, EvidenceBundle,
    JobPolicy, JobRecord, JobState, JoinRecord, NodeRecord, ResultRecord, Signed,
};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).expect("clock before epoch").as_secs() }

fn node(key: &SigningKey) -> NodeRecord {
    let pk = key.verifying_key().to_bytes();
    NodeRecord {
        node_id: node_id_for(&pk), pubkey: hex::encode(pk), endpoint: "node:8080".into(),
        max_parties: 2, supported_thresholds: vec![0], operator_label: "evidence".into(),
        attestation: AttestationBlob { quote_hex: "quote".into(), collateral_json: "{}".into(), event_log: "measurement".into() },
        announced_at: now(), signature: String::new(),
    }
}

fn node_with(key: &SigningKey, max_parties: usize, supported_thresholds: Vec<usize>) -> NodeRecord {
    let mut n = node(key); n.max_parties = max_parties; n.supported_thresholds = supported_thresholds; n
}

fn job(proposer: &str, n_parties: usize, threshold: usize) -> JobRecord {
    let program_id = "ab".repeat(32);
    JobRecord {
        job_id: job_id_for(&program_id, "main", n_parties, threshold).unwrap(), program_id,
        program_url: None, entry: "main".into(), n_parties, threshold,
        policy: JobPolicy::default(), not_before: None,
        state: JobState::Open, proposer: proposer.into(), created_at: now(), signature: String::new(),
    }
}

fn signed<T: Signed + Clone + serde::Serialize>(mut record: T, key: &SigningKey) -> Value {
    sign_record(&mut record, key).unwrap();
    serde_json::to_value(&record).unwrap()
}

struct Server { child: Child, addr: SocketAddr, stderr: Arc<Mutex<Vec<String>>> }

fn command(store: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_stoffel-lobby"));
    // a port we hold and release, so the test knows where the server will be
    let port = std::net::TcpListener::bind("127.0.0.1:0").expect("allocate a port").local_addr().unwrap().port();
    c.env("LOBBY_ADDR", format!("127.0.0.1:{port}")).env("LOBBY_STORE", store).stderr(Stdio::piped());
    c
}

fn start(store: &Path) -> Server {
    let mut child = command(store).spawn().expect("spawn stoffel-lobby");
    let pipe = child.stderr.take().unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            match line { Ok(l) => sink.lock().unwrap().push(l), Err(_) => break }
        }
    });
    // the startup line echoes LOBBY_ADDR, so the port it names is the one we chose in spawn_on()
    let prefix = "stoffel lobby listening on ";
    let deadline = Instant::now() + Duration::from_secs(60);
    let addr = loop {
        if let Some(line) = lines.lock().unwrap().iter().find(|l| l.starts_with(prefix)) {
            break line[prefix.len()..].split(',').next().unwrap().trim().parse().expect("parse listening addr");
        }
        if let Some(status) = child.try_wait().expect("poll server") {
            panic!("server exited before listening ({status}): {}", lines.lock().unwrap().join("\n"));
        }
        assert!(Instant::now() < deadline, "server never listened");
        thread::sleep(Duration::from_millis(20));
    };
    Server { child, addr, stderr: lines }
}

impl Server {
    fn stop(&mut self) { self.child.kill().expect("kill server"); self.child.wait().unwrap(); }
}

fn http(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, String) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match TcpStream::connect(addr) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("connect to {addr}: {e}"),
        }
    };
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: lobby\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("write request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read response");
    let status = raw.split_whitespace().nth(1).unwrap().parse().expect("status code");
    (status, raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn exchange(addr: SocketAddr, method: &str, path: &str, body: &str, expected: u16) -> String {
    let (status, payload) = http(addr, method, path, body);
    let shown: String = payload.chars().take(400).collect();
    println!("{} {} -> {} {}", method, path, status, shown);
    assert_eq!(status, expected, "unexpected status for {method} {path}: {payload}");
    payload
}

fn listed(addr: SocketAddr, state: &str) -> Vec<String> {
    let (status, payload) = http(addr, "GET", &format!("/jobs?state={state}"), "");
    assert_eq!(status, 200, "GET /jobs?state={state}: {payload}");
    let jobs: Vec<Value> = serde_json::from_str(&payload).expect("job list deserializes");
    println!("GET /jobs?state={state} -> {:?}", jobs.iter().map(|j| j["job_id"].as_str().unwrap_or("?")).collect::<Vec<_>>());
    jobs.iter().map(|j| j["job_id"].as_str().expect("job_id").to_string()).collect()
}

#[test]
fn http_write_path_gates_transcript() {
    let store: PathBuf = std::env::temp_dir().join(format!("lobby-http-gates-{}-{}.jsonl", std::process::id(), now()));
    let mut server = start(&store);
    println!("server stderr: {}", server.stderr.lock().unwrap().join("\n"));

    let proposer = SigningKey::from_bytes(&[9; 32]);
    let good = [SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32])];
    let mut p = node(&proposer); sign_record(&mut p, &proposer).unwrap();
    exchange(server.addr, "POST", "/nodes", &signed(p.clone(), &proposer).to_string(), 201);
    let mut nodes = [node(&good[0]), node(&good[1])];
    for (i, n) in nodes.iter_mut().enumerate() { sign_record(n, &good[i]).unwrap(); exchange(server.addr, "POST", "/nodes", &serde_json::to_value(n).unwrap().to_string(), 201); }
    // announced below the job's (n=2, t=0) needs
    let small = SigningKey::from_bytes(&[4; 32]);
    let mut too_small = node_with(&small, 1, vec![0]); sign_record(&mut too_small, &small).unwrap();
    let picky = SigningKey::from_bytes(&[5; 32]);
    let mut no_threshold = node_with(&picky, 2, vec![]); sign_record(&mut no_threshold, &picky).unwrap();
    for n in [&too_small, &no_threshold] { exchange(server.addr, "POST", "/nodes", &serde_json::to_value(n).unwrap().to_string(), 201); }

    // job ids are derived, never proposer-chosen
    let mut chosen = job(&p.pubkey, 2, 0); chosen.job_id = "proposer-chosen".into(); sign_record(&mut chosen, &proposer).unwrap();
    let rejected = exchange(server.addr, "POST", "/jobs", &serde_json::to_value(&chosen).unwrap().to_string(), 400);
    assert!(rejected.contains("job_id does not match"), "{rejected}");

    let j = job(&p.pubkey, 2, 0); let id = j.job_id.clone();
    exchange(server.addr, "POST", "/jobs", &signed(j.clone(), &proposer).to_string(), 201);
    println!("derived job_id: {id}");

    // GET /jobs filters on the state derived from the record stream
    assert!(listed(server.addr, "open").contains(&id));
    assert!(!listed(server.addr, "finished").contains(&id));

    // joins are gated by the node's announced capabilities
    for (key, n, why) in [(&small, &too_small, "max_parties < n_parties"), (&picky, &no_threshold, "threshold not in supported_thresholds")] {
        let join = JoinRecord { job_id: id.clone(), node_id: n.node_id.clone(), pubkey: n.pubkey.clone(), party_id: 0, joined_at: now(), signature: String::new() };
        let out = exchange(server.addr, "POST", &format!("/jobs/{id}/join"), &signed(join, key).to_string(), 400);
        assert!(out.contains("capabilities"), "{why}: {out}");
    }

    // a byte-identical node replay conflicts and appends nothing
    let lines = || BufReader::new(std::fs::File::open(&store).unwrap()).lines().count();
    let before = lines();
    let replay = exchange(server.addr, "POST", "/nodes", &signed(nodes[0].clone(), &good[0]).to_string(), 409);
    assert!(replay.contains("already stored"), "{replay}");
    assert_eq!(lines(), before, "a 409 replay must not append");

    // the lifecycle advances open -> forming -> finished, from the record counts
    for (i, party) in [(0usize, 0usize), (1, 1)] {
        let join = JoinRecord { job_id: id.clone(), node_id: nodes[i].node_id.clone(), pubkey: nodes[i].pubkey.clone(), party_id: party, joined_at: now(), signature: String::new() };
        exchange(server.addr, "POST", &format!("/jobs/{id}/join"), &signed(join, &good[i]).to_string(), 201);
        if party == 0 { assert!(listed(server.addr, "open").contains(&id)); assert!(!listed(server.addr, "forming").contains(&id)); }
    }
    assert!(listed(server.addr, "forming").contains(&id));
    assert!(!listed(server.addr, "open").contains(&id));
    for (i, party) in [(0usize, 0usize), (1, 1)] {
        let result = ResultRecord { job_id: id.clone(), node_id: nodes[i].node_id.clone(), pubkey: nodes[i].pubkey.clone(), party_id: party, value: "7".into(), program_id: j.program_id.clone(), completed_at: now(), signature: String::new() };
        exchange(server.addr, "POST", &format!("/jobs/{id}/result"), &signed(result, &good[i]).to_string(), 201);
    }
    assert!(listed(server.addr, "finished").contains(&id));
    assert!(!listed(server.addr, "forming").contains(&id));
    exchange(server.addr, "GET", &format!("/jobs/{id}/bundle"), "", 200);
    server.stop();

    // reload runs the same validation: the store above must come back up, and a bad reference must not
    let mut server = start(&store);
    assert!(listed(server.addr, "finished").contains(&id), "reloaded store must still list the finished job");
    server.stop();

    let mut orphan = JoinRecord { job_id: "00".repeat(32), node_id: nodes[0].node_id.clone(), pubkey: nodes[0].pubkey.clone(), party_id: 0, joined_at: now(), signature: String::new() };
    sign_record(&mut orphan, &good[0]).unwrap();
    let mut file = std::fs::OpenOptions::new().append(true).open(&store).unwrap();
    writeln!(file, "{}", json!({"kind": "join", "record": orphan})).unwrap();
    drop(file);
    let out = command(&store).output().expect("run stoffel-lobby on a store with an orphan join");
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!("restart with an orphan join -> exit {:?}, stderr: {}", out.status.code(), stderr.trim_end());
    assert!(!out.status.success());
    assert!(stderr.contains("unknown job"), "orphan join was accepted on reload: {stderr}");

    let impostor_store = std::env::temp_dir().join(format!("lobby-http-impostor-{}-{}.jsonl", std::process::id(), now()));
    let mut impostor = node(&proposer); impostor.node_id = "00".repeat(32); sign_record(&mut impostor, &proposer).unwrap();
    std::fs::write(&impostor_store, json!({"kind": "node", "record": impostor}).to_string() + "\n").unwrap();
    let out = command(&impostor_store).output().expect("run stoffel-lobby on an impostor node store");
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!("restart with a mismatched node_id -> exit {:?}, stderr: {}", out.status.code(), stderr.trim_end());
    assert!(!out.status.success());
    assert!(stderr.contains("node_id does not match pubkey"), "mismatched node_id accepted on reload: {stderr}");

    let _ = std::fs::remove_file(&store);
    let _ = std::fs::remove_file(&impostor_store);
}

#[test]
fn http_lifecycle_bundle_and_reload_transcript() {
    let store: PathBuf = std::env::temp_dir().join(format!("lobby-http-evidence-{}-{}.jsonl", std::process::id(), now()));
    let mut server = start(&store);
    println!("server stderr: {}", server.stderr.lock().unwrap().join("\n"));

    let keys = [SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32])];
    let nodes = [node(&keys[0]), node(&keys[1])];

    exchange(server.addr, "POST", "/nodes", &signed(nodes[0].clone(), &keys[0]).to_string(), 201);
    exchange(server.addr, "POST", "/nodes", &signed(nodes[1].clone(), &keys[1]).to_string(), 201);

    let mut tampered = signed(nodes[0].clone(), &keys[0]);
    tampered["operator_label"] = json!("tampered");
    exchange(server.addr, "POST", "/nodes", &tampered.to_string(), 400);
    // the record names node 0's key but node 1 signed it
    exchange(server.addr, "POST", "/nodes", &signed(nodes[0].clone(), &keys[1]).to_string(), 400);
    let mut unknown_field = signed(nodes[0].clone(), &keys[0]);
    unknown_field["unexpected"] = json!(true);
    exchange(server.addr, "POST", "/nodes", &unknown_field.to_string(), 400);
    exchange(server.addr, "POST", "/nodes", "{not json", 400);

    let j = job(&nodes[0].pubkey, 2, 0); let id = j.job_id.clone();
    exchange(server.addr, "POST", "/jobs", &signed(j.clone(), &keys[0]).to_string(), 201);
    // the lifecycle is incomplete: the service must refuse, not fabricate a bundle
    exchange(server.addr, "GET", &format!("/jobs/{id}/bundle"), "", 409);

    for i in 0..2 {
        let join = JoinRecord { job_id: id.clone(), node_id: nodes[i].node_id.clone(), pubkey: nodes[i].pubkey.clone(), party_id: i, joined_at: now(), signature: String::new() };
        exchange(server.addr, "POST", &format!("/jobs/{id}/join"), &signed(join, &keys[i]).to_string(), 201);
        let result = ResultRecord { job_id: id.clone(), node_id: nodes[i].node_id.clone(), pubkey: nodes[i].pubkey.clone(), party_id: i, value: "7".into(), program_id: j.program_id.clone(), completed_at: now(), signature: String::new() };
        exchange(server.addr, "POST", &format!("/jobs/{id}/result"), &signed(result, &keys[i]).to_string(), 201);
    }

    let body = exchange(server.addr, "GET", &format!("/jobs/{id}/bundle"), "", 200);
    println!("bundle: {body}");
    let bundle: EvidenceBundle = serde_json::from_str(&body).expect("bundle deserializes");
    assert_eq!((bundle.nodes.len(), bundle.joins.len(), bundle.results.len()), (2, 2, 2));
    assert_eq!(bundle.job.job_id, id);

    // independent re-verification, lobby_records only; the service is not involved
    verify_signature(&bundle.job).unwrap();
    for record in &bundle.nodes { verify_signature(record).unwrap(); }
    for record in &bundle.joins { verify_signature(record).unwrap(); }
    for record in &bundle.results { verify_signature(record).unwrap(); }
    println!("independent verify_signature over job + 2 nodes + 2 joins + 2 results: ok");
    let mut forged = serde_json::from_str::<Value>(&body).unwrap();
    forged["results"][0]["value"] = json!("different");
    let forged: EvidenceBundle = serde_json::from_value(forged).unwrap();
    let rejected = verify_signature(&forged.results[0]).unwrap_err();
    println!("tampered bundle result rejected without the service: {rejected}");

    println!("store file:\n{}", std::fs::read_to_string(&store).unwrap().trim_end());
    server.stop();

    // restart on the same store: every record reloads and re-verifies
    let mut server = start(&store);
    println!("server stderr: {}", server.stderr.lock().unwrap().join("\n"));
    exchange(server.addr, "GET", &format!("/jobs/{id}/bundle"), "", 200);
    server.stop();

    // a tampered line in the store must stop the next startup, not be downgraded
    let mut line = json!({"kind": "node", "record": signed(nodes[0].clone(), &keys[0])});
    line["record"]["operator_label"] = json!("tampered");
    let mut file = std::fs::OpenOptions::new().append(true).open(&store).unwrap();
    writeln!(file, "{line}").unwrap();
    drop(file);
    let out = command(&store).output().expect("run stoffel-lobby on tampered store");
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!("restart with a tampered store line -> exit {:?}, stderr: {}", out.status.code(), stderr.trim_end());
    assert!(!out.status.success());
    assert!(stderr.contains("signature does not verify"), "tampered record was accepted on reload: {stderr}");

    let _ = std::fs::remove_file(&store);
}
