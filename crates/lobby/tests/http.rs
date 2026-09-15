//! Socket-level evidence for issue #2: drives the real `stoffel-lobby` binary
//! over HTTP from a separate process, then re-verifies the returned bundle with
//! `lobby_records` alone — the reader re-verifies, the service is never asked
//! for a verdict. This repo has no staging deployment, so this run captured
//! with `-- --nocapture` is the Tier 1 transcript.

use ed25519_dalek::SigningKey;
use lobby_records::{
    node_id_for, sign_record, verify_signature, AttestationBlob, EvidenceBundle, JobPolicy,
    JobRecord, JobState, JoinRecord, NodeRecord, ResultRecord, Signed,
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

fn node(key: &SigningKey, measurement: &str) -> NodeRecord {
    let pk = key.verifying_key().to_bytes();
    NodeRecord {
        node_id: node_id_for(&pk), pubkey: hex::encode(pk), endpoint: "node:8080".into(),
        max_parties: 2, supported_thresholds: vec![0], operator_label: "evidence".into(),
        attestation: AttestationBlob { quote_hex: "quote".into(), collateral_json: "{}".into(), event_log: "measurement".into() },
        measurement: measurement.into(), announced_at: now(), signature: String::new(),
    }
}

fn job(proposer: &str) -> JobRecord {
    JobRecord {
        job_id: "job".into(), program_id: "program".into(), program_url: None, entry: "main".into(),
        n_parties: 2, threshold: 0, policy: JobPolicy::default(), not_before: None,
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

/// Write the request bytes verbatim, for headers `http()` would normalize.
fn raw_http(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.write_all(request.as_bytes()).expect("write request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read response");
    println!("raw request -> {}", raw.split("\r\n\r\n").nth(1).unwrap_or(""));
    let status = raw.split_whitespace().nth(1).unwrap().parse().expect("status code");
    (status, raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

#[test]
fn http_lifecycle_bundle_and_reload_transcript() {
    let store: PathBuf = std::env::temp_dir().join(format!("lobby-http-evidence-{}-{}.jsonl", std::process::id(), now()));
    let mut server = start(&store);
    println!("server stderr: {}", server.stderr.lock().unwrap().join("\n"));

    let keys = [SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32])];
    let m0 = "aa".repeat(32);
    let m1 = "55".repeat(32);
    let nodes = [node(&keys[0], &m0), node(&keys[1], &m1)];

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

    exchange(server.addr, "POST", "/jobs", &signed(job(&nodes[0].pubkey), &keys[0]).to_string(), 201);
    // the lifecycle is incomplete: the service must refuse, not fabricate a bundle
    exchange(server.addr, "GET", "/jobs/job/bundle", "", 409);

    for i in 0..2 {
        let join = JoinRecord { job_id: "job".into(), node_id: nodes[i].node_id.clone(), pubkey: nodes[i].pubkey.clone(), party_id: i, joined_at: now(), signature: String::new() };
        exchange(server.addr, "POST", "/jobs/job/join", &signed(join, &keys[i]).to_string(), 201);
        let result = ResultRecord { job_id: "job".into(), node_id: nodes[i].node_id.clone(), pubkey: nodes[i].pubkey.clone(), party_id: i, value: "7".into(), program_id: "program".into(), completed_at: now(), signature: String::new() };
        exchange(server.addr, "POST", "/jobs/job/result", &signed(result, &keys[i]).to_string(), 201);
    }

    let body = exchange(server.addr, "GET", "/jobs/job/bundle", "", 200);
    println!("bundle: {body}");
    let bundle: EvidenceBundle = serde_json::from_str(&body).expect("bundle deserializes");
    assert_eq!((bundle.nodes.len(), bundle.joins.len(), bundle.results.len()), (2, 2, 2));
    assert_eq!(bundle.job.job_id, "job");

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
    exchange(server.addr, "GET", "/jobs/job/bundle", "", 200);
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

#[test]
fn measurement_filter_and_query_validation_transcript() {
    let store: PathBuf = std::env::temp_dir().join(format!("lobby-http-filter-{}-{}.jsonl", std::process::id(), now()));
    let mut server = start(&store);

    // node 0 runs m0, node 1 runs m1; both announce through the real HTTP path
    let keys = [SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32])];
    let m0 = "aa".repeat(32);
    let m1 = "55".repeat(32);
    let nodes = [node(&keys[0], &m0), node(&keys[1], &m1)];
    for (i, n) in nodes.iter().enumerate() {
        exchange(server.addr, "POST", "/nodes", &signed(n.clone(), &keys[i]).to_string(), 201);
    }

    // exact equality: one matching node out of two, the other is not returned
    let body = exchange(server.addr, "GET", &format!("/nodes?measurement={m0}"), "", 200);
    let listed: Vec<NodeRecord> = serde_json::from_str(&body).expect("nodes deserialize");
    assert_eq!(listed.len(), 1, "measurement filter must be exact, got: {body}");
    assert_eq!(listed[0].node_id, nodes[0].node_id);
    assert_eq!(listed[0].measurement, m0);
    let body = exchange(server.addr, "GET", &format!("/nodes?measurement={m1}"), "", 200);
    let listed: Vec<NodeRecord> = serde_json::from_str(&body).expect("nodes deserialize");
    assert_eq!((listed.len(), listed[0].node_id.as_str()), (1, nodes[1].node_id.as_str()));

    // the old substring behavior: a two-char value that appears inside both
    // measurements is now a 400, not a list of every node
    let (status, body) = http(server.addr, "GET", "/nodes?measurement=aa", "");
    assert_eq!(status, 400, "substring measurement must not filter: {body}");
    assert!(body.contains("measurement"), "400 must name the parameter: {body}");
    println!("GET /nodes?measurement=aa -> {status} {body}");
    // 64 chars but not hex
    exchange(server.addr, "GET", &format!("/nodes?measurement={}", "zz".repeat(32)), "", 400);
    // freshness that does not parse as u64
    let (status, body) = http(server.addr, "GET", "/nodes?freshness=soon", "");
    assert_eq!(status, 400, "unparsable freshness must 400: {body}");
    assert!(body.contains("freshness"), "400 must name the parameter: {body}");
    println!("GET /nodes?freshness=soon -> {status} {body}");
    // state that is not a JobState
    let (status, body) = http(server.addr, "GET", "/jobs?state=running-behind", "");
    assert_eq!(status, 400, "unknown state must 400: {body}");
    assert!(body.contains("state"), "400 must name the parameter: {body}");
    println!("GET /jobs?state=running-behind -> {status} {body}");
    // a query pair without '='
    let (status, body) = http(server.addr, "GET", "/nodes?measurement", "");
    assert_eq!(status, 400, "pair without '=' must 400: {body}");
    assert!(body.contains("measurement"), "400 must name the parameter: {body}");
    println!("GET /nodes?measurement -> {status} {body}");
    let (status, body) = http(server.addr, "GET", "/nodes?freshness=5&measurement", "");
    assert_eq!(status, 400, "pair without '=' must 400 even after valid pairs: {body}");
    assert!(body.contains("measurement"), "400 must name the parameter: {body}");
    println!("GET /nodes?freshness=5&measurement -> {status} {body}");

    // the valid forms still work
    let body = exchange(server.addr, "GET", "/nodes?freshness=60", "", 200);
    let listed: Vec<NodeRecord> = serde_json::from_str(&body).expect("nodes deserialize");
    assert_eq!(listed.len(), 2, "both nodes are fresh: {body}");
    let body = exchange(server.addr, "GET", "/nodes?measurement=zz", "", 400);
    assert!(body.contains("measurement"));
    exchange(server.addr, "GET", "/jobs?state=open", "", 200);
    // POST with a malformed query is refused too, not silently stripped
    let mut post = serde_json::to_value(&nodes[0]).unwrap();
    post["signature"] = json!("");
    let (status, body) = http(server.addr, "POST", "/nodes?measurement", &post.to_string());
    assert_eq!(status, 400, "POST query syntax must be validated: {body}");
    println!("POST /nodes?measurement -> {status} {body}");

    server.stop();
    let _ = std::fs::remove_file(&store);
}

#[test]
fn content_length_header_transcript() {
    let store: PathBuf = std::env::temp_dir().join(format!("lobby-http-cl-{}-{}.jsonl", std::process::id(), now()));
    let mut server = start(&store);

    // any casing is honored: CONTENT-LENGTH: 0 reads as a bodyless GET
    let (status, body) = raw_http(server.addr, "GET /nodes HTTP/1.1\r\nHost: lobby\r\nCONTENT-LENGTH: 0\r\nConnection: close\r\n\r\n");
    assert_eq!(status, 200, "case-insensitive Content-Length must be honored: {body}");
    println!("GET with CONTENT-LENGTH: 0 -> {status} {body}");

    // missing Content-Length: the old code fell back to 0 and read no body
    let (status, body) = raw_http(server.addr, "GET /nodes HTTP/1.1\r\nHost: lobby\r\nConnection: close\r\n\r\n");
    assert_eq!(status, 400, "missing Content-Length must 400: {body}");
    assert!(body.contains("Content-Length"), "400 must say what is wrong: {body}");
    println!("GET without Content-Length -> {status} {body}");

    // present but unparsable
    let (status, body) = raw_http(server.addr, "GET /nodes HTTP/1.1\r\nHost: lobby\r\nContent-Length: many\r\nConnection: close\r\n\r\n");
    assert_eq!(status, 400, "unparsable Content-Length must 400: {body}");
    assert!(body.contains("Content-Length"), "400 must say what is wrong: {body}");
    println!("GET with Content-Length: many -> {status} {body}");

    server.stop();
    let _ = std::fs::remove_file(&store);
}
