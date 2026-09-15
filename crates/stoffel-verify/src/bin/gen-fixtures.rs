//! Deterministic generator for the committed bundle fixtures under
//! `evidence/bundles/`. Run from the workspace root:
//!
//! ```text
//! cargo run -p stoffel-verify --bin gen-fixtures
//! ```
//!
//! Provenance of the attestation material (see `tests/fixtures/README.md`):
//! the raw TDX quote + DCAP collateral are the real `dcap-qvl` sample vendored
//! in the StoffelVM fork, and the event log is the captured w7 pod log. The
//! node keys, job and results are synthetic but properly signed. Two of the
//! six fixtures the issue asks for cannot be produced from these materials and
//! are not written; `evidence/bundles/README.md` says why.
//!
//! Everything is derived from fixed seeds and fixed timestamps, so re-running
//! reproduces the committed files byte for byte.

use lobby_records::{sign_record, AttestationBlob, EvidenceBundle, JobPolicy, JobRecord, JobState, JoinRecord, NodeRecord, ResultRecord, BUNDLE_VERSION};
use std::path::PathBuf;

/// Inside the vendored collateral validity window (2025-06-19 .. 2025-07-19).
/// Every fixture that reaches quote verification must be verified with
/// `stoffel-verify --at` inside this window; the collateral is expired at wall
/// clock time and that expiry is a real check, not something to work around.
pub const FIXTURE_VERIFY_AT: u64 = 1_751_328_000; // 2025-07-01T00:00:00Z

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn materials() -> (String, String, String) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let quote_hex = hex::encode(std::fs::read(dir.join("tdx_quote.bin")).expect("tdx_quote.bin"));
    let collateral_json = std::fs::read_to_string(dir.join("tdx_quote_collateral.json")).expect("collateral json");
    let event_log = std::fs::read_to_string(dir.join("pod_event_log.json")).expect("pod event log");
    (quote_hex, collateral_json, event_log)
}

/// `blake3(mr_td || rtmr0..2)` of the sample quote — the measurement the
/// verifier extracts. Read straight out of the quote bytes (TD v4 layout:
/// 48-byte header, then the TD report; mr_td and rt_mr0..2 precede report_data).
fn measurement_of_quote(quote: &[u8]) -> [u8; 32] {
    use std::io::Read;
    let mut cursor = std::io::Cursor::new(quote);
    let mut take = |n: usize| {
        let mut buf = vec![0u8; n];
        cursor.read_exact(&mut buf).expect("quote truncated");
        buf
    };
    let _header = take(48);
    let _tee_tcb_svn = take(16);
    let _mr_seam = take(48);
    let _mr_signer_seam = take(48);
    let _seam_attributes = take(8);
    let _td_attributes = take(8);
    let _xfam = take(8);
    let mr_td = take(48);
    let _mr_config_id = take(48);
    let _mr_owner = take(48);
    let _mr_owner_config = take(48);
    let rtmr0 = take(48);
    let rtmr1 = take(48);
    let rtmr2 = take(48);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&mr_td);
    hasher.update(&rtmr0);
    hasher.update(&rtmr1);
    hasher.update(&rtmr2);
    *hasher.finalize().as_bytes()
}

fn main() {
    let (quote_hex, collateral_json, event_log) = materials();
    let measurement = hex::encode(measurement_of_quote(&hex::decode(&quote_hex).expect("quote hex")));

    let node0 = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let node1 = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
    let proposer = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);

    let attestation = AttestationBlob { quote_hex, collateral_json, event_log };

    let node = |key: &ed25519_dalek::SigningKey, label: &str| {
        let pk = key.verifying_key().to_bytes();
        let mut r = NodeRecord {
            node_id: lobby_records::node_id_for(&pk),
            pubkey: hex::encode(pk),
            endpoint: format!("{label}:8080"),
            max_parties: 2,
            supported_thresholds: vec![0],
            operator_label: label.to_string(),
            attestation: attestation.clone(),
            announced_at: 1_786_836_042,
            signature: String::new(),
        };
        sign_record(&mut r, key).expect("sign node");
        r
    };

    let mut base_job = JobRecord {
        job_id: "f00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeed".into(),
        program_id: "7144a194d6364ed2".into(),
        program_url: None,
        entry: "main".into(),
        n_parties: 2,
        threshold: 0,
        policy: JobPolicy { allowed_measurements: vec![measurement], allowed_compose_hashes: vec![] },
        not_before: None,
        state: JobState::Finished,
        proposer: hex::encode(proposer.verifying_key().to_bytes()),
        created_at: 1_786_836_030,
        signature: String::new(),
    };
    sign_record(&mut base_job, &proposer).expect("sign job");

    let join = |key: &ed25519_dalek::SigningKey, node: &NodeRecord, party: usize, at: u64| {
        let mut r = JoinRecord {
            job_id: base_job.job_id.clone(),
            node_id: node.node_id.clone(),
            pubkey: node.pubkey.clone(),
            party_id: party,
            joined_at: at,
            signature: String::new(),
        };
        sign_record(&mut r, key).expect("sign join");
        r
    };
    let result = |key: &ed25519_dalek::SigningKey, node: &NodeRecord, party: usize, value: &str| {
        let mut r = ResultRecord {
            job_id: base_job.job_id.clone(),
            node_id: node.node_id.clone(),
            pubkey: node.pubkey.clone(),
            party_id: party,
            value: value.into(),
            program_id: base_job.program_id.clone(),
            completed_at: 1_786_836_064,
            signature: String::new(),
        };
        sign_record(&mut r, key).expect("sign result");
        r
    };

    let nodes = vec![node(&node0, "w7-p0"), node(&node1, "w7-p1")];
    let joins = vec![
        join(&node0, &nodes[0], 0, 1_786_836_042),
        join(&node1, &nodes[1], 1, 1_786_836_049),
    ];
    // The value the real w7 pod committee agreed on (evidence/w7-pod-evidence.txt).
    let value = "-4645747589851520984";
    let results = vec![
        result(&node0, &nodes[0], 0, value),
        result(&node1, &nodes[1], 1, value),
    ];

    let write = |name: &str, bundle: &EvidenceBundle| {
        let path = repo_root().join("evidence/bundles").join(name);
        std::fs::create_dir_all(path.parent().expect("parent dir")).expect("create evidence/bundles");
        std::fs::write(&path, serde_json::to_string_pretty(bundle).expect("serialize bundle")).expect("write fixture");
        println!("wrote {}", path.display());
    };

    // wrong-key-binding.json: the base bundle unchanged. The sample quote's
    // report_data[8..40] binds bytes that are not blake3 of any node key here,
    // so the key-binding check is the first attestation failure — exactly the
    // "quote whose report_data binds the wrong key" case. The quote itself is
    // real and verifies against the Intel root (verify with --at inside the
    // collateral window).
    write("wrong-key-binding.json", &EvidenceBundle { version: BUNDLE_VERSION, job: base_job.clone(), nodes: nodes.clone(), joins: joins.clone(), results: results.clone() });

    // tampered-measurement.json: policy pins a measurement the (real, valid)
    // quote does not attest. The quote signature cannot be tampered without
    // failing the Intel chain first, so the operator-side refusal is the
    // honest rendering of "a tampered measurement".
    let mut job_wrong_measurement = base_job.clone();
    job_wrong_measurement.policy.allowed_measurements = vec!["00".repeat(32)];
    job_wrong_measurement.signature = String::new();
    sign_record(&mut job_wrong_measurement, &proposer).expect("re-sign job");
    write("tampered-measurement.json", &EvidenceBundle { version: BUNDLE_VERSION, job: job_wrong_measurement, nodes: nodes.clone(), joins: joins.clone(), results: results.clone() });

    // bad-join-signature.json: one byte of join[0]'s signature flipped. The
    // signature no longer verifies under the declared key.
    let mut joins_bad_sig = joins.clone();
    let mut sig = hex::decode(&joins_bad_sig[0].signature).expect("sig hex");
    sig[63] ^= 1;
    joins_bad_sig[0].signature = hex::encode(sig);
    write("bad-join-signature.json", &EvidenceBundle { version: BUNDLE_VERSION, job: base_job.clone(), nodes: nodes.clone(), joins: joins_bad_sig, results: results.clone() });

    // disagreeing-results.json: party 1 opens a different value, properly
    // signed — the signature layer is fine, the committee did not agree.
    let results_disagree = vec![
        results[0].clone(),
        result(&node1, &nodes[1], 1, "-4645747589851520983"),
    ];
    write("disagreeing-results.json", &EvidenceBundle { version: BUNDLE_VERSION, job: base_job, nodes, joins, results: results_disagree });

    // valid.json and mutated-event-log.json are deliberately NOT generated:
    // see evidence/bundles/README.md. Both need a quote whose report_data
    // binds a key the fixture holds and whose own event log replays onto its
    // registers; only a real TDX run can produce that pair.
}
