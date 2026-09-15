//! Deterministic generator for the synthetic mock jobs served by `web/mock/`
//! (issue #4). Writes `web/mock/data/mock-jobs.json`. Run via
//! `./scripts/build.sh run -p stoffel-lobby --bin gen-mock-data`.
//!
//! The lobby fixtures under `evidence/bundles/` cover exactly one job state
//! (`finished`) and pin measurements in every policy. The jobs view must group
//! by `JobState` and must render an empty `JobPolicy` as "unconstrained" with
//! a warning, so the mock needs jobs in the other states and one unconstrained
//! job. These records are synthetic — signed by a fixed throwaway key, no
//! attestation material, job_ids that are obviously not content hashes — and
//! exist only to exercise rendering. Provenance is recorded next to the output
//! in `web/mock/data/README.md`. They are never presented as evidence.

use ed25519_dalek::SigningKey;
use lobby_records::{sign_record, JobPolicy, JobRecord, JobState};

fn main() {
    // Throwaway key; nothing verifies these records and nothing should.
    let proposer = SigningKey::from_bytes(&[0x4a; 32]);
    let mut jobs: Vec<JobRecord> = Vec::new();

    let mut job = |id: &str, state: JobState, policy: JobPolicy, created_at: u64| {
        let mut r = JobRecord {
            job_id: id.to_string(),
            program_id: format!("mock-program-{id}"),
            program_url: None,
            entry: "main".to_string(),
            n_parties: 2,
            threshold: 0,
            policy,
            not_before: None,
            state,
            proposer: hex::encode(proposer.verifying_key().to_bytes()),
            created_at,
            signature: String::new(),
        };
        sign_record(&mut r, &proposer).expect("sign mock job");
        jobs.push(r);
    };

    // One job per remaining state. The `open` one is deliberately unconstrained:
    // it is the fixture for the "unconstrained JobPolicy" warning the page must
    // render (lobby-records `JobPolicy` doc comment).
    job(
        "6d6f636b2d6f70656e0000000000000000000000000000000000000000000000",
        JobState::Open,
        JobPolicy::default(),
        1_786_920_000,
    );
    job(
        "6d6f636b2d666f726d696e6700000000000000000000000000000000000000",
        JobState::Forming,
        JobPolicy { allowed_measurements: vec!["11".repeat(32)], allowed_compose_hashes: vec![] },
        1_786_918_000,
    );
    job(
        "6d6f636b2d72756e6e696e6700000000000000000000000000000000000000",
        JobState::Running,
        JobPolicy { allowed_measurements: vec!["22".repeat(32)], allowed_compose_hashes: vec!["33".repeat(32)] },
        1_786_916_000,
    );
    job(
        "6d6f636b2d6661696c65640000000000000000000000000000000000000000",
        JobState::Failed,
        JobPolicy { allowed_measurements: vec!["44".repeat(32)], allowed_compose_hashes: vec![] },
        1_786_914_000,
    );

    let out = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../web/mock/data");
    std::fs::create_dir_all(&out).expect("create web/mock/data");
    let path = out.join("mock-jobs.json");
    std::fs::write(&path, serde_json::to_string_pretty(&jobs).expect("serialize jobs"))
        .expect("write mock-jobs.json");
    println!("wrote {}", path.display());
}
