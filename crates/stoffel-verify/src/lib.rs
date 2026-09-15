//! Offline verifier for stoffel-lobby evidence bundles.
//!
//! A bundle makes one claim: *n TDX-attested nodes running an allowed
//! measurement agreed on this value.* This crate checks every link of that
//! claim from the records and attestation material alone — no network, no
//! asking the lobby or the nodes. The lobby that served the bundle is not
//! trusted for any of it; it can only omit (censorship/equivocation, out of
//! scope per the design).
//!
//! The two cryptographic primitives are used exactly as the StoffelVM fork
//! provides them and are not re-implemented here:
//!
//! - [`stoffel_vm::net::attestation::verify_dstack_quote_with_registers`] —
//!   Intel trust-chain verification of the raw TD quote against the DCAP
//!   collateral carried in the bundle, plus the measurement registers.
//! - [`stoffel_vm::net::dstack_event_log::verify_event_log`] — replay of the
//!   RTMR event log onto the verified quote's own registers.
//!
//! Everything else (signatures, node identity, committee structure, result
//! agreement, policy) is checked here on top of those anchors.
//!
//! ## Fail-closed
//!
//! Absent evidence is an error, never a downgrade: an empty `collateral_json`,
//! an empty `event_log`, a join with no `NodeRecord`, a log with no compose
//! event under a policy that pins compose hashes — all reject the bundle.

use lobby_records::{
    verify_signature, EvidenceBundle, DigestHex, JobRecord, NodeRecord, BUNDLE_VERSION,
};
use std::collections::HashSet;
use std::fmt;

/// Where in the 64-byte TD `report_data` the L1 key binding lives:
/// `hash(long_term_pubkey)` at `[8..40]` (lobby design / fork spec L1).
const KEY_BINDING: std::ops::Range<usize> = 8..40;

/// Why a bundle was rejected. Every variant prints distinctly on stderr so a
/// caller can tell *which* link of the claim failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    BundleVersion { found: u32 },
    MalformedQuote { node_id: DigestHex, detail: String },
    QuoteRejected { node_id: DigestHex, detail: String },
    MissingEvidence { node_id: Option<DigestHex>, what: &'static str },
    DuplicateQuote { node_id: DigestHex, first_node_id: DigestHex },
    BadSignature { what: &'static str, node_id: Option<DigestHex> },
    NodeIdentity { node_id: DigestHex },
    UnknownNode { node_id: DigestHex, what: &'static str },
    JoinKeyOrParty { node_id: DigestHex },
    WrongJob { what: &'static str, node_id: DigestHex },
    CommitteeIncomplete { joins: usize, results: usize, expected: usize },
    ResultProgram { node_id: DigestHex },
    ResultWithoutJoin { node_id: DigestHex },
    DuplicateResult { node_id: DigestHex },
    DisagreeingResults { values: Vec<String> },
    InvalidCommittee { n_parties: usize, threshold: usize },
    MeasurementNotAllowed { node_id: DigestHex, found: DigestHex },
    KeyBinding { node_id: DigestHex, bound: DigestHex, expected: DigestHex },
    EventLogRejected { node_id: DigestHex, detail: String },
    ComposeHashNotAllowed { node_id: DigestHex, found: Option<String> },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::BundleVersion { found } => {
                write!(f, "bundle version mismatch: expected {BUNDLE_VERSION}, found {found}")
            }
            VerifyError::MalformedQuote { node_id, detail } => {
                write!(f, "malformed quote (node {node_id}): {detail}")
            }
            VerifyError::QuoteRejected { node_id, detail } => {
                write!(f, "quote verification failed (node {node_id}): {detail}")
            }
            VerifyError::MissingEvidence { node_id, what } => match node_id {
                Some(id) => write!(f, "missing evidence (node {id}): {what}"),
                None => write!(f, "missing evidence: {what}"),
            },
            VerifyError::DuplicateQuote { node_id, first_node_id } => {
                write!(f, "duplicate quote (node {node_id}): the same TDX quote already backs node {first_node_id}; the committee is not made of distinct TEEs")
            }
            VerifyError::BadSignature { what, node_id } => match node_id {
                Some(id) => write!(f, "bad {what} signature (node {id}): does not verify under the declared key"),
                None => write!(f, "bad {what} signature: does not verify under the declared key"),
            },
            VerifyError::NodeIdentity { node_id } => {
                write!(f, "node identity mismatch (node {node_id}): node_id is not blake3(pubkey)")
            }
            VerifyError::UnknownNode { node_id, what } => {
                write!(f, "{what} references unknown node {node_id}")
            }
            VerifyError::JoinKeyOrParty { node_id } => {
                write!(f, "join key or party invalid (node {node_id}): pubkey does not match the node record, or party_id is out of range/duplicated")
            }
            VerifyError::WrongJob { what, node_id } => {
                write!(f, "{what} references a different job (node {node_id})")
            }
            VerifyError::CommitteeIncomplete { joins, results, expected } => {
                write!(f, "committee incomplete: {joins} joins and {results} results for n_parties={expected}")
            }
            VerifyError::ResultProgram { node_id } => {
                write!(f, "result program mismatch (node {node_id}): not the program the job proposed")
            }
            VerifyError::ResultWithoutJoin { node_id } => {
                write!(f, "result without a matching join (node {node_id})")
            }
            VerifyError::DuplicateResult { node_id } => {
                write!(f, "duplicate result (node {node_id}): a node posted more than one result")
            }
            VerifyError::DisagreeingResults { values } => {
                write!(f, "results disagree: {values:?}")
            }
            VerifyError::InvalidCommittee { n_parties, threshold } => {
                write!(f, "invalid committee: n_parties={n_parties} does not satisfy n >= 3*{threshold} + 1")
            }
            VerifyError::MeasurementNotAllowed { node_id, found } => {
                write!(f, "measurement not allowed (node {node_id}): {found} is not in the job policy")
            }
            VerifyError::KeyBinding { node_id, bound, expected } => {
                write!(f, "key binding mismatch (node {node_id}): quote report_data[{KEY_BINDING:?}] binds {bound}, not blake3 of the node's pubkey ({expected})")
            }
            VerifyError::EventLogRejected { node_id, detail } => {
                write!(f, "event log rejected (node {node_id}): {detail}")
            }
            VerifyError::ComposeHashNotAllowed { node_id, found } => match found {
                Some(h) => write!(f, "compose hash not allowed (node {node_id}): {h} is not in the job policy"),
                None => write!(f, "compose hash not allowed (node {node_id}): the anchored event log records no compose-hash event but the job policy pins compose hashes"),
            },
        }
    }
}

impl std::error::Error for VerifyError {}

/// What a fully verified bundle establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub n_parties: usize,
    /// The value every committee member opened.
    pub value: String,
    /// Distinct hardware measurements the committee ran (hex).
    pub measurements: Vec<DigestHex>,
}

/// Verify a whole bundle at verification time `now_secs` (unix seconds). The
/// time must lie inside every DCAP collateral validity window carried in the
/// bundle — collateral expiry is a real check and is not bypassed; a caller
/// verifying a historical bundle pins the time deliberately (the same way the
/// fork's own tests do).
pub fn verify_bundle(bundle: &EvidenceBundle, now_secs: u64) -> Result<Verdict, VerifyError> {
    if bundle.version != BUNDLE_VERSION {
        return Err(VerifyError::BundleVersion { found: bundle.version });
    }
    verify_job(&bundle.job)?;
    verify_nodes(bundle)?;
    verify_joins(bundle)?;
    verify_results(bundle)?;

    let mut seen_quotes: Vec<(Vec<u8>, DigestHex)> = Vec::new();
    let mut measurements = Vec::new();
    for node in &bundle.nodes {
        let attested = verify_attestation(node, &bundle.job, now_secs)?;
        if let Some(first_node_id) = duplicate_of(&seen_quotes, &attested.raw_quote) {
            return Err(VerifyError::DuplicateQuote {
                node_id: node.node_id.clone(),
                first_node_id: first_node_id.clone(),
            });
        }
        if !measurements.contains(&attested.measurement) {
            measurements.push(attested.measurement.clone());
        }
        seen_quotes.push((attested.raw_quote, node.node_id.clone()));
    }

    Ok(Verdict {
        n_parties: bundle.job.n_parties,
        value: bundle.results[0].value.clone(),
        measurements,
    })
}

/// A node's attestation, established link by link: the quote's Intel trust
/// chain, the job's measurement policy, the L1 key binding, and the event
/// log's replay onto the quote's own registers.
struct Attested {
    raw_quote: Vec<u8>,
    measurement: DigestHex,
}

/// Which already-seen node (if any) presented this exact quote: one TDX
/// quote backing two nodes means the committee is not made of distinct TEEs
/// (fork spec §4). Only reachable once real L1-bound quotes exist — every
/// currently available quote fails its key binding first.
fn duplicate_of<'a>(seen: &'a [(Vec<u8>, DigestHex)], raw: &[u8]) -> Option<&'a DigestHex> {
    seen.iter().find(|(q, _)| q == raw).map(|(_, id)| id)
}

fn verify_job(job: &JobRecord) -> Result<(), VerifyError> {
    verify_signature(job)
        .map_err(|_| VerifyError::BadSignature { what: "job", node_id: None })?;
    if job.n_parties == 0 || job.n_parties < 3 * job.threshold + 1 {
        return Err(VerifyError::InvalidCommittee {
            n_parties: job.n_parties,
            threshold: job.threshold,
        });
    }
    Ok(())
}

fn node_by_id<'a>(bundle: &'a EvidenceBundle, node_id: &str) -> Option<&'a NodeRecord> {
    bundle.nodes.iter().find(|n| n.node_id == node_id)
}

fn verify_nodes(bundle: &EvidenceBundle) -> Result<(), VerifyError> {
    for node in &bundle.nodes {
        verify_signature(node).map_err(|_| VerifyError::BadSignature {
            what: "node",
            node_id: Some(node.node_id.clone()),
        })?;
        let pk = hex::decode(&node.pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| VerifyError::NodeIdentity { node_id: node.node_id.clone() })?;
        if lobby_records::node_id_for(&pk) != node.node_id {
            return Err(VerifyError::NodeIdentity { node_id: node.node_id.clone() });
        }
    }
    Ok(())
}

fn verify_joins(bundle: &EvidenceBundle) -> Result<(), VerifyError> {
    let mut parties = HashSet::new();
    let mut joiners = HashSet::new();
    for join in &bundle.joins {
        verify_signature(join).map_err(|_| VerifyError::BadSignature {
            what: "join",
            node_id: Some(join.node_id.clone()),
        })?;
        if join.job_id != bundle.job.job_id {
            return Err(VerifyError::WrongJob { what: "join", node_id: join.node_id.clone() });
        }
        let node = node_by_id(bundle, &join.node_id).ok_or_else(|| VerifyError::UnknownNode {
            node_id: join.node_id.clone(),
            what: "join",
        })?;
        if node.pubkey != join.pubkey
            || join.party_id >= bundle.job.n_parties
            || !parties.insert(join.party_id)
            || !joiners.insert(join.node_id.clone())
        {
            return Err(VerifyError::JoinKeyOrParty { node_id: join.node_id.clone() });
        }
    }
    if bundle.joins.len() != bundle.job.n_parties {
        return Err(VerifyError::CommitteeIncomplete {
            joins: bundle.joins.len(),
            results: bundle.results.len(),
            expected: bundle.job.n_parties,
        });
    }
    Ok(())
}

fn verify_results(bundle: &EvidenceBundle) -> Result<(), VerifyError> {
    let mut posters = HashSet::new();
    for result in &bundle.results {
        verify_signature(result).map_err(|_| VerifyError::BadSignature {
            what: "result",
            node_id: Some(result.node_id.clone()),
        })?;
        if result.job_id != bundle.job.job_id {
            return Err(VerifyError::WrongJob { what: "result", node_id: result.node_id.clone() });
        }
        let node = node_by_id(bundle, &result.node_id).ok_or_else(|| VerifyError::UnknownNode {
            node_id: result.node_id.clone(),
            what: "result",
        })?;
        if node.pubkey != result.pubkey {
            return Err(VerifyError::JoinKeyOrParty { node_id: result.node_id.clone() });
        }
        if result.program_id != bundle.job.program_id {
            return Err(VerifyError::ResultProgram { node_id: result.node_id.clone() });
        }
        if !bundle
            .joins
            .iter()
            .any(|j| j.job_id == result.job_id && j.node_id == result.node_id && j.party_id == result.party_id)
        {
            return Err(VerifyError::ResultWithoutJoin { node_id: result.node_id.clone() });
        }
        if !posters.insert(result.node_id.clone()) {
            return Err(VerifyError::DuplicateResult { node_id: result.node_id.clone() });
        }
    }
    if bundle.results.len() != bundle.job.n_parties {
        return Err(VerifyError::CommitteeIncomplete {
            joins: bundle.joins.len(),
            results: bundle.results.len(),
            expected: bundle.job.n_parties,
        });
    }
    if bundle.results.windows(2).any(|w| w[0].value != w[1].value) {
        return Err(VerifyError::DisagreeingResults {
            values: bundle.results.iter().map(|r| r.value.clone()).collect(),
        });
    }
    Ok(())
}

fn verify_attestation(
    node: &NodeRecord,
    job: &JobRecord,
    now_secs: u64,
) -> Result<Attested, VerifyError> {
    let att = &node.attestation;
    if att.quote_hex.trim().is_empty() {
        return Err(VerifyError::MissingEvidence {
            node_id: Some(node.node_id.clone()),
            what: "quote_hex is empty",
        });
    }
    if att.collateral_json.trim().is_empty() {
        return Err(VerifyError::MissingEvidence {
            node_id: Some(node.node_id.clone()),
            what: "collateral_json is empty",
        });
    }
    if att.event_log.trim().is_empty() {
        return Err(VerifyError::MissingEvidence {
            node_id: Some(node.node_id.clone()),
            what: "event_log is empty",
        });
    }

    let raw_quote = hex::decode(&att.quote_hex).map_err(|e| VerifyError::MalformedQuote {
        node_id: node.node_id.clone(),
        detail: format!("quote_hex is not hex: {e}"),
    })?;

    // Signature chain against the Intel root — entirely
    // `verify_dstack_quote_with_registers`; nothing here re-implements it.
    let collateral: dcap_qvl::QuoteCollateralV3 =
        serde_json::from_str(&att.collateral_json).map_err(|e| VerifyError::MalformedQuote {
            node_id: node.node_id.clone(),
            detail: format!("collateral_json does not deserialize as DCAP collateral: {e}"),
        })?;
    let (verified, rtmrs) = verify_quote(&raw_quote, &collateral, now_secs, &node.node_id)?;
    let measurement = check_measurement(verified.measurement, job, &node.node_id)?;

    let report_data = report_data_of(&raw_quote, &node.node_id)?;
    check_key_binding(&report_data, &pk_of(node)?, &node.node_id)?;

    let identity = check_event_log(&att.event_log, &rtmrs, &node.node_id)?;
    check_compose(&identity, job, &node.node_id)?;

    Ok(Attested { raw_quote, measurement })
}

fn pk_of(node: &NodeRecord) -> Result<[u8; 32], VerifyError> {
    hex::decode(&node.pubkey)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| VerifyError::NodeIdentity { node_id: node.node_id.clone() })
}

fn verify_quote(
    raw_quote: &[u8],
    collateral: &dcap_qvl::QuoteCollateralV3,
    now_secs: u64,
    node_id: &str,
) -> Result<(stoffel_vm::net::attestation::VerifiedAttestation, stoffel_vm::net::attestation::QuoteRtmrs), VerifyError> {
    use stoffel_vm::net::attestation::verify_dstack_quote_with_registers;
    verify_dstack_quote_with_registers(raw_quote, collateral, now_secs).map_err(|e| {
        VerifyError::QuoteRejected {
            node_id: node_id.to_string(),
            detail: e.to_string(),
        }
    })
}

fn check_measurement(
    measurement: [u8; 32],
    job: &JobRecord,
    node_id: &str,
) -> Result<DigestHex, VerifyError> {
    let measurement = hex::encode(measurement);
    // An empty allowlist is the documented "unconstrained" choice
    // (lobby-records `JobPolicy`); a non-empty one is enforced exactly.
    if !job.policy.allowed_measurements.is_empty()
        && !job.policy.allowed_measurements.contains(&measurement)
    {
        return Err(VerifyError::MeasurementNotAllowed {
            node_id: node_id.to_string(),
            found: measurement,
        });
    }
    Ok(measurement)
}

/// L1 key binding: the hardware-signed `report_data[8..40]` must be blake3 of
/// the pubkey this node signs with. An all-zero binding is simply a mismatch —
/// a quote from a node without the L1 change can never pose as one that has
/// it.
fn check_key_binding(
    report_data: &[u8; 64],
    pubkey: &[u8; 32],
    node_id: &str,
) -> Result<(), VerifyError> {
    let bound = hex::encode(&report_data[KEY_BINDING]);
    let expected_binding = hex::encode(blake3::hash(pubkey).as_bytes());
    if bound != expected_binding {
        return Err(VerifyError::KeyBinding {
            node_id: node_id.to_string(),
            bound,
            expected: expected_binding,
        });
    }
    Ok(())
}

/// Event log: must replay onto this verified quote's own registers.
fn check_event_log(
    raw_log: &str,
    rtmrs: &stoffel_vm::net::attestation::QuoteRtmrs,
    node_id: &str,
) -> Result<stoffel_vm::net::dstack_event_log::AppIdentity, VerifyError> {
    use stoffel_vm::net::dstack_event_log::verify_event_log;
    verify_event_log(raw_log, [&rtmrs[0], &rtmrs[1], &rtmrs[2], &rtmrs[3]]).map_err(|e| {
        VerifyError::EventLogRejected {
            node_id: node_id.to_string(),
            detail: e.to_string(),
        }
    })
}

/// Compose-hash policy, read out of the now-anchored log. A policy that pins
/// compose hashes and a log that records none is a rejection, not a pass.
fn check_compose(
    identity: &stoffel_vm::net::dstack_event_log::AppIdentity,
    job: &JobRecord,
    node_id: &str,
) -> Result<(), VerifyError> {
    if !job.policy.allowed_compose_hashes.is_empty() {
        match &identity.compose_hash {
            Some(found) if job.policy.allowed_compose_hashes.contains(found) => {}
            other => {
                return Err(VerifyError::ComposeHashNotAllowed {
                    node_id: node_id.to_string(),
                    found: other.clone(),
                })
            }
        }
    }
    Ok(())
}

/// Read `report_data` out of a raw TDX quote. Parse-only — the quote's
/// authenticity is established by `verify_dstack_quote_with_registers`, which
/// is why a parse failure here is reported before (and separately from) the
/// trust-chain check: a quote that cannot even be decoded is malformed, not
/// "untrusted".
fn report_data_of(raw_quote: &[u8], node_id: &str) -> Result<[u8; 64], VerifyError> {
    use parity_scale_codec::Decode;
    let quote = dcap_qvl::quote::Quote::decode(&mut &raw_quote[..]).map_err(|e| {
        VerifyError::MalformedQuote {
            node_id: node_id.to_string(),
            detail: format!("does not decode as an Intel quote: {e}"),
        }
    })?;
    let td = quote.report.as_td10().ok_or_else(|| VerifyError::MalformedQuote {
        node_id: node_id.to_string(),
        detail: "not a TD report (dstack evidence must be TD, version 4)".to_string(),
    })?;
    Ok(td.report_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lobby_records::{sign_record, AttestationBlob, JobPolicy, JobState, JoinRecord, ResultRecord};
    use stoffel_vm::net::dstack_event_log::AppIdentity;

    /// 2025-07-01T00:00:00Z — inside the vendored collateral validity window
    /// (2025-06-19 .. 2025-07-19).
    const AT: u64 = 1_751_328_000;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn real_quote() -> Vec<u8> {
        let raw = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tdx_quote.bin"),
        )
        .expect("tdx_quote.bin");
        raw
    }

    fn real_collateral() -> dcap_qvl::QuoteCollateralV3 {
        serde_json::from_str(&fixture("tdx_quote_collateral.json")).expect("collateral")
    }

    // ------------------------------------------------------------------
    // Real materials: the Intel trust chain, end to end.
    // ------------------------------------------------------------------

    #[test]
    fn real_tdx_quote_verifies_against_the_intel_root_at_a_pinned_time() {
        let (verified, rtmrs) = verify_quote(&real_quote(), &real_collateral(), AT, "node").expect("verify");
        // blake3(mr_td || rtmr0..2) of the sample quote — pinned so a change
        // in the sample or in the measurement convention is caught here.
        assert_eq!(
            hex::encode(verified.measurement),
            "b850cee4ffd9bee71c7626ab4c23fa1a2c92971401764a2089db9d2ff721fd78"
        );
        assert!(rtmrs.iter().all(|r| r.len() == 48));
    }

    #[test]
    fn real_tdx_quote_is_rejected_outside_the_collateral_window() {
        let err = verify_quote(&real_quote(), &real_collateral(), 1_789_000_000, "node")
            .expect_err("expired collateral must reject");
        assert!(matches!(err, VerifyError::QuoteRejected { .. }), "{err}");
    }

    #[test]
    fn tampering_the_quote_breaks_the_intel_chain_not_just_the_output() {
        let mut raw = real_quote();
        raw[600] ^= 1; // inside report_data: covered by the QE signature
        let err = verify_quote(&raw, &real_collateral(), AT, "node").expect_err("must reject");
        assert!(matches!(err, VerifyError::QuoteRejected { .. }), "{err}");
    }

    #[test]
    fn report_data_of_the_real_quote_carries_a_nonzero_l1_slot() {
        let rd = report_data_of(&real_quote(), "node").expect("parse");
        assert_eq!(
            hex::encode(&rd[KEY_BINDING]),
            "d3d1b34e1e5e1742d4bb02dd6ddd551862c1211d35c304f9eca3efdbb481601c"
        );
    }

    // ------------------------------------------------------------------
    // The five named rejection classes, at check granularity.
    // ------------------------------------------------------------------

    #[test]
    fn an_all_zero_key_binding_is_rejected_not_passed() {
        // A quote from a node without the L1 change binds nothing: the slot is
        // all zeros and no pubkey hashes to that.
        let rd = [0u8; 64];
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pk = key.verifying_key().to_bytes();
        let err = check_key_binding(&rd, &pk, "node").expect_err("all-zero binding must reject");
        match err {
            VerifyError::KeyBinding { bound, expected, .. } => {
                assert_eq!(bound, "00".repeat(32));
                assert_eq!(expected, hex::encode(blake3::hash(&pk).as_bytes()));
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_correctly_bound_key_passes_and_a_wrong_key_is_named() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pk = key.verifying_key().to_bytes();
        let mut rd = [0u8; 64];
        rd[KEY_BINDING].copy_from_slice(blake3::hash(&pk).as_bytes());
        check_key_binding(&rd, &pk, "node").expect("bound key must pass");

        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let err =
            check_key_binding(&rd, &other.verifying_key().to_bytes(), "node").expect_err("must reject");
        match err {
            VerifyError::KeyBinding { bound, expected, .. } => {
                assert_eq!(bound, hex::encode(blake3::hash(&pk).as_bytes()));
                assert_eq!(expected, hex::encode(blake3::hash(&other.verifying_key().to_bytes()).as_bytes()));
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn the_real_pod_log_does_not_replay_onto_the_sample_quote_registers() {
        // The event log and the quote come from different boots: the replay
        // must fail. This is the real-material form of "a mutated event log".
        let (_, rtmrs) = verify_quote(&real_quote(), &real_collateral(), AT, "node").expect("verify");
        let err = check_event_log(&fixture("pod_event_log.json"), &rtmrs, "node")
            .expect_err("cross-boot log must reject");
        assert!(matches!(err, VerifyError::EventLogRejected { .. }), "{err}");
        assert!(err.to_string().contains("does not reconstruct"), "{err}");
    }

    #[test]
    fn the_real_pod_log_replays_onto_its_own_registers() {
        // Green path of the log wrapper, on the captured pod pair: the log is
        // internally consistent and yields the pod's compose hash.
        let regs: serde_json::Value = serde_json::from_str(&fixture("pod_registers.json")).unwrap();
        let rtmr: Vec<Vec<u8>> = regs["rtmr"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
            .collect();
        let rtmrs: stoffel_vm::net::attestation::QuoteRtmrs = [
            rtmr[0].as_slice().try_into().unwrap(),
            rtmr[1].as_slice().try_into().unwrap(),
            rtmr[2].as_slice().try_into().unwrap(),
            rtmr[3].as_slice().try_into().unwrap(),
        ];
        let identity = check_event_log(&fixture("pod_event_log.json"), &rtmrs, "node")
            .expect("the pod pair is internally consistent");
        assert_eq!(
            identity.compose_hash.as_deref(),
            Some("ea07fc3d1894fe056c43d21ad1b57bc626f43a1b2b9aef1d974907a1fee68eba")
        );
    }

    fn identity(compose: Option<&str>) -> AppIdentity {
        AppIdentity { compose_hash: compose.map(str::to_string), ..Default::default() }
    }

    fn policy(measurements: &[&str], compose: &[&str]) -> JobRecord {
        JobRecord {
            job_id: "job".into(),
            program_id: "program".into(),
            program_url: None,
            entry: "main".into(),
            n_parties: 1,
            threshold: 0,
            policy: JobPolicy {
                allowed_measurements: measurements.iter().map(|s| s.to_string()).collect(),
                allowed_compose_hashes: compose.iter().map(|s| s.to_string()).collect(),
            },
            not_before: None,
            state: JobState::Finished,
            proposer: "00".repeat(32),
            created_at: 0,
            signature: String::new(),
        }
    }

    #[test]
    fn measurement_policy_empty_means_unconstrained_and_nonempty_is_exact() {
        let m = [1u8; 32];
        check_measurement(m, &policy(&[], &[]), "node").expect("empty policy is unconstrained");
        check_measurement(m, &policy(&[&hex::encode(m)], &[]), "node").expect("listed measurement passes");
        let err = check_measurement(m, &policy(&["deadbeef"], &[]), "node").expect_err("must reject");
        assert!(matches!(err, VerifyError::MeasurementNotAllowed { .. }));
    }

    #[test]
    fn compose_policy_pins_the_anchored_log_and_absent_is_a_rejection() {
        let h = "ea07fc3d1894fe056c43d21ad1b57bc626f43a1b2b9aef1d974907a1fee68eba";
        check_compose(&identity(Some(h)), &policy(&[], &[h]), "node").expect("matching compose passes");
        let mismatch = check_compose(&identity(Some(h)), &policy(&[], &["other"]), "node")
            .expect_err("mismatch must reject");
        assert!(matches!(mismatch, VerifyError::ComposeHashNotAllowed { found: Some(_), .. }));
        let absent = check_compose(&identity(None), &policy(&[], &[h]), "node")
            .expect_err("no compose event under a pinning policy must reject");
        assert!(matches!(absent, VerifyError::ComposeHashNotAllowed { found: None, .. }));
    }

    #[test]
    fn the_same_quote_backing_two_nodes_is_named() {
        let seen = vec![(vec![1, 2, 3], "node-a".to_string())];
        assert_eq!(duplicate_of(&seen, &[1, 2, 3]).map(String::as_str), Some("node-a"));
        assert!(duplicate_of(&seen, &[1, 2, 4]).is_none());
    }

    // ------------------------------------------------------------------
    // Whole-bundle structure, on synthetic but properly signed records.
    // ------------------------------------------------------------------

    fn keys() -> [ed25519_dalek::SigningKey; 2] {
        [ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]), ed25519_dalek::SigningKey::from_bytes(&[2u8; 32])]
    }

    /// A bundle whose attestation is syntactically present but not a real TDX
    /// quote — every check below this layer is exercised by construction.
    fn bundle() -> EvidenceBundle {
        let keys = keys();
        let attestation = AttestationBlob {
            quote_hex: "00".repeat(64),
            collateral_json: "{}".to_string(),
            event_log: "[]".to_string(),
        };
        let node_record = |key: &ed25519_dalek::SigningKey| {
            let pk = key.verifying_key().to_bytes();
            let mut n = NodeRecord {
                node_id: lobby_records::node_id_for(&pk),
                pubkey: hex::encode(pk),
                endpoint: "node:8080".into(),
                max_parties: 2,
                supported_thresholds: vec![0],
                operator_label: "test".into(),
                attestation: attestation.clone(),
                announced_at: 0,
                signature: String::new(),
            };
            sign_record(&mut n, key).unwrap();
            n
        };
        let nodes = vec![node_record(&keys[0])];
        let zeros = "00".repeat(32);
        let mut job = policy(&[&zeros], &[]);
        job.n_parties = 1;
        job.proposer = nodes[0].pubkey.clone();
        sign_record(&mut job, &keys[0]).unwrap();
        let mut join = JoinRecord {
            job_id: job.job_id.clone(),
            node_id: nodes[0].node_id.clone(),
            pubkey: nodes[0].pubkey.clone(),
            party_id: 0,
            joined_at: 0,
            signature: String::new(),
        };
        sign_record(&mut join, &keys[0]).unwrap();
        let mut result = ResultRecord {
            job_id: job.job_id.clone(),
            node_id: nodes[0].node_id.clone(),
            pubkey: nodes[0].pubkey.clone(),
            party_id: 0,
            value: "42".into(),
            program_id: job.program_id.clone(),
            completed_at: 0,
            signature: String::new(),
        };
        sign_record(&mut result, &keys[0]).unwrap();
        EvidenceBundle { version: BUNDLE_VERSION, job, nodes, joins: vec![join], results: vec![result] }
    }

    fn err_of(bundle: &EvidenceBundle) -> VerifyError {
        verify_bundle(bundle, AT).expect_err("synthetic attestation cannot verify; the error below it is the subject")
    }

    #[test]
    fn version_mismatch_is_named() {
        let mut b = bundle();
        b.version = BUNDLE_VERSION + 1;
        assert_eq!(verify_bundle(&b, AT).unwrap_err(), VerifyError::BundleVersion { found: BUNDLE_VERSION + 1 });
    }

    #[test]
    fn invalid_committee_arithmetic_is_named() {
        let keys = keys();
        let mut b = bundle();
        b.job.n_parties = 1;
        b.job.threshold = 1; // 1 < 3*1+1
        b.job.signature = String::new();
        sign_record(&mut b.job, &keys[0]).unwrap();
        assert_eq!(verify_bundle(&b, AT).unwrap_err(), VerifyError::InvalidCommittee { n_parties: 1, threshold: 1 });
    }

    #[test]
    fn a_bad_node_signature_is_named() {
        let mut b = bundle();
        b.nodes[0].operator_label = "tampered".into(); // breaks the signature
        assert!(matches!(err_of(&b), VerifyError::BadSignature { what: "node", .. }));
    }

    #[test]
    fn node_identity_mismatch_is_named() {
        let keys = keys();
        let mut b = bundle();
        b.nodes[0].node_id = "00".repeat(32);
        b.nodes[0].signature = String::new();
        sign_record(&mut b.nodes[0], &keys[0]).unwrap();
        b.joins[0].node_id = b.nodes[0].node_id.clone();
        b.joins[0].signature = String::new();
        sign_record(&mut b.joins[0], &keys[0]).unwrap();
        b.results[0].node_id = b.nodes[0].node_id.clone();
        b.results[0].signature = String::new();
        sign_record(&mut b.results[0], &keys[0]).unwrap();
        assert!(matches!(err_of(&b), VerifyError::NodeIdentity { .. }));
    }

    #[test]
    fn a_join_for_an_unknown_node_is_missing_evidence() {
        let keys = keys();
        let mut b = bundle();
        b.joins[0].node_id = "ff".repeat(32);
        b.joins[0].signature = String::new();
        sign_record(&mut b.joins[0], &keys[0]).unwrap();
        assert!(matches!(err_of(&b), VerifyError::UnknownNode { what: "join", .. }));
    }

    #[test]
    fn a_join_referencing_another_job_is_named() {
        let keys = keys();
        let mut b = bundle();
        b.joins[0].job_id = "other".into();
        b.joins[0].signature = String::new();
        sign_record(&mut b.joins[0], &keys[0]).unwrap();
        assert!(matches!(err_of(&b), VerifyError::WrongJob { what: "join", .. }));
    }

    #[test]
    fn empty_attestation_evidence_is_an_error_never_skipped() {
        for (field, expected) in [
            ("collateral_json", "collateral_json is empty"),
            ("event_log", "event_log is empty"),
            ("quote_hex", "quote_hex is empty"),
        ] {
            let mut b = bundle();
            match field {
                "collateral_json" => b.nodes[0].attestation.collateral_json = String::new(),
                "event_log" => b.nodes[0].attestation.event_log = String::new(),
                _ => b.nodes[0].attestation.quote_hex = String::new(),
            }
            let keys = keys();
            b.nodes[0].signature = String::new();
            sign_record(&mut b.nodes[0], &keys[0]).unwrap();
            let err = err_of(&b);
            assert!(
                matches!(&err, VerifyError::MissingEvidence { what, .. } if what.contains(expected)),
                "{field}: {err}"
            );
        }
    }

    #[test]
    fn an_incomplete_committee_is_named() {
        let mut b = bundle();
        b.joins.clear();
        assert!(matches!(err_of(&b), VerifyError::CommitteeIncomplete { joins: 0, results: 1, expected: 1 }));
    }

    #[test]
    fn a_result_for_the_wrong_program_is_named() {
        let keys = keys();
        let mut b = bundle();
        b.results[0].program_id = "other".into();
        b.results[0].signature = String::new();
        sign_record(&mut b.results[0], &keys[0]).unwrap();
        assert!(matches!(err_of(&b), VerifyError::ResultProgram { .. }));
    }

    #[test]
    fn a_result_without_a_join_is_named() {
        let keys = keys();
        let mut b = bundle();
        b.results[0].party_id = 3; // no join for party 3
        b.results[0].signature = String::new();
        sign_record(&mut b.results[0], &keys[0]).unwrap();
        assert!(matches!(err_of(&b), VerifyError::ResultWithoutJoin { .. }));
    }

    #[test]
    fn duplicate_results_from_one_node_are_named() {
        let keys = keys();
        let mut b = bundle();
        let mut extra = b.results[0].clone();
        extra.value = "43".into();
        extra.signature = String::new();
        sign_record(&mut extra, &keys[0]).unwrap();
        b.results.push(extra);
        assert!(matches!(err_of(&b), VerifyError::DuplicateResult { .. }));
    }

    #[test]
    fn disagreeing_results_are_named() {
        let keys = keys();
        let mut b = bundle();
        // A second, distinct node joins party 1 and opens a different value.
        let pk1 = keys[1].verifying_key().to_bytes();
        let mut node1 = NodeRecord {
            node_id: lobby_records::node_id_for(&pk1),
            pubkey: hex::encode(pk1),
            endpoint: "node1:8080".into(),
            max_parties: 2,
            supported_thresholds: vec![0],
            operator_label: "test".into(),
            attestation: b.nodes[0].attestation.clone(),
            announced_at: 0,
            signature: String::new(),
        };
        sign_record(&mut node1, &keys[1]).unwrap();
        let mut join1 = JoinRecord {
            job_id: b.job.job_id.clone(),
            node_id: node1.node_id.clone(),
            pubkey: node1.pubkey.clone(),
            party_id: 1,
            joined_at: 0,
            signature: String::new(),
        };
        sign_record(&mut join1, &keys[1]).unwrap();
        let mut result1 = ResultRecord {
            job_id: b.job.job_id.clone(),
            node_id: node1.node_id.clone(),
            pubkey: node1.pubkey.clone(),
            party_id: 1,
            value: "43".into(),
            program_id: b.job.program_id.clone(),
            completed_at: 0,
            signature: String::new(),
        };
        sign_record(&mut result1, &keys[1]).unwrap();
        b.job.n_parties = 2;
        b.job.signature = String::new();
        sign_record(&mut b.job, &keys[0]).unwrap();
        b.nodes.push(node1);
        b.joins.push(join1);
        b.results.push(result1);
        let err = err_of(&b);
        assert!(matches!(&err, VerifyError::DisagreeingResults { values } if values == &["42".to_string(), "43".to_string()]));
    }

    #[test]
    fn a_malformed_quote_is_named_before_the_trust_chain_check() {
        let keys = keys();
        let mut b = bundle();
        b.nodes[0].attestation.quote_hex = "zz".to_string(); // not hex
        b.nodes[0].signature = String::new();
        sign_record(&mut b.nodes[0], &keys[0]).unwrap();
        assert!(matches!(err_of(&b), VerifyError::MalformedQuote { .. }));
    }
}
