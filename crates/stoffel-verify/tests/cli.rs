//! End-to-end CLI tests over the committed fixtures: the binary's exit code
//! and the named error on stderr, for each of the four fixtures these
//! materials can honestly produce (see `evidence/bundles/README.md` for why
//! `valid.json` and `mutated-event-log.json` are not among them).

use std::process::Command;

/// Inside the vendored collateral validity window (2025-06-19 .. 2025-07-19).
/// The collateral is expired at wall-clock time and that expiry is enforced —
/// verification of these bundles is pinned deliberately, as the fork's own
/// tests do.
const AT: &str = "1751328000";

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../evidence/bundles")
        .join(name)
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_stoffel-verify"))
        .args(args)
        .output()
        .expect("run stoffel-verify");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn bad_join_signature_fixture_exits_nonzero_with_named_error() {
    let (code, _, stderr) = run(&["--at", AT, &fixture("bad-join-signature.json").to_string_lossy()]);
    assert_ne!(code, 0);
    assert!(stderr.contains("bad join signature"), "stderr: {stderr}");
}

#[test]
fn disagreeing_results_fixture_exits_nonzero_with_named_error() {
    let (code, _, stderr) = run(&["--at", AT, &fixture("disagreeing-results.json").to_string_lossy()]);
    assert_ne!(code, 0);
    assert!(stderr.contains("results disagree"), "stderr: {stderr}");
}

#[test]
fn tampered_measurement_fixture_exits_nonzero_with_named_error() {
    let (code, _, stderr) = run(&["--at", AT, &fixture("tampered-measurement.json").to_string_lossy()]);
    assert_ne!(code, 0);
    assert!(stderr.contains("measurement not allowed"), "stderr: {stderr}");
    // The measurement being refused was extracted from a quote that verified
    // against the Intel root — this is the operator-side refusal for an
    // unexpected image, not a broken quote.
    assert!(stderr.contains("b850cee4"), "stderr: {stderr}");
}

#[test]
fn wrong_key_binding_fixture_exits_nonzero_with_named_error() {
    let (code, _, stderr) = run(&["--at", AT, &fixture("wrong-key-binding.json").to_string_lossy()]);
    assert_ne!(code, 0);
    assert!(stderr.contains("key binding mismatch"), "stderr: {stderr}");
    // The binding refused is the real, non-zero report_data[8..40] of a quote
    // that verified against the Intel root.
    assert!(stderr.contains("d3d1b34e"), "stderr: {stderr}");
}

/// The five named errors the issue requires are pairwise distinct strings on
/// stderr. The fifth (`event log rejected`) is exercised in the lib tests
/// with the real materials, since no committed fixture can reach it.
#[test]
fn named_errors_are_pairwise_distinct() {
    let mut seen: Vec<String> = Vec::new();
    for name in ["bad-join-signature.json", "disagreeing-results.json", "tampered-measurement.json", "wrong-key-binding.json"] {
        let (_, _, stderr) = run(&["--at", AT, &fixture(name).to_string_lossy()]);
        let reason = stderr
            .lines()
            .find(|l| l.starts_with("stoffel-verify: "))
            .map(|l| l.trim_start_matches("stoffel-verify: ").to_string())
            .unwrap_or_default();
        assert!(!reason.is_empty(), "{name}: no reason on stderr");
        assert!(
            seen.iter().all(|other| !reason.starts_with(other.as_str()) && !other.starts_with(&reason)),
            "{name}: reason {reason:?} collides with {seen:?}"
        );
        seen.push(reason);
    }
}

/// Collateral expiry is a real check: at wall-clock time (outside every
/// validity window in the vendored collateral) the same bundle that fails
/// with a key-binding error when pinned fails with a quote rejection instead.
#[test]
fn wall_clock_verification_rejects_expired_collateral() {
    let (code, _, stderr) = run(&[&fixture("wrong-key-binding.json").to_string_lossy()]);
    assert_ne!(code, 0);
    assert!(stderr.contains("quote verification failed"), "stderr: {stderr}");
}

#[test]
fn missing_bundle_file_is_an_error() {
    let (code, _, stderr) = run(&["/nonexistent/bundle.json"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("cannot read"), "stderr: {stderr}");
}
