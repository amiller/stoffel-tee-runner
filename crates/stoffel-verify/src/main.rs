//! `stoffel-verify [--at <unix-secs>] <bundle.json>` — bundle in, verdict out.
//!
//! Exit 0 with a one-line verdict on stdout when every check passes; exit 1
//! with the specific failure reason on stderr otherwise. No network access is
//! performed or needed: the DCAP collateral travels inside the bundle.
//!
//! `--at` pins the verification instant for the DCAP collateral validity
//! windows (TCB info, QE identity, CRLs, certificate chains). Default is the
//! wall clock. Verifying a historical bundle — whose collateral has since
//! expired, as expiry is a real check — means pinning a time inside its
//! window, deliberately, exactly as the fork's own tests do.

use std::env;
use std::process::ExitCode;

fn usage() -> ! {
    eprintln!("usage: stoffel-verify [--at <unix-secs>] <bundle.json>");
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1).peekable();
    let mut at = None;
    let mut path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--at" => {
                at = Some(args.next().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage()));
            }
            _ if path.is_none() => path = Some(arg),
            _ => usage(),
        }
    }
    let path = path.unwrap_or_else(|| usage());
    let now = at.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_secs()
    });

    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("stoffel-verify: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let bundle: lobby_records::EvidenceBundle = match serde_json::from_str(&raw) {
        Ok(bundle) => bundle,
        Err(e) => {
            eprintln!("stoffel-verify: {path} is not an EvidenceBundle: {e}");
            return ExitCode::from(2);
        }
    };

    match stoffel_verify::verify_bundle(&bundle, now) {
        Ok(verdict) => {
            println!(
                "verified: {} distinct-TEE nodes on measurement(s) {:?} agreed on value {}",
                verdict.n_parties, verdict.measurements, verdict.value
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("stoffel-verify: {e}");
            ExitCode::FAILURE
        }
    }
}
