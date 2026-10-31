# PLAN — issue #3 (L1 — Durable node identity)

Code lands on a branch of amiller/StoffelVM (off `w7-committee-demo`); this repo's PR carries
the evidence and points at the fork commit. Checkboxes derived from the issue's `## Acceptance`.

- [x] `crates/stoffel-vm/src/net/attestation.rs`: `NodeKey` — load-or-create Ed25519 keypair,
      persisted at `/data/stoffel-node.key` (0600), `node_id = hex(blake3(pubkey))`.
- [x] Quote binding: `report_data[0..8]` LE `tls_derived_id` unchanged; `report_data[8..40] =
      blake3(pubkey)` written by `obtain_dstack_evidence`, read back by the verifier.
- [x] `GET /attestation` gains `node_id` and `pubkey`, `node_id == lobby_records::node_id_for(pubkey)`
      (recomputed independently in the transcript; lobby-records has its own pinning test).
- [x] `AdmissionAttestation::verify_registration` keeps every existing check (no call site passes
      `attestation=None`; the diff removes none) and adds the node-key binding check with
      distinct `AttestationError` variants (`PubKeyBindingMismatch`, `MissingNodePubKey`).
- [x] New tests: binding match, binding mismatch, restart-stable `node_id`; plus MAC-covers-binding,
      corrupt-key-is-fatal, no-parent-is-fatal, real-TDX-fixture refusal.
- [x] `CC=clang cargo test -p stoffel-vm attestation` passes in the capped container (24 passed),
      and the `--features attestation-dstack` variant (29 passed). `hb_itest` check clean.
- [x] deploy/w7-deploy.sh, w7-final.sh, w7-parties.sh, w7-dbg.sh: every node — parties and debug
      runs included — mounts `/data`.
- [x] README: durable-identity section + restart evidence + report_data layout + human review stated.
- [x] Tier 1 evidence: `GET /attestation` before/after restart (local docker on zed), decoded
      key-file state, independent blake3 recompute, test output —
      `evidence/l1-node-identity-restart.txt`.
- [x] PR body states "needs human review before merge"; label `ready` → `in-review`.

## Fork landing note

The broker only pushes `ready-*` branches, so the fork work is on
`amiller/StoffelVM@ready-3` (commit `c5ef97c`, off `w7-committee-demo`). The issue asks
for it to land on `w7-committee-demo`; fast-forwarding that branch to `c5ef97c` is the
one operator step — flagged in the PR.

## Deviations from the frontier plan

- The plan expected to update `evidence/w7-pod-evidence.txt` with restart evidence; the
  new transcript lives in its own file (`evidence/l1-node-identity-restart.txt`) because
  the pod capture is a historical record of the August run and zed cannot reach the pod.
- The plan assumed "restart tests" only at unit level; the real-TDX fixture forced a
  semantic decision (see the fork commit message): the vendored quote was minted by a
  pre-0.4 dstack that hashed report_data, so it is refused under the L1 gate — the test
  now asserts that refusal instead of admission.
