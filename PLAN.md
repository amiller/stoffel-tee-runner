# PLAN — issue #10: pin the bundle to the announce a node joined under

`bundle()` assembles `nodes` from `latest_node(node_id)`, so a re-announce after
joining rewrites the bundle's attestation for that join. Fix by pinning.

- [x] `JoinRecord` gains signed `node_announce_hash` = blake3 of the NodeRecord's
      signing preimage (the exact bytes the node signed), set in `lobby-records`.
- [x] Join admission computes the hash of the node's current announce and rejects
      a join whose pin does not match (400).
- [x] `bundle()` resolves each join's NodeRecord by its pinned hash; a pin with no
      record in the store is a 500, never a silent drop.
- [x] `crates/lobby/tests/http.rs`: announce, join, re-announce with a different
      attestation, fetch the bundle, assert it carries the FIRST announce.
- [x] `./scripts/build.sh test -p lobby` and `-p lobby-records` pass.
- [x] Tier 1 transcript captured under `.evidence/issue-10/`.

Schema note: this is a deliberate change to the frozen `JoinRecord` (the issue's
acceptance option 1). `BUNDLE_VERSION` bumps 1 → 2; JSONL stores containing v1
joins refuse to load — no migration shim, per the no-fallbacks rule.
