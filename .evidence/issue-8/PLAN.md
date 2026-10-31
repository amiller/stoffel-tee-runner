# PLAN — issue #8 (measurement filter + query validation)

Checkboxes derived from the issue's `## Acceptance`.

- [x] `NodeRecord` gains a signed `measurement: DigestHex` field (hex
      `blake3(mr_td||rtmr0..2)`), `lobby-records` test added proving the field is
      covered by the signature (`node_measurement_is_signed`), schema documented in
      `docs/lobby-design.md`, `BUNDLE_VERSION` bumped 1→2 per the crate's own
      "bump on any breaking change" rule.
- [x] `GET /nodes?measurement=<hex>` matches by exact equality on the signed field
      (substring match over `event_log`/`quote_hex` deleted).
- [x] 400 with an error body naming the parameter for: `?measurement=` not 64 hex
      chars, `?freshness=` not a `u64`, `?state=` not a `JobState`, any query pair
      without `=` (GET and POST both).
- [x] `Content-Length` matched case-insensitively; missing or unparsable value is a
      400 before body handling, never a silent `0`.
- [x] `crates/lobby/tests/http.rs`: exact-match filter (one matching node, one
      non-matching, both directions) and every required 400 above, over a real socket
      against the real binary.
- [x] Both test commands pass: `cargo test -p lobby-records` (7 passed) and
      `cargo test -p stoffel-lobby` (2 unit + 3 http tests passed), zero warnings.
- [x] Tier 1 transcript: `.evidence/issue-8/http-transcript.txt`.

## Notes for review

- The issue names `JobPolicy.accepted_measurements`; this checkout calls the field
  `allowed_measurements`. The doc comments now cross-reference the two by digest.
- `scripts/build.sh` cannot run on this host (kernel rejects docker `--cpus`); the
  equivalent memory-capped container command was used, noted in the transcript header.
  The workspace package is `stoffel-lobby`, so the issue's literal `-p lobby` matches
  nothing (also true at main).
- POST /nodes additionally rejects a `measurement` that is not 32-byte hex, mirroring
  the existing `pubkey`/`node_id` checks: a stored non-hex measurement would make the
  GET filter silently useless, which is the masking the issue is about.
