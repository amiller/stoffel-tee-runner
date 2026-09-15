# PLAN — issue #9: lobby write path

Base: `origin/main` (0f2fbcd). Acceptance copied from the issue, one checkbox each.

- [ ] `POST /jobs` rejects with 400 a `JobRecord` whose `job_id !=
      blake3(program_id || entry || n_parties || threshold)` — exact preimage stated
      in `lobby-records` next to the domain constants (new `job_id_for` helper;
      numbers are 8-byte little-endian so the concatenation is unambiguous).
      `docs/lobby-design.md` updated to the derived form, and the PR says which.
- [ ] `state` derived by the lobby from record counts (`open` below `n_parties`
      joins, `forming` at `n_parties` joins, `finished` at `n_parties` results);
      `GET /jobs?state=finished` returns a job that has all results. The signed
      `state` field in returned records is NOT rewritten — that would break offline
      signature verification (the lobby is an untrusted index).
- [ ] `POST /nodes` with a byte-identical record already stored returns 409 and
      appends nothing.
- [ ] `POST /jobs/{id}/join` returns 400 when `max_parties < n_parties` or
      `threshold` is not in `supported_thresholds`.
- [ ] Records read back on startup pass the same validation as writes (node_id,
      capabilities, references) via shared validators called from both `post` and
      `add_loaded`; a bad line aborts startup. Scope note: job-id derivation and
      duplicate detection are write-side only (issue #9's parenthetical scopes
      reload to node_id/capabilities/references; re-checking derivation would
      refuse every store written before this change).
- [ ] `./scripts/build.sh test -p lobby` passes with a test for each bullet.

Evidence: Tier 1 — `.evidence/issue-9/http-transcript.txt`, socket-level HTTP
transcript of each rejection and the state transitions (same shape as issue #2's).
