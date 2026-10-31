# PLAN — issue #7: Lobby must return the bundle even when results disagree or the lifecycle is incomplete

`GET /jobs/{id}/bundle` issues verdicts it must not have: 409 when results disagree (that is
verification step 5 in `docs/lobby-design.md`, the reader's check) and 409 when the lifecycle is
incomplete. Per the design the lobby is an untrusted index; a disagreeing bundle is the evidence a
verifier needs, and a 409 hides it exactly like censorship-by-omission.

## Acceptance (from the issue)

- [x] `GET /jobs/{id}/bundle` returns 200 with whatever joins and results exist for a known job,
      including when result values differ and when the lifecycle is incomplete. 404 only for an
      unknown job.
- [x] `crates/lobby/tests/http.rs` gains a case with two disagreeing results that asserts 200 and
      both `ResultRecord`s present in the bundle, and a case with one join that asserts 200 with one
      join and zero results.
- [x] `./scripts/build.sh test -p lobby` passes.

## Steps

- [x] Remove the two 409 guards in `bundle` (`crates/lobby/src/main.rs`); 404 for unknown job stays.
- [x] Update the existing socket test's mid-lifecycle fetch from 409 to 200 (zero joins, zero
      results) and fix its now-false comment.
- [x] Add a socket test: job "disagree" with two results of different values → 200, both
      `ResultRecord`s present; job "partial" with one join, no results → 200, one join, zero
      results; unknown job → 404.
- [x] Fix the one clause in `docs/lobby-design.md` that still enumerates "refusal to fabricate a
      bundle from an incomplete lifecycle" as covered behavior.
- [x] `./scripts/build.sh test -p lobby` green; transcript captured to `.evidence/issue-7/`.

## Evidence tier

Tier 1 — HTTP transcript of the disagreeing-results bundle fetch, from the socket-level test run
with `-- --nocapture`, committed under `.evidence/issue-7/http-transcript.txt`.
