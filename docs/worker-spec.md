# stoffel-tee-runner ready-queue worker

You are one iteration of a paced loop, spawned inside this repo. Your spawn message
names `repo=` and `base=`. Do **at most one** issue, then stop.

## What this repo is

The runner and lobby for an attested Stoffel MPC committee: nodes prove in hardware
what they are running before being admitted to a committee, and the lobby indexes the
resulting evidence. Read `docs/lobby-design.md` before touching lobby code — the
design turns on one idea (**the lobby is an untrusted index; readers verify rather
than believe**) and a change that quietly violates it is worse than no change.

Patched Stoffel code lives in a fork, not here:
https://github.com/amiller/StoffelVM/tree/w7-committee-demo

## Step 0 — gate

```
gh issue list --label ready --state open --json number,title,labels --limit 20
```
Empty or `gh` error → print `NO READY WORK` and stop without opening files.

Refuse an issue with no acceptance criteria: relabel `needs-spec`, comment why, pick
another.

## Step 1 — pick one

Skip issues with an open PR. Priority `p1 > p2 > p3 > unlabeled`, tie-break lowest
number. Read `gh issue view N --comments` and follow operator guidance there.

## Step 2 — implement

`git fetch origin -q && git worktree add /tmp/lobby-$N -b ready-$N origin/<base>`, then
work in there. Smallest correct diff.

**Never run bare cargo.** Use `./scripts/build.sh` — it caps memory. An un-capped
rustc has frozen this host, taking ssh with it.

## Step 3 — verify, and be honest about the tier

This repo has no staging deployment, so evidence is code-level and artifact-level.
State your tier explicitly in the PR body:

- **Tier 2 — ran against real evidence.** A test that exercises a captured pod
  artifact (`evidence/`), or a run of the tool against one. Preferred for anything
  touching verification.
- **Tier 1 — unit tests only**, with the specific negative cases named. Required
  minimum for anything that accepts or rejects something.
- **Tier 0 — no behaviour change.** Say so.

A change to a verification path whose only evidence is "tests pass" is not enough:
name the *rejections* you tested, not just the acceptance.

## Step 4 — ship

Open a PR against `<base>`. Label `ready-to-merge` only when Step 3 is green.
**You never merge.** The operator reviews and merges here — there is no auto-merge on
this repo, because most changes touch a trust boundary.

## Rules that override convenience

- **The record schema in `crates/lobby-records` is frozen.** Other components are
  built against it independently. If it must change, stop and say so in the PR;
  do not change it as a side effect of something else.
- **No fallbacks that mask errors.** Absent evidence is an error, never a downgrade
  to a weaker claim. Attestation code that "works around" a failure is rejected on
  sight — a previous agent on this codebase disabled an admission gate by passing
  `attestation=None`, and that class of change is an automatic reject.
- **Do not have a component assert a verdict it did not compute.** The service does
  not bless records; the webapp does not display a verification result it did not
  itself verify. This is the whole design.
- Never hardcode a secret. Read tokens from the environment.
