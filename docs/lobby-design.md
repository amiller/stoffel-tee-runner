# A lobby for attested MPC committees

Status: v1 service implemented, 2026-08-29. Quote verification and deployment integration remain downstream work.

The v1 service is now implemented as the `stoffel-lobby` binary. It listens on
`LOBBY_ADDR` (default `127.0.0.1:8080`) and stores signed JSONL envelopes at
`LOBBY_STORE` (default `lobby.jsonl`). The service verifies signatures and record
references; it does not verify TDX quotes or claim a verifier verdict. Run it with
`LOBBY_ADDR=0.0.0.0:8080 LOBBY_STORE=/var/lib/stoffel-lobby/lobby.jsonl` behind the
dstack tenant's proxied port. The JSONL file should be on durable, access-controlled
storage and backed up as an append-only artifact.

The repository's code-level evidence is Tier 1: the tests exercise the full two-node
announce → propose → join → result → bundle lifecycle over a real HTTP socket against
the `stoffel-lobby` binary (`crates/lobby/tests/http.rs`, transcript committed under
`.evidence/issue-2/`), including unknown fields, a forged signature, a record tampered
after signing, refusal to fabricate a bundle from an incomplete lifecycle, reload of
the store with re-verification, and rejection of a tampered store line at startup.
The bundle the service returns is also re-verified signature-by-signature with
`lobby-records` alone, without asking the service. There is no staging deployment or
`stoffel-verify` binary in this repository, so quote verification and full independent
bundle verification remain downstream work.

## The problem, stated from what exists

The runner produces a real attested committee. Checking that it did anything requires
knowing four endpoint names in advance and curling them by hand:

```sh
curl $HOST/stoffel-node/peers                       # who got admitted
for i in 0 1 2 3; do curl $HOST/stoffel-p$i/result; done   # do they agree
```

Three things are wrong with that as a product surface, and none of them are fixed by
putting a page in front of it.

**Identity does not survive a restart.** A node's identity is its `tls_derived_id`, derived
from a TLS key generated per process. Restart the node and it is a different node. There is
nothing to accumulate reputation against, nothing to address a job to, and nothing stable to
show in a list.

**A session exists only inside the gatekeeper's memory.** `/peers` is an in-memory vector on
the bootnode. When the CVM bounced today it came back `{"admitted":[],"rejected":[]}` with no
record that four parties had ever been admitted. There is no job object, so there is nothing
to schedule, queue, resume, or look up after the fact.

**The interesting claim is self-reported.** `/peers` is the gatekeeper telling you it admitted
four parties. The quotes it verified are not published anywhere. A third party cannot check
the claim; they can only ask the same node and get the same assertion back.

That last one is the important one. The system does hardware attestation and then throws the
evidence away.

## The design

**The lobby is not trusted.** It is an index. Every record in it is signed by whoever made
it, and the attestation evidence travels with the record, so a reader verifies rather than
believes. This means the lobby can be an ordinary web service — the interesting properties
do not depend on where it runs or who operates it.

What that buys: the operator of the lobby cannot forge a committee, cannot fake a result,
and cannot invent a node. What it does not buy: they can still *omit*. Censorship and
equivocation are the residual trust, and the fix for those is a transparency log with
inclusion proofs, which is deliberately out of scope for v1 and noted rather than pretended
away.

### Objects

Four record types, each signed, each self-contained enough to verify offline.

**`NodeRecord`** — signed by the node's long-term key.
```
node_id       = hash(long_term_pubkey)
endpoint      how to reach it
capabilities  max n, supported t, backends
attestation   quote + DCAP collateral + RTMR event log
heartbeat     last seen
```
The quote's `report_data` binds `long_term_pubkey`. That binding is what makes the identity
durable and what makes every later signature by this node meaningful.

**`JobRecord`** — signed by the proposer.
```
job_id     = hash(program_bytecode, entry, n, t)
program    bytecode, or a hash plus where to fetch it
policy     accepted measurements, accepted compose hashes
not_before optional; this is what "scheduled" means
state      open -> forming -> running -> finished | failed
```

**`JoinRecord`** — a node signs "I will serve job_id as party i".

**`ResultRecord`** — a node signs "job_id opened this value at this time".

### Verification

Given a job and the records referencing it, a verifier with no network access checks:

1. every node's quote verifies to the Intel root, and its event log replays onto the quote's
   own registers
2. each measurement and compose hash satisfies the job's policy
3. each quote's `report_data` binds that node's long-term pubkey
4. every Join and Result signature verifies under that pubkey
5. the results agree

That is exactly the check done by hand today, made mechanical and runnable by someone who
does not operate any of it. The verifier is already most of the way there: quote verification
and event-log replay are pure functions carrying their own collateral.

### What changes in the node

Today a party is deploy-and-immediately-run: the tenant starts, runs the program baked into
its image, and exits. Under the lobby it becomes announce → match → join → run → publish.
That is the largest behavioural change and the one worth reviewing carefully, because it puts
a network-driven work source in front of the execution path.

### Where scheduling comes from

Once a job is an object with a `not_before`, scheduling is a query, not a subsystem. A node
polls for jobs whose policy it satisfies and whose start time has passed. "Instances running
or scheduled to run" becomes a listing rather than a feature.

## The webapp

Read-only, and it verifies rather than displays.

- **Nodes** — who is online, what measurement they attest to, when last seen
- **Jobs** — open, forming, running, finished, with the committee for each
- **Evidence** — per job, the bundle, and a verdict computed in the reader's browser

The last point is the one that makes it worth building. A page that says "verified" because
the server said so adds nothing to the curl commands. A page that verifies the DCAP chain
client-side and shows its own verdict is a different artifact. The verifier is pure Rust with
a rustcrypto backend, so compiling it to wasm is plausible; if that turns out not to work,
the honest fallback is to show the bundle and the one command that checks it, not to assert a
verdict the page did not compute.

## Deliberately not in v1

- Transparency log with inclusion proofs (omission/equivocation remain trusted)
- Payment, staking, slashing
- Node reputation beyond "attested and recently seen"
- Committee selection policy beyond "first n eligible nodes that join"
- Resharing or membership change mid-job

## Relationship to the existing critique

This is the gap flagged to Stoffel in July: there is no node lobby or marketplace anywhere,
and the coordinator contract takes a manually maintained node list. Nothing in this design
requires changing the MPC protocol — it is a layer above the committee, which is why it can
be built against the runner without touching Stoffel's consensus or preprocessing code.
