# stoffel-tee-runner

A Stoffel MPC committee where every party runs inside an Intel TDX confidential VM,
and no party is admitted to the committee until it has proven, in hardware, what code
it is running.

The MPC code is Stoffel's. What is here is the runner: the attestation gate, the
deployment recipe for a dstack pod, the observability needed to check that any of it
actually happened, and the four things that had to be fixed before it did.

Code changes live on a branch of a StoffelVM fork:
**https://github.com/amiller/StoffelVM/tree/w7-committee-demo**

## What it demonstrates

Plain MPC gives you secrecy from your peers — nobody sees anyone's input, and a bounded
number of parties can misbehave without breaking the result. What it does not tell you is
what code the other parties are running. You know party 2 followed the protocol. You do
not know whether party 2 also logged everything it saw.

TDX gives the complementary guarantee and none of the first one: it attests that a
specific measured software stack is running in a hardware-isolated VM, signed up to
Intel, but says nothing about how many such VMs exist or who operates them.

Stacked, the argument closes. Each node proves by hardware attestation that it is the
published code; the MPC protocol means no single node holds the secret anyway. A member
that cannot attest is refused before it learns anything.

Committee is n=4, t=1 — the smallest that tolerates one Byzantine member, since the code
enforces `n >= 3t + 1`.

## The result

Four parties, four distinct hardware identities, same attested stack, same opened value:

```
GET /<party>/attestation
  measurement     c5c28030fadd6fd685b0007d02a453ae40e8aa950d95b7ab11427103016ddfb5
                                   identical across all four
  tcb_status      UpToDate         identical across all four
  tls_derived_id  17002393024715824550 / 6746756146887130905 /
                  15243419626202361534 / 15060249417481226423

GET /<party>/result
  {"program_id":"7144a194d6364ed2","entry":"main",
   "value":"-4645747589851520984","completed_at":1786836064}    × 4, byte-identical
```

Full capture in [`evidence/w7-pod-evidence.txt`](evidence/w7-pod-evidence.txt).

Read it as three claims. Same measurement four times: same attested stack. Four different
derived identities: genuinely four nodes, not one answering four times. Same opened value
four times: the computation ran and the parties agree on its output.

The gate refuses as well as admits. Pin the allowlist to zeros, redeploy the same four
parties, and every one is turned away with the measurement it presented:

```
{"admitted":[],"rejected":[
  {"reason":"attestation: attestation measurement c5c28030…fb5 is not in the allowlist"},
  … four times
]}
```

## The program

Small on purpose, but it exercises the whole machine — two secret values sampled jointly,
multiplied (which consumes preprocessing and forces the parties to talk), and opened:

```python
def main() -> int64:
  var a: secret int64 = Share.random()
  var b: secret int64 = Share.random()
  var c: secret int64 = Share.mul(a, b)
  return c.reveal()
```

Nobody holds `a`, `b`, or `c` — each party holds a share. The open is what makes the run
checkable from outside: ask each node separately what it got, and see whether the four
answers agree.

## What had to be fixed

Everything below looked fine from the outside while being broken. That is the part worth
reading.

**The pinned measurement could never be stable.** The obvious digest to pin covers `mr_td`
and all four RTMRs. RTMR3 is the runtime-extended register, and its contents are per-boot and
per-deployment — the log carries `instance-id` and a `tee-daemon/promote` event per app.
Three distinct values inside one hour, spanning a CVM restart, with `mr_td` and RTMR0..2
byte-identical across all three. The allowlist went stale between
deploying the bootnode and deploying the parties, so every party was refused against a
value nobody could have pinned in advance.

Dropping RTMR3 from the pin fixes stability but throws away the app identity it carries.
So it is verified instead of pinned: replay the dstack event log into all four registers,
require each to equal the register in the Intel-verified quote, and only then read
`compose-hash` / `app-id` / `os-image-hash` back out. The replay is the load-bearing step
— until the fold lands on a value Intel signed, the log is just JSON the host handed you.
Verified against a live CVM: all four registers reconstruct exactly. Boot events carry
their digest; runtime events derive it as
`sha384(le32(event_type) : event : event_payload)`.

**The setting that makes peers reachable breaks quote verification.** Committee members
have to join a shared network to reach each other, and joining it makes the platform
inject `ALL_PROXY=socks5://…`. The HTTP client that fetches DCAP collateral honours that
variable and is compiled without SOCKS support, so the fetch fails outright and the node
exits about a second in — before registering, so the gate records neither an admission nor
a rejection. An empty admitted list *and* an empty rejected list means the party never
arrived, not that it was turned away. Fix: `NO_PROXY` for the collateral hosts, which are
directly reachable.

**Parties published an address no peer could reach.** Each tenant sits on two networks: a
private per-project one and the shared bridge. Advertising by resolving your own container
name asks for a name that exists on both, in no defined order. Draw the private address
and every peer connect times out; preprocessing dies with `PartyNotFound`. Registration
still works, because the bootnode is reachable — so the gate reports four healthy
admissions while the mesh underneath cannot connect. Fix: resolve the bootstrap host,
whose address is necessarily on a shared network, and advertise your own address on that
subnet. Covered by [`docker/test-advertise-pick.sh`](docker/test-advertise-pick.sh).

**The shared network is attached after the container starts.** Briefly the only address is
the private one, so the corrected selection still had nothing right to choose, and whichever
party started fastest published the wrong address anyway. One bad member stalls the whole
mesh. Fix: wait for an address on the bootstrap's subnet, and fail loudly rather than
publish something unroutable.

## Observability

A node exposes one HTTP port through the platform, and that is the entire outside view.

| route | says |
|---|---|
| `/health` | the process is alive, and its role |
| `/attestation` | this node's own attested measurement, TCB status, derived identity |
| `/peers` | on the bootnode: who was admitted, who was rejected and why |
| `/result` | what this party opened, once the run completes |

`/result` and a hold-open mode were added because a party used to exit as soon as it
finished, taking its result with it — a successful run erased its own evidence.

For crashes there is [`docker/debug-entrypoint.sh`](docker/debug-entrypoint.sh): run the
node with output captured to a file, then `exec busybox httpd` on the same proxied port,
so a dead node's full log is readable at `/<project>/node.log`. That is what surfaced the
peer-connect timeouts. If your platform exposes container logs you do not need it.

## Deploying

Scripts assume a dstack host running the tee-daemon project API, and expect
`WEBHOST_STAGING` and `TEE_DAEMON_TOKEN` in the environment, plus `STOFFEL_AUTH_TOKEN`
for the committee registration secret.

```sh
# 1. what CVM stack are we pinning?
python3 deploy/measurement_from_quote.py <(curl -s "$WEBHOST_STAGING/_api/verification/<project>" \
  -H "Authorization: Bearer $TEE_DAEMON_TOKEN" | jq -r .platform_quote.quote)

# 2. bootnode + four parties, attested
deploy/w7-final.sh <image@digest> <measurement>

# 3. did it work?
curl -s "$WEBHOST_STAGING/stoffel-node/peers"
for i in 0 1 2 3; do curl -s "$WEBHOST_STAGING/stoffel-p$i/result"; echo; done
```

Recompute the measurement after any CVM restart or upgrade — the boot registers are stable
for the life of a CVM, not across CVMs. Within one CVM the pin holds: a pin taken at one
point admitted a second generation of parties deployed eight minutes later, unchanged.

To watch the gate refuse, deploy the bootnode with an all-zeros pin first and read
`/peers`.

The image builds from `docker/dstack.Dockerfile` on the branch. It compiles the node with
real-TDX attestation, builds the StoffelLang compiler, and compiles the demo program from
source so the baked bytecode is derived from the committed `.stfl`.

## What this does not establish

- **That the quote describes this container image.** The pinned measurement covers the CVM
  stack; every tenant on a pod presents the same one. App binding comes from the anchored
  event log's `compose-hash`, which is a different and weaker statement than "this exact
  image".
- **That the allowlist holds the right value.** The pin's provenance is a separate problem.
- **Independence of the four parties.** They share a pod, an operator, and a host kernel. A
  real committee wants distinct operators — this is the interesting remaining work.
- **Recovery.** There is no resharing or membership change; a compromised member is not
  rotated out.

## Layout

```
deploy/    pod deployment + the offline measurement tool
docker/    debug entrypoint, advertise-selection test
evidence/  captured pod readouts, event-log fixture
```

Stoffel: https://stoffelmpc.com · dstack: https://github.com/Dstack-TEE/dstack
