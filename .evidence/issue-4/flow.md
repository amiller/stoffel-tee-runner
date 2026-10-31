# Flow evidence — issue #4 (L5 webapp over the lobby)

Story acceptance (from the issue's `## Acceptance`), and what was done for each
box. The page has no sign-in — the issue says no account is needed — so the
flow is the page itself against the mock API.

## Reproduce

    python3 web/mock/serve.py            # mock lobby + page on http://127.0.0.1:8081/

Open http://127.0.0.1:8081/ in a browser. Screenshots below were captured from
that exact command (fixture `tampered-measurement.json` mounted, its default)
by driving the real snap Firefox headless via geckodriver (W3C WebDriver, no
CDP — this is our own page on loopback). Each capture asserts the DOM
condition it screenshots before shooting; a blank or stale frame cannot pass
the script.

## The walk

1. **Nodes view** — `01-nodes.png`. The page (base URL empty = same origin)
   fetches `GET /nodes` and renders both nodes from the fixture bundle:
   label, endpoint, capabilities, pubkey, last seen (`announced_at`, absolute
   + relative), and attestation material with a SHA-256 fingerprint of each
   quote. Capture-time assertions: table rows present; `quote sha256 …`
   fingerprints resolved (async WebCrypto).
2. **Jobs view** — `02-jobs.png`. `GET /jobs` rendered grouped by `JobState`:
   open (1), forming (1), running (1), finished (1), failed (1). The open job
   carries the visible warning badge **UNCONSTRAINED — no accepted
   measurements: any code is admitted to this job** (capture asserted the
   badge text in the DOM). This is the empty-`JobPolicy` rendering the
   `JobPolicy` doc comment in `lobby-records` demands.
3. **Evidence view** — `03-evidence-tampered.png`. Deep link
   `/#job=f00dfeed…` opens the job's bundle from `GET /jobs/{id}/bundle`:
   self-reported record summary, each node's collateral validity window, and
   the command

       stoffel-verify --at 1751624163 f00dfeedf00dfeed.bundle.json

   (also in `command-shown.txt`). `--at 1751624163` is computed by the page
   as the midpoint of the intersection of every node's collateral window
   (issueDate 2025-06-19T10:16:03Z .. nextUpdate 2025-07-19T10:16:03Z); the
   capture asserted the shown value equals the independently computed
   1751624163. The full bundle JSON is shown beneath, plus a download link
   that saves it under the exact filename in the command.
4. **The verdict that names the failure** — `stoffel-verify-tampered.txt`:
   running the page's command, the real verifier rejects the bundle with

       stoffel-verify: measurement not allowed (node 83561adb…): b850cee4…
       is not in the job policy

   The named link is `MeasurementNotAllowed` — the check the issue's
   tampered fixture exists to trip. That the rejection is *not*
   `CrlExpired` (the wall-clock failure mode) is what proves the page's
   pinned `--at` really lies inside the collateral window.

## The page never asserts a verdict

There is no verdict, verified, valid or status text anywhere in the page, and
none in the frozen `lobby-records` schema it renders. Per the issue's
fallback clause the Evidence view shows the bundle and the exact check
command instead.

## What could NOT be verified

- **In-browser verdict.** `stoffel-verify` does not compile for
  `wasm32-unknown-unknown`: it depends on `stoffel-vm` (git, feature
  `attestation-dstack`), whose tokio/quinn tree pulls `mio` unconditionally,
  and mio rejects the target outright ("This wasm target is unsupported by
  mio"). Transcript: `wasm-build-failure.txt`. The fallback path was taken;
  the primary path can be revisited when the fork's attestation code builds
  without the net stack.
- **Passing verdict on `valid.json`.** No such fixture exists or can exist
  yet: every bundle that passes every check needs a real TDX quote whose
  `report_data[8..40]` binds a key the fixture author holds — hardware-minted
  (PR #11 documents this same blocker for issue #1). The page's passing
  render path exists but no fixture can drive it; demonstrated instead: the
  failing verdict above.
- **"Attested measurement" in the nodes view.** The measurement is
  *established by* quote verification (stoffel-vm returns it from the
  verified quote); without the wasm build the page cannot honestly display
  one, so it shows the quote fingerprint and sizes instead, labeled as
  identifiers. Anything more would be a verdict the page did not compute.
