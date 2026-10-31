# Lobby webapp

Read-only page over the lobby API (`GET /nodes`, `GET /jobs`,
`GET /jobs/{id}/bundle`). The lobby is an untrusted index, so the page renders
what the records say and asserts no verdict of its own — see the Evidence view
for the exact command that checks a bundle.

## Run it (mock lobby, no deployment needed)

    python3 web/mock/serve.py

then open http://127.0.0.1:8081/ . The mock serves the page and the API
same-origin from the committed fixtures; it mounts
`evidence/bundles/tampered-measurement.json` by default, and takes any fixture
as an argument (all four share one job_id, so one is mounted per run):

    python3 web/mock/serve.py wrong-key-binding.json

The synthetic jobs in the other states come from
`web/mock/data/mock-jobs.json` (see `web/mock/data/README.md` for
provenance; regenerate with `./scripts/build.sh run -p stoffel-lobby --bin
gen-mock-data`).

## Against a real lobby

Type the lobby's base URL into the header field and Load. Note: the
`stoffel-lobby` service sends no CORS headers, so the page must be served
from the lobby's own origin (or behind a proxy that adds them) — a
cross-origin fetch fails, and the page says so rather than showing stale
data.

## Why no in-browser verdict

The issue allows the verifier compiled for `wasm32-unknown-unknown` as the
primary path. That build does not compile: `stoffel-verify` depends on
`stoffel-vm`, whose dependency tree pulls tokio/quinn → `mio` unconditionally,
and `mio` does not build for wasm32 (48 errors; reproduce with
`./scripts/build.sh build -p stoffel-verify --lib --target
wasm32-unknown-unknown` after `rustup target add wasm32-unknown-unknown`).
Per the issue's fallback, the Evidence view therefore shows the bundle JSON
and the exact `stoffel-verify --at … ` command — pinned inside the bundle's
collateral validity window — and no verdict text at all. When the fork's
attestation feature can be built without the net stack, the primary path can
be revisited.
