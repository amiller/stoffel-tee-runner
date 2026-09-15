Attestation material for the stoffel-verify tests and fixtures. All four
files are copied verbatim from the StoffelVM fork at branch
`w7-committee-demo` (commit `5d4e69edbccb5b7ecd76694e8bb3b8c57280d805`),
where their provenance is documented:

- `tdx_quote.bin` — a real Intel TDX quote (TD report, version 4), the
  canonical `dcap-qvl` sample vendored by the fork at
  `crates/stoffel-vm/src/tests/fixtures/dstack/tdx_quote.bin`. It carries a
  real Intel signature chain and verifies against the Intel root of trust
  via `verify_dstack_quote_with_registers`.
- `tdx_quote_collateral.json` — the DCAP collateral matching that quote
  (fork path `crates/stoffel-vm/src/tests/fixtures/dstack/tdx_quote_collateral.json`).
  Its validity window is 2025-06-19..2025-07-19, so verification of this
  quote must be pinned with `--at` inside that window; expiry is enforced,
  not bypassed.
- `pod_event_log.json`, `pod_registers.json` — the w7 pod's RTMR event log
  and the registers it replays onto (fork paths
  `crates/stoffel-vm/tests/fixtures/dstack/{pod_event_log,pod_registers}.json`).
  Shape and digest convention captured from a live dstack CVM;
  deployment-identifying payloads replaced and the registers recomputed so
  the pair is internally consistent — this pair is NOT the log of
  `tdx_quote.bin`, which is exactly what makes it a real "event log does not
  replay onto this quote" test case.
