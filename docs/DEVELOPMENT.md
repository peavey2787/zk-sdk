# Development

## Prerequisites

Rust (stable), Python 3, Node 20+ for the interop script, and for the browser parts `wasm-pack` plus `rustup target add wasm32-unknown-unknown`. A Chrome/Chromium/Edge install is used by the browser test. Nothing is installed automatically and nothing needs administrator or root rights.

## Validation

`run-all-windows.cmd [fast|full]` and `./run-all-linux.sh [fast|full]` both call `scripts/run_all.py`.

| Step | What it does |
|---|---|
| layout / pins | required files, six facade names, no private artifacts; every git dependency pinned to a 40-hex rev and the lockfile agrees |
| fmt / clippy / test | `cargo fmt --check`, `clippy --all-targets -D warnings`, release tests with real proofs |
| wasm-build | `scripts/build_wasm.py` writes `web/pkg` and `web/circuits` (both git-ignored) |
| browser | `scripts/browser_test.py` serves `web/` and drives `selftest.html` in headless Chrome/Edge over the DevTools protocol |
| interop | `scripts/interop.py`: native CLI and wasm-under-Node each produce proofs and each verifies the other's, with wrong-statement and corrupted-proof negatives for every pair and circuit |
| audit | `cargo audit --deny warnings` (two unmaintained-crate notices are ignored by ID in `.cargo/audit.toml`) |
| perf | `scripts/perf_gate.py`: median native prove latency per circuit must stay under 1000 ms (target 500) |

Logs: `target/validation/*.log`; timings: `target/validation/report.txt`.

## Circuits

See `circuits/README.md`. Compiled vectors in `testdata/` are small and tracked. `age_over.wtns` is a reference witness from the C++ generator; a test asserts `zk-witness` reproduces it byte for byte.

## Rules

Warnings are errors, no dead or duplicated code, and the portable workflow lives once in `zk_sdk::portable`.
