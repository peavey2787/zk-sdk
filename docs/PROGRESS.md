# Progress

Measured on Windows 11, native `x86_64-pc-windows-msvc`, rustc 1.98.1; wasm in headless Edge and Node 24. Re-run `run-all-windows.cmd full` to reproduce.

| Area | Status | Evidence |
|---|---|---|
| Native Windows prove/verify (no WSL) | **Validated** | `zk-cli` e2e tests; age_over, arithmetic, millionaires |
| Pure-Rust witness generation | **Validated** | byte-identical to the C++ reference `.wtns` for age_over; other circuits checked by satisfiability and real proof verification |
| WebAssembly prove/verify | **Validated** | `scripts/browser_test.py` (headless Edge) and a manual run of `web/` |
| Native <-> wasm interop | **Validated** | `scripts/interop.py`: 4 producer/verifier pairs x 3 circuits, with negatives |
| Negative tests | **Validated** | wrong witness, wrong statement, corrupted/truncated proof, foreign vk, unsupported security |
| Security sweep | **Validated** | 100..=118 bits x 3 soundness modes on age_over; the advertised range was narrowed to match |
| Linux native | **NOT VALIDATED** | no Linux host here; `run-all-linux.sh` is written but unexecuted |
| Linux-produced <-> Windows/wasm interop | **NOT VALIDATED** | needs a Linux run |
| Firefox / Safari | **NOT VALIDATED** | only Chromium-based Edge was run |
| macOS | **NOT VALIDATED** | |
| Sweep on circuits other than age_over | Not done | |

## Performance (Ryzen 7 5800X, 16 threads, Windows 11, default 116-bit full ZK, `zk bench --runs 20-40`)

Gate: target 500 ms, ceiling 1000 ms, median of the whole prove call (`scripts/perf_gate.py`, part of `run-all ... full`).

| Circuit | Median | p95 |
|---|---|---|
| age_over, arithmetic, millionaires | 42-49 ms | 170-195 ms |

Where the time went (millionaires, median): decode_key ~25 us, prepare_key ~25 us, import_witness ~7 us, encode_proof ~0.3 ms, **spartan_whir_prove essentially all of it**. Caching the prepared key therefore saves nothing and was not done. The measured wins were: the build without AVX2 (baseline x86-64) took ~420-640 ms median with spikes beyond 1.3 s, and `target-cpu=x86-64-v3` cut that to ~45-65 ms. Enabling upstream `parallel` only affects grinding and rayon call sites. A 2,068 ms result was not reproducible here and its circuit/machine are unknown; it is consistent with a baseline-CPU build on a loaded machine (this one was running a game, p95s reflect that).

Browser (headless-free Edge pane, age_over, single thread, simd128): prove ~8.1 s (was ~13 s without simd128), verify ~32 ms. **The 500-1000 ms target is not met in the browser** and is not claimed there. Proof ~214-260 KB, vk ~3-8 KB.

## Known gaps

- Linux and other-browser runs (above).
- Browser proving is single-threaded and ~170x slower than native; target not met there.
- Release binaries require AVX2/BMI2 on x86-64.
- `cargo audit` ignores two unmaintained-crate notices by ID (see SECURITY).
- Reference-witness differential tests exist only for age_over.
