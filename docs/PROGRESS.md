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
| Linux native, interop, browser | **Validated in CI** | GitHub Actions ubuntu-latest and windows-latest ran `run_all.py full` on the first push |
| Firefox / Safari | **NOT VALIDATED** | only Chromium-based Edge was run |
| macOS | **NOT VALIDATED** | |
| Sweep on circuits other than age_over | Not done | |

## Performance (Ryzen 7 5800X, Windows 11, default 116-bit full ZK)

Gate: target 500 ms, ceiling 1000 ms, median of the whole prove call (`scripts/perf_gate.py`, part of `run-all ... full`, default portable build).

| Setting | Median prove | p95 |
|---|---|---|
| native, 16 threads, portable build | ~40-50 ms | <200 ms |
| native, 1 thread (`RAYON_NUM_THREADS=1`) | ~69 ms | ~79 ms |
| wasm in Node, single thread (age_over) | ~70 ms (first run ~125 ms) | |
| wasm in the browser | re-measure; run `web/` | |

Root cause of the earlier 8-19 s browser times: upstream's recommended proof-of-work ceiling of 22 bits makes the prover grind a random nonce. With threads that is hidden; single-threaded it was ~1.5 s median and up to ~20 s p95. Capping it at 12 bits (query counts are derived from `security - pow_bits`, so the security target is unchanged; proof size unchanged at ~215 KB) gives ~70 ms with no variance. Key decode/prepare/witness import/encode total under 0.5 ms, so caching the prepared key saves nothing. The AVX2 build is no longer required; it helps natively but the portable build already meets the target. `simd128` for wasm was measured slower (~105 ms vs ~70 ms) and is not used.

Verify ~17-32 ms; proof ~215 KB; vk ~3-8 KB.

## Known gaps

- Linux and other-browser runs (above).
- `cargo audit` ignores two unmaintained-crate notices by ID (see SECURITY).
- Reference-witness differential tests exist only for age_over.
