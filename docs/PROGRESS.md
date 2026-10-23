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
| Predicate library: open / compare (6 ops) / range / committed-vs-committed, u32 i32 u64 i64 u128 i128 | **Validated natively** | `crates/zk-sdk/tests/predicates.rs`: real full-ZK proofs, positive, boundary, negative, malformed, adversarial |
| Poseidon2 commitment, circuit vs host | **Validated** | host commitments are accepted by the compiled circuit in every predicate proof |
| Predicate CLI (`zk predicate ...`), wasm bindings, browser demo (Worker, cancel, no overlap) | **Validated** | `crates/zk-cli/tests/e2e.rs`, `web/predicates-selftest.html` (14 checks, real browser proofs), docs/PREDICATES.md |
| Native <-> WASM predicate interop | **Validated (Windows host)** | `scripts/interop.py`: native- and WASM-made commitments, proofs from both verified by both, altered-claim and corrupted-proof negatives |
| Per-predicate browser perf | **Measured** | table below; 5 samples, so p50 only |
| Circuit reproducibility (`scripts/build_circuits.py --check`) | **In the full gate** | byte-identical rebuild on Windows; Linux result comes from CI |
| Arithmetic and conservation: sums, balances, conservation (fees, mint/burn), products, bounded division, mixed public/private operands, six types | **Validated** | circuits vs unbounded-integer reference: `predicate/differential.rs` (5 suites x 40 rounds x 6 types, true and false cases); real proofs: `crates/zk-sdk/tests/arithmetic.rs` (14 tests incl. tampering, wrap-around, wrong openings); CLI e2e; browser self-test (22 checks, real in-browser proofs); native<->WASM interop for conserve/product/divide |
| CI for `3623bc0` (previous milestone) | **Validated** | `validate` job green on ubuntu-latest and windows-latest (incl. Linux circuit reproducibility and interop); the separate `performance` job fails as before (latency gate, `continue-on-error`) |
| Set/Merkle membership, proximity, credentials, state transitions, composition | **Not started** | |

## Performance (Ryzen 7 5800X, Windows 11, default 116-bit full ZK, upstream parameters)

Latency is gated separately from security/correctness: `run-all ... perf` (own CI job, `continue-on-error`). The target is 500 ms and the ceiling 1000 ms on p50; a miss is reported, not hidden. 20 runs per circuit, whole prove call, default portable build, 16 threads for native (`scripts/perf_gate.py`, `scripts/browser_test.py perftest.html`; raw numbers in `target/validation/perf-*.json`).

| Circuit | Native p50 | p95 | p99 | Browser WASM p50 | p95 | p99 |
|---|---|---|---|---|---|---|
| age_over | 689 ms | 1886 ms | 1886 ms | 6881 ms | 20256 ms | 20256 ms |
| arithmetic | 522 ms | 1150 ms | 1150 ms | not measured | | |
| millionaires | 379 ms | 1561 ms | 1561 ms | not measured | | |

(With 20 runs p95 and p99 are the same sample.) Single-thread native earlier measured ~2100 ms p50 / ~12000 ms p95 on age_over; numbers vary run to run (the machine is not quiet).

**The secure prover does not meet the 1000 ms target in the browser (p50 ~6.9 s, p95 ~20 s) and misses it at p95/p99 natively.** Cause: upstream's proof-of-work grinding is a random nonce search with a heavy tail; threads hide it natively but browser WASM is single-threaded. The 70-90 ms figures reported earlier came from a 12-bit grinding cap that was reverted because its security effect was not established.

Unresolved: security-preserving options not yet evaluated, each requiring its own soundness review: multi-worker grinding (needs an upstream change or WASM threads with cross-origin isolation), an upstream-approved parameter schedule with matching soundness calculations, a faster Poseidon hash, or a different transparent backend. Applications must prove asynchronously (the demo already runs in a Worker). Key decode/prepare/witness import/encode total under 0.5 ms, so key caching saves nothing. The AVX2 build is optional and not benchmarked separately yet.

### Arithmetic and conservation circuits

Constraints: `sum4` 7963 / 8403 / 12947, `sum8` 15487 / 16079 / 24591, `arith` 8506 / 9548 / 15392 (32 / 64 / 128-bit). **Upstream attains 116 bits only up to 8192 constraints**: `sum4_32` runs at 116, every larger circuit at 115 (reported by `Predicates::security_bits`, see SECURITY). Native, Ryzen 7 5800X, 16 threads, 20 samples, whole prove call (`bench_predicates`); optimized = `-C target-cpu=x86-64-v3`:

| Circuit (32 / 64 / 128-bit) | native portable p50 | native portable p95 | native optimized p50 | native optimized p95 | proof |
|---|---|---|---|---|---|
| conserve4 (`sum4`) | 1815 / 3440 / 3051 ms | 2965 / 5537 / 4950 | 331 / 556 / 696 ms | 436 / 779 / 973 | 822-880 KB |
| conserve8 (`sum8`) | 2820 / 3779 / 4074 ms | 5234 / 4632 / 5467 | 744 / 631 / 1041 ms | 940 / 959 / 1393 | 876-975 KB |
| multiply (`arith`) | 3077 / 2725 / 3144 ms | 3645 / 4762 / 5712 | 492 / 501 / 654 ms | 657 / 802 / 844 | 876-881 KB |
| divide (`arith`) | 3131 / 2764 / 2885 ms | 4414 / 3828 / 4527 | 541 / 533 / 669 ms | 760 / 735 / 905 | 880-886 KB |

Verify 33-75 ms. **Target status (optimized build):** only `conserve4_32` (331 ms) and `multiply_32` (492 ms) meet the 500 ms target; every other new circuit lands at 501-1041 ms, and `conserve8_128` (1041 ms) exceeds the 1000 ms ceiling. The portable build misses both targets everywhere (1.8-4.1 s). The machine was not quiet (the pre-existing circuits measured 1.0-1.5 s portable in this run versus 1.06-1.77 s before). These are performance misses, reported as such; no parameter was touched.

**Browser (headless Chromium 155 via `scripts/browser_test.py predicates-perftest.html?n=3`, Worker, portable WASM, n=3 so p50 only; p95/p99 not reported).** Real in-browser proofs, all verified. Prove p50 (ms): opens 13774 / 11591 / 31137; compare 18787 / 15109 / 18975; range 20528 / 19173 / 19301; compare_committed 19211 / 17500 / 17356; conserve4 21417 / 36552 / 56188; conserve8 34948 / 22247 / 59065; multiply 34139 / 41410 / 31188; divide 52104 / 46448 / 29733 (32 / 64 / 128-bit). Verify 59-160 ms, proofs 0.63-0.97 MB, WASM memory up to 226 MiB, UI stall at most 5 ms. **Every circuit misses the 500 ms and 1000 ms browser targets by 10-60x**, the pre-existing four families included, and the run is far noisier than native (the same circuit varies 2x between first prove and p50). Timings were taken on a machine that was also doing other work during part of the run, so treat them as an upper bound, not a characterisation; the browser performance gap is open and is not closed by this milestone.

### Predicate library (all 12 circuits, default upstream 116-bit full-ZK policy)

Native: Ryzen 7 5800X, 16 threads, 20 samples per circuit, whole prove call including witness (`cargo run --release -p zk-sdk --example bench_predicates`). Optimized = `-C target-cpu=x86-64-v3` (AVX2/BMI2, opt-in). Browser: headless Edge 155 on the same machine, 5 samples per circuit (`scripts/browser_test.py predicates-perftest.html?n=5`), so **p95/p99 are not supported by the sample count and are not reported**; native p99 needs >=100 samples and is not reported either.

| Circuit | constraints | proof | native portable p50 / p95 | native optimized p50 / p95 | browser WASM p50 | verify native / browser |
|---|---|---|---|---|---|---|
| open_32 / 64 / 128 | 1867 / 1901 / 2885 | 633-726 KB | 1059 / 1134 / 1308 ms; 2758 / 2017 / 2834 | 161 / 178 / 238 ms; 250 / 293 / 312 | 10.8 / 6.8 / 18.3 s | 23-42 / 43-53 ms |
| compare_32 / 64 / 128 | 1989 / 2137 / 3349 | 631-728 KB | 1315 / 1558 / 1461 ms; 2251 / 2486 / 2565 | 222 / 183 / 232 ms; 348 / 309 / 295 | 12.9 / 19.6 / 14.8 s | 23-43 / 49-59 ms |
| range_32 / 64 / 128 | 2103 / 2365 / 3805 | 725-730 KB | 1225 / 1348 / 1423 ms; 1690 / 2134 / 2045 | 219 / 226 / 224 ms; 338 / 285 / 311 | 10.5 / 14.1 / 9.7 s | 25-50 / 48-53 ms |
| compare_committed_32 / 64 / 128 | 3821 / 3969 / 6097 | 726-824 KB | 1273 / 1550 / 1767 ms; 1917 / 2674 / 2982 | 231 / 255 / 347 ms; 327 / 308 / 516 | 11.0 / 12.4 / 11.9 s | 27-58 / 53-75 ms |

Browser extras: wasm linear memory 16-63 MiB (cumulative over the run, one worker), longest main-thread stall while proving 1-18 ms (the page stays responsive), first prove per circuit (circuit load + key setup + prove) 7.6-32 s. Browser numbers are noisy (5 samples; the machine was not otherwise idle).

**Target status (500 ms target, 1000 ms ceiling, p50):**
- Native optimized (AVX2): **met** for every circuit (161-347 ms); p95 up to 516 ms.
- Native portable: **missed** (1.06-1.77 s p50; p95 1.7-3.0 s).
- Browser WASM: **missed** by 7-20x (6.8-19.6 s). Dominated by single-threaded proof-of-work grinding and unvectorised field arithmetic; the application must prove asynchronously (the demo does, in a Worker).

The optimized build is opt-in and refuses to start on CPUs without AVX2/BMI2. Nothing above lowers any security parameter. Investigation of the browser path (WASM threads for grinding, upstream-approved schedules, other transparent backends) is open and tracked in ROADMAP; each option needs its own soundness review.

**End-to-end soundness of the configured 116-bit target is still not independently recomputed.** Nothing here claims 116-bit post-quantum security.

Verify ~17-32 ms; proof ~215 KB; vk ~3-8 KB.

## Known gaps

- Linux and other-browser runs (above).
- `cargo audit` ignores two unmaintained-crate notices by ID (see SECURITY).
- Reference-witness differential tests exist only for age_over.
