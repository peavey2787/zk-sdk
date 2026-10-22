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
| Predicate CLI, wasm bindings, browser demo, per-predicate browser perf | **Not done** | the shared engine (`zk_sdk::predicate`) is not yet exposed there |
| Circuit reproducibility (`scripts/build_circuits.py --check`) | Implemented, **not in the gate** | pinned circom fork; byte-identity across Windows/Linux not yet confirmed |
| Arithmetic, set/Merkle membership, proximity, credentials, state transitions, composition | **Not started** | |

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

### Predicate library (native, release, 16 threads, 20 samples, whole prove call incl. witness)

| Circuit | setup | p50 | p95 | verify | proof |
|---|---|---|---|---|---|
| open_32 / 64 / 128 | 1.2-2.9 s | 1814 / 1877 / 1537 ms | 3285 / 3474 / 3624 ms | 48-64 ms | 634-725 KB |
| compare_32 / 64 / 128 | 1.9-3.5 s | 2176 / 1406 / 1384 ms | 3706 / 3170 / 2140 ms | 42-76 ms | 632-732 KB |
| range_32 / 64 / 128 | 0.7-3.0 s | 1698 / 1939 / 1236 ms | 4771 / 2771 / 1922 ms | 41-78 ms | 726 KB |
| compare_committed_32 / 64 / 128 | 2.2-2.9 s | 2142 / 1822 / 1699 ms | 3138 / 4536 / 3014 ms | 46-69 ms | 722-818 KB |

**No predicate meets the 1000 ms target natively**: the commitment opening (Poseidon2 inside the circuit) makes every circuit larger than age_over, and the same grinding tail applies. p99 needs >=100 samples and is not reported. Browser numbers for predicates are not measured yet. Reproduce with `cargo run --release -p zk-sdk --example bench_predicates`.

**End-to-end soundness of the configured 116-bit target is still not independently recomputed.** Nothing here claims 116-bit post-quantum security.

Verify ~17-32 ms; proof ~215 KB; vk ~3-8 KB.

## Known gaps

- Linux and other-browser runs (above).
- `cargo audit` ignores two unmaintained-crate notices by ID (see SECURITY).
- Reference-witness differential tests exist only for age_over.
