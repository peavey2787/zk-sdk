# Roadmap

Keep the facade at six operations. Mark a milestone done only when its acceptance test actually ran; `docs/PROGRESS.md` holds the evidence.

## Done

- [x] Workspace: `zk-core`, `zk-witness`, `zk-spartan-whir`, `zk-sdk`, `zk-cli`, `zk-wasm`.
- [x] Native library integration with the pinned upstream (no subprocesses, no WSL).
- [x] Pure-Rust witness generation, byte-identical to the C++ reference for `age_over`.
- [x] Security policy bound into keys and proofs; range 100..=118 validated by sweep.
- [x] Browser WebAssembly build and demo, tested in headless Edge.
- [x] Native/wasm interop matrix with negative tests.
- [x] `run-all` fast and full modes, logs, timing report, pinned-revision check, `cargo audit`.

- [x] Predicate library, first four families (opening, comparison, range, committed comparison) across `u32 i32 u64 i64 u128 i128`: Rust, CLI and browser WASM, native/WASM interop, circuit reproducibility check in the gate.

- [x] Arithmetic and conservation: sums, balances, conservation with fees and explicit mint/burn, products, bounded division, mixed public/private operands, all six types; differential-tested against a reference semantics; Rust, CLI, browser, native/WASM interop.

- [x] Merkle/set membership and non-membership (member and gap trees, depths 8 and 20, all six types): Rust, CLI, browser, native/WASM interop, differential-tested; publisher-honesty assumption documented.

- [x] Predicate composition (interval unions, negation, shared-commitment conjunctions): Rust, browser, interop, differential-tested.
- [x] Credentials (issuer-backed attribute, serial, expiry, unlinkable presentations, revocation via set non-membership; 115-bit opt-in): Rust, CLI, WASM, differential-tested.
- [x] Private state transitions (rule vocabulary lowered to conjunctions; chaining by commitment identity): Rust, CLI, WASM, browser, interop.
- [x] Private proximity/distance (committed 2D point vs public centre and radius, exact squares, all six types): Rust, browser, native/WASM interop, differential-tested.

- [x] Groth16 backend, first slice: `zk-groth16` (Groth16 on arkworks curves against snarkjs zkeys), BN254 builds of open/compare/range/compare_committed at 32/64/128 bits, public Hermez phase 1 plus a documented phase 2 (`docs/GROTH16_SETUP.md`), benchmark.
- [x] Groth16 integration: scheme-tagged commitments and proofs in `Predicates` (including conjunctions), CLI (`--scheme`) and WASM/browser; native/WASM interop.
- [ ] Groth16: remaining families on BN254; more phase-2 contributors; optional Rapidsnark; browser timings.

## Next predicate families (in order; reuse the shared gadgets in `circuits/lib`)


## Performance research (separate from correctness)

- [ ] Profile proof-of-work grinding and the commitment gadget; evaluate upstream-supported parameter schedules (each with its own soundness review), multi-worker grinding, other transparent backends. Target 500 ms, ceiling 1000 ms; currently missed (see PROGRESS).
- [ ] Independent recomputation of end-to-end soundness for the configured parameters.

## Open

- [ ] Run `run-all-linux.sh full` on Linux and add Linux-produced interop (currently NOT VALIDATED).
- [ ] Run the browser test on Firefox and Safari.
- [ ] Sweep the security range on the other circuits and add reference-witness differential tests for them.
- [x] Multi-threaded browser proving (`web/pkg-threads`, cross-origin-isolated pages) and native AVX2 auto-dispatch.
- [ ] WASM SIMD: Plonky3 has no wasm32 packed field, so browser arithmetic stays scalar (upstream work).
- [ ] Replace `bincode` 1.x when upstream moves, then drop the audit ignores.
- [ ] Spark matrix-closing mode (only DirectSparse is wired up).
