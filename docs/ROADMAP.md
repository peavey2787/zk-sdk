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

## Open

- [ ] Run `run-all-linux.sh full` on Linux and add Linux-produced interop (currently NOT VALIDATED).
- [ ] Run the browser test on Firefox and Safari.
- [ ] Sweep the security range on the other circuits and add reference-witness differential tests for them.
- [ ] Multi-threaded browser proving (needs `SharedArrayBuffer` and cross-origin isolation); today it is single-threaded.
- [ ] Replace `bincode` 1.x when upstream moves, then drop the audit ignores.
- [ ] Committed private-state circuits (commitment/hash, transitions); `range7` is a syntactic example only.
- [ ] Spark matrix-closing mode (only DirectSparse is wired up).
