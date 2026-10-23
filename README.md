# zk-sdk

Full-zero-knowledge proving and verification behind one small Rust facade. The same code runs natively on Windows 11 and Linux, and as WebAssembly in the browser, over the KoalaBear field with the upstream [Spartan-WHIR](https://github.com/ethereum/spartan-whir) backend. Nothing here is a mock: every proof is produced and checked by the real prover and verifier.

## Four calls

```rust
use zk_sdk::{Circuit, SecurityPolicy, Soundness};

let circuit = Circuit::new(r1cs_bytes, sym_text);
let (prover, verifier) = circuit.setup()?;                       // 116-bit full ZK by default
let proof = prover.prove(r#"{"age":"20","threshold":"18"}"#)?;   // witness + proof
verifier.verify(&[1, 18], &proof)?;                              // the statement YOU trust

// Power users: explicit policy (rejected, never adjusted, if the backend can't honor it)
let policy = SecurityPolicy::default().with_bits(110).with_soundness(Soundness::CapacityBound);
let (prover, verifier) = circuit.setup_with(policy)?;
```

`prover.to_bytes()` / `Prover::from_bytes` and the `Verifier` equivalents store and restore keys. The `zk` CLI, the wasm bindings and the six-operation facade below all sit on the same code.

## Predicates: prove facts about committed integers, no circuit needed

```rust
use zk_sdk::predicate::{Commitment, IntType, Predicate, Predicates};

let (a, open_a) = Commitment::commit(IntType::U64, 700u32)?;     // publish `a`, keep `open_a`
let (b, open_b) = Commitment::commit(IntType::U64, 690u32)?;
let claim = Predicate::conserve(vec![a], vec![b], 10u8);         // 700 == 690 + fee 10
let zk = Predicates::new();
let proof = zk.prove(&claim, vec![open_a, open_b])?;
zk.verify(&claim, &proof)?;                                      // needs only the claim and the proof
```

Opening, comparison, range, committed comparison, and exact-integer arithmetic (sums, balances, conservation with fees and explicit mint/burn, products, bounded division), over `u32 i32 u64 i64 u128 i128`, through Rust, the `zk predicate` CLI and the browser, with portable proofs verified across all of them. See [PREDICATES](docs/PREDICATES.md).

## Six operations

| Method | Purpose |
|---|---|
| `compile` | Validate a Circom R1CS and bind it to a program id |
| `setup` | Create proving/verifying keys under a security policy |
| `prove` | Produce a full-ZK proof from a witness |
| `verify` | Check a proof against a **trusted expected statement** and verifying key |
| `verify_batch` | Verify many proofs, one real verification each |
| `inspect` | Read proof metadata; this is **not** verification |

Byte-oriented entry points for the CLI and WebAssembly share one implementation, `zk_sdk::portable`; file helpers (`zk_sdk::files`) exist natively only.

## Quick start (Windows or Linux, no WSL)

```sh
cargo build --release -p zk-cli
D=testdata/age_over
target/release/zk setup  --r1cs $D/age_over.r1cs --pk pk.bin --vk vk.bin
target/release/zk prove  --pk pk.bin --r1cs $D/age_over.r1cs --sym $D/age_over.sym --input $D/input.json --proof proof.bin
target/release/zk verify --vk vk.bin --expected 1,18 --proof proof.bin
```

`--expected` is the public statement you trust (circom order: outputs, then public inputs). The statement a proof claims is never trusted.

## Browser

```sh
python scripts/build_wasm.py          # needs wasm-pack and the wasm32-unknown-unknown target
python -m http.server 8000 --directory web
```

Open `http://localhost:8000`. Witness generation, setup, proving and verification run in a Web Worker, all inside the page; private inputs and keys are never sent anywhere. Proofs and verifying keys can be exported, imported and deliberately corrupted. Proving is single-threaded (no threads are assumed), so it is slower than native (see PROGRESS). Any static host works; the page has no server component.

## Security policy

`SecurityPolicy { bits, full_zero_knowledge, soundness }`; the default is 116 bits, full ZK, Johnson bound. The backend advertises what it supports (currently 100..=118 bits, all three soundness modes, ZK only) and `setup` rejects anything else. The policy is bound into keys and proofs, so a proof made under one policy is refused under another. No 128-bit claim is made. See [SECURITY](docs/SECURITY.md).

## Validation

```sh
run-all-windows.cmd full        # or ./run-all-linux.sh full; omit "full" for the fast subset
```

Fast: layout, pinned revisions, `fmt`, `clippy -D warnings`, tests. Full adds the wasm build, a real-browser test, the native/wasm interop matrix, and `cargo audit`. `perf` is a separate mode with native and browser latency gates (500 ms target, 1000 ms ceiling), which the secure prover currently misses in the browser. Logs and timings land in `target/validation/`. Linux and macOS are **NOT VALIDATED** until you run it there; see [PROGRESS](docs/PROGRESS.md).

## Workspace

- `zk-core`: formats, policy, key/proof binding, backend trait
- `zk-spartan-whir`: the Spartan-WHIR backend
- `zk-witness`: pure-Rust Circom witness solver (native and wasm)
- `zk-sdk`: facade, `portable` byte API, native `files`
- `zk-cli`: the `zk` binary
- `zk-wasm`: wasm-bindgen exports
- `web`: static browser demos (generic circuits and predicates); `circuits`, `testdata`: sources and compiled vectors

[Architecture](docs/ARCHITECTURE.md) · [Development](docs/DEVELOPMENT.md) · [Security](docs/SECURITY.md) · [Progress](docs/PROGRESS.md) · [Roadmap](docs/ROADMAP.md)
