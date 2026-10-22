# Predicates

Say what is true about a committed integer and prove it. Built-in predicates need no circuit, compiler or setup: the SDK bundles pinned, identity-checked circuits and keys each one on first use.

```rust
use zk_sdk::predicate::{Commitment, IntType, Predicate, Predicates};

let (commitment, opening) = Commitment::commit(IntType::U32, 20u32)?; // publish `commitment`, keep `opening`
let zk = Predicates::new();
let claim = Predicate::at_least(commitment, 18);
let proof = zk.prove(&claim, opening)?;
zk.verify(&claim, &proof)?;
```

## Families (all work through Rust, the `zk` CLI and browser WASM)

| Family | Constructors | Statement |
|---|---|---|
| Commitment opening | `opens` | the prover knows the value and blinding behind a commitment |
| Comparison | `at_least` `at_most` `greater_than` `less_than` `equals` `not_equals` (or `compare(c, Op, bound)`) | committed value `op` public bound |
| Range | `in_range` (inclusive), `in_range_with(.., lo_inclusive, hi_inclusive)` | `lo <(=) value <(=) hi` |
| Committed vs committed | `compare_committed(left, op, right)` | `left op right`; both openings held by the same prover (not a two-party protocol) |

Types: `u32 i32 u64 i64 u128 i128`. A bound or value outside its type is an error, never wrapped or saturated.

## Claim JSON (CLI, browser, interchange)

```json
{"kind":"opens","commitment":"u32:<64 hex>"}
{"kind":"compare","commitment":"u32:<64 hex>","op":"ge","bound":"18"}
{"kind":"range","commitment":"i64:..","lo":"-10","hi":"5","lo_inclusive":true,"hi_inclusive":false}
{"kind":"compare_committed","left":"i64:..","right":"i64:..","op":"lt"}
```

`op` is one of `lt le gt ge eq ne`. Numbers are decimal strings so 128-bit values survive JSON.

## CLI

```sh
zk predicate commit   --type u32 --value 20 --commitment age.c --secret age.s   # prints the commitment
zk predicate describe --claim claim.json                                         # circuit and public inputs
zk predicate prove    --claim claim.json --secret age.s [--secret2 other.s] --proof p.zkp
zk predicate verify   --claim claim.json --proof p.zkp                           # prints VALID or fails
```

Each command is its own process: verification needs only the claim and the proof, never the secret.

## Browser

`web/predicates.html` (served with `web/pkg` built by `scripts/build_wasm.py`) offers family and type selection, private values, commitment, prove, verify, claim/proof import and export, a corrupt-the-proof button and timings. All cryptography runs in a Web Worker through `web/job-runner.js`: one job at a time (overlapping jobs are refused, not queued), and Cancel terminates the worker and starts a fresh one (warmed keys are dropped). The page reports the longest main-thread stall while working.

## Security model

- **Trusted inputs.** `verify` takes the claim from the application; public inputs are derived from it, never read from the proof. Keys are derived deterministically from the bundled circuit and the policy and are bound into the proof (circuit, policy, backend version).
- **Commitment.** `digest = Poseidon2(width 16, rate 8, capacity [domain, length])` over `[signed, limb count, 16-bit limbs.., 8 random blinding elements]`. Binding up to the sponge's collision resistance (8 x 31-bit digest); hiding while the blinding is secret and uniformly random (rejection-sampled from the OS or browser CSPRNG). The type is part of the preimage, so a commitment cannot be reinterpreted under another width or signedness.
- **Integers.** 16-bit limbs, each range-checked in the circuit; signed values are offset-binary (`v + 2^(w-1)`), so one unsigned borrow-chain comparison serves both. Every public bound is range-checked in the circuit. No field wrap-around is possible at 17-bit decompositions.
- **Host/circuit agreement.** The host commitment (Plonky3's Poseidon2) is accepted by the compiled circuit in every predicate proof, natively and in WASM; the interop matrix mixes native- and WASM-made commitments.
- **Circuit identity.** Each bundled R1CS is SHA-256-checked against `approved.rs` before use; `scripts/build_circuits.py --check` (part of `run-all full`) rebuilds the circuits with the pinned compiler and fails on any difference.
- **Not established.** The end-to-end soundness of the configured 116-bit target has not been independently recomputed, so no post-quantum bit-security figure is claimed. Secrets stay in browser/process memory and are not zeroized. `compare_committed` is a statement by one prover about two of their own secrets.
