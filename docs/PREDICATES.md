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
| Sum / balance | `sum(plus, plus_const, op, minus, minus_const)`, `sum_equals`, `total_compare(terms, op, bound)`, `add`, `subtract` | `Σplus + c1  op  Σminus + c2` on exact integers; at most 8 committed terms of one type |
| Conservation | `conserve(inputs, outputs, fees)`, `conserve_with_supply(inputs, outputs, fees, minted, burned)` | `Σinputs (+ minted) == Σoutputs + fees (+ burned)`; mint and burn are explicit public amounts |
| Product | `multiply(x, y, product)`, `arithmetic(x, y, z, op, t)` | `x·y + z op t` on exact integers; each operand is public (`3u8`) or committed |
| Division | `divide(dividend, divisor, quotient, remainder)` | `dividend = quotient·divisor + remainder`, `divisor > 0`, `0 <= remainder < divisor` |
| Set membership | `member_of(commitment, set)` | the committed value is in the published set; which member stays hidden |
| Set non-membership | `not_member_of(commitment, set)` | the committed value is not in the published set |

Types: `u32 i32 u64 i64 u128 i128`. A bound or value outside its type is an error, never wrapped or saturated.

## Arithmetic and conservation

```rust
let claim = Predicate::conserve(vec![in1, in2], vec![out1, out2], 10u8); // in1 + in2 == out1 + out2 + 10
let proof = zk.prove(&claim, vec![open_in1, open_in2, open_out1, open_out2])?;
zk.verify(&claim, &proof)?;
```

- **Exact integers, never modular.** Every committed value is bound to its commitment (type, value, blinding). Sums and products are computed on unbounded integers in the circuit and compared exactly: `u32::MAX + u32::MAX` is `2^33 - 2`, not a wrapped value, and a product that does not fit the type is simply not equal to a value that does. Signed values use offset-binary, so signedness is enforced, not assumed. No field wrap-around is possible: every carry and limb is range-checked.
- **Division** has no hidden quotient. The quotient and remainder are committed (or public) operands, so the circuit only has to check `dividend = quotient·divisor + remainder` and the three side conditions. Division by zero, a negative divisor and an out-of-range remainder have no proof.
- **Constants** in sums are non-negative amounts that fit the type's width; `conserve_with_supply` is an error rather than a wrap if `fees + burned` overflows.
- **Bounds.** At most 8 committed terms in a sum (the `sum4` circuit up to 4, `sum8` up to 8), four operands in a product, all of one integer type. The circuit is chosen from the claim's shape; there is nothing to configure.
- **Openings** are supplied in the order the committed values appear in the claim. For `sum` that is `plus` then `minus`; for `arithmetic` it is `x, y, z, t`; for `divide` it is `dividend, divisor, quotient, remainder` (public operands take no opening).
- **Several owners.** One prover must hold every opening. If the secrets belong to different parties, they must first run a collaborative witness-generation protocol; this SDK does not provide one and does not pretend a single prover knows secrets it does not hold. `From<Vec<Opening>> for Witness` documents this.
- **Attained security level.** Upstream refuses a 116-bit target for circuits above 8192 constraints (it supports at most 115 for them). `Predicates::new()` therefore **fails** (`ZkError::SecurityUnattainable`) for those circuits: the security level is never lowered silently. The caller opts in explicitly with `Predicates::new().with_minimum_bits(115)` (CLI `--min-bits 115`, WASM `predicate_set_minimum_bits(115)`, the demo's "Minimum security" selector). With that, a circuit runs at the highest level upstream accepts provided it is not below the stated minimum, and `Predicates::security_bits(circuit)` and `zk predicate describe` report it. `sum4_32` and the smaller circuits run at 116; the larger arithmetic circuits at 115. A verifier must be configured the same way: a proof made at 115 is refused by a 116-only verifier. This is a configured target, not a verified security level (see below).

## Sets: membership and non-membership

```rust
let tree = SetTree::new(IntType::U64, [10u64, 20, 30].map(Number::from))?;   // publisher
let set = tree.commitment();                                                  // publish this
let claim = Predicate::member_of(commitment, set);                            // or not_member_of
let witness = Witness::from(opening).with_path(tree.member_path(20u64)?);     // absence_path for not_member_of
let proof = zk.prove(&claim, witness)?;
zk.verify(&claim, &proof)?;
```

- **Design.** `SetCommitment` holds two Poseidon2 Merkle roots: a *member tree* with one leaf per member, and a *gap tree* whose leaves are the open intervals between consecutive sorted members (unbounded at both ends). Membership proves the committed value's leaf is under the member root; absence proves the value lies strictly inside an interval that is under the gap root. The path (leaf index and siblings) is private, so the proof does not reveal which member matched or where a stranger falls. Leaves are domain-separated from commitments and from each other, and include the type, so sets of different widths or signedness never collide.
- **Sizes.** Trees are 8 deep (up to 255 members) or 20 deep (up to about a million); the smaller fitting depth is chosen automatically and is part of the `SetCommitment` text (`set:<type>:<depth>:<hex>`). Circuits `member8/absent8/member20/absent20` exist for each of the three widths. Empty subtrees are zero hashes, so a sparse tree costs nothing to store.
- **Trust assumption (important).** The roots are only as honest as their publisher. A verifier that does not rebuild the tree from the whole set trusts that it was built from sorted, duplicate-free values; a dishonestly built gap tree could "prove" the absence of a value that is really a member. Publish the member list (or have the roots signed) if consumers must check.
- **The path is secret.** It identifies the member. `SetPath` has a redacted `Debug`, is zeroized when dropped, and travels to the prover as the last secret (CLI: `zk predicate path ... --path p.json`, then `--secrets a.s,p.json`; WASM: `predicate_set_path`).
- **Large circuits.** The set circuits are 10k to 25k constraints and so, like the larger arithmetic circuits, attain at most 115 bits upstream: they fail unless the caller authorizes `with_minimum_bits(115)`.

## Claim JSON (CLI, browser, interchange)

```json
{"kind":"opens","commitment":"u32:<64 hex>"}
{"kind":"compare","commitment":"u32:<64 hex>","op":"ge","bound":"18"}
{"kind":"range","commitment":"i64:..","lo":"-10","hi":"5","lo_inclusive":true,"hi_inclusive":false}
{"kind":"compare_committed","left":"i64:..","right":"i64:..","op":"lt"}
{"kind":"sum","plus":["u64:..","u64:.."],"minus":["u64:..","u64:.."],"plus_constant":"0","minus_constant":"10","op":"eq"}
{"kind":"arithmetic","x":"u64:..","y":"3","z":"0","t":"u64:..","op":"eq"}
{"kind":"divide","dividend":"u64:..","divisor":"9","quotient":"u64:..","remainder":"u64:.."}
{"kind":"member","commitment":"u64:..","set":"set:u64:8:<128 hex>"}
{"kind":"absent","commitment":"u64:..","set":"set:u64:8:<128 hex>"}
```

An operand is a commitment (`type:hex`) or a public decimal number.

`op` is one of `lt le gt ge eq ne`. Numbers are decimal strings so 128-bit values survive JSON.

## CLI

```sh
zk predicate commit   --type u32 --value 20 --commitment age.c --secret age.s   # prints the commitment
zk predicate set      --type u64 --values set.json --commitment set.c            # publish: JSON array of decimal strings
zk predicate path     --type u64 --values set.json --value 20 --proves member --path p.json   # private path
zk predicate describe --claim claim.json                                         # circuit, attained security bits, public inputs
zk predicate prove    --claim claim.json --secrets a.s[,b.s,...] --proof p.zkp   # one secret per committed value, in claim order
zk predicate verify   --claim claim.json --proof p.zkp                           # prints VALID or fails
```

Each command is its own process: verification needs only the claim and the proof, never the secret.

## Browser

`web/predicates.html` (served with `web/pkg` built by `scripts/build_wasm.py`) offers family and type selection, private values (lists for conservation and totals; public-or-private operands for products and division), commitment, prove, verify, claim/proof import and export, a corrupt-the-proof button and timings. All cryptography runs in a Web Worker through `web/job-runner.js`: one job at a time (overlapping jobs are refused, not queued), and Cancel terminates the worker and starts a fresh one (warmed keys are dropped). The page reports the longest main-thread stall while working.

## Security model

- **Trusted inputs.** `verify` takes the claim from the application; public inputs are derived from it, never read from the proof. Keys are derived deterministically from the bundled circuit and the policy and are bound into the proof (circuit, policy, backend version).
- **Commitment.** `digest = Poseidon2(width 16, rate 8, capacity [domain, length])` over `[signed, limb count, 16-bit limbs.., 8 random blinding elements]`. Binding up to the sponge's collision resistance (8 x 31-bit digest); hiding while the blinding is secret and uniformly random (rejection-sampled from the OS or browser CSPRNG). The type is part of the preimage, so a commitment cannot be reinterpreted under another width or signedness.
- **Differential testing.** `Predicate::holds` is an unbounded-integer reference semantics. `differential.rs` checks, over thousands of random and boundary claims on all six types, that each circuit's witness exists exactly when the reference says the claim is true (unsound and incomplete circuits both fail it). Real proofs are in `tests/arithmetic.rs`.
- **Integers.** 16-bit limbs, each range-checked in the circuit; signed values are offset-binary (`v + 2^(w-1)`), so one unsigned borrow-chain comparison serves both. Every public bound is range-checked in the circuit. No field wrap-around is possible at 17-bit decompositions.
- **Host/circuit agreement.** The host commitment (Plonky3's Poseidon2) is accepted by the compiled circuit in every predicate proof, natively and in WASM; the interop matrix mixes native- and WASM-made commitments.
- **Circuit identity.** Each bundled R1CS is SHA-256-checked against `approved.rs` before use; `scripts/build_circuits.py --check` (part of `run-all full`) rebuilds the circuits with the pinned compiler and fails on any difference.
- **Not established.** The end-to-end soundness of the configured 116-bit target has not been independently recomputed, so no post-quantum bit-security figure is claimed. Secrets are handled best effort (see SECURITY, "Secret handling"); they are not guaranteed erased from memory. `compare_committed` is a statement by one prover about two of their own secrets.
