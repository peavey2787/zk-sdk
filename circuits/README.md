# Circuits

Sources for the circuits whose compiled `.r1cs`/`.sym` (and a reference `.wtns` for `age_over`) live in `testdata/`.

| Circuit | Statement |
|---|---|
| `age_over.circom` | private `age` is greater than public `threshold`; output `over` |
| `millionaires.circom` | private `alice` wealth is greater than private `bob` wealth; output only the verdict |
| `arithmetic.circom` | `y = (x * secret + x)^2 + 3` with public `x` and private `secret` |
| `range7.circom` | 7-bit decomposition only; **does not** bind a witness to a commitment |

Comparison circuits (`lib/compare.circom`) are range-checked. The KoalaBear field is 31 bits, so `LessThan(n)` is only sound for `n <= 29`.

## Built-in predicate library

`predicates/library.circom` holds `OpenCommitment`, `CompareToBound`, `InRange` and `CompareCommitted`, instantiated at 32/64/128 bits by 12 generated mains (`predicates/*_{32,64,128}.circom`). Values are 16-bit limbs (signed values are offset-binary), commitments are domain-separated Poseidon2 sponge digests (`lib/koalabear/commit.circom`, constants generated from the pinned Plonky3 by `crates/zk-circuitgen`). The compiled circuits are bundled into the SDK; `crates/zk-sdk/src/predicate/approved.rs` records each SHA-256.

Rebuild everything reproducibly (clones the pinned Circom fork into the git-ignored `target/toolchain/circom`; nothing outside this repository is touched):

```sh
python scripts/build_circuits.py          # rewrite testdata/predicates and approved.rs
python scripts/build_circuits.py --check  # fail if a fresh build differs from the repository
```

Field-specific gadgets live in `lib/koalabear/` and `lib/bn254/` and are selected with circom `-l`; `lib/opens.circom` is shared. The same `open`/`compare`/`range`/`compare_committed` mains are also built for BN254 (one-element Poseidon commitment, light-poseidon parameters) into `testdata/groth16/`, whose keys come from `scripts/groth16_setup.py` (see `docs/GROTH16_SETUP.md`).

Other circuits are recompiled with the same compiler: `target/toolchain/circom/target/release/circom circuits/age_over.circom --prime koalabear --r1cs --sym -o testdata/age_over`.

No C++ witness generator is needed: `zk-witness` solves the witness from the `.r1cs`/`.sym` pair in Rust, natively and in WebAssembly, and always re-checks that every constraint holds.
