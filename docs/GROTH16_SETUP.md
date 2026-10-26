# Groth16 trusted setup

`crates/zk-groth16` proves the BN254 predicate circuits (`open`, `compare`, `range`, `compare_committed` at 32/64/128 bits) with Groth16. Groth16 needs a structured reference string; this document records how ours was made and how to check or strengthen it. `testdata/groth16/setup.json` is the machine-readable transcript.

**Caveats.** Groth16 over BN254 is **not post-quantum** and offers roughly 100-110 bits of classical security. Its soundness rests on the setup: anyone who knows the toxic waste of *every* contribution can forge proofs (zero knowledge does not depend on the setup). Phase 2 currently has a **single contributor** plus a public beacon, so you are trusting that this contributor discarded their entropy. The end-to-end soundness of this backend has **not been independently verified**. The Spartan-WHIR backend remains the transparent, post-quantum default.

## Phase 1: public Powers of Tau

The Hermez/PSE perpetual ceremony output `powersOfTau28_hez_final_16.ptau` (2^16 constraints, enough for every bundled circuit). It is downloaded into the git-ignored `target/ptau/` and accepted only if its BLAKE2b-512 equals

```
6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125
```

which is the hash published in the snarkjs README for this file.

## Phase 2: per-circuit contribution

`scripts/groth16_setup.py` (snarkjs 0.7.6, installed into `target/toolchain/snarkjs`) runs, for each circuit:

1. `groth16 setup` from the r1cs in `testdata/groth16/` and the ptau;
2. `zkey contribute` with 64 bytes of OS entropy fed on stdin and never stored;
3. `zkey beacon` with drand round 6585312 (randomness `2af344e1eaa0ba62f9606abfb916c66b1ae04d0dd446c5d8d5ee7704efb55ddf`, 2^10 iterations), which was published after the contribution and so could not be chosen by the contributor;
4. `zkey verify` against the r1cs and ptau, then `zkey export verificationkey`.

The resulting `*.zkey` and `*.vkey.json` are committed in `testdata/groth16/`. The SHA-256 of each r1cs and zkey is generated into `crates/zk-groth16/src/approved.rs`, and the crate refuses any bundled artifact whose bytes no longer match.

## Verifying

```sh
python scripts/groth16_setup.py --check
```

re-runs `snarkjs zkey verify` on every committed zkey and checks `approved.rs` (this is part of `run-all full`). The crate's own tests check that its zkey reader reproduces snarkjs's verification-key exports exactly.

## Adding contributions

Anyone can strengthen the setup: run `snarkjs zkey contribute <circuit>.zkey <out>.zkey` on each committed zkey (before the beacon step for a fresh ceremony, or on top of the current keys), publish the attestation, then regenerate `approved.rs` and `setup.json` with the script. Soundness then holds if *any one* contributor was honest.
