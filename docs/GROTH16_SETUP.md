# Groth16 trusted setups

`crates/zk-groth16` proves every BN254 predicate circuit with Groth16. That is 45 circuits:
- `open`, `compare`, `range`, `compare_committed`, `arith`, `sum4`/`sum8`, `anyrange` and `distance` at 32, 64 and 128 bits;
- `member`, `absent` and `cred` at depths 8 and 20.

Groth16 needs a trusted setup per circuit. **No setup ships with zk-sdk.** The repository holds only the circuits (r1cs and sym, pinned by SHA-256 in `crates/zk-groth16/src/approved.rs`). Every setup is created by the people who use it, from a published phase 1, and anyone can verify it.

The transparent, post-quantum Spartan-WHIR backend remains the default. Groth16 is used only for commitments made with `Scheme::Groth16` (`--scheme groth16`).

**Caveats**
- Groth16 over BN254 is **not post-quantum** and offers roughly 100-110 bits of classical security.
- Soundness rests on the setup: whoever knows the secret of *every* contribution (phase 1 and phase 2) can forge proofs. Zero knowledge does not depend on the setup.
- The ceremony code below is cross-checked byte for byte against snarkjs 0.7.6. The end-to-end soundness of this backend has **not been independently verified or audited**.

## Phase 1: the published Hermez Powers of Tau

Every key starts from one of the published Hermez/PSE perpetual-ceremony files, `powersOfTau28_hez_final_NN.ptau` (54 contributions plus a beacon).
- A file is accepted only if its BLAKE2b-512 equals the hash the snarkjs project publishes for that power. The table is in `crates/zk-groth16/src/ceremony/phase1.rs`.
- Any power from 14 upward fits every circuit and yields **the same** starting keys.

```sh
python scripts/groth16_setup.py --fetch     # powersOfTau28_hez_final_14.ptau (~19 MB) into target/ptau, then checked
zk groth16 phase1                           # VALID: published Hermez Powers of Tau, power 14
```

`zk` finds the file in this order: `--ptau F`, then `$ZK_PTAU`, then a `ptau/` directory beside the binary, then `target/ptau/`. The circuits come from `--groth16-dir D`, then `$ZK_GROTH16_DIR`, then `groth16/` beside the binary, then `testdata/groth16/`. A file whose hash does not match is refused, so the download host is not trusted.

## Phase 2: create, contribute, verify

Each circuit's phase-2 starting key is derived from its approved r1cs and phase 1 alone. It is byte-identical to `snarkjs zkey new` (`zk groth16 initial --circuit C --out C.zkey` writes it), so it needs no trust. A key becomes usable only after at least one contribution. Contributions are sequential, and each one is recorded in the key in snarkjs's format:
- delta after the contribution;
- the contributor's public key (g1_s, g1_sx, g2_spx) and transcript hash;
- an optional name;
- for a beacon, its value and iteration exponent.

```sh
# Alice creates a setup for every circuit (or --circuits compare_32,open_32,...)
zk groth16 new --circuits all --name alice --out alice.zkg16keys
# Bob verifies Alice's keys and adds his own contribution; repeat with as many participants as wanted
zk groth16 contribute --keys alice.zkg16keys --name bob --out bob.zkg16keys
# optionally finish with a public beacon (a value nobody could predict when the last contribution was
# made, e.g. a future drand round), so the final step is reproducible by anyone
zk groth16 contribute --keys bob.zkg16keys --name beacon --beacon <hex> --beacon-exponent 10 --out final.zkg16keys
# anyone: check every key against phase 1 and print the transcript and the setup id
zk groth16 verify --keys final.zkg16keys --trust-out final.trust
```

A random contribution draws fresh OS (or browser) entropy and discards it as soon as the contribution is made. The new keys are sound if **any one** contributor in the chain was honest. A beacon contribution is deterministic: 2^N SHA-256 iterations of the value, with N from 10 to 28, as in `snarkjs zkey beacon`.

`verify` runs the same checks as `snarkjs zkey verify`:
1. Re-derive the starting key from phase 1 and the circuit.
2. Check every contribution's proof of knowledge and the transcript chain.
3. Check delta against the last contribution.
4. Check the L and H points against the starting key, by random linear combination.

It also refuses a key with no contribution and any point outside its group.

### Interoperability with snarkjs

`zk groth16 export --keys P --dir D` writes one `<circuit>.zkey` per key, and `zk groth16 import --dir D --circuits ... --out P` packs them back. Exported keys pass `snarkjs zkey verify <circuit>.r1cs <ptau> <circuit>.zkey`, and snarkjs contributions (`zkey contribute`, `zkey beacon`) on them import and verify here. Running the same beacon in both produces byte-identical keys.

`python scripts/groth16_setup.py --reference` checks all of this on representative circuits; `--reference --all` checks every circuit.

## Identities and who trusts what

- **Key id**: SHA-256 over `"zk-groth16/key/v1"`, the circuit name, a zero byte, the r1cs SHA-256 (hex), and the key's header and IC sections. It names the verifying key.
- **Setup id**: SHA-256 over `"zk-groth16/setup/v1"`, then, for each circuit in name order, the name, a zero byte and the key id. It names a whole key pack. Every contribution yields a new setup id.

**Provers** need only the key pack (`--groth16-keys P`). Each key is checked against phase 1 on first use.

**Verifiers** must also say which setups they accept. `--groth16-trust F` names a file of setup ids or key ids, one per line, with `#` starting a comment; `zk groth16 verify --trust-out F` writes one. A proof made under a setup that is valid but not authorized is **rejected**. Importing a setup never makes it trusted: a verifier authorizes a setup only once they accept its contributors (for example, because they contributed themselves).

In the library:
```rust
let ceremony = predicate::load_ceremony(None, None)?;            // circuits + published phase 1
let pack = ceremony.create(&names, &Contribution::Random { name }, &mut |_, _, _| {})?;
let setup = Groth16Setup::new(ceremony, pack, trust)?;          // trust: Trust::parse(..)
let zk = Predicates::new().with_groth16(setup);
```
Without `with_groth16`, Groth16 claims fail with an error that says how to make a setup.

## Key packs

A key pack (`.zkg16keys`) starts with the magic `ZKG16KEY`. It then holds a count, followed by, for each circuit, its name, length and zkey bytes. Packs are the same natively, in WASM and in the browser. A pack may hold any subset of the approved circuits. A claim can be proved only if its circuits are in the pack.

## In the browser

In `web/predicates.html`, choosing Groth16 shows a **Trusted Setup** section. The worker fetches the phase-1 file from `web/ptau/` and the circuits from `web/groth16/` (`scripts/build_wasm.py` copies them; no keys are shipped), and checks each against its published or pinned hash.
- **Create new setup** starts a new setup for the current claim's circuits or for all of them, with your contribution.
- **Contribute to the setup in use** verifies that setup, then adds your contribution.
- **Import an existing setup** checks every key and shows the transcript.
- **Authorized for verification** lists the setup or key ids this tab accepts. A setup you created or contributed to is added automatically; an imported one is not.

Contributions use the browser's CSPRNG, and their secret never leaves WebAssembly. Packs made in the browser and with `zk groth16` are interchangeable.

## Validation

Tests never use stored keys. Each test run creates ephemeral setups from the published phase 1:
- the crate tests: contributions, transcripts, beacons, authorization, and rejection of damaged, foreign, mislabelled and uncontributed keys;
- the SDK facade tests: every circuit;
- the CLI end-to-end tests;
- the browser self-test;
- the native/WASM interop matrix: WASM creates a setup, native contributes, both verify it and refuse a damaged copy, then both prove and verify under it and reject an unauthorized setup.

`run-all full` fetches phase 1 and runs all of the above, plus the snarkjs reference check on representative circuits. `run-all groth16-all`, a separate CI job, runs the reference check on all 45 circuits.
