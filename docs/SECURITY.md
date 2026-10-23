# Security

**Not independently audited.** The cryptography is the pinned upstream Spartan-WHIR; this repository wraps, binds and tests it.

## Verifier rules

1. Verify against an expected statement from your own trusted context. A proof's claimed statement is untrusted; `verify` takes the expected one and the backend checks it.
2. Pin the verifying key (its `vk_id`) out of band. Binding stops accidental mismatch, not a party who controls both key and proof.
3. The circuit must constrain every fact being claimed. `range7.circom` alone proves nothing about a commitment.
4. Full ZK only; there is no non-ZK fallback.

## Security policy

Default 116 bits, full ZK, Johnson bound. Upstream accepts 80..=123 in principle; the portable promise is narrower, **100..=118**, because Poseidon commitments cap attainable security at 118 bits and low levels fail setup for some circuits (observed for 80 with the Johnson mode and 95-97 with unique decoding). Every level in 100..=118 was swept under all three soundness modes on `age_over` (setup, prove, verify). Out-of-range or non-ZK policies are rejected at `setup`, and a proof is rejected under any other policy. There is no 128-bit claim, and 116 bits is a composed-soundness target of the classical analysis, not a quantum security category.

## Proof-of-work grinding

Parameters are upstream's `recommended_quintic_zk_whir_params` unmodified, including its proof-of-work grinding. An earlier revision capped grinding at 12 bits for latency; it was removed because the claim that the query budget compensates was unverified (proof size did not change, which suggests it does not) and security takes priority over the latency target.

**Attained level per circuit.** For the larger predicate circuits (above 8192 constraints: `sum4_64` and up, `sum8_*`, `arith_*`) upstream's own composed-security check refuses a 116-bit target and accepts at most 115. `Predicates` sets each circuit up at the policy's target or, when upstream reports a lower attainable level (`ZkError::SecurityUnattainable`), at exactly that level, never below the backend minimum of 100 and never raised. `Predicates::security_bits(circuit)` and `zk predicate describe` report the level in force; the level is part of the key binding, so a proof made at one level is refused at another. Nothing here changes a WHIR or grinding parameter.

Regression guards: unit tests in `zk-spartan-whir/src/params.rs` pin the profile (WHIR parameters equal upstream's recommendation for every policy and size, grinding not below upstream's floor, requested bits/soundness passed through, full-ZK only, pinned revision), and `scripts/check-layout.py` fails the build if any source assigns or clamps WHIR parameters. Not yet done: an independent recomputation of the end-to-end soundness error from the WHIR/Spartan formulas. The 116-bit figure is a configured classical protocol-soundness target; no post-quantum security level is claimed.

## Randomness and secrets

Native builds use the OS CSPRNG; wasm uses the browser CSPRNG (`crypto.getRandomValues`) and fails rather than falling back. Witnesses and proving keys are sensitive; `PrivateInputs` has a redacted `Debug`. Proofs expose their public inputs. Browser memory is not zeroized, and there has been no side-channel review.

## Resource limits

Artifacts and circuits have hard size caps and strict decoding. Proving cost grows with circuit size; in the browser it runs in a worker and can only be interrupted by terminating the worker.

## Dependency audit

`cargo audit` reports two unmaintained-crate notices, ignored by ID: RUSTSEC-2025-0141 (`bincode` 1.x, whose fixed-int little-endian encoding is this project's artifact format and the upstream's key encoding) and RUSTSEC-2024-0436 (`paste`, a proc macro pulled in transitively). Neither is a vulnerability advisory.

## Predicates

See `docs/PREDICATES.md` for the commitment, integer encoding and circuit-identity model. Verification derives public inputs from the caller's claim. Bundled circuits are SHA-256-checked and reproducibly rebuilt (`scripts/build_circuits.py --check`). The end-to-end soundness of the configured 116-bit target is **not independently recomputed**; do not quote a post-quantum bit-security figure for it.

## Not covered

Side channels, fault attacks, supply-chain review of upstream beyond pinning, and the soundness of the circuits you add.
