# Security

**Not independently audited.** The cryptography is the pinned upstream Spartan-WHIR; this repository wraps, binds and tests it.

## Verifier rules

1. Verify against an expected statement from your own trusted context. A proof's claimed statement is untrusted; `verify` takes the expected one and the backend checks it.
2. Pin the verifying key (its `vk_id`) out of band. Binding stops accidental mismatch, not a party who controls both key and proof.
3. The circuit must constrain every fact being claimed. `range7.circom` alone proves nothing about a commitment.
4. Full ZK only; there is no non-ZK fallback.

## Security policy

Default 116 bits, full ZK, Johnson bound. Upstream accepts 80..=123 in principle; the portable promise is narrower, **100..=118**, because Poseidon commitments cap attainable security at 118 bits and low levels fail setup for some circuits (observed for 80 with the Johnson mode and 95-97 with unique decoding). Every level in 100..=118 was swept under all three soundness modes on `age_over` (setup, prove, verify). Out-of-range or non-ZK policies are rejected at `setup`, and a proof is rejected under any other policy. There is no 128-bit claim, and 116 bits is a composed-soundness target of the classical analysis, not a quantum security category.

## Proof-of-work cap

Grinding is capped at 12 bits instead of upstream's recommended 22. Upstream recomputes the query budget from `security_level - pow_bits` for prover and verifier alike, so the configured level is still what is targeted; the verifier rejects proofs whose witness fails the (lower) work check. This is a latency/proof-size trade-off made in `zk-spartan-whir/src/params.rs`; it has not had independent cryptographic review.

## Randomness and secrets

Native builds use the OS CSPRNG; wasm uses the browser CSPRNG (`crypto.getRandomValues`) and fails rather than falling back. Witnesses and proving keys are sensitive; `PrivateInputs` has a redacted `Debug`. Proofs expose their public inputs. Browser memory is not zeroized, and there has been no side-channel review.

## Resource limits

Artifacts and circuits have hard size caps and strict decoding. Proving cost grows with circuit size; in the browser it runs in a worker and can only be interrupted by terminating the worker.

## Dependency audit

`cargo audit` reports two unmaintained-crate notices, ignored by ID: RUSTSEC-2025-0141 (`bincode` 1.x, whose fixed-int little-endian encoding is this project's artifact format and the upstream's key encoding) and RUSTSEC-2024-0436 (`paste`, a proc macro pulled in transitively). Neither is a vulnerability advisory.

## Not covered

Side channels, fault attacks, supply-chain review of upstream beyond pinning, and the soundness of the circuits you add.
