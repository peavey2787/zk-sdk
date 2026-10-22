# Architecture

```text
 CLI (zk-cli)            Browser (web/ -> Worker -> zk-wasm)
        \                   /
         zk_sdk::portable  (bytes in, bytes out, size-bounded)
                 |
            Zk facade  (compile, setup, prove, verify, verify_batch, inspect)
                 |
   zk-core (policy, formats, KeyBinding)   zk-witness (R1CS + sym -> .wtns)
                 |
        zk-spartan-whir  ->  upstream spartan-whir (pinned), KoalaBear, Poseidon
```

- `zk-core` knows nothing about a specific backend. `Backend` is the only seam.
- Keys and proofs carry a `KeyBinding {backend, backend_version, policy, program_id, vk_id}`. `vk_id` is a domain-separated SHA-256 over those fields and the verifying-key bytes. Decoding re-derives it, so tampered or foreign keys fail before any cryptography runs.
- Artifacts are framed (`ZKSDK002` magic, format version 2, length-prefixed, hard size limits). Backends use bounded bincode, fixed-int little-endian.
- Verification always calls the upstream verifier after `verifying_key.authenticate()`; the expected public inputs are supplied by the caller, never read from the proof.
- File I/O (`zk_sdk::files`) is compiled out on wasm32. Randomness on wasm comes from the browser CSPRNG through `getrandom`'s `wasm_js` backend; there is no fallback.
- Native builds enable upstream `parallel` (rayon); wasm32 is single-threaded, so it runs in a worker without `SharedArrayBuffer`. The default build is portable x86-64. `scripts/build_optimized.py` is an opt-in AVX2/BMI2 build (`target/optimized`) whose `zk` exits with a clear message on CPUs lacking them. Proof bytes are identical across these configurations.
- Proof-of-work grinding is capped at 12 bits (`MAX_POW_BITS`, upstream recommends 22). Upstream derives query counts from `security - pow_bits`, so the security target is kept; the cap removes a multi-second, high-variance random search.
- `prove` returns per-phase timings (`ProveOutput::phases`): decode_key, prepare_key, import_witness, spartan_whir_prove, encode_proof.

## Backend swapping

Implement `zk_core::Backend`. Proof artifacts record their backend id and version and are only accepted by a matching implementation.
