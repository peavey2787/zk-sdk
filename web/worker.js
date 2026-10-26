// Runs all cryptography off the main thread. Everything here is local to the browser:
// the private inputs, witness, secrets and proving key are never sent over the network.
//
// A cross-origin-isolated page (COOP same-origin + COEP require-corp) gets the threaded bundle,
// which proves on every core; any other page gets the single-threaded one. Both run the same
// code and parameters, so their proofs are interchangeable.
const threads = self.crossOriginIsolated && typeof SharedArrayBuffer === "function" ? navigator.hardwareConcurrency : 1;
let zk;

const ready = (async () => {
  const bundle = await import(threads > 1 ? "./pkg-threads/zk_wasm.js" : "./pkg/zk_wasm.js");
  const exports = await bundle.default();
  if (threads > 1) await bundle.initThreadPool(threads);
  zk = bundle;
  return exports;
})();

const operations = {
  capabilities: () => zk.capabilities(),
  threads: () => threads,
  setup: ({ r1cs, bits, soundness }) => {
    const keys = zk.setup(r1cs, bits, soundness);
    return { proving: keys.proving, verifying: keys.verifying };
  },
  witness: ({ r1cs, sym, input }) => zk.witness(r1cs, sym, input),
  prove: ({ provingKey, wtns }) => zk.prove(provingKey, wtns),
  verify: ({ verifyingKey, expected, proof }) => {
    zk.verify(verifyingKey, Uint32Array.from(expected), proof);
    return true;
  },
  describe: ({ proof }) => zk.describe(proof),
  // Built-in predicates: no circuit, key or setup handling on the page.
  predicateCommit: ({ type, value }) => zk.predicate_commit(type, value),
  predicateSetCommitment: ({ type, values }) => zk.predicate_set_commitment(type, values),
  predicateSetPath: ({ type, values, value, absent }) => zk.predicate_set_path(type, values, value, absent),
  predicateCredentialIssue: ({ type, entries }) => zk.predicate_credential_issue(type, entries),
  predicateCredentialPresent: ({ credential, now, options }) => zk.predicate_credential_present(credential, now, options),
  predicateTransition: ({ spec }) => zk.predicate_transition(spec),
  predicateMinimumBits: ({ bits }) => zk.predicate_set_minimum_bits(bits),
  predicateProve: ({ claim, secrets }) => zk.predicate_prove(claim, secrets),
  predicateVerify: ({ claim, proof }) => {
    zk.predicate_verify(claim, proof);
    return true;
  },
  predicateDescribe: ({ claim }) => zk.predicate_describe(claim),
};

self.onmessage = async ({ data: { id, op, args } }) => {
  try {
    const exports = await ready;
    const start = performance.now();
    const result = operations[op](args);
    const ms = Math.round(performance.now() - start);
    self.postMessage({ id, ok: true, result, ms, wasmBytes: exports.memory.buffer.byteLength });
  } catch (error) {
    self.postMessage({ id, ok: false, error: String(error?.message ?? error) });
  }
};
