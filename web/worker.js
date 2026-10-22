// Runs all cryptography off the main thread. Everything here is local to the browser:
// the private inputs, witness and proving key are never sent over the network.
import init, * as zk from "./pkg/zk_wasm.js";

const ready = init();

const operations = {
  capabilities: () => zk.capabilities(),
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
};

self.onmessage = async ({ data: { id, op, args } }) => {
  try {
    await ready;
    const start = performance.now();
    const result = operations[op](args);
    self.postMessage({ id, ok: true, result, ms: Math.round(performance.now() - start) });
  } catch (error) {
    self.postMessage({ id, ok: false, error: String(error?.message ?? error) });
  }
};
