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

// Groth16 needs the published phase-1 file (./ptau/) and each circuit's r1cs and sym (./groth16/),
// fetched when first needed. The server is not trusted: the WASM side checks the phase-1 file
// against its published hash and each circuit file against its pinned SHA-256. No keys are fetched:
// setups are created, contributed to or imported on the page.
async function fetchBytes(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`cannot fetch ${url}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function phase1() {
  if (zk.groth16_has_phase1()) return;
  for (const file of zk.groth16_phase1_files()) {
    const response = await fetch(`./ptau/${file}`);
    if (response.ok) return void zk.groth16_set_phase1(new Uint8Array(await response.arrayBuffer()));
  }
  throw new Error("no published phase-1 file under ./ptau/ (scripts/build_wasm.py copies one)");
}

async function circuitFiles(names) {
  await phase1();
  for (const name of names) {
    for (const file of [`${name}.r1cs`, `${name}.sym`]) {
      if (!zk.groth16_has_artifact(file)) zk.groth16_add_artifact(file, await fetchBytes(`./groth16/${file}`));
    }
  }
}

const claimArtifacts = (claim) => circuitFiles(zk.predicate_groth16_circuits(claim));

// Runs `step` on every circuit, reporting progress; returns the pack of the keys it made.
async function eachKey(names, progress, step) {
  await circuitFiles(names);
  for (const [index, name] of names.entries()) {
    step(name);
    progress({ done: index + 1, total: names.length });
  }
  const pack = zk.groth16_take_pack();
  return { pack, setupId: JSON.parse(zk.groth16_load_pack(pack)).setupId };
}

// The setup in use survives only as long as this worker; the page names it by id and installs it
// again after a cancel respawned the worker.
let installedSetup = null;

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
  predicateCommit: ({ scheme = "spartan-whir", type, value }) => zk.predicate_commit(scheme, type, value),
  predicateSetCommitment: ({ scheme, type, values }) => zk.predicate_set_commitment(scheme, type, values),
  predicateSetPath: ({ scheme, type, values, value, absent }) => zk.predicate_set_path(scheme, type, values, value, absent),
  predicateCredentialIssue: ({ scheme, type, entries }) => zk.predicate_credential_issue(scheme, type, entries),
  predicateCredentialPresent: ({ credential, now, options }) => zk.predicate_credential_present(credential, now, options),
  predicateTransition: ({ spec }) => zk.predicate_transition(spec),
  predicateMinimumBits: ({ bits }) => zk.predicate_set_minimum_bits(bits),
  predicateProve: async ({ claim, secrets }) => {
    await claimArtifacts(claim);
    return zk.predicate_prove(claim, secrets);
  },
  predicateVerify: async ({ claim, proof }) => {
    await claimArtifacts(claim);
    zk.predicate_verify(claim, proof);
    return true;
  },
  predicateDescribe: async ({ claim }) => {
    await claimArtifacts(claim);
    return zk.predicate_describe(claim);
  },
  // Groth16 trusted setups. Contributions draw fresh browser entropy whose secret never leaves
  // WASM. `circuits` null means every approved circuit.
  groth16Circuits: ({ claim }) => (claim ? zk.predicate_groth16_circuits(claim) : zk.groth16_circuits()),
  groth16Create: ({ circuits, contributor }, progress) =>
    eachKey(circuits ?? zk.groth16_circuits(), progress, (name) => zk.groth16_create_key(name, contributor)),
  groth16Contribute: ({ pack, contributor }, progress) =>
    eachKey(JSON.parse(zk.groth16_load_pack(pack)).circuits, progress, (name) => zk.groth16_contribute_key(name, contributor)),
  // Every key checked against phase 1: `{setupId, keys: [{circuit, keyId, circuitHash, contributions}]}`.
  groth16Verify: async ({ pack }, progress) => {
    const { setupId, circuits } = JSON.parse(zk.groth16_load_pack(pack));
    await circuitFiles(circuits);
    const keys = circuits.map((name, index) => {
      const report = JSON.parse(zk.groth16_verify_key(name));
      progress({ done: index + 1, total: circuits.length });
      return report;
    });
    return { setupId, keys };
  },
  // Prove with `pack` and verify only under the ids in `trust`; a null pack disables Groth16.
  groth16Use: async ({ id, pack, trust }) => {
    if (id !== installedSetup) {
      if (pack) await phase1();
      zk.groth16_use(pack, trust);
      installedSetup = id;
    }
  },
};

self.onmessage = async ({ data: { id, op, args } }) => {
  try {
    const exports = await ready;
    const start = performance.now();
    const progress = (update) => self.postMessage({ id, progress: update });
    const result = await operations[op](args, progress);
    const ms = Math.round(performance.now() - start);
    self.postMessage({ id, ok: true, result, ms, wasmBytes: exports.memory.buffer.byteLength });
  } catch (error) {
    self.postMessage({ id, ok: false, error: String(error?.message ?? error) });
  }
};
