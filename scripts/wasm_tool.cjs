// File-based driver for the wasm build under Node, used by interop.py. It mirrors the `zk` CLI.
const fs = require("fs");
const path = require("path");
const zk = require(process.argv[2]);

const [command, ...args] = process.argv.slice(3);
const read = (path) => new Uint8Array(fs.readFileSync(path));
const text = (path) => fs.readFileSync(path, "utf8");

// Groth16 circuit files come from testdata/groth16, as the browser fetches them from web/groth16,
// and the phase-1 file from $ZK_PTAU or target/ptau, as the browser fetches it from web/ptau; the
// WASM side checks every file against its pinned or published hash.
const ROOT = path.join(__dirname, "..");
const GROTH16 = path.join(ROOT, "testdata", "groth16");

function phase1() {
  if (zk.groth16_has_phase1()) return;
  const candidates = process.env.ZK_PTAU ? [process.env.ZK_PTAU] : zk.groth16_phase1_files().map((f) => path.join(ROOT, "target", "ptau", f));
  const file = candidates.find((f) => fs.existsSync(f));
  if (!file) throw new Error("no phase-1 file: run python scripts/groth16_setup.py --fetch");
  zk.groth16_set_phase1(read(file));
}

function circuitFiles(names) {
  phase1();
  for (const name of names) {
    for (const extension of ["r1cs", "sym"]) {
      const file = `${name}.${extension}`;
      if (!zk.groth16_has_artifact(file)) zk.groth16_add_artifact(file, read(path.join(GROTH16, file)));
    }
  }
}

// ZK_MIN_BITS is the explicit authorization to run circuits below the 116-bit default;
// ZK_GROTH16_KEYS and ZK_GROTH16_TRUST are the key pack and the verifier's trust list.
function engine(claim) {
  if (process.env.ZK_MIN_BITS) zk.predicate_set_minimum_bits(Number(process.env.ZK_MIN_BITS));
  const names = zk.predicate_groth16_circuits(claim);
  if (!names.length || !process.env.ZK_GROTH16_KEYS) return;
  circuitFiles(names);
  const trust = process.env.ZK_GROTH16_TRUST ? text(process.env.ZK_GROTH16_TRUST) : "";
  zk.groth16_use(read(process.env.ZK_GROTH16_KEYS), trust);
}

function loadPack(file) {
  const loaded = JSON.parse(zk.groth16_load_pack(read(file)));
  circuitFiles(loaded.circuits);
  return loaded;
}

const commands = {
  setup: ([r1cs, pk, vk]) => {
    const keys = zk.setup(read(r1cs), 116, "johnson");
    fs.writeFileSync(pk, keys.proving);
    fs.writeFileSync(vk, keys.verifying);
  },
  prove: ([pk, r1cs, sym, input, proof]) => {
    const wtns = zk.witness(read(r1cs), text(sym), text(input));
    fs.writeFileSync(proof, zk.prove(read(pk), wtns));
  },
  verify: ([vk, expected, proof]) => {
    zk.verify(read(vk), Uint32Array.from(expected.split(",").map(Number)), read(proof));
  },
  // Groth16 trusted setups, mirroring `zk groth16 new|contribute|verify`.
  "groth16-circuits": ([claim]) => console.log(zk.predicate_groth16_circuits(text(claim)).join(",")),
  "groth16-new": ([circuits, out, name]) => {
    const names = circuits.split(",");
    circuitFiles(names);
    for (const circuit of names) zk.groth16_create_key(circuit, name);
    fs.writeFileSync(out, zk.groth16_take_pack());
  },
  "groth16-contribute": ([keys, out, name]) => {
    for (const circuit of loadPack(keys).circuits) zk.groth16_contribute_key(circuit, name);
    fs.writeFileSync(out, zk.groth16_take_pack());
  },
  "groth16-verify": ([keys]) => {
    const loaded = loadPack(keys);
    for (const circuit of loaded.circuits) zk.groth16_verify_key(circuit);
    console.log(`VALID: setup ${loaded.setupId}`);
  },
  // Built-in predicates, mirroring `zk predicate ...` (same files, same claim JSON).
  "predicate-commit": ([scheme, type, value, commitment, secret]) => {
    const made = JSON.parse(zk.predicate_commit(scheme, type, value));
    fs.writeFileSync(commitment, made.commitment);
    fs.writeFileSync(secret, made.secret);
  },
  "predicate-set": ([scheme, type, values, commitment]) => {
    fs.writeFileSync(commitment, zk.predicate_set_commitment(scheme, type, text(values)));
  },
  "predicate-path": ([scheme, type, values, value, proves, out]) => {
    fs.writeFileSync(out, zk.predicate_set_path(scheme, type, text(values), value, proves === "absent"));
  },
  "predicate-transition": ([spec, claim, open]) => {
    const lowered = JSON.parse(zk.predicate_transition(text(spec)));
    fs.writeFileSync(claim, JSON.stringify(lowered.claim));
    fs.writeFileSync(open, JSON.stringify(lowered.open));
  },
  "predicate-issue": ([scheme, type, entries, out]) => {
    fs.writeFileSync(out, zk.predicate_credential_issue(scheme, type, text(entries)));
  },
  "predicate-present": ([credential, now, options, claim, prefix]) => {
    const presented = JSON.parse(zk.predicate_credential_present(text(credential), now, text(options)));
    fs.writeFileSync(claim, JSON.stringify(presented.claim));
    presented.secrets.forEach((secret, index) => fs.writeFileSync(`${prefix}${index}`, secret));
  },
  "predicate-prove": ([claim, proof, ...secrets]) => {
    const json = text(claim);
    engine(json);
    fs.writeFileSync(proof, zk.predicate_prove(json, secrets.map(text)));
  },
  "predicate-verify": ([claim, proof]) => {
    const json = text(claim);
    engine(json);
    zk.predicate_verify(json, read(proof));
  },
};

try {
  commands[command](args);
} catch (error) {
  console.error(String(error.message ?? error));
  process.exit(1);
}
