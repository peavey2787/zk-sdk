// File-based driver for the wasm build under Node, used by interop.py. It mirrors the `zk` CLI.
const fs = require("fs");
const zk = require(process.argv[2]);

const [command, ...args] = process.argv.slice(3);
const read = (path) => new Uint8Array(fs.readFileSync(path));

const authorize = () => {
  if (process.env.ZK_MIN_BITS) zk.predicate_set_minimum_bits(Number(process.env.ZK_MIN_BITS));
};

const commands = {
  setup: ([r1cs, pk, vk]) => {
    const keys = zk.setup(read(r1cs), 116, "johnson");
    fs.writeFileSync(pk, keys.proving);
    fs.writeFileSync(vk, keys.verifying);
  },
  prove: ([pk, r1cs, sym, input, proof]) => {
    const wtns = zk.witness(read(r1cs), fs.readFileSync(sym, "utf8"), fs.readFileSync(input, "utf8"));
    fs.writeFileSync(proof, zk.prove(read(pk), wtns));
  },
  verify: ([vk, expected, proof]) => {
    zk.verify(read(vk), Uint32Array.from(expected.split(",").map(Number)), read(proof));
  },
  // Built-in predicates, mirroring `zk predicate ...` (same files, same claim JSON).
  "predicate-commit": ([type, value, commitment, secret]) => {
    const made = JSON.parse(zk.predicate_commit(type, value));
    fs.writeFileSync(commitment, made.commitment);
    fs.writeFileSync(secret, made.secret);
  },
  // ZK_MIN_BITS is the explicit authorization to run circuits below the 116-bit default.
  "predicate-prove": ([claim, proof, ...secrets]) => {
    authorize();
    const texts = secrets.map((path) => fs.readFileSync(path, "utf8"));
    fs.writeFileSync(proof, zk.predicate_prove(fs.readFileSync(claim, "utf8"), texts));
  },
  "predicate-verify": ([claim, proof]) => {
    authorize();
    zk.predicate_verify(fs.readFileSync(claim, "utf8"), read(proof));
  },
};

try {
  commands[command](args);
} catch (error) {
  console.error(String(error.message ?? error));
  process.exit(1);
}
