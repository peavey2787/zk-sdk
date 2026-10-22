// File-based driver for the wasm build under Node, used by interop.py. It mirrors the `zk` CLI.
const fs = require("fs");
const zk = require(process.argv[2]);

const [command, ...args] = process.argv.slice(3);
const read = (path) => new Uint8Array(fs.readFileSync(path));

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
};

try {
  commands[command](args);
} catch (error) {
  console.error(String(error.message ?? error));
  process.exit(1);
}
