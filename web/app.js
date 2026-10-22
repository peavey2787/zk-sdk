import { circuits } from "./circuits.js";

const $ = (id) => document.getElementById(id);
const worker = new Worker("./worker.js", { type: "module" });
const pending = new Map();
let nextId = 0;
const state = { r1cs: null, sym: null, keys: null, proof: null, circuit: null };

worker.onmessage = ({ data }) => {
  const settle = pending.get(data.id);
  pending.delete(data.id);
  if (data.ok) settle.resolve(data);
  else settle.reject(new Error(data.error));
};

function call(op, args = {}) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, args });
  });
}

function log(message, kind = "") {
  const line = document.createElement("div");
  line.className = kind;
  line.textContent = message;
  $("log").prepend(line);
}

function setTiming(name, ms) {
  $(`t-${name}`).textContent = `${ms} ms`;
}

async function guarded(label, work) {
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    await work();
  } catch (error) {
    log(`${label} failed: ${error.message}`, "bad");
  } finally {
    document.querySelectorAll("button").forEach((b) => (b.disabled = false));
  }
}

function download(name, bytes) {
  const url = URL.createObjectURL(new Blob([bytes]));
  Object.assign(document.createElement("a"), { href: url, download: name }).click();
  URL.revokeObjectURL(url);
}

function fieldValues() {
  const config = circuits[$("circuit").value];
  return Object.fromEntries(
    [...config.private, ...config.public].map((f) => [f.name, BigInt($(`f-${f.name}`).value)]),
  );
}

function renderFields() {
  const config = circuits[$("circuit").value];
  $("fields").replaceChildren(
    ...[...config.private, ...config.public].map((f) => {
      const label = document.createElement("label");
      label.textContent = f.label;
      const input = Object.assign(document.createElement("input"), {
        id: `f-${f.name}`, type: "number", min: 0, max: f.max, value: f.value,
      });
      input.addEventListener("input", updateStatement);
      label.append(input);
      return label;
    }),
  );
  updateStatement();
}

function updateStatement() {
  const config = circuits[$("circuit").value];
  try {
    $("expected").value = config.statement(fieldValues()).join(",");
  } catch {
    $("expected").value = "";
  }
}

async function loadCircuit() {
  const name = $("circuit").value;
  const [r1cs, sym] = await Promise.all([
    fetch(`circuits/${name}.r1cs`).then((r) => r.arrayBuffer()),
    fetch(`circuits/${name}.sym`).then((r) => r.text()),
  ]);
  Object.assign(state, { r1cs: new Uint8Array(r1cs), sym, keys: null, proof: null, circuit: name });
  log(`loaded ${name} (${state.r1cs.length} byte R1CS)`);
}

async function ensureCircuit() {
  if (state.circuit !== $("circuit").value) await loadCircuit();
}

async function setup() {
  await ensureCircuit();
  const bits = Number($("bits").value);
  const { result, ms } = await call("setup", { r1cs: state.r1cs, bits, soundness: $("soundness").value });
  state.keys = result;
  setTiming("setup", ms);
  log(`setup ok: ${bits}-bit full ZK, proving key ${result.proving.length} B, verifying key ${result.verifying.length} B`, "good");
}

async function prove() {
  await ensureCircuit();
  if (!state.keys) await setup();
  const input = JSON.stringify(Object.fromEntries(Object.entries(fieldValues()).map(([k, v]) => [k, v.toString()])));
  const witness = await call("witness", { r1cs: state.r1cs, sym: state.sym, input });
  setTiming("witness", witness.ms);
  const proved = await call("prove", { provingKey: state.keys.proving, wtns: witness.result });
  state.proof = proved.result;
  setTiming("prove", proved.ms);
  log(`proved locally: ${state.proof.length} byte proof (private inputs never left this tab)`, "good");
}

async function verify() {
  if (!state.keys || !state.proof) throw new Error("need a verifying key and a proof (prove or import)");
  const expected = $("expected").value.split(",").map((n) => Number(n.trim()));
  try {
    const { ms } = await call("verify", { verifyingKey: state.keys.verifying, expected, proof: state.proof });
    setTiming("verify", ms);
    const config = circuits[$("circuit").value];
    log(`ACCEPTED: ${config.describe(expected)}`, "good");
  } catch (error) {
    log(`REJECTED: ${error.message}`, "bad");
  }
}

function tamper() {
  if (!state.proof) throw new Error("no proof to tamper with");
  state.proof = state.proof.slice();
  state.proof[state.proof.length >> 1] ^= 0x55;
  log("flipped one proof byte; verify should now reject", "warn");
}

async function importFile(input, apply) {
  const file = input.files[0];
  if (file) apply(new Uint8Array(await file.arrayBuffer()), file.name);
  input.value = "";
}

function wire() {
  $("circuit").addEventListener("change", () => { renderFields(); state.circuit = null; });
  $("setup").onclick = () => guarded("setup", setup);
  $("prove").onclick = () => guarded("prove", prove);
  $("verify").onclick = () => guarded("verify", verify);
  $("tamper").onclick = () => guarded("tamper", async () => tamper());
  $("exportProof").onclick = () => state.proof && download("proof.zkp", state.proof);
  $("exportVk").onclick = () => state.keys && download("verifying.zkk", state.keys.verifying);
  $("importProof").onchange = (e) => importFile(e.target, (bytes, name) => { state.proof = bytes; log(`imported proof ${name} (${bytes.length} B)`); });
  $("importVk").onchange = (e) => importFile(e.target, (bytes, name) => {
    state.keys = { proving: state.keys?.proving, verifying: bytes };
    log(`imported verifying key ${name} (${bytes.length} B)`);
  });
}

async function start() {
  for (const [id, config] of Object.entries(circuits)) {
    $("circuit").append(Object.assign(document.createElement("option"), { value: id, textContent: config.title }));
  }
  for (let bits = 118; bits >= 100; bits--) {
    $("bits").append(Object.assign(document.createElement("option"), { value: bits, textContent: `${bits} bits`, selected: bits === 116 }));
  }
  renderFields();
  wire();
  $("backend").textContent = (await call("capabilities")).result;
  log("ready: all proving and verification runs in this browser tab");
}

start().catch((error) => log(`startup failed: ${error.message}`, "bad"));
