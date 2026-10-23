import { buildClaim, FAMILIES, INT_TYPES, OPS, privateValues } from "./claims.js";
import { JobRunner } from "./job-runner.js";

const $ = (id) => document.getElementById(id);
const runner = new JobRunner("./worker.js");
const state = { secrets: [], proof: null };
const ROWS = {
  valueA: "rowValueA", valueB: "rowValueB", op: "rowOp", bound: "rowBound", lo: "rowLo", hi: "rowHi",
  ends: "rowEnds", inputs: "rowInputs", outputs: "rowOutputs", fee: "rowFee", operands: "rowOperands",
};
const DEFAULT_OPERANDS = { x: "300", y: "3", z: "30", t: "900", dividend: "47", divisor: "9", quotient: "5", remainder: "2" };
const PUBLIC_BY_DEFAULT = new Set(["y", "divisor"]);

function log(message, kind = "") {
  $("log").prepend(Object.assign(document.createElement("div"), { className: kind, textContent: message }));
}

const text = (id) => $(id).value.trim();

function form() {
  const operands = (FAMILIES[$("family").value].operands ?? []).map((name) => ({
    mode: $(`mode-${name}`).value, value: text(`operand-${name}`),
  }));
  return {
    op: $("op").value, bound: text("bound"), lo: text("lo"), hi: text("hi"),
    loInclusive: $("loInclusive").checked, hiInclusive: $("hiInclusive").checked,
    valueA: text("valueA"), valueB: text("valueB"),
    inputs: text("inputs"), outputs: text("outputs"), fee: text("fee"), operands,
  };
}

// One row per operand: public (visible in the claim) or private (committed, never revealed).
function renderOperands(names) {
  $("rowOperands").replaceChildren(...names.map((name) => {
    const label = Object.assign(document.createElement("label"), { textContent: `${name} ` });
    const mode = Object.assign(document.createElement("select"), { id: `mode-${name}` });
    mode.append(new Option("private", "private", false, !PUBLIC_BY_DEFAULT.has(name)), new Option("public", "public", false, PUBLIC_BY_DEFAULT.has(name)));
    const value = Object.assign(document.createElement("input"), { id: `operand-${name}`, type: "text", value: DEFAULT_OPERANDS[name] });
    label.append(mode, " ", value);
    return label;
  }));
}

function renderFamily() {
  const family = FAMILIES[$("family").value];
  for (const [field, row] of Object.entries(ROWS)) $(row).classList.toggle("hidden", !family.fields.includes(field));
  renderOperands(family.operands ?? []);
}

function setBusy(busy) {
  document.querySelectorAll("button").forEach((b) => (b.disabled = busy && b.id !== "cancel"));
  $("cancel").disabled = !busy;
}

// Runs a worker job and records the longest gap between main-thread timer ticks as a
// responsiveness measure.
async function job(label, work) {
  setBusy(true);
  let last = performance.now();
  let stall = 0;
  const ticker = setInterval(() => {
    const now = performance.now();
    stall = Math.max(stall, now - last - 50);
    last = now;
  }, 50);
  try {
    await work();
  } catch (error) {
    const cancelled = error.message === "cancelled";
    log(`${label} ${cancelled ? "cancelled" : "failed"}: ${error.message}`, cancelled ? "warn" : "bad");
  } finally {
    clearInterval(ticker);
    $("t-stall").textContent = `${Math.round(stall)} ms`;
    setBusy(false);
  }
}

const show = (id, ms) => ($(id).textContent = `${ms} ms`);

async function commit() {
  const values = privateValues($("family").value, form());
  if (!values.length) throw new Error("the claim needs at least one private value");
  const made = [];
  let total = 0;
  for (const value of values) {
    const { result, ms } = await runner.run("predicateCommit", { type: $("type").value, value });
    made.push(JSON.parse(result));
    total += ms;
  }
  state.secrets = made.map((m) => m.secret);
  state.proof = null;
  $("claim").value = JSON.stringify(buildClaim($("family").value, form(), made.map((m) => m.commitment)), null, 1);
  show("t-commit", total);
  log(`committed ${values.length} value(s); the claim is public, the secrets stay in this tab`, "good");
}

async function prove() {
  if (!state.secrets.length) throw new Error("commit first");
  const { result, ms, wasmBytes } = await runner.run("predicateProve", { claim: $("claim").value, secrets: state.secrets });
  state.proof = result;
  show("t-prove", ms);
  $("t-size").textContent = `${result.length} B`;
  $("t-memory").textContent = `${(wasmBytes / 1048576).toFixed(0)} MiB`;
  log(`proved locally: ${result.length} B proof (private values never left this tab)`, "good");
}

async function verify() {
  if (!state.proof) throw new Error("need a proof (prove or import)");
  try {
    const { ms } = await runner.run("predicateVerify", { claim: $("claim").value, proof: state.proof });
    show("t-verify", ms);
    log("ACCEPTED: the proof is valid for exactly this claim", "good");
  } catch (error) {
    if (error.message === "cancelled") throw error;
    log(`REJECTED: ${error.message}`, "bad");
  }
}

function download(name, bytes) {
  const url = URL.createObjectURL(new Blob([bytes]));
  Object.assign(document.createElement("a"), { href: url, download: name }).click();
  URL.revokeObjectURL(url);
}

async function importFile(input, apply) {
  const file = input.files[0];
  if (file) apply(file.name, new Uint8Array(await file.arrayBuffer()));
  input.value = "";
}

function wire() {
  $("family").onchange = renderFamily;
  $("commit").onclick = () => job("commit", commit);
  $("prove").onclick = () => job("prove", prove);
  $("verify").onclick = () => job("verify", verify);
  $("cancel").onclick = () => runner.cancel();
  $("tamper").onclick = () => {
    if (!state.proof) return log("no proof to corrupt", "bad");
    state.proof = state.proof.slice();
    state.proof[state.proof.length >> 1] ^= 0x55;
    return log("flipped one proof byte; verify should now reject", "warn");
  };
  $("exportProof").onclick = () => state.proof && download("predicate.zkp", state.proof);
  $("exportClaim").onclick = () => download("claim.json", $("claim").value);
  $("exportSecrets").onclick = () => state.secrets.length && download("secrets.json", JSON.stringify(state.secrets));
  $("importProof").onchange = (e) => importFile(e.target, (name, bytes) => { state.proof = bytes; log(`imported proof ${name} (${bytes.length} B)`); });
  $("importClaim").onchange = (e) => importFile(e.target, (name, bytes) => { $("claim").value = new TextDecoder().decode(bytes); log(`imported claim ${name}`); });
}

async function start() {
  for (const [id, family] of Object.entries(FAMILIES)) $("family").append(new Option(family.title, id));
  for (const type of INT_TYPES) $("type").append(new Option(type, type, false, type === "u32"));
  for (const [op, symbol] of Object.entries(OPS)) $("op").append(new Option(symbol, op, false, op === "ge"));
  renderFamily();
  wire();
  $("backend").textContent = (await runner.run("capabilities")).result;
  log("ready: commitments, proofs and verification all run in this browser tab");
}

start().catch((error) => log(`startup failed: ${error.message}`, "bad"));
