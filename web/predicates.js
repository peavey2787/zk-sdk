import { buildClaim, FAMILIES, INT_TYPES, OPS, privateValues, setValuesJson } from "./claims.js";
import { JobRunner } from "./job-runner.js";

const $ = (id) => document.getElementById(id);
const runner = new JobRunner("./worker.js");
const NO_SETUP = { id: null, pack: null, setupId: null, label: "none (create or import one)" };
const state = { secrets: [], proof: null, setup: NO_SETUP };
let setupIds = 0;
const ROWS = {
  valueA: "rowValueA", valueB: "rowValueB", op: "rowOp", bound: "rowBound", lo: "rowLo", hi: "rowHi",
  ends: "rowEnds", setValues: "rowSetValues", inputs: "rowInputs", outputs: "rowOutputs", fee: "rowFee", operands: "rowOperands",
  centerX: "rowCenterX", centerY: "rowCenterY", ranges: "rowRanges",
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
    valueA: text("valueA"), valueB: text("valueB"), centerX: text("centerX"), centerY: text("centerY"), ranges: text("ranges"),
    setValues: text("setValues"), inputs: text("inputs"), outputs: text("outputs"), fee: text("fee"), operands,
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
  if (!busy) useSetup(state.setup);
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

// For set claims: the published set commitment and the private Merkle path (sent to the prover as
// one more secret). Other claims have neither.
async function setArtifacts() {
  const family = $("family").value;
  if (family !== "member" && family !== "absent") return { path: [] };
  const base = { scheme: $("scheme").value, type: $("type").value, values: setValuesJson(form()) };
  const { result: commitment } = await runner.run("predicateSetCommitment", base);
  const { result: path } = await runner.run("predicateSetPath", { ...base, value: text("valueA"), absent: family === "absent" });
  return { commitment, path: [path] };
}

async function commit() {
  const values = privateValues($("family").value, form());
  if (!values.length) throw new Error("the claim needs at least one private value");
  const made = [];
  let total = 0;
  for (const value of values) {
    const { result, ms } = await runner.run("predicateCommit", { scheme: $("scheme").value, type: $("type").value, value });
    made.push(JSON.parse(result));
    total += ms;
  }
  const set = await setArtifacts();
  state.secrets = [...made.map((m) => m.secret), ...set.path];
  state.proof = null;
  const claimForm = { ...form(), setCommitment: set.commitment };
  $("claim").value = JSON.stringify(buildClaim($("family").value, claimForm, made.map((m) => m.commitment)), null, 1);
  show("t-commit", total);
  log(`committed ${values.length} value(s); the claim is public, the secrets stay in this tab`, "good");
}

function showProgress({ done, total }) {
  const bar = $("setupProgress");
  bar.classList.remove("hidden");
  Object.assign(bar, { value: done, max: total });
}

// The worker is respawned on cancel, so the chosen minimum, the Groth16 setup and the trust list
// travel with every job that needs them (the worker skips both when they are already in place).
async function authorize() {
  await runner.run("predicateMinimumBits", { bits: Number($("minBits").value) });
  const { id, pack } = state.setup;
  const trust = $("setupTrust").value;
  await runner.run("groth16Use", { id: `${id}:${trust}`, pack, trust });
}

function useSetup(setup) {
  state.setup = setup;
  $("setupStatus").textContent = setup.setupId ? `${setup.label}, setup ${setup.setupId}` : setup.label;
  $("setupDownload").disabled = setup.pack === null;
  $("setupContribute").disabled = setup.pack === null;
}

// Authorize `setupId` for verification (it stays listed until removed from the text box).
function trustSetup(setupId) {
  const listed = $("setupTrust").value.split(/\s+/).filter(Boolean);
  if (!listed.includes(setupId)) $("setupTrust").value = [...listed, setupId].join("\n");
}

function describeKey({ circuit, keyId, contributions }) {
  const lines = contributions.map((c, i) => {
    const beacon = c.beacon ? ` beacon ${c.beacon.value} 2^${c.beacon.exponent}` : "";
    return `  #${i + 1} ${c.name ?? "(unnamed)"}${beacon} ${c.hash}`;
  });
  return [`${circuit} key ${keyId}`, ...lines].join("\n");
}

// Check every key of `pack` against phase 1 and show its contribution transcript.
async function checkSetup(pack) {
  const { result } = await runner.run("groth16Verify", { pack }, showProgress);
  $("setupTranscript").textContent = [`setup ${result.setupId}`, ...result.keys.map(describeKey)].join("\n");
  return result.setupId;
}

async function scopeCircuits() {
  if ($("setupScope").value === "all") return null;
  if (!$("claim").value.trim()) throw new Error("commit first: the claim decides which circuits the setup covers");
  return (await runner.run("groth16Circuits", { claim: $("claim").value })).result;
}

// A setup you created or contributed to is sound for you, so it is authorized for verification
// here; other verifiers decide for themselves.
async function adoptSetup(pack, label, own) {
  const setupId = await checkSetup(pack);
  useSetup({ id: ++setupIds, pack, setupId, label });
  if (own) trustSetup(setupId);
  $("setupProgress").classList.add("hidden");
  return setupId;
}

async function createSetup() {
  const circuits = await scopeCircuits();
  log(`creating a new Groth16 setup for ${circuits ? circuits.join(", ") : "every circuit"} (fetches phase 1 on first use)...`);
  const { result, ms } = await runner.run("groth16Create", { circuits, contributor: text("contributor") }, showProgress);
  const setupId = await adoptSetup(result.pack, "your new setup", true);
  log(`new setup ${setupId}: ${(result.pack.length / 1048576).toFixed(1)} MiB key pack in ${ms} ms; share it (and its id) with the next contributor or your verifiers`, "good");
}

async function contributeSetup() {
  log("verifying the setup in use, then adding your contribution to every key...");
  const { result, ms } = await runner.run("groth16Contribute", { pack: state.setup.pack, contributor: text("contributor") }, showProgress);
  const setupId = await adoptSetup(result.pack, "the setup with your contribution", true);
  log(`contributed in ${ms} ms: new setup ${setupId}; pass the key pack on or publish it`, "good");
}

async function importSetup(name, pack) {
  const setupId = await adoptSetup(pack, `imported ${name}`, false);
  const trusted = $("setupTrust").value.includes(setupId);
  log(`imported ${name}: every key checks out against phase 1 (setup ${setupId}); ${trusted ? "authorized" : "NOT authorized for verification until you add its id"}`, trusted ? "good" : "warn");
}

// Drop every reference to the private openings (and the proof made from them) so the browser may
// reclaim them. JavaScript strings cannot be overwritten, so this is release, not erasure.
function forgetSecrets() {
  state.secrets = [];
  state.proof = null;
}

async function prove() {
  if (!state.secrets.length) throw new Error("commit first");
  await authorize();
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
    await authorize();
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
  $("scheme").onchange = () => $("trustedSetup").classList.toggle("hidden", $("scheme").value !== "groth16");
  $("setupCreate").onclick = () => job("create setup", createSetup);
  $("setupContribute").onclick = () => job("contribute", contributeSetup);
  $("setupTrustCurrent").onclick = () => state.setup.setupId && trustSetup(state.setup.setupId);
  $("setupDownload").onclick = () => state.setup.pack && download(`setup-${state.setup.setupId.slice(0, 12)}.zkg16keys`, state.setup.pack);
  $("setupImport").onchange = (e) => importFile(e.target, (name, bytes) => job("import setup", () => importSetup(name, bytes)));
  $("commit").onclick = () => job("commit", commit);
  $("prove").onclick = () => job("prove", prove);
  $("verify").onclick = () => job("verify", verify);
  $("cancel").onclick = () => runner.cancel();
  $("forget").onclick = forgetSecrets;
  // Secrets live only in this tab's memory; leaving the page drops the references too.
  addEventListener("pagehide", forgetSecrets);
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
  useSetup(NO_SETUP);
  $("backend").textContent = (await runner.run("capabilities")).result;
  log("ready: commitments, proofs and verification all run in this browser tab");
}

start().catch((error) => log(`startup failed: ${error.message}`, "bad"));
