//! Thin wasm-bindgen layer over `zk_sdk::portable`. Every byte stays in the browser: there is no
//! network access here, and the heavy calls are meant to run inside a Web Worker.
use std::cell::RefCell;
use std::sync::Arc;

use wasm_bindgen::prelude::*;
use zk_sdk::predicate::{
    self, Ceremony, Contribution, Groth16Memory, Groth16Setup, KeyPack, KeyReport, Phase1,
    Predicates, Trust,
};
use zk_sdk::{portable, SecurityPolicy, Zk};

/// `initThreadPool(n)` for the threaded bundle: start `n` proving threads before any other call.
#[cfg(all(target_arch = "wasm32", feature = "threads"))]
pub use wasm_bindgen_rayon::init_thread_pool;

fn js(error: impl std::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}

fn zk(bits: u16, soundness: &str) -> Result<Zk, JsError> {
    let policy = SecurityPolicy {
        bits,
        soundness: soundness.parse().map_err(js)?,
        ..SecurityPolicy::default()
    };
    Ok(Zk::spartan_whir().with_policy(policy))
}

/// Serialized keys. The proving key is secret; the verifying key is public.
#[wasm_bindgen]
pub struct Keys {
    proving: Vec<u8>,
    verifying: Vec<u8>,
}

#[wasm_bindgen]
impl Keys {
    #[wasm_bindgen(getter)]
    pub fn proving(&self) -> Vec<u8> {
        self.proving.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn verifying(&self) -> Vec<u8> {
        self.verifying.clone()
    }
}

/// Supported security range and defaults, as text for display.
#[wasm_bindgen]
pub fn capabilities() -> String {
    let caps = Zk::spartan_whir().capabilities();
    format!(
        "{} {}..={} bits, soundness {:?}, default {:?}",
        caps.backend_version,
        caps.min_bits,
        caps.max_bits,
        caps.soundness,
        SecurityPolicy::default()
    )
}

#[wasm_bindgen]
pub fn setup(r1cs: Vec<u8>, bits: u16, soundness: &str) -> Result<Keys, JsError> {
    let keys = portable::setup(&zk(bits, soundness)?, r1cs).map_err(js)?;
    Ok(Keys {
        proving: keys.proving,
        verifying: keys.verifying,
    })
}

/// Compute the witness from private inputs entirely locally. Returns `.wtns` bytes.
#[wasm_bindgen]
pub fn witness(r1cs: &[u8], sym: &str, input_json: &str) -> Result<Vec<u8>, JsError> {
    portable::witness(&Zk::spartan_whir(), r1cs, sym, input_json).map_err(js)
}

#[wasm_bindgen]
pub fn prove(proving_key: &[u8], wtns: &[u8]) -> Result<Vec<u8>, JsError> {
    portable::prove(&Zk::spartan_whir(), proving_key, wtns).map_err(js)
}

/// `expected` is the independently trusted statement, as field elements below 2^32.
#[wasm_bindgen]
pub fn verify(verifying_key: &[u8], expected: &[u32], proof: &[u8]) -> Result<(), JsError> {
    let expected: Vec<u64> = expected.iter().map(|v| u64::from(*v)).collect();
    portable::verify(&Zk::spartan_whir(), verifying_key, &expected, proof).map_err(js)
}

/// Metadata only; does not verify the proof.
#[wasm_bindgen]
pub fn describe(proof: &[u8]) -> Result<String, JsError> {
    Ok(format!("{:?}", portable::describe(proof).map_err(js)?))
}

/// The worker's predicate engine. Built-in circuits are loaded and keyed on first use, then kept
/// warm for the lifetime of the worker. Groth16 needs a trusted setup: the host hands over the
/// published phase-1 file and each circuit's r1cs and sym (all checked against their pinned hashes),
/// then creates a setup, contributes to one, or installs one with the verifier's trust list.
struct Engine {
    circuits: Arc<Groth16Memory>,
    ceremony: Option<Ceremony>,
    setup: Option<Groth16Setup>,
    predicates: Predicates,
    /// The key pack being contributed to or verified ([`groth16_load_pack`]).
    loaded: KeyPack,
    /// Keys made since the last [`groth16_take_pack`].
    made: KeyPack,
}

impl Engine {
    fn new() -> Self {
        Self {
            circuits: Arc::new(Groth16Memory::default()),
            ceremony: None,
            setup: None,
            predicates: Predicates::new(),
            loaded: KeyPack::default(),
            made: KeyPack::default(),
        }
    }

    /// Rebuild the engine (dropping cached keys) at `bits` with the current setup.
    fn rebuild(&mut self, bits: u16) {
        let predicates = Predicates::new().with_minimum_bits(bits);
        self.predicates = match &self.setup {
            Some(setup) => predicates.with_groth16(setup.clone()),
            None => predicates,
        };
    }

    fn ceremony(&self) -> Result<&Ceremony, JsError> {
        self.ceremony
            .as_ref()
            .ok_or_else(|| JsError::new("hand over the phase-1 file first (groth16_set_phase1)"))
    }
}

thread_local! {
    static ENGINE: RefCell<Engine> = RefCell::new(Engine::new());
}

fn with_engine<T>(f: impl FnOnce(&mut Engine) -> T) -> T {
    ENGINE.with(|engine| f(&mut engine.borrow_mut()))
}

/// Authorize circuits that cannot reach the 116-bit default to run at the highest level they
/// attain, never below `bits` (the larger arithmetic circuits attain 115). Discards keys cached at
/// any other level (repeating the same value keeps them); without a call these circuits fail.
#[wasm_bindgen]
pub fn predicate_set_minimum_bits(bits: u16) {
    with_engine(|engine| {
        let wanted = Predicates::new().with_minimum_bits(bits).minimum_bits();
        if engine.predicates.minimum_bits() != wanted {
            engine.rebuild(bits);
        }
    });
}

/// Every approved Groth16 circuit.
#[wasm_bindgen]
pub fn groth16_circuits() -> Vec<String> {
    predicate::groth16_circuits()
}

/// The Groth16 circuits a claim needs, so their artifacts can be fetched before proving.
#[wasm_bindgen]
pub fn predicate_groth16_circuits(claim_json: &str) -> Result<Vec<String>, JsError> {
    predicate::claim_groth16_circuits(claim_json).map_err(js)
}

/// The published phase-1 file names any setup can start from, smallest first.
#[wasm_bindgen]
pub fn groth16_phase1_files() -> Vec<String> {
    predicate::phase1_powers()
        .map(predicate::phase1_file_name)
        .collect()
}

#[wasm_bindgen]
pub fn groth16_has_phase1() -> bool {
    with_engine(|engine| engine.ceremony.is_some())
}

/// Hand over a published phase-1 file (checked against its published hash); returns its power.
#[wasm_bindgen]
pub fn groth16_set_phase1(bytes: Vec<u8>) -> Result<u32, JsError> {
    let phase1 = Phase1::new(Arc::from(bytes)).map_err(js)?;
    let power = phase1.power();
    with_engine(|engine| {
        engine.ceremony = Some(Ceremony::new(engine.circuits.clone(), phase1));
    });
    Ok(power)
}

/// Whether the circuit file `file` (`<circuit>.r1cs` or `.sym`) was handed over.
#[wasm_bindgen]
pub fn groth16_has_artifact(file: &str) -> bool {
    with_engine(|engine| engine.circuits.contains(file))
}

/// Hand over a circuit file fetched by the host; it is checked against its pin when used.
#[wasm_bindgen]
pub fn groth16_add_artifact(file: &str, bytes: Vec<u8>) {
    with_engine(|engine| engine.circuits.insert(file, bytes));
}

fn contribution(contributor: &str) -> Contribution {
    let name = Some(contributor.trim()).filter(|n| !n.is_empty());
    Contribution::Random {
        name: name.map(str::to_owned),
    }
}

/// Load a key pack to contribute to or verify; returns `{"setupId","circuits":[..]}`.
#[wasm_bindgen]
pub fn groth16_load_pack(pack: &[u8]) -> Result<String, JsError> {
    let pack = KeyPack::from_bytes(pack).map_err(js)?;
    let summary = serde_json::json!({
        "setupId": pack.setup_id().map_err(js)?.to_string(),
        "circuits": pack.names().collect::<Vec<_>>(),
    });
    with_engine(|engine| engine.loaded = pack);
    Ok(summary.to_string())
}

/// Start circuit `name`'s key of a new setup with a contribution made from fresh browser entropy
/// (the secret never leaves this call); collect the setup with [`groth16_take_pack`].
#[wasm_bindgen]
pub fn groth16_create_key(name: &str, contributor: &str) -> Result<(), JsError> {
    with_engine(|engine| {
        let key = engine
            .ceremony()?
            .create_key(name, &contribution(contributor))
            .map_err(js)?;
        engine.made.insert(name, key).map_err(js)
    })
}

/// Verify circuit `name`'s key of the loaded pack, then add a fresh contribution to it.
#[wasm_bindgen]
pub fn groth16_contribute_key(name: &str, contributor: &str) -> Result<(), JsError> {
    with_engine(|engine| {
        let zkey = engine
            .loaded
            .get(name)
            .ok_or_else(|| JsError::new(&format!("the loaded pack has no key for `{name}`")))?;
        let key = engine
            .ceremony()?
            .contribute_key(name, zkey, &contribution(contributor))
            .map_err(js)?;
        engine.made.insert(name, key).map_err(js)
    })
}

/// The key pack of every key made since the last call.
#[wasm_bindgen]
pub fn groth16_take_pack() -> Vec<u8> {
    with_engine(|engine| std::mem::take(&mut engine.made).to_bytes())
}

fn report_json(report: &KeyReport) -> serde_json::Value {
    let contributions: Vec<_> = report
        .contributions
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "hash": c.hash,
                "beacon": c.beacon.as_ref().map(|b| serde_json::json!({
                    "value": b.value.iter().map(|x| format!("{x:02x}")).collect::<String>(),
                    "exponent": b.exponent,
                })),
            })
        })
        .collect();
    serde_json::json!({
        "circuit": report.circuit,
        "keyId": report.key_id.to_string(),
        "circuitHash": report.circuit_hash,
        "contributions": contributions,
    })
}

/// Check circuit `name`'s key of the loaded pack against phase 1; returns its report as JSON
/// `{"circuit","keyId","circuitHash","contributions":[{"name","hash","beacon"}]}`.
#[wasm_bindgen]
pub fn groth16_verify_key(name: &str) -> Result<String, JsError> {
    with_engine(|engine| {
        let zkey = engine
            .loaded
            .get(name)
            .ok_or_else(|| JsError::new(&format!("the loaded pack has no key for `{name}`")))?;
        let report = engine.ceremony()?.verify_key(name, zkey).map_err(js)?;
        Ok(report_json(&report).to_string())
    })
}

/// Prove Groth16 claims with key pack `pack` (each key checked against phase 1 on first use) and
/// verify them only under the setup or key ids listed in `trust` (one hex id per line); with no
/// pack, Groth16 claims fail.
#[wasm_bindgen]
pub fn groth16_use(pack: Option<Vec<u8>>, trust: &str) -> Result<(), JsError> {
    with_engine(|engine| {
        engine.setup = match pack {
            None => None,
            Some(pack) => {
                let keys = KeyPack::from_bytes(&pack).map_err(js)?;
                let trust = Trust::parse(trust).map_err(js)?;
                Some(Groth16Setup::new(engine.ceremony()?.clone(), keys, trust).map_err(js)?)
            }
        };
        let bits = engine.predicates.minimum_bits();
        engine.rebuild(bits);
        Ok(())
    })
}

/// A fresh commitment for `scheme` (`spartan-whir` or `groth16`) as JSON `{"commitment","secret"}`:
/// publish the first, keep the second.
#[wasm_bindgen]
pub fn predicate_commit(scheme: &str, int_type: &str, value: &str) -> Result<String, JsError> {
    Ok(predicate::commit(scheme, int_type, value)
        .map_err(js)?
        .to_json())
}

/// The public commitment of the set of decimal strings in the JSON array `values_json`, for claims
/// about `scheme` commitments.
#[wasm_bindgen]
pub fn predicate_set_commitment(
    scheme: &str,
    int_type: &str,
    values_json: &str,
) -> Result<String, JsError> {
    predicate::set_commitment(scheme, int_type, values_json).map_err(js)
}

/// The private Merkle path (JSON) proving `value` is in the set, or with `absent` that it is not.
#[wasm_bindgen]
pub fn predicate_set_path(
    scheme: &str,
    int_type: &str,
    values_json: &str,
    value: &str,
    absent: bool,
) -> Result<String, JsError> {
    predicate::set_path(scheme, int_type, values_json, value, absent).map_err(js)
}

/// Issue credentials presented with `scheme` commitments from a JSON array of
/// `{"attribute","serial","expiry"}`; returns JSON `{"issuer", "credentials"}`: publish the
/// issuer, hand each holder their (secret) credential.
#[wasm_bindgen]
pub fn predicate_credential_issue(
    scheme: &str,
    int_type: &str,
    entries_json: &str,
) -> Result<String, JsError> {
    predicate::credential_issue(scheme, int_type, entries_json).map_err(js)
}

/// Present a credential to a verifier whose clock reads `now` (Unix seconds); `options_json` is
/// `{}` or adds `also` claims and a `revoked` serial list. Returns JSON `{"claim", "secrets"}`
/// ready for `predicate_prove`.
#[wasm_bindgen]
pub fn predicate_credential_present(
    credential_json: &str,
    now: &str,
    options_json: &str,
) -> Result<String, JsError> {
    predicate::credential_present(credential_json, now, options_json)
        .map(|presented| presented.to_json())
        .map_err(js)
}

/// Lower a private state transition `{"old":[..],"new":[..],"rules":[..]}` to JSON
/// `{"claim", "open"}`: prove `claim` with one secret per `open` commitment, in that order.
#[wasm_bindgen]
pub fn predicate_transition(spec_json: &str) -> Result<String, JsError> {
    predicate::transition_claim(spec_json)
        .map(|lowered| lowered.to_json())
        .map_err(js)
}

/// Prove a JSON claim with one secret per commitment, in claim order; a set claim takes its
/// Merkle path as one more, final secret.
#[wasm_bindgen]
pub fn predicate_prove(claim_json: &str, secrets: Vec<String>) -> Result<Vec<u8>, JsError> {
    with_engine(|engine| predicate::prove(&engine.predicates, claim_json, secrets)).map_err(js)
}

/// Verify against the claim the caller trusts; nothing is read from the proof.
#[wasm_bindgen]
pub fn predicate_verify(claim_json: &str, proof: &[u8]) -> Result<(), JsError> {
    with_engine(|engine| predicate::verify(&engine.predicates, claim_json, proof)).map_err(js)
}

#[wasm_bindgen]
pub fn predicate_describe(claim_json: &str) -> Result<String, JsError> {
    with_engine(|engine| predicate::describe(&engine.predicates, claim_json)).map_err(js)
}
