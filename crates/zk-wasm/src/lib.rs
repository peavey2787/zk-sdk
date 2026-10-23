//! Thin wasm-bindgen layer over `zk_sdk::portable`. Every byte stays in the browser: there is no
//! network access here, and the heavy calls are meant to run inside a Web Worker.
use std::cell::RefCell;

use wasm_bindgen::prelude::*;
use zk_sdk::predicate::{self, Predicates};
use zk_sdk::{portable, SecurityPolicy, Zk};

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

thread_local! {
    // Built-in predicate circuits are loaded and keyed on first use, then kept warm for the
    // lifetime of the worker.
    static PREDICATES: RefCell<Predicates> = RefCell::new(Predicates::new());
}

/// Authorize circuits that cannot reach the 116-bit default to run at the highest level they
/// attain, never below `bits` (the larger arithmetic circuits attain 115). Discards keys cached at
/// any other level (repeating the same value keeps them); without a call these circuits fail.
#[wasm_bindgen]
pub fn predicate_set_minimum_bits(bits: u16) {
    PREDICATES.with(|zk| {
        let wanted = Predicates::new().with_minimum_bits(bits);
        if zk.borrow().minimum_bits() != wanted.minimum_bits() {
            *zk.borrow_mut() = wanted;
        }
    });
}

/// A fresh commitment as JSON `{"commitment","secret"}`: publish the first, keep the second.
#[wasm_bindgen]
pub fn predicate_commit(int_type: &str, value: &str) -> Result<String, JsError> {
    Ok(predicate::commit(int_type, value).map_err(js)?.to_json())
}

/// The public commitment of the set of decimal strings in the JSON array `values_json`.
#[wasm_bindgen]
pub fn predicate_set_commitment(int_type: &str, values_json: &str) -> Result<String, JsError> {
    predicate::set_commitment(int_type, values_json).map_err(js)
}

/// The private Merkle path (JSON) proving `value` is in the set, or with `absent` that it is not.
#[wasm_bindgen]
pub fn predicate_set_path(
    int_type: &str,
    values_json: &str,
    value: &str,
    absent: bool,
) -> Result<String, JsError> {
    predicate::set_path(int_type, values_json, value, absent).map_err(js)
}

/// Issue credentials from a JSON array of `{"attribute","serial","expiry"}`; returns JSON
/// `{"issuer", "credentials"}`: publish the issuer, hand each holder their (secret) credential.
#[wasm_bindgen]
pub fn predicate_credential_issue(int_type: &str, entries_json: &str) -> Result<String, JsError> {
    predicate::credential_issue(int_type, entries_json).map_err(js)
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
    PREDICATES
        .with(|zk| predicate::prove(&zk.borrow(), claim_json, secrets))
        .map_err(js)
}

/// Verify against the claim the caller trusts; nothing is read from the proof.
#[wasm_bindgen]
pub fn predicate_verify(claim_json: &str, proof: &[u8]) -> Result<(), JsError> {
    PREDICATES
        .with(|zk| predicate::verify(&zk.borrow(), claim_json, proof))
        .map_err(js)
}

#[wasm_bindgen]
pub fn predicate_describe(claim_json: &str) -> Result<String, JsError> {
    PREDICATES
        .with(|zk| predicate::describe(&zk.borrow(), claim_json))
        .map_err(js)
}
