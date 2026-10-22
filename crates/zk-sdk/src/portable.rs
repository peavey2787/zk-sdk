//! The complete workflow over plain bytes: the single implementation behind the native CLI and
//! the browser (wasm) bindings, so no prove or verify logic is duplicated per platform.

use crate::{
    decode_artifact, encode_artifact, parse_inputs_json, Inspect, PrivateInputs, Proof,
    ProofMetadata, ProvingKey, Result, VerifyingKey, WitnessCalculator, Zk, ZkError,
};

/// Serialized keys, ready to store or transfer. The proving key is secret material.
pub struct KeyBytes {
    pub proving: Vec<u8>,
    pub verifying: Vec<u8>,
}

pub fn setup(zk: &Zk, r1cs: Vec<u8>) -> Result<KeyBytes> {
    let keys = zk.setup(&zk.compile(r1cs)?)?;
    Ok(KeyBytes {
        proving: encode_artifact(&keys.proving)?,
        verifying: encode_artifact(&keys.verifying)?,
    })
}

/// Generate a `.wtns` witness from circom input JSON. Fails when the inputs violate the circuit.
pub fn witness(zk: &Zk, r1cs: &[u8], sym: &str, input_json: &str) -> Result<Vec<u8>> {
    let calculator =
        WitnessCalculator::new(r1cs, sym).map_err(|e| ZkError::Format(e.to_string()))?;
    let inputs = parse_inputs_json(input_json).map_err(|e| ZkError::Format(e.to_string()))?;
    Ok(zk.witness(&calculator, &inputs)?.wtns_bytes().to_vec())
}

pub fn prove(zk: &Zk, proving_key: &[u8], wtns: &[u8]) -> Result<Vec<u8>> {
    let key: ProvingKey = decode_artifact(proving_key)?;
    let witness = PrivateInputs::from_wtns_bytes(wtns.to_vec())?;
    encode_artifact(&zk.prove(&key, &witness)?.proof)
}

/// `expected` is the independently trusted public statement (circom order: outputs, then public
/// inputs), never something read out of the proof.
pub fn verify(zk: &Zk, verifying_key: &[u8], expected: &[u64], proof: &[u8]) -> Result<()> {
    let key: VerifyingKey = decode_artifact(verifying_key)?;
    let proof: Proof = decode_artifact(proof)?;
    zk.verify(&key, &zk.encode_public_inputs(expected)?, &proof)
}

/// Metadata only. This does NOT verify the proof.
pub fn describe(proof: &[u8]) -> Result<ProofMetadata> {
    Ok(decode_artifact::<Proof>(proof)?.inspect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1CS: &[u8] = include_bytes!("../../../testdata/age_over/age_over.r1cs");
    const SYM: &str = include_str!("../../../testdata/age_over/age_over.sym");
    const INPUT: &str = r#"{"age":"20","threshold":"18"}"#;

    #[test]
    fn full_workflow_over_bytes() {
        let zk = Zk::spartan_whir();
        let keys = setup(&zk, R1CS.to_vec()).unwrap();
        let wtns = witness(&zk, R1CS, SYM, INPUT).unwrap();
        let proof = prove(&zk, &keys.proving, &wtns).unwrap();
        verify(&zk, &keys.verifying, &[1, 18], &proof).unwrap();
        assert!(verify(&zk, &keys.verifying, &[1, 19], &proof).is_err());
        assert!(verify(&zk, &keys.verifying, &[1, 18], &proof[..proof.len() - 1]).is_err());
        assert_eq!(describe(&proof).unwrap().policy.bits, 116);
    }

    #[test]
    fn invalid_witness_inputs_are_rejected() {
        let zk = Zk::spartan_whir();
        assert!(witness(&zk, R1CS, SYM, r#"{"age":"256","threshold":"18"}"#).is_err());
        assert!(witness(&zk, R1CS, SYM, "not json").is_err());
        assert!(witness(&zk, b"junk", SYM, INPUT).is_err());
    }
}
