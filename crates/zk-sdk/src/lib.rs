//! Small, byte-oriented frontend to a real full zero-knowledge prover.
//!
//! The same API runs natively (Windows, Linux) and in the browser (wasm32). Security note: a
//! proof's embedded public inputs are a CLAIM. Verification must use a separately authenticated
//! expected public statement and verifying key.

#[cfg(not(target_arch = "wasm32"))]
pub mod files;
pub mod portable;
mod simple;

pub use simple::{Circuit, Prover, Verifier};

pub use zk_core::{
    decode_artifact, encode_artifact, Backend, Capabilities, CompiledCircuit, Inspect, KeyPair,
    Phase, PrivateInputs, Proof, ProofMetadata, ProveOutput, ProvingKey, PublicInputs, Result,
    SecurityPolicy, Soundness, VerifyingKey, ZkError,
};
pub use zk_spartan_whir::SpartanWhir;
pub use zk_witness::{parse_inputs_json, Inputs, WitnessCalculator};

/// Public six-operation facade. `verify_batch` is a correct independent fallback, NOT an
/// optimized cryptographic batch verification primitive.
pub struct Zk {
    backend: Box<dyn Backend>,
    policy: SecurityPolicy,
}

impl Zk {
    pub fn new(backend: impl Backend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
            policy: SecurityPolicy::default(),
        }
    }

    /// The Spartan-WHIR full-ZK backend with the default 116-bit policy.
    pub fn spartan_whir() -> Self {
        Self::new(SpartanWhir::new())
    }

    /// The policy is checked against the backend's capabilities at `setup`, never silently
    /// adjusted.
    pub fn with_policy(mut self, policy: SecurityPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn capabilities(&self) -> Capabilities {
        self.backend.capabilities()
    }

    /// Step 1: Import canonical R1CS bytes (circom `.r1cs`) as a circuit.
    pub fn compile(&self, r1cs: Vec<u8>) -> Result<CompiledCircuit> {
        self.backend.compile(r1cs)
    }

    /// Step 2: Setup reusable full-ZK keys for an approved circuit.
    pub fn setup(&self, circuit: &CompiledCircuit) -> Result<KeyPair> {
        self.backend.setup(circuit, self.policy)
    }

    /// Step 3: Prove. The returned `claimed_public_inputs` are prover-generated, not
    /// authoritative for later independent verification.
    pub fn prove(&self, key: &ProvingKey, witness: &PrivateInputs) -> Result<ProveOutput> {
        self.backend.prove(key, witness)
    }

    /// Step 4: Verify against a trusted verifying key AND independently trusted expected inputs.
    /// A backend error MUST NOT be treated as success.
    pub fn verify(&self, key: &VerifyingKey, expected: &PublicInputs, proof: &Proof) -> Result<()> {
        self.backend.verify(key, expected, proof)
    }

    /// Step 5: Independent per-proof checks; future backends may optimize this.
    pub fn verify_batch(&self, jobs: &[(&VerifyingKey, &PublicInputs, &Proof)]) -> Vec<Result<()>> {
        jobs.iter()
            .map(|(key, inputs, proof)| self.verify(key, inputs, proof))
            .collect()
    }

    /// Step 6: Parse metadata only; inspecting a proof does NOT verify it.
    pub fn inspect(&self, proof: &Proof) -> ProofMetadata {
        proof.inspect()
    }

    /// Encode the independently trusted public statement (circom order: outputs, then public
    /// inputs) in the backend's canonical field encoding.
    pub fn encode_public_inputs(&self, signals: &[u64]) -> Result<PublicInputs> {
        self.backend.encode_public_inputs(signals)
    }

    /// Compute the private witness for named circuit inputs. Fails if the inputs violate the
    /// circuit, never returning a witness for a false statement.
    pub fn witness(
        &self,
        calculator: &WitnessCalculator,
        inputs: &Inputs,
    ) -> Result<PrivateInputs> {
        let witness = calculator
            .witness(inputs)
            .map_err(|e| ZkError::Backend(e.to_string()))?;
        PrivateInputs::from_wtns_bytes(witness.wtns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1CS: &[u8] = include_bytes!("../../../testdata/age_over/age_over.r1cs");

    #[test]
    fn rejects_non_zk_config_at_setup() {
        let zk = Zk::spartan_whir().with_policy(SecurityPolicy {
            full_zero_knowledge: false,
            ..SecurityPolicy::default()
        });
        let circuit = zk.compile(R1CS.to_vec()).unwrap();
        assert!(zk.setup(&circuit).is_err());
    }

    #[test]
    fn no_fake_proof_for_garbage_circuit() {
        assert!(Zk::spartan_whir()
            .compile(b"not-a-real-circuit".to_vec())
            .is_err());
    }

    #[test]
    fn capabilities_are_inspectable() {
        let caps = Zk::spartan_whir().capabilities();
        assert!(caps.check(SecurityPolicy::default()).is_ok());
        assert_eq!((caps.min_bits, caps.max_bits), (100, 118));
    }
}
