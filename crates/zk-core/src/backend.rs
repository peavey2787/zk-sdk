use crate::{
    Capabilities, CompiledCircuit, KeyPair, PrivateInputs, Proof, ProveOutput, ProvingKey,
    PublicInputs, Result, SecurityPolicy, VerifyingKey,
};

/// Implement only inside adapters. Downstream code should use `zk_sdk::Zk`.
/// Every method works on in-memory bytes so one backend runs natively and in WebAssembly.
pub trait Backend: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    /// Parse R1CS bytes with the real importer and bind them to a circuit identity.
    fn compile(&self, r1cs: Vec<u8>) -> Result<CompiledCircuit>;
    fn setup(&self, circuit: &CompiledCircuit, policy: SecurityPolicy) -> Result<KeyPair>;
    fn prove(&self, key: &ProvingKey, witness: &PrivateInputs) -> Result<ProveOutput>;
    /// Error means rejected or unavailable. Never interpret failure as a valid proof.
    fn verify(&self, key: &VerifyingKey, expected: &PublicInputs, proof: &Proof) -> Result<()>;
    /// Encode canonical integer public signals (circom order) in the backend's field encoding.
    fn encode_public_inputs(&self, signals: &[u64]) -> Result<PublicInputs>;
}
