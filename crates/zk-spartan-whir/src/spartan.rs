use p3_field::PrimeField64;
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use spartan_whir::{
    engine::F, import_r1cs_bytes, import_witness_bytes, CircomR1cs, InvalidConfigReason,
    PoseidonZkProof, PoseidonZkProvingKey, PoseidonZkVerifyingKey, QuinticExtension,
    SpartanWhirError,
};
use web_time::Instant;
use zk_core::{
    Backend, Capabilities, CompiledCircuit, KeyPair, Phase, PrivateInputs, Proof, ProveOutput,
    ProvingKey, PublicInputs, Result, SecurityPolicy, VerifyingKey, ZkError, MAX_PROOF_BYTES,
    MAX_PROVING_KEY_BYTES, MAX_PUBLIC_INPUTS_BYTES, MAX_VERIFYING_KEY_BYTES,
};

use crate::{
    codec::{decode, encode},
    params::{capabilities, setup_config},
};

type UpstreamProvingKey = PoseidonZkProvingKey<QuinticExtension>;
type UpstreamVerifyingKey = PoseidonZkVerifyingKey<QuinticExtension>;
type UpstreamProof = PoseidonZkProof<QuinticExtension>;

/// Layout of the serialized proving key: the relation is stored beside the key.
#[derive(Serialize, Deserialize)]
struct ProvingArtifact {
    circuit: CircomR1cs,
    key: UpstreamProvingKey,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SpartanWhir;

/// Records how long each named stage of `prove` takes.
struct Stopwatch {
    started: Instant,
    phases: Vec<Phase>,
}

impl Stopwatch {
    fn start() -> Self {
        Self {
            started: Instant::now(),
            phases: Vec::new(),
        }
    }

    fn lap<T>(&mut self, name: &'static str, value: T) -> T {
        let micros = self.started.elapsed().as_micros() as u64;
        self.phases.push(Phase { name, micros });
        self.started = Instant::now();
        value
    }
}

fn backend_error(error: impl std::fmt::Display) -> ZkError {
    ZkError::Backend(error.to_string())
}

fn upstream(error: SpartanWhirError) -> ZkError {
    match error {
        SpartanWhirError::InvalidConfig(InvalidConfigReason::ComposedSecurityUnavailable {
            requested_bits,
            attainable_bits,
            ..
        }) => ZkError::SecurityUnattainable {
            requested: requested_bits as u16,
            attainable: attainable_bits as u16,
        },
        other => backend_error(other),
    }
}

fn check_binding(caps: &Capabilities, backend: &str, version: &str) -> Result<()> {
    if backend == caps.backend && version == caps.backend_version {
        Ok(())
    } else {
        Err(ZkError::Format(format!(
            "artifact is for {backend} ({version}); this backend is {} ({})",
            caps.backend, caps.backend_version
        )))
    }
}

fn import_relation(circuit: &CompiledCircuit) -> Result<CircomR1cs> {
    circuit.validate()?;
    import_r1cs_bytes(circuit.r1cs()).map_err(backend_error)
}

impl SpartanWhir {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for SpartanWhir {
    fn capabilities(&self) -> Capabilities {
        capabilities()
    }

    fn compile(&self, r1cs: Vec<u8>) -> Result<CompiledCircuit> {
        let circuit = CompiledCircuit::from_r1cs(r1cs)?;
        import_relation(&circuit)?;
        Ok(circuit)
    }

    fn setup(&self, circuit: &CompiledCircuit, policy: SecurityPolicy) -> Result<KeyPair> {
        let caps = capabilities();
        caps.check(policy)?;
        let relation = import_relation(circuit)?;
        let num_vars = relation.shape.num_vars.next_power_of_two().ilog2() as usize;
        let (key, verifying) =
            UpstreamProvingKey::setup(relation.shape.clone(), setup_config(policy, num_vars))
                .map_err(upstream)?;
        let proving = encode(
            &ProvingArtifact {
                circuit: relation,
                key,
            },
            MAX_PROVING_KEY_BYTES,
        )?;
        let verifying = encode(&verifying, MAX_VERIFYING_KEY_BYTES)?;
        KeyPair::new(&caps, policy, circuit.program_id(), proving, verifying)
    }

    fn prove(&self, key: &ProvingKey, witness: &PrivateInputs) -> Result<ProveOutput> {
        key.validate()?;
        let binding = key.binding();
        check_binding(&capabilities(), &binding.backend, &binding.backend_version)?;
        let mut clock = Stopwatch::start();
        let mut artifact: ProvingArtifact = decode(key.raw_bytes(), MAX_PROVING_KEY_BYTES)?;
        clock.lap("decode_key", ());
        artifact.key.prepare_for_proving().map_err(upstream)?;
        clock.lap("prepare_key", ());
        let (values, public) = import_witness_bytes(&artifact.circuit.shape, witness.wtns_bytes())
            .map_err(backend_error)?;
        clock.lap("import_witness", ());
        let proof = artifact.key.prove(values, public).map_err(upstream)?;
        clock.lap("spartan_whir_prove", ());
        let public_bytes = encode(&proof.instance.public_inputs, MAX_PUBLIC_INPUTS_BYTES)?;
        let proof_bytes = encode(&proof, MAX_PROOF_BYTES)?;
        let claimed = PublicInputs::from_bytes(public_bytes)?;
        let proof = Proof::new(key, proof_bytes, claimed.clone())?;
        clock.lap("encode_proof", ());
        Ok(ProveOutput {
            proof,
            phases: clock.phases,
            claimed_public_inputs: claimed,
        })
    }

    fn verify(&self, key: &VerifyingKey, expected: &PublicInputs, proof: &Proof) -> Result<()> {
        proof.validate_against(key, expected)?;
        let binding = key.binding();
        check_binding(&capabilities(), &binding.backend, &binding.backend_version)?;
        let mut verifying: UpstreamVerifyingKey = decode(key.raw_bytes(), MAX_VERIFYING_KEY_BYTES)?;
        verifying.authenticate().map_err(upstream)?;
        let expected: Vec<F> = decode(expected.bytes(), MAX_PUBLIC_INPUTS_BYTES)?;
        let proof: UpstreamProof = decode(proof.proof_bytes(), MAX_PROOF_BYTES)?;
        verifying.verify(&expected, &proof).map_err(upstream)
    }

    fn encode_public_inputs(&self, signals: &[u64]) -> Result<PublicInputs> {
        let field: Vec<F> = signals
            .iter()
            .map(|s| {
                Some(*s)
                    .filter(|v| *v < KoalaBear::ORDER_U64)
                    .map(|v| KoalaBear::new(v as u32))
                    .ok_or_else(|| {
                        ZkError::Format("signal is not a canonical field element".into())
                    })
            })
            .collect::<Result<_>>()?;
        PublicInputs::from_bytes(encode(&field, MAX_PUBLIC_INPUTS_BYTES)?)
    }
}
