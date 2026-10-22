//! Translation from the portable `SecurityPolicy` to upstream setup parameters.

use spartan_whir::{
    recommended_quintic_zk_whir_params, MatrixClosingMode, PoseidonZkSetupConfig, SecurityConfig,
    SoundnessAssumption, WhirParams, DEFAULT_ZK_ELL, DEFAULT_ZK_MASK_LOG_INV_RATE,
};
use zk_core::{Capabilities, SecurityPolicy, Soundness};

pub const BACKEND_NAME: &str = "spartan-whir-koalabear-quintic-zk-poseidon";
pub const BACKEND_VERSION: &str = "spartan-whir@02bec8d0c13417452b0a1a52e585d20a8b47cee9";

/// Empirically swept range: every level here proves and verifies under all three soundness modes.
/// Upstream accepts 80..=123 in principle, but Poseidon commitments cap attainable security at 118
/// bits and small levels fail setup for some circuits, so the portable promise is narrower.
pub const MIN_BITS: u16 = 100;
pub const MAX_BITS: u16 = 118;

pub fn capabilities() -> Capabilities {
    Capabilities {
        backend: BACKEND_NAME.into(),
        backend_version: BACKEND_VERSION.into(),
        min_bits: MIN_BITS,
        max_bits: MAX_BITS,
        soundness: vec![
            Soundness::UniqueDecoding,
            Soundness::JohnsonBound,
            Soundness::CapacityBound,
        ],
        full_zero_knowledge: true,
    }
}

fn assumption(soundness: Soundness) -> SoundnessAssumption {
    match soundness {
        Soundness::UniqueDecoding => SoundnessAssumption::UniqueDecoding,
        Soundness::JohnsonBound => SoundnessAssumption::JohnsonBound,
        Soundness::CapacityBound => SoundnessAssumption::CapacityBound,
    }
}

/// Ceiling on proof-of-work grinding, in bits. Upstream recommends 22, whose random search costs
/// seconds (up to ~20 s in single-threaded wasm). Upstream derives the query count from
/// `security - pow_bits`, so lowering it keeps the security target and trades a few more queries
/// for latency. 12 bits measured ~75 ms single-threaded with unchanged proof size.
const MAX_POW_BITS: u32 = 12;

fn whir_params(num_vars: usize) -> WhirParams {
    let mut params = recommended_quintic_zk_whir_params(num_vars);
    params.pow_bits = params.pow_bits.min(MAX_POW_BITS);
    params
}

pub fn setup_config(policy: SecurityPolicy, num_vars: usize) -> PoseidonZkSetupConfig {
    let bits = u32::from(policy.bits);
    PoseidonZkSetupConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security: SecurityConfig {
            security_level_bits: bits,
            merkle_security_bits: bits,
            soundness_assumption: assumption(policy.soundness),
        },
        whir_params: whir_params(num_vars),
        spark_whir_params: None,
        ell_zk: DEFAULT_ZK_ELL,
        mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
    }
}
