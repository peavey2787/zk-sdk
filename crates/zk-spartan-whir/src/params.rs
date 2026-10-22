//! Translation from the portable `SecurityPolicy` to upstream setup parameters.

use spartan_whir::{
    recommended_quintic_zk_whir_params, MatrixClosingMode, PoseidonZkSetupConfig, SecurityConfig,
    SoundnessAssumption, DEFAULT_ZK_ELL, DEFAULT_ZK_MASK_LOG_INV_RATE,
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

pub fn setup_config(policy: SecurityPolicy, num_vars: usize) -> PoseidonZkSetupConfig {
    let bits = u32::from(policy.bits);
    PoseidonZkSetupConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security: SecurityConfig {
            security_level_bits: bits,
            merkle_security_bits: bits,
            soundness_assumption: assumption(policy.soundness),
        },
        whir_params: recommended_quintic_zk_whir_params(num_vars),
        spark_whir_params: None,
        ell_zk: DEFAULT_ZK_ELL,
        mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
    }
}

/// Security invariants: the approved Spartan-WHIR profile is upstream's recommended one, unmodified.
/// A change to any of these must be a deliberate, reviewed decision, never a latency tweak.
#[cfg(test)]
mod tests {
    use super::*;
    use spartan_whir::MatrixClosingMode;

    const SIZES: [usize; 10] = [10, 12, 14, 16, 18, 19, 20, 21, 22, 24];

    #[test]
    fn whir_params_are_upstreams_recommendation_for_every_policy() {
        for num_vars in SIZES {
            for bits in [MIN_BITS, 116, MAX_BITS] {
                for soundness in [
                    Soundness::UniqueDecoding,
                    Soundness::JohnsonBound,
                    Soundness::CapacityBound,
                ] {
                    let config = setup_config(
                        SecurityPolicy::default()
                            .with_bits(bits)
                            .with_soundness(soundness),
                        num_vars,
                    );
                    assert_eq!(
                        config.whir_params,
                        recommended_quintic_zk_whir_params(num_vars)
                    );
                }
            }
        }
    }

    #[test]
    fn grinding_difficulty_is_not_below_upstreams_floor() {
        for num_vars in SIZES {
            let floor = if matches!(num_vars, 19 | 20) { 4 } else { 22 };
            let pow = setup_config(SecurityPolicy::default(), num_vars)
                .whir_params
                .pow_bits;
            assert!(
                pow >= floor,
                "num_vars {num_vars}: pow_bits {pow} < {floor}"
            );
        }
    }

    #[test]
    fn config_carries_requested_security_unchanged() {
        let policy = SecurityPolicy::default()
            .with_bits(111)
            .with_soundness(Soundness::CapacityBound);
        let config = setup_config(policy, 16);
        assert_eq!(config.security.security_level_bits, 111);
        assert_eq!(config.security.merkle_security_bits, 111);
        assert!(matches!(
            config.security.soundness_assumption,
            SoundnessAssumption::CapacityBound
        ));
        assert!(matches!(
            config.matrix_closing,
            MatrixClosingMode::DirectSparse
        ));
        assert_eq!(config.ell_zk, DEFAULT_ZK_ELL);
        assert_eq!(config.mask_log_inv_rate, DEFAULT_ZK_MASK_LOG_INV_RATE);
        assert!(config.spark_whir_params.is_none());
    }

    #[test]
    fn capabilities_are_full_zk_only_and_pinned() {
        let caps = capabilities();
        assert!(caps.full_zero_knowledge);
        assert_eq!((caps.min_bits, caps.max_bits), (100, 118));
        assert!(caps
            .backend_version
            .ends_with("02bec8d0c13417452b0a1a52e585d20a8b47cee9"));
    }
}
