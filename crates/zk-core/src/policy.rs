//! Security policy requested by a caller and capabilities offered by a backend.

use serde::{Deserialize, Serialize};

use crate::{Result, ZkError};

/// Which list-decoding assumption the proof system's soundness analysis relies on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Soundness {
    UniqueDecoding,
    JohnsonBound,
    CapacityBound,
}

impl std::str::FromStr for Soundness {
    type Err = ZkError;

    fn from_str(name: &str) -> Result<Self> {
        match name {
            "unique" => Ok(Self::UniqueDecoding),
            "johnson" => Ok(Self::JohnsonBound),
            "capacity" => Ok(Self::CapacityBound),
            other => Err(ZkError::Policy(format!("unknown soundness `{other}`"))),
        }
    }
}

/// A configured security target, not a certified quantum-security level.
/// The default is 116-bit full zero knowledge under the Johnson bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub bits: u16,
    pub full_zero_knowledge: bool,
    pub soundness: Soundness,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            bits: 116,
            full_zero_knowledge: true,
            soundness: Soundness::JohnsonBound,
        }
    }
}

impl SecurityPolicy {
    /// Power-user knob: target security level in bits (checked against the backend at setup).
    pub fn with_bits(mut self, bits: u16) -> Self {
        self.bits = bits;
        self
    }

    /// Power-user knob: the soundness assumption the parameters are derived under.
    pub fn with_soundness(mut self, soundness: Soundness) -> Self {
        self.soundness = soundness;
        self
    }

    /// Backend-independent checks. Full zero knowledge is mandatory.
    pub fn validate(self) -> Result<()> {
        if !self.full_zero_knowledge {
            return Err(ZkError::Policy("full zero knowledge is required".into()));
        }
        if self.bits == 0 {
            return Err(ZkError::Policy("security bits must be positive".into()));
        }
        Ok(())
    }
}

/// What a backend genuinely supports. Callers inspect this instead of guessing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub backend: String,
    pub backend_version: String,
    pub min_bits: u16,
    pub max_bits: u16,
    pub soundness: Vec<Soundness>,
    pub full_zero_knowledge: bool,
}

impl Capabilities {
    /// Reject a policy the backend cannot honour. Never rounds or downgrades.
    pub fn check(&self, policy: SecurityPolicy) -> Result<()> {
        policy.validate()?;
        if policy.full_zero_knowledge && !self.full_zero_knowledge {
            return Err(ZkError::Policy(format!(
                "backend {} does not support full zero knowledge",
                self.backend
            )));
        }
        if !(self.min_bits..=self.max_bits).contains(&policy.bits) {
            return Err(ZkError::Policy(format!(
                "{} bits unsupported; backend {} supports {}..={}",
                policy.bits, self.backend, self.min_bits, self.max_bits
            )));
        }
        if !self.soundness.contains(&policy.soundness) {
            return Err(ZkError::Policy(format!(
                "soundness assumption {:?} unsupported by backend {}",
                policy.soundness, self.backend
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities() -> Capabilities {
        Capabilities {
            backend: "test".into(),
            backend_version: "1".into(),
            min_bits: 80,
            max_bits: 123,
            soundness: vec![Soundness::JohnsonBound],
            full_zero_knowledge: true,
        }
    }

    fn policy(bits: u16) -> SecurityPolicy {
        SecurityPolicy {
            bits,
            ..SecurityPolicy::default()
        }
    }

    #[test]
    fn default_is_116_bit_full_zk() {
        let p = SecurityPolicy::default();
        assert_eq!((p.bits, p.full_zero_knowledge), (116, true));
        assert!(capabilities().check(p).is_ok());
    }

    #[test]
    fn soundness_names_parse_strictly() {
        assert_eq!(
            "johnson".parse::<Soundness>().unwrap(),
            Soundness::JohnsonBound
        );
        assert!("fast".parse::<Soundness>().is_err());
    }

    #[test]
    fn rejects_non_zk() {
        let p = SecurityPolicy {
            full_zero_knowledge: false,
            ..SecurityPolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn range_is_backend_defined_not_hardcoded() {
        let caps = capabilities();
        assert!(caps.check(policy(80)).is_ok());
        assert!(caps.check(policy(123)).is_ok());
        assert!(caps.check(policy(79)).is_err());
        assert!(caps.check(policy(128)).is_err());
    }

    #[test]
    fn rejects_unsupported_soundness() {
        let p = SecurityPolicy {
            soundness: Soundness::CapacityBound,
            ..SecurityPolicy::default()
        };
        assert!(capabilities().check(p).is_err());
    }
}
