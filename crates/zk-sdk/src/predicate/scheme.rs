//! The proof system a commitment belongs to. A commitment is made for one scheme and every claim
//! about it is proved and verified by that scheme; schemes never mix within a claim.

use crate::ZkError;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Spartan-WHIR over KoalaBear with Poseidon2 commitments: transparent (no trusted setup),
    /// post-quantum, and the only scheme for every predicate family.
    #[default]
    SpartanWhir,
    /// Groth16 over BN254 with Poseidon commitments: 128-byte proofs and fast proving, but it relies
    /// on a trusted setup (docs/GROTH16_SETUP.md) and is not post-quantum. Supports `opens`,
    /// `compare`, `range` and `compare_committed`, alone or in conjunctions.
    Groth16,
}

impl Scheme {
    pub fn name(self) -> &'static str {
        match self {
            Self::SpartanWhir => "spartan-whir",
            Self::Groth16 => "groth16",
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for Scheme {
    type Err = ZkError;

    fn from_str(text: &str) -> Result<Self, ZkError> {
        match text {
            "spartan-whir" => Ok(Self::SpartanWhir),
            "groth16" => Ok(Self::Groth16),
            _ => Err(ZkError::Format(format!(
                "unknown scheme `{text}` (spartan-whir or groth16)"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for scheme in [Scheme::SpartanWhir, Scheme::Groth16] {
            assert_eq!(scheme.name().parse::<Scheme>().unwrap(), scheme);
        }
        assert!("plonk".parse::<Scheme>().is_err());
        assert_eq!(Scheme::default(), Scheme::SpartanWhir);
    }
}
