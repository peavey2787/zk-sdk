//! The approved circuits compiled into the SDK. A circuit is only ever used after its SHA-256
//! matches the identity recorded at build time (`approved.rs`), so a corrupted or swapped bundle
//! fails closed instead of silently proving a different statement.

use sha2::{Digest, Sha256};

use super::approved::BUNDLED;
use crate::{Result, ZkError};

pub(super) struct Bundled {
    pub name: &'static str,
    pub r1cs: &'static [u8],
    pub sym: &'static str,
    pub sha256: &'static str,
}

impl Bundled {
    fn verify_identity(&self) -> Result<&Self> {
        let actual: String = Sha256::digest(self.r1cs)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if actual == self.sha256 {
            Ok(self)
        } else {
            Err(ZkError::Format(format!(
                "bundled circuit `{}` does not match its approved hash",
                self.name
            )))
        }
    }
}

/// The approved circuit called `name`, identity-checked.
pub(super) fn lookup(name: &str) -> Result<&'static Bundled> {
    BUNDLED
        .iter()
        .find(|b| b.name == name)
        .ok_or_else(|| ZkError::Predicate(format!("no approved circuit `{name}`")))?
        .verify_identity()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_circuit_matches_its_approved_hash() {
        assert_eq!(BUNDLED.len(), 45);
        for bundled in BUNDLED {
            lookup(bundled.name).unwrap();
        }
    }

    #[test]
    fn unknown_and_tampered_circuits_are_rejected() {
        assert!(lookup("compare_7").is_err());
        let tampered = Bundled {
            sha256: "00",
            ..BUNDLED[0]
        };
        assert!(tampered.verify_identity().is_err());
    }
}
