//! Private witness and public statement byte containers.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{Result, ZkError};

pub const MAX_PUBLIC_INPUTS_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_WITNESS_BYTES: u64 = 1024 * 1024 * 1024;

/// Public input bytes use the backend's canonical encoding (see
/// `Backend::encode_public_inputs`). Expected inputs must come from an
/// independent trusted application statement, never from the prover.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInputs(Vec<u8>);

impl PublicInputs {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_PUBLIC_INPUTS_BYTES {
            return Err(ZkError::Format(
                "public input encoding empty or oversized".into(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A circom `.wtns` witness. Contents are secret and are never printed.
#[derive(Clone)]
pub struct PrivateInputs {
    wtns: Vec<u8>,
}

impl PrivateInputs {
    pub fn from_wtns_bytes(wtns: Vec<u8>) -> Result<Self> {
        if wtns.is_empty() || wtns.len() as u64 > MAX_WITNESS_BYTES {
            return Err(ZkError::Format("witness empty or oversized".into()));
        }
        Ok(Self { wtns })
    }

    pub fn wtns_bytes(&self) -> &[u8] {
        &self.wtns
    }
}

impl Drop for PrivateInputs {
    fn drop(&mut self) {
        self.wtns.zeroize();
    }
}

impl fmt::Debug for PrivateInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateInputs({} bytes, redacted)", self.wtns.len())
    }
}
