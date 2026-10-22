//! Proving/verifying keys. Every key is bound to its backend, backend version,
//! circuit and security policy, so a mismatch is rejected before any cryptography.

use serde::{Deserialize, Serialize};

use crate::{digest, Capabilities, Result, SecurityPolicy, ZkError, FORMAT_VERSION};

pub const MAX_PROVING_KEY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_VERIFYING_KEY_BYTES: u64 = 512 * 1024 * 1024;
const VK_DOMAIN: &[u8] = b"zk-sdk/vk/v2";

/// What a key, and every proof made with it, is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBinding {
    pub backend: String,
    pub backend_version: String,
    pub policy: SecurityPolicy,
    pub program_id: [u8; 32],
    pub vk_id: [u8; 32],
}

fn vk_fingerprint(
    backend: &str,
    version: &str,
    policy: SecurityPolicy,
    program_id: [u8; 32],
    vk: &[u8],
) -> Result<[u8; 32]> {
    let framed = bincode::serialize(&(backend, version, policy, program_id, vk))
        .map_err(|e| ZkError::Format(e.to_string()))?;
    Ok(digest(VK_DOMAIN, &framed))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProvingKey {
    version: u16,
    binding: KeyBinding,
    bytes: Vec<u8>,
}

impl ProvingKey {
    pub fn binding(&self) -> &KeyBinding {
        &self.binding
    }

    /// Sensitive key material: do not log it or put it into public proof exports.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != FORMAT_VERSION || self.bytes.len() as u64 > MAX_PROVING_KEY_BYTES {
            return Err(ZkError::Format("invalid proving key format or size".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyingKey {
    version: u16,
    binding: KeyBinding,
    bytes: Vec<u8>,
}

impl VerifyingKey {
    pub fn binding(&self) -> &KeyBinding {
        &self.binding
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.binding.vk_id
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn validate(&self) -> Result<()> {
        let b = &self.binding;
        let expected = vk_fingerprint(
            &b.backend,
            &b.backend_version,
            b.policy,
            b.program_id,
            &self.bytes,
        )?;
        if self.version != FORMAT_VERSION
            || self.bytes.len() as u64 > MAX_VERIFYING_KEY_BYTES
            || b.vk_id != expected
        {
            return Err(ZkError::Format(
                "verifying key corrupt or version mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub proving: ProvingKey,
    pub verifying: VerifyingKey,
}

impl KeyPair {
    pub fn new(
        backend: &Capabilities,
        policy: SecurityPolicy,
        program_id: [u8; 32],
        proving: Vec<u8>,
        verifying: Vec<u8>,
    ) -> Result<Self> {
        if proving.is_empty()
            || verifying.is_empty()
            || proving.len() as u64 > MAX_PROVING_KEY_BYTES
            || verifying.len() as u64 > MAX_VERIFYING_KEY_BYTES
        {
            return Err(ZkError::Format("empty or oversized key".into()));
        }
        let vk_id = vk_fingerprint(
            &backend.backend,
            &backend.backend_version,
            policy,
            program_id,
            &verifying,
        )?;
        let binding = KeyBinding {
            backend: backend.backend.clone(),
            backend_version: backend.backend_version.clone(),
            policy,
            program_id,
            vk_id,
        };
        Ok(Self {
            proving: ProvingKey {
                version: FORMAT_VERSION,
                binding: binding.clone(),
                bytes: proving,
            },
            verifying: VerifyingKey {
                version: FORMAT_VERSION,
                binding,
                bytes: verifying,
            },
        })
    }
}
