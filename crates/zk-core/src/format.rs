//! Portable artifact framing. Pure byte functions: no file system, no clock.

use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};

use crate::{Result, ZkError};

const MAGIC: &[u8; 8] = b"ZKSDK002";
const HEADER_LEN: usize = 16;
pub const MAX_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_ARTIFACT_BYTES)
}

/// Frame a value as magic, little-endian payload length, then fixed-int bincode.
/// Artifacts are NOT self-authenticating. Pin the verifying key out of band.
pub fn encode_artifact<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = codec()
        .serialize(value)
        .map_err(|e| ZkError::Format(e.to_string()))?;
    let size = payload.len() as u64;
    if size > MAX_ARTIFACT_BYTES {
        return Err(ZkError::Format("artifact too large".into()));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_artifact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() < HEADER_LEN || bytes.len() as u64 > MAX_ARTIFACT_BYTES + HEADER_LEN as u64 {
        return Err(ZkError::Format("invalid artifact length".into()));
    }
    if &bytes[..8] != MAGIC {
        return Err(ZkError::Format("invalid artifact magic".into()));
    }
    let size = u64::from_le_bytes(bytes[8..HEADER_LEN].try_into().expect("8-byte slice"));
    if size != (bytes.len() - HEADER_LEN) as u64 {
        return Err(ZkError::Format("noncanonical artifact length".into()));
    }
    codec()
        .deserialize(&bytes[HEADER_LEN..])
        .map_err(|e| ZkError::Format(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes = encode_artifact(&vec![1u64, 2, 3]).unwrap();
        assert_eq!(decode_artifact::<Vec<u64>>(&bytes).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn rejects_tampering_and_truncation() {
        let bytes = encode_artifact(&vec![1u64, 2, 3]).unwrap();
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert!(decode_artifact::<Vec<u64>>(&bad_magic).is_err());
        assert!(decode_artifact::<Vec<u64>>(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_artifact::<Vec<u64>>(&trailing).is_err());
        assert!(decode_artifact::<Vec<u64>>(&[]).is_err());
    }
}
