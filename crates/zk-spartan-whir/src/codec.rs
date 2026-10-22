//! Bounded bincode for upstream types: fixed-int, little-endian, no trailing bytes.

use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};
use zk_core::{Result, ZkError};

fn options(limit: u64) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(limit)
}

pub fn encode<T: Serialize>(value: &T, limit: u64) -> Result<Vec<u8>> {
    options(limit)
        .serialize(value)
        .map_err(|e| ZkError::Format(e.to_string()))
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8], limit: u64) -> Result<T> {
    if bytes.len() as u64 > limit {
        return Err(ZkError::Format("encoded value exceeds size limit".into()));
    }
    options(limit)
        .deserialize(bytes)
        .map_err(|e| ZkError::Format(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_round_trip_rejects_trailing_and_oversized() {
        let bytes = encode(&vec![1u64, 2], 64).unwrap();
        assert_eq!(decode::<Vec<u64>>(&bytes, 64).unwrap(), vec![1, 2]);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode::<Vec<u64>>(&trailing, 64).is_err());
        assert!(decode::<Vec<u64>>(&bytes, 8).is_err());
        assert!(decode::<Vec<u8>>(&u64::MAX.to_le_bytes(), 64).is_err());
    }
}
