//! Hash helpers: lowercase hex, SHA-256 and BLAKE2b-512.

use blake2::Blake2b512;
use sha2::{Digest, Sha256};

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// BLAKE2b-512 over the concatenation of `parts`.
pub(crate) fn blake2b(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The 32-byte value `bytes` as eight big-endian words (how snarkjs seeds ChaCha from a hash).
pub(crate) fn be_words(bytes: &[u8]) -> [u32; 8] {
    std::array::from_fn(|i| u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().expect("4")))
}
