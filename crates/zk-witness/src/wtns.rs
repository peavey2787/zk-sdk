//! Encoder for circom `.wtns` (version 2) over any supported field.

use crate::field::Field;

const SECTION_HEADER: u32 = 1;
const SECTION_VALUES: u32 = 2;

fn section(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
}

pub fn encode<F: Field>(values: &[F::Element]) -> Vec<u8> {
    let modulus = F::modulus_le();
    let mut header = Vec::new();
    header.extend_from_slice(&(modulus.len() as u32).to_le_bytes());
    header.extend_from_slice(&modulus);
    header.extend_from_slice(&(values.len() as u32).to_le_bytes());
    let body: Vec<u8> = values.iter().flat_map(|v| F::to_le(*v)).collect();
    let mut out = b"wtns".to_vec();
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());
    section(&mut out, SECTION_HEADER, &header);
    section(&mut out, SECTION_VALUES, &body);
    out
}
