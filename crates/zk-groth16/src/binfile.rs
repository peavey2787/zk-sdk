//! The iden3 binary container shared by `.zkey` and `.ptau` files: a 4-byte magic, a `u32` version
//! (1), a `u32` section count, then per section a `u32` id, a `u64` size and the section bytes.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::{Groth16Error, Result};

fn u32_at(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("4 bytes"))
}

/// Every section's byte range in `bytes`, by section id. Refuses duplicate sections, truncation
/// and trailing bytes.
pub(crate) fn sections(bytes: &[u8], magic: &[u8; 4]) -> Result<BTreeMap<u32, Range<usize>>> {
    let kind = String::from_utf8_lossy(magic);
    let bad = |what: &str| Groth16Error::Format(format!("{kind}: {what}"));
    let field = |at: usize, n: usize| bytes.get(at..at + n).ok_or_else(|| bad("unexpected end"));
    if field(0, 4)? != magic || u32_at(field(4, 4)?) != 1 {
        return Err(bad("not a version 1 file"));
    }
    let mut out = BTreeMap::new();
    let mut at = 12;
    for _ in 0..u32_at(field(8, 4)?) {
        let id = u32_at(field(at, 4)?);
        let size = u64::from_le_bytes(field(at + 4, 8)?.try_into().expect("8 bytes"));
        let start = at + 12;
        let end = usize::try_from(size)
            .ok()
            .and_then(|size| start.checked_add(size))
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| bad("unexpected end"))?;
        if out.insert(id, start..end).is_some() {
            return Err(bad("duplicate section"));
        }
        at = end;
    }
    if at != bytes.len() {
        return Err(bad("trailing bytes"));
    }
    Ok(out)
}

/// A container holding `sections` in the order given.
pub(crate) fn write(magic: &[u8; 4], sections: &[(u32, &[u8])]) -> Vec<u8> {
    let size = 12 + sections.iter().map(|(_, s)| 12 + s.len()).sum::<usize>();
    let mut out = Vec::with_capacity(size);
    out.extend(magic);
    out.extend(1u32.to_le_bytes());
    out.extend((sections.len() as u32).to_le_bytes());
    for (id, bytes) in sections {
        out.extend(id.to_le_bytes());
        out.extend((bytes.len() as u64).to_le_bytes());
        out.extend(*bytes);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containers_round_trip_and_reject_damage() {
        let file = write(b"zkey", &[(2, &[1, 2, 3]), (1, &[])]);
        let sections = sections(&file, b"zkey").unwrap();
        assert_eq!(&file[sections[&2].clone()], &[1, 2, 3]);
        assert!(sections[&1].is_empty());
        assert!(super::sections(&file, b"ptau").is_err());
        assert!(super::sections(&file[..file.len() - 1], b"zkey").is_err());
        assert!(super::sections(&[file.as_slice(), &[0]].concat(), b"zkey").is_err());
        let twice = write(b"zkey", &[(1, &[]), (1, &[])]);
        assert!(super::sections(&twice, b"zkey").is_err());
    }
}
