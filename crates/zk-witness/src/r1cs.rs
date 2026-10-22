//! Parser for circom binary `.r1cs` files over a 4-byte prime field.

use std::collections::BTreeMap;

use crate::{
    field::{add, P},
    Result, WitnessError,
};

const FIELD_BYTES: u32 = 4;
const SECTION_HEADER: u32 = 1;
const SECTION_CONSTRAINTS: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Term {
    pub wire: u32,
    pub coef: u64,
}

pub type LinearCombination = Vec<Term>;

#[derive(Clone, Debug)]
pub struct Constraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

#[derive(Clone, Debug)]
pub struct R1cs {
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
    pub constraints: Vec<Constraint>,
}

impl R1cs {
    /// Wire indexes of circuit inputs: public inputs, then private inputs.
    pub fn input_wires(&self) -> std::ops::Range<u32> {
        let first = 1 + self.n_pub_out;
        first..first + self.n_pub_in + self.n_prv_in
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.bytes.len() < n {
            return Err(WitnessError::Format("unexpected end of r1cs".into()));
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
}

/// Sort by wire and merge duplicate wires so every wire appears once, with a non-zero coefficient.
fn normalize(terms: Vec<Term>) -> LinearCombination {
    let mut merged = BTreeMap::new();
    for term in terms {
        let slot = merged.entry(term.wire).or_insert(0);
        *slot = add(*slot, term.coef);
    }
    merged
        .into_iter()
        .filter(|(_, coef)| *coef != 0)
        .map(|(wire, coef)| Term { wire, coef })
        .collect()
}

fn read_lc(reader: &mut Reader, n_wires: u32) -> Result<LinearCombination> {
    let count = reader.u32()? as usize;
    if count.saturating_mul(8) > reader.bytes.len() {
        return Err(WitnessError::Format("term count exceeds file size".into()));
    }
    let mut terms = Vec::with_capacity(count);
    for _ in 0..count {
        let wire = reader.u32()?;
        let coef = u64::from(reader.u32()?);
        if wire >= n_wires || coef >= P {
            return Err(WitnessError::Format("term out of range".into()));
        }
        terms.push(Term { wire, coef });
    }
    Ok(normalize(terms))
}

struct Header {
    n_wires: u32,
    n_pub_out: u32,
    n_pub_in: u32,
    n_prv_in: u32,
    n_constraints: u32,
}

fn read_header(section: &[u8]) -> Result<Header> {
    let mut r = Reader { bytes: section };
    let field_bytes = r.u32()?;
    let prime = r.take(field_bytes as usize)?;
    if field_bytes != FIELD_BYTES
        || u64::from(u32::from_le_bytes(prime.try_into().expect("4"))) != P
    {
        return Err(WitnessError::Format("r1cs is not over KoalaBear".into()));
    }
    let n_wires = r.u32()?;
    let (n_pub_out, n_pub_in, n_prv_in) = (r.u32()?, r.u32()?, r.u32()?);
    r.u64()?; // label count: unused
    let n_constraints = r.u32()?;
    let used = u64::from(n_pub_out) + u64::from(n_pub_in) + u64::from(n_prv_in);
    if used + 1 > u64::from(n_wires) {
        return Err(WitnessError::Format("inconsistent wire counts".into()));
    }
    Ok(Header {
        n_wires,
        n_pub_out,
        n_pub_in,
        n_prv_in,
        n_constraints,
    })
}

fn read_constraints(section: &[u8], header: &Header) -> Result<Vec<Constraint>> {
    let mut r = Reader { bytes: section };
    let count = header.n_constraints as usize;
    if count.saturating_mul(12) > section.len() {
        return Err(WitnessError::Format("constraint count exceeds file".into()));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(Constraint {
            a: read_lc(&mut r, header.n_wires)?,
            b: read_lc(&mut r, header.n_wires)?,
            c: read_lc(&mut r, header.n_wires)?,
        });
    }
    Ok(out)
}

fn split_sections(bytes: &[u8]) -> Result<BTreeMap<u32, &[u8]>> {
    let mut r = Reader { bytes };
    if r.take(4)? != b"r1cs" || r.u32()? != 1 {
        return Err(WitnessError::Format("not an r1cs v1 file".into()));
    }
    let mut sections = BTreeMap::new();
    for _ in 0..r.u32()? {
        let kind = r.u32()?;
        let size = usize::try_from(r.u64()?)
            .map_err(|_| WitnessError::Format("section too large".into()))?;
        sections.insert(kind, r.take(size)?);
    }
    Ok(sections)
}

pub fn parse(bytes: &[u8]) -> Result<R1cs> {
    let sections = split_sections(bytes)?;
    let section = |kind: u32| {
        sections
            .get(&kind)
            .copied()
            .ok_or_else(|| WitnessError::Format(format!("missing r1cs section {kind}")))
    };
    let header = read_header(section(SECTION_HEADER)?)?;
    let constraints = read_constraints(section(SECTION_CONSTRAINTS)?, &header)?;
    Ok(R1cs {
        n_wires: header.n_wires,
        n_pub_out: header.n_pub_out,
        n_pub_in: header.n_pub_in,
        n_prv_in: header.n_prv_in,
        constraints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGE_OVER: &[u8] = include_bytes!("../../../testdata/age_over/age_over.r1cs");

    #[test]
    fn parses_reference_circuit() {
        let r1cs = parse(AGE_OVER).unwrap();
        assert_eq!(r1cs.n_wires, 30);
        assert_eq!((r1cs.n_pub_out, r1cs.n_pub_in, r1cs.n_prv_in), (1, 1, 1));
        assert_eq!(r1cs.input_wires(), 2..4);
        assert!(!r1cs.constraints.is_empty());
    }

    #[test]
    fn rejects_truncated_and_foreign_files() {
        for cut in [0, 3, 11, 40, AGE_OVER.len() - 1] {
            assert!(parse(&AGE_OVER[..cut]).is_err(), "cut at {cut}");
        }
        let mut other_prime = AGE_OVER.to_vec();
        let at = other_prime
            .windows(8)
            .position(|w| w == [4, 0, 0, 0, 1, 0, 0, 0x7f])
            .expect("header prime present");
        other_prime[at + 4] ^= 1;
        assert!(parse(&other_prime).is_err());
    }

    #[test]
    fn normalize_merges_and_drops_zero() {
        let lc = normalize(vec![
            Term { wire: 2, coef: 5 },
            Term { wire: 1, coef: 3 },
            Term {
                wire: 2,
                coef: P - 5,
            },
        ]);
        assert_eq!(lc, vec![Term { wire: 1, coef: 3 }]);
    }
}
