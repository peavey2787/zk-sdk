//! Reader for snarkjs Groth16 `.zkey` files (BN254). Curve points are stored little-endian in
//! Montgomery form, `(0, 0)` encodes the point at infinity, and every point is checked to be on the
//! curve and in the prime-order subgroup. The coefficient section is not read: the prover takes its
//! constraint matrices from the `.r1cs`, which `snarkjs zkey verify` binds to this key.

use std::collections::BTreeMap;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};

use crate::{
    binfile,
    points::{ELEMENT, G1_BYTES, G2_BYTES},
    Groth16Error, Result,
};

pub(crate) const MAGIC: &[u8; 4] = b"zkey";
pub(crate) const PROTOCOL_GROTH16: u32 = 1;
/// Section ids: protocol, header (with delta), IC, coefficients, A, B1, B2, L, H, contributions.
pub(crate) const PROTOCOL: u32 = 1;
pub(crate) const HEADER: u32 = 2;
pub(crate) const IC: u32 = 3;
pub(crate) const COEFFICIENTS: u32 = 4;
pub(crate) const A_QUERY: u32 = 5;
pub(crate) const B1_QUERY: u32 = 6;
pub(crate) const B2_QUERY: u32 = 7;
pub(crate) const L_QUERY: u32 = 8;
pub(crate) const H_QUERY: u32 = 9;
pub(crate) const CONTRIBUTIONS: u32 = 10;
/// Offset of `delta_g1` (then `delta_g2`) in the header: two moduli, three counts, alpha, beta
/// (G1 and G2) and gamma.
pub(crate) const DELTA_OFFSET: usize = 2 * (4 + ELEMENT) + 12 + 2 * G1_BYTES + 2 * G2_BYTES;

/// The verifying-key points (`ic` holds one point per input, the constant wire first).
pub struct VerifyingKeyPoints {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic: Vec<G1Affine>,
}

/// The proving key; queries are indexed by wire (`l_query` by private wire, `h_query` by coset
/// point).
pub struct ProvingKey {
    pub vk: VerifyingKeyPoints,
    pub beta_g1: G1Affine,
    pub delta_g1: G1Affine,
    pub a_query: Vec<G1Affine>,
    pub b_g1_query: Vec<G1Affine>,
    pub b_g2_query: Vec<G2Affine>,
    pub l_query: Vec<G1Affine>,
    pub h_query: Vec<G1Affine>,
}

/// A parsed zkey: the proving key and the shape it was generated for.
pub struct Zkey {
    pub n_vars: usize,
    pub n_public: usize,
    pub domain_size: usize,
    pub proving_key: ProvingKey,
}

fn malformed(what: &str) -> Groth16Error {
    Groth16Error::Format(format!("zkey: {what}"))
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.bytes.len() < n {
            return Err(malformed("unexpected end"));
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }

    fn count(&mut self) -> Result<usize> {
        Ok(self.u32()? as usize)
    }

    /// A base-field element in Montgomery form; rejects non-canonical encodings.
    fn fq(&mut self) -> Result<Fq> {
        let bytes = self.take(ELEMENT)?;
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().expect("8"));
        }
        let raw = BigInt(limbs);
        if raw >= Fq::MODULUS {
            return Err(malformed("field element out of range"));
        }
        Ok(Fq::new_unchecked(raw))
    }

    fn g1(&mut self) -> Result<G1Affine> {
        let (x, y) = (self.fq()?, self.fq()?);
        if x.is_zero() && y.is_zero() {
            return Ok(G1Affine::zero());
        }
        in_group(G1Affine::new_unchecked(x, y))
    }

    fn g2(&mut self) -> Result<G2Affine> {
        let x = Fq2::new(self.fq()?, self.fq()?);
        let y = Fq2::new(self.fq()?, self.fq()?);
        if x.is_zero() && y.is_zero() {
            return Ok(G2Affine::zero());
        }
        in_group(G2Affine::new_unchecked(x, y))
    }
}

/// A G1 point from LEM bytes, checked to be canonical, on the curve and in the subgroup.
pub(crate) fn checked_g1(bytes: &[u8]) -> Result<G1Affine> {
    Reader { bytes }.g1()
}

/// A G2 point from LEM bytes, checked like [`checked_g1`].
pub(crate) fn checked_g2(bytes: &[u8]) -> Result<G2Affine> {
    Reader { bytes }.g2()
}

fn in_group<C: SWCurveConfig>(point: Affine<C>) -> Result<Affine<C>> {
    if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
        Ok(point)
    } else {
        Err(malformed("point not in the BN254 group"))
    }
}

/// Every section of a zkey, by id.
pub(crate) fn sections(bytes: &[u8]) -> Result<BTreeMap<u32, &[u8]>> {
    Ok(binfile::sections(bytes, MAGIC)?
        .into_iter()
        .map(|(kind, range)| (kind, &bytes[range]))
        .collect())
}

struct Header {
    n_vars: usize,
    n_public: usize,
    domain_size: usize,
    alpha_g1: G1Affine,
    beta_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g1: G1Affine,
    delta_g2: G2Affine,
}

fn modulus(r: &mut Reader, expected: Vec<u8>) -> Result<()> {
    let size = r.count()?;
    if size != ELEMENT || r.take(size)? != expected.as_slice() {
        return Err(malformed("not over BN254"));
    }
    Ok(())
}

fn header(section: &[u8]) -> Result<Header> {
    let mut r = Reader { bytes: section };
    modulus(&mut r, Fq::MODULUS.to_bytes_le())?;
    modulus(&mut r, Fr::MODULUS.to_bytes_le())?;
    let (n_vars, n_public, domain_size) = (r.count()?, r.count()?, r.count()?);
    if n_public >= n_vars || !domain_size.is_power_of_two() {
        return Err(malformed("inconsistent header"));
    }
    Ok(Header {
        n_vars,
        n_public,
        domain_size,
        alpha_g1: r.g1()?,
        beta_g1: r.g1()?,
        beta_g2: r.g2()?,
        gamma_g2: r.g2()?,
        delta_g1: r.g1()?,
        delta_g2: r.g2()?,
    })
}

/// Read `count` points of `width` bytes from section `kind`, requiring the exact size.
fn points<T>(
    sections: &BTreeMap<u32, &[u8]>,
    kind: u32,
    count: usize,
    width: usize,
    read: fn(&mut Reader) -> Result<T>,
) -> Result<Vec<T>> {
    let section = sections
        .get(&kind)
        .ok_or_else(|| malformed(&format!("missing section {kind}")))?;
    if section.len() != count * width {
        return Err(malformed(&format!("section {kind} has the wrong size")));
    }
    let mut r = Reader { bytes: section };
    (0..count).map(|_| read(&mut r)).collect()
}

pub fn parse(bytes: &[u8]) -> Result<Zkey> {
    let sections = sections(bytes)?;
    let section = |kind: u32| {
        sections
            .get(&kind)
            .copied()
            .ok_or_else(|| malformed(&format!("missing section {kind}")))
    };
    if (Reader {
        bytes: section(PROTOCOL)?,
    })
    .u32()?
        != PROTOCOL_GROTH16
    {
        return Err(malformed("not a Groth16 key"));
    }
    let h = header(section(HEADER)?)?;
    let private = h.n_vars - h.n_public - 1;
    let ic = points(&sections, IC, h.n_public + 1, G1_BYTES, |r| r.g1())?;
    let proving_key = ProvingKey {
        vk: VerifyingKeyPoints {
            alpha_g1: h.alpha_g1,
            beta_g2: h.beta_g2,
            gamma_g2: h.gamma_g2,
            delta_g2: h.delta_g2,
            ic,
        },
        beta_g1: h.beta_g1,
        delta_g1: h.delta_g1,
        a_query: points(&sections, A_QUERY, h.n_vars, G1_BYTES, |r| r.g1())?,
        b_g1_query: points(&sections, B1_QUERY, h.n_vars, G1_BYTES, |r| r.g1())?,
        b_g2_query: points(&sections, B2_QUERY, h.n_vars, G2_BYTES, |r| r.g2())?,
        l_query: points(&sections, L_QUERY, private, G1_BYTES, |r| r.g1())?,
        h_query: points(&sections, H_QUERY, h.domain_size, G1_BYTES, |r| r.g1())?,
    };
    Ok(Zkey {
        n_vars: h.n_vars,
        n_public: h.n_public,
        domain_size: h.domain_size,
        proving_key,
    })
}
