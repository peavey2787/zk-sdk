//! A circuit's phase-2 starting key from phase 1, byte for byte what `snarkjs zkey new` writes:
//! delta is the generator (so the key is not yet usable), and section 10 holds the circuit hash and
//! no contributions. Anyone can recompute it from the r1cs and a published phase-1 file, which is
//! how every contribution chain is checked.

use ark_bn254::{Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, One, PrimeField};
use zk_witness::{LinearCombination, R1cs};

use super::mpc::Mpc;
use super::phase1::{
    Phase1, ALPHA_TAU_G1, BETA_G2, BETA_TAU_G1, LAGRANGE_ALPHA_TAU_G1, LAGRANGE_BETA_TAU_G1,
    LAGRANGE_TAU_G1, LAGRANGE_TAU_G2, TAU_G1,
};
use crate::digest::blake2b;
use crate::points::{
    encode_g1, encode_g2, g1_unchecked, g2_unchecked, uncompressed_g1, uncompressed_g2, G1_BYTES,
    G2_BYTES,
};
use crate::zkey::{
    self, A_QUERY, B1_QUERY, B2_QUERY, COEFFICIENTS, CONTRIBUTIONS, HEADER, H_QUERY, IC, L_QUERY,
    PROTOCOL, PROTOCOL_GROTH16,
};
use crate::{binfile, par, Groth16Error, Result};

/// snarkjs hashes the H points in chunks of this many.
const H_CHUNK: usize = 1 << 14;

/// The sizes a key is laid out by.
#[derive(Clone, Copy)]
struct Shape {
    n_vars: usize,
    n_public: usize,
    n_constraints: usize,
    domain: usize,
}

impl Shape {
    fn new(r1cs: &R1cs<Fr>, phase1: &Phase1) -> Result<Self> {
        let n_public = r1cs.n_public();
        let n_constraints = r1cs.constraints.len();
        let power = (n_constraints + n_public).max(1).ilog2() + 1;
        if power > phase1.power() {
            return Err(Groth16Error::Setup(format!(
                "the circuit needs a phase-1 file of power {power} or more, this one has {}",
                phase1.power()
            )));
        }
        Ok(Self {
            n_vars: r1cs.n_wires as usize,
            n_public,
            n_constraints,
            domain: 1 << power,
        })
    }
}

/// Which phase-1 Lagrange basis a term draws on.
#[derive(Clone, Copy)]
enum Basis {
    Tau,
    AlphaTau,
    BetaTau,
}

type Terms = Vec<Vec<(usize, Fr)>>;
type MixedTerms = Vec<Vec<(Basis, usize, Fr)>>;

/// Per wire, the Lagrange terms of each query, in snarkjs's order.
struct Queries {
    a: Terms,
    b: Terms,
    /// IC for public wires (and the constant), L for private ones.
    c: MixedTerms,
    /// Section 4: `(matrix, row, wire, coefficient)`.
    coefficients: Vec<(u32, usize, u32, Fr)>,
}

fn terms(lc: &LinearCombination<Fr>) -> impl Iterator<Item = (usize, Fr)> + '_ {
    lc.iter().map(|t| (t.wire as usize, t.coef))
}

impl Queries {
    fn new(r1cs: &R1cs<Fr>, shape: Shape) -> Self {
        let mut q = Self {
            a: vec![Vec::new(); shape.n_vars],
            b: vec![Vec::new(); shape.n_vars],
            c: vec![Vec::new(); shape.n_vars],
            coefficients: Vec::new(),
        };
        for (row, constraint) in r1cs.constraints.iter().enumerate() {
            for (wire, coef) in terms(&constraint.a) {
                q.a[wire].push((row, coef));
                q.c[wire].push((Basis::BetaTau, row, coef));
                q.coefficients.push((0, row, wire as u32, coef));
            }
            for (wire, coef) in terms(&constraint.b) {
                q.b[wire].push((row, coef));
                q.c[wire].push((Basis::AlphaTau, row, coef));
                q.coefficients.push((1, row, wire as u32, coef));
            }
            for (wire, coef) in terms(&constraint.c) {
                q.c[wire].push((Basis::Tau, row, coef));
            }
        }
        // One extra constraint per public input (and the constant) keeps them linearly independent.
        for wire in 0..=shape.n_public {
            let row = shape.n_constraints + wire;
            q.a[wire].push((row, Fr::one()));
            q.c[wire].push((Basis::BetaTau, row, Fr::one()));
            q.coefficients.push((0, row, wire as u32, Fr::one()));
        }
        q
    }

    fn coefficient_section(&self) -> Vec<u8> {
        let r = Fr::from(2u8).pow([256u64]);
        let r2 = r * r;
        let mut out = (self.coefficients.len() as u32).to_le_bytes().to_vec();
        for (matrix, row, wire, coef) in &self.coefficients {
            out.extend(matrix.to_le_bytes());
            out.extend((*row as u32).to_le_bytes());
            out.extend(wire.to_le_bytes());
            out.extend((*coef * r2).into_bigint().to_bytes_le());
        }
        out
    }
}

/// The decoded Lagrange bases for the circuit's domain.
struct Bases {
    tau_g1: Vec<G1Affine>,
    tau_g2: Vec<G2Affine>,
    alpha_tau_g1: Vec<G1Affine>,
    beta_tau_g1: Vec<G1Affine>,
}

fn decode<T: Send>(bytes: &[u8], width: usize, f: fn(&[u8]) -> T) -> Vec<T> {
    par::map(bytes.len() / width, |i| {
        f(&bytes[i * width..(i + 1) * width])
    })
}

impl Bases {
    fn read(phase1: &Phase1, domain: usize) -> Result<Self> {
        let g1 = |id| -> Result<Vec<G1Affine>> {
            Ok(decode(
                phase1.lagrange(id, G1_BYTES, domain)?,
                G1_BYTES,
                g1_unchecked,
            ))
        };
        Ok(Self {
            tau_g1: g1(LAGRANGE_TAU_G1)?,
            tau_g2: decode(
                phase1.lagrange(LAGRANGE_TAU_G2, G2_BYTES, domain)?,
                G2_BYTES,
                g2_unchecked,
            ),
            alpha_tau_g1: g1(LAGRANGE_ALPHA_TAU_G1)?,
            beta_tau_g1: g1(LAGRANGE_BETA_TAU_G1)?,
        })
    }

    fn g1(&self, basis: Basis) -> &[G1Affine] {
        match basis {
            Basis::Tau => &self.tau_g1,
            Basis::AlphaTau => &self.alpha_tau_g1,
            Basis::BetaTau => &self.beta_tau_g1,
        }
    }
}

/// `sum coef * base` over each wire's terms.
fn compose<P: VariableBaseMSM<ScalarField = Fr>, T: Sync>(
    wires: &[Vec<T>],
    term: impl Fn(&T) -> (P::MulBase, Fr) + Sync + Send,
) -> Vec<P::MulBase> {
    let sums = par::map(wires.len(), |wire| {
        let (bases, scalars): (Vec<P::MulBase>, Vec<Fr>) = wires[wire].iter().map(&term).unzip();
        P::msm_unchecked(&bases, &scalars)
    });
    P::batch_convert_to_mul_base(&sums)
}

/// A key section and the bytes it adds to the circuit hash.
struct Points {
    section: Vec<u8>,
    hashed: Vec<u8>,
}

impl Points {
    fn g1(points: &[G1Affine]) -> Self {
        Self::new(points, encode_g1, uncompressed_g1)
    }

    fn g2(points: &[G2Affine]) -> Self {
        Self::new(points, encode_g2, uncompressed_g2)
    }

    fn new<T>(points: &[T], lem: fn(&T) -> Vec<u8>, u: fn(&T) -> Vec<u8>) -> Self {
        let mut hashed = (points.len() as u32).to_be_bytes().to_vec();
        hashed.extend(points.iter().flat_map(u));
        Self {
            section: points.iter().flat_map(lem).collect(),
            hashed,
        }
    }
}

/// Section 9: the odd points of the Lagrange basis of twice the domain.
fn h_section(phase1: &Phase1, domain: usize) -> Result<Vec<u8>> {
    let doubled = phase1.lagrange(LAGRANGE_TAU_G1, G1_BYTES, 2 * domain)?;
    Ok(doubled
        .chunks_exact(G1_BYTES)
        .skip(1)
        .step_by(2)
        .flatten()
        .copied()
        .collect())
}

/// What snarkjs hashes for H: `tau^(i+n) - tau^i` in G1, including its chunking quirk.
fn h_hashed(phase1: &Phase1, domain: usize) -> Result<Vec<u8>> {
    let count = if domain - 1 <= H_CHUNK {
        domain - 1
    } else {
        (domain - 1).div_ceil(H_CHUNK) * H_CHUNK
    };
    let powers = phase1.section(TAU_G1)?;
    let point = |i: usize| g1_unchecked(&powers[i * G1_BYTES..(i + 1) * G1_BYTES]);
    let differences = par::map(count, |i| point(i + domain).into_group() - point(i));
    let mut out = ((domain - 1) as u32).to_be_bytes().to_vec();
    for p in G1Projective::normalize_batch(&differences) {
        out.extend(uncompressed_g1(&p));
    }
    Ok(out)
}

fn header(shape: Shape, phase1: &Phase1) -> Result<(Vec<u8>, Vec<u8>)> {
    let alpha = &phase1.section(ALPHA_TAU_G1)?[..G1_BYTES];
    let beta = &phase1.section(BETA_TAU_G1)?[..G1_BYTES];
    let beta_g2 = phase1.section(BETA_G2)?;
    let (g1, g2) = (G1Affine::generator(), G2Affine::generator());
    let mut section = Vec::new();
    for modulus in [Fq::MODULUS.to_bytes_le(), Fr::MODULUS.to_bytes_le()] {
        section.extend(32u32.to_le_bytes());
        section.extend(modulus);
    }
    for count in [shape.n_vars, shape.n_public, shape.domain] {
        section.extend((count as u32).to_le_bytes());
    }
    for bytes in [
        alpha,
        beta,
        beta_g2,
        &encode_g2(&g2),
        &encode_g1(&g1),
        &encode_g2(&g2),
    ] {
        section.extend(bytes);
    }
    let hashed = [
        uncompressed_g1(&g1_unchecked(alpha)),
        uncompressed_g1(&g1_unchecked(beta)),
        uncompressed_g2(&g2_unchecked(beta_g2)),
        uncompressed_g2(&g2),
        uncompressed_g1(&g1),
        uncompressed_g2(&g2),
    ]
    .concat();
    Ok((section, hashed))
}

/// The starting key of the circuit `r1cs` (snarkjs `zkey new`).
pub(crate) fn initialize(r1cs: &R1cs<Fr>, phase1: &Phase1) -> Result<Vec<u8>> {
    let shape = Shape::new(r1cs, phase1)?;
    let bases = Bases::read(phase1, shape.domain)?;
    let queries = Queries::new(r1cs, shape);
    let c = compose::<G1Projective, _>(&queries.c, |(basis, row, coef)| {
        (bases.g1(*basis)[*row], *coef)
    });
    let ic = Points::g1(&c[..=shape.n_public]);
    let l = Points::g1(&c[shape.n_public + 1..]);
    let tau_g1 = |(row, coef): &(usize, Fr)| (bases.tau_g1[*row], *coef);
    let a = Points::g1(&compose::<G1Projective, _>(&queries.a, tau_g1));
    let b1 = Points::g1(&compose::<G1Projective, _>(&queries.b, tau_g1));
    let b2 = Points::g2(&compose::<G2Projective, _>(&queries.b, |(row, coef)| {
        (bases.tau_g2[*row], *coef)
    }));
    let (header, header_hashed) = header(shape, phase1)?;
    let h = h_section(phase1, shape.domain)?;
    let cs_hash = blake2b(&[
        &header_hashed,
        &ic.hashed,
        &h_hashed(phase1, shape.domain)?,
        &l.hashed,
        &a.hashed,
        &b1.hashed,
        &b2.hashed,
    ]);
    let mpc = Mpc {
        cs_hash,
        records: Vec::new(),
    }
    .to_bytes();
    let protocol = PROTOCOL_GROTH16.to_le_bytes();
    let coefficients = queries.coefficient_section();
    Ok(binfile::write(
        zkey::MAGIC,
        &[
            (PROTOCOL, &protocol),
            (HEADER, &header),
            (COEFFICIENTS, &coefficients),
            (IC, &ic.section),
            (H_QUERY, &h),
            (L_QUERY, &l.section),
            (A_QUERY, &a.section),
            (B1_QUERY, &b1.section),
            (B2_QUERY, &b2.section),
            (CONTRIBUTIONS, &mpc),
        ],
    ))
}
