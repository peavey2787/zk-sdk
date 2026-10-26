//! Checks that a key descends from the circuit's phase-2 starting key through valid contributions,
//! as `snarkjs zkey verify` does:
//!
//! * every section but delta, L, H and the record equals the starting key's, and the record starts
//!   from the same circuit hash;
//! * each contribution's transcript is the hash of everything before it, its public key proves
//!   knowledge of its secret (`e(g1_s, g2_spx) = e(g1_sx, g2_sp)`) and it moved delta by that secret
//!   (`e(delta, g2_spx) = e(delta_after, g2_sp)`); a beacon contribution is recomputed in full;
//! * the final delta is the last contribution's, consistent in G1 and G2;
//! * L and H are the starting key's divided by delta, checked with a random linear combination.
//!
//! A key with no contribution is refused: its delta is public and proofs could be forged.

use ark_bn254::{Bn254 as Curve, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, Zero};

use super::mpc::{Beacon, Mpc, Record};
use super::rng::{beacon as beacon_rng, hash_to_g2};
use crate::points::{g1_unchecked, G1_BYTES, G2_BYTES};
use crate::random::random_scalar;
use crate::zkey::{
    self, A_QUERY, B1_QUERY, B2_QUERY, COEFFICIENTS, CONTRIBUTIONS, DELTA_OFFSET, HEADER, H_QUERY,
    IC, L_QUERY, PROTOCOL,
};
use crate::{Groth16Error, Result};

fn rejected(why: &str) -> Groth16Error {
    Groth16Error::Setup(format!("key rejected: {why}"))
}

/// `e(a, d) = e(b, c)`: `b/a = d/c` in the exponent.
fn same_ratio(a: G1Affine, b: G1Affine, c: G2Affine, d: G2Affine) -> bool {
    Curve::multi_pairing([a, -b], [d, c]).is_zero()
}

/// The parts of the header outside delta.
fn without_delta(header: &[u8]) -> Vec<u8> {
    let mut bytes = header.to_vec();
    if let Some(delta) = bytes.get_mut(DELTA_OFFSET..DELTA_OFFSET + G1_BYTES + G2_BYTES) {
        delta.fill(0);
    }
    bytes
}

fn check_beacon(record: &Record, beacon: &Beacon) -> Result<()> {
    beacon.check()?;
    let mut rng = beacon_rng(&beacon.value, beacon.exponent);
    let x = rng.scalar();
    if rng.g1() != record.g1_s || (record.g1_s * x).into_affine() != record.g1_sx {
        return Err(rejected("a beacon contribution does not match its beacon"));
    }
    Ok(())
}

/// One contribution on top of `chain`, which moved delta from `delta`.
fn check_record(chain: &Mpc, record: &Record, delta: G1Affine) -> Result<()> {
    let points_zero = record.g1_s.is_zero() || record.g1_sx.is_zero();
    if points_zero || record.g2_spx.is_zero() || record.delta_after.is_zero() {
        return Err(rejected("a contribution has an identity point"));
    }
    if record.transcript != chain.next_transcript(&record.g1_s, &record.g1_sx) {
        return Err(rejected("a contribution's transcript breaks the chain"));
    }
    let g2_sp = hash_to_g2(&record.transcript);
    if !same_ratio(record.g1_s, record.g1_sx, g2_sp, record.g2_spx) {
        return Err(rejected("a contribution's proof of knowledge is invalid"));
    }
    if !same_ratio(delta, record.delta_after, g2_sp, record.g2_spx) {
        return Err(rejected(
            "a contribution did not apply its own secret to delta",
        ));
    }
    match &record.beacon {
        Some(beacon) => check_beacon(record, beacon),
        None => Ok(()),
    }
}

/// The contributions of `mpc`, re-checked from the starting key's circuit hash. Returns the final
/// delta.
fn check_chain(mpc: &Mpc, cs_hash: &[u8; 64]) -> Result<G1Affine> {
    if mpc.cs_hash != *cs_hash {
        return Err(rejected("it was made for a different circuit or phase 1"));
    }
    if mpc.records.is_empty() {
        return Err(rejected("it has no phase-2 contribution"));
    }
    let mut chain = Mpc {
        cs_hash: *cs_hash,
        records: Vec::new(),
    };
    let mut delta = G1Affine::generator();
    for record in &mpc.records {
        check_record(&chain, record, delta)?;
        delta = record.delta_after;
        chain.records.push(record.clone());
    }
    Ok(delta)
}

/// `sum rho^i p_i` over the L then H points.
fn combination(points: &[G1Affine], rho: Fr) -> G1Affine {
    let powers: Vec<Fr> = std::iter::successors(Some(Fr::one()), |p| Some(*p * rho))
        .take(points.len())
        .collect();
    G1Projective::msm_unchecked(points, &powers).into_affine()
}

fn initial_points(section: &[u8]) -> impl Iterator<Item = G1Affine> + '_ {
    section.chunks_exact(G1_BYTES).map(g1_unchecked)
}

/// Accept `zkey` only if it descends from `initial` (see the module docs); returns its
/// contribution record.
pub(crate) fn verify(initial: &[u8], zkey: &[u8]) -> Result<Mpc> {
    let (start, sections) = (zkey::sections(initial)?, zkey::sections(zkey)?);
    if start.keys().ne(sections.keys()) {
        return Err(rejected("its sections differ from the circuit's"));
    }
    for id in [PROTOCOL, IC, COEFFICIENTS, A_QUERY, B1_QUERY, B2_QUERY] {
        if start[&id] != sections[&id] {
            return Err(rejected(&format!(
                "section {id} differs from the circuit's"
            )));
        }
    }
    if without_delta(start[&HEADER]) != without_delta(sections[&HEADER]) {
        return Err(rejected("its header differs from the circuit's"));
    }
    let key = zkey::parse(zkey)?.proving_key;
    let mpc = Mpc::parse(sections[&CONTRIBUTIONS])?;
    let delta = check_chain(&mpc, &Mpc::parse(start[&CONTRIBUTIONS])?.cs_hash)?;
    let (g1, g2) = (G1Affine::generator(), G2Affine::generator());
    if key.delta_g1 != delta || !same_ratio(g1, key.delta_g1, g2, key.vk.delta_g2) {
        return Err(rejected("its delta is not the last contribution's"));
    }
    let rho = random_scalar()?;
    let new: Vec<G1Affine> = key.l_query.iter().chain(&key.h_query).copied().collect();
    let old: Vec<G1Affine> = initial_points(start[&L_QUERY])
        .chain(initial_points(start[&H_QUERY]))
        .collect();
    if !same_ratio(
        combination(&old, rho),
        combination(&new, rho),
        key.vk.delta_g2,
        g2,
    ) {
        return Err(rejected(
            "its L and H points are not the circuit's divided by delta",
        ));
    }
    Ok(mpc)
}
