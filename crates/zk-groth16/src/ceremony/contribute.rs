//! One phase-2 contribution, in snarkjs's format so `snarkjs zkey verify` accepts it.
//!
//! The contributor's secret `x` multiplies delta (G1 and G2) and divides every L and H point. The
//! public record proves knowledge of `x` without revealing it: a random `g1_s`, `g1_sx = x·g1_s`,
//! and `g2_spx = x·g2_sp` where `g2_sp` is hashed from the transcript of everything before it.
//! Groth16 stays sound if any one contributor (and one phase-1 participant) discarded their secret.

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use zeroize::Zeroize;

use super::mpc::{check_name, Beacon, Mpc, Record};
use super::rng::{beacon as beacon_rng, hash_to_g2};
use crate::points::{encode_g1, encode_g2, G1_BYTES, G2_BYTES};
use crate::random::random_scalar;
use crate::zkey::{self, CONTRIBUTIONS, DELTA_OFFSET, HEADER, H_QUERY, L_QUERY};
use crate::{binfile, par, Groth16Error, Result};

/// `points * scalar`, re-encoded back to back.
fn scaled(points: &[G1Affine], scalar: Fr) -> Vec<u8> {
    let products = par::map(points.len(), |i| points[i] * scalar);
    G1Projective::normalize_batch(&products)
        .iter()
        .flat_map(encode_g1)
        .collect()
}

/// `zkey` with one more contribution of secret `x`, whose public key starts from `g1_s`.
fn apply(
    zkey: &[u8],
    x: Fr,
    g1_s: G1Affine,
    name: Option<&str>,
    beacon: Option<Beacon>,
) -> Result<Vec<u8>> {
    if let Some(name) = name {
        check_name(name)?;
    }
    let key = zkey::parse(zkey)?.proving_key;
    let sections = zkey::sections(zkey)?;
    let mut mpc = Mpc::parse(sections.get(&CONTRIBUTIONS).copied().unwrap_or_default())?;
    let g1_sx = (g1_s * x).into_affine();
    let transcript = mpc.next_transcript(&g1_s, &g1_sx);
    let delta_g1 = (key.delta_g1 * x).into_affine();
    mpc.records.push(Record {
        delta_after: delta_g1,
        g1_s,
        g1_sx,
        g2_spx: (hash_to_g2(&transcript) * x).into_affine(),
        transcript,
        name: name.map(str::to_owned),
        beacon,
    });
    let mut header = sections[&HEADER].to_vec();
    header[DELTA_OFFSET..DELTA_OFFSET + G1_BYTES].copy_from_slice(&encode_g1(&delta_g1));
    header[DELTA_OFFSET + G1_BYTES..DELTA_OFFSET + G1_BYTES + G2_BYTES]
        .copy_from_slice(&encode_g2(&(key.vk.delta_g2 * x).into_affine()));
    let mut inverse = x
        .inverse()
        .ok_or_else(|| Groth16Error::Randomness("drew zero".into()))?;
    let l = scaled(&key.l_query, inverse);
    let h = scaled(&key.h_query, inverse);
    inverse.zeroize();
    let mpc = mpc.to_bytes();
    let replaced = |id: u32| match id {
        HEADER => header.as_slice(),
        L_QUERY => &l,
        H_QUERY => &h,
        CONTRIBUTIONS => &mpc,
        _ => sections[&id],
    };
    let order: Vec<(u32, &[u8])> = (1..=CONTRIBUTIONS).map(|id| (id, replaced(id))).collect();
    Ok(binfile::write(zkey::MAGIC, &order))
}

/// A contribution from fresh OS entropy. The secret never leaves this function.
pub(crate) fn contribute(zkey: &[u8], name: Option<&str>) -> Result<Vec<u8>> {
    let mut x = random_scalar()?;
    let mut s = random_scalar()?;
    let g1_s = (G1Affine::generator() * s).into_affine();
    let out = apply(zkey, x, g1_s, name, None);
    x.zeroize();
    s.zeroize();
    out
}

/// A contribution expanded from a public beacon (normally the last one): anyone can recompute it.
pub(crate) fn beacon(zkey: &[u8], name: Option<&str>, beacon: &Beacon) -> Result<Vec<u8>> {
    beacon.check()?;
    let mut rng = beacon_rng(&beacon.value, beacon.exponent);
    let x = rng.scalar();
    let g1_s = rng.g1();
    apply(zkey, x, g1_s, name, Some(beacon.clone()))
}
