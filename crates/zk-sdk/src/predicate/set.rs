//! Sets of integers committed by Merkle roots, for membership and non-membership claims.
//!
//! A [`SetTree`] is built by whoever publishes the set. It yields one public [`SetCommitment`]
//! holding two roots: a *member tree* with a leaf per member, and a *gap tree* whose leaves are the
//! open intervals between consecutive sorted members (unbounded at both ends). A holder of a
//! committed value asks the tree for a [`SetPath`] and proves, against the published roots, that the
//! value is a member (its leaf is in the member tree) or is absent (it lies strictly inside one
//! interval of the gap tree) without revealing the value or which leaf it is. The hashes are in
//! `hash.rs`; `circuits/predicates/sets.circom` is the circuit.
//!
//! Trust: the roots are only as honest as their publisher. A verifier who does not rebuild the tree
//! from the whole set relies on the publisher having used sorted, duplicate-free values; a
//! dishonestly built gap tree could "prove" absence of a real member.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::commit::DIGEST_ELEMENTS;
use super::hash::{compress, sponge, Digest, FIELD_MODULUS, GAP_DOMAIN, LEAF_DOMAIN};
use super::int::{IntType, Number};
use crate::{Result, ZkError};

/// Tree depths with an approved circuit; a set of `n` members needs `n + 1 <= 2^depth`.
pub const SET_DEPTHS: [usize; 2] = [8, 20];

const ZERO: Digest = [0; DIGEST_ELEMENTS];

fn error(message: impl Into<String>) -> ZkError {
    ZkError::Predicate(message.into())
}

fn limb_words(ty: IntType, encoded: u128) -> Vec<u32> {
    ty.limbs(encoded).iter().map(|l| *l as u32).collect()
}

fn member_leaf(ty: IntType, encoded: u128) -> Digest {
    let limbs = limb_words(ty, encoded);
    let mut message = vec![u32::from(ty.signed), limbs.len() as u32];
    message.extend(limbs);
    sponge(LEAF_DOMAIN, &message)
}

/// One open interval of the gap tree; `None` is unbounded on that side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Gap {
    pub lo: Option<u128>,
    pub hi: Option<u128>,
}

impl Gap {
    pub(super) fn contains(&self, encoded: u128) -> bool {
        self.lo.is_none_or(|lo| lo < encoded) && self.hi.is_none_or(|hi| encoded < hi)
    }

    fn leaf(&self, ty: IntType) -> Digest {
        let lo = limb_words(ty, self.lo.unwrap_or(0));
        let hi = limb_words(ty, self.hi.unwrap_or(0));
        let mut message = vec![
            u32::from(ty.signed),
            lo.len() as u32,
            u32::from(self.lo.is_none()),
            u32::from(self.hi.is_none()),
        ];
        message.extend(lo);
        message.extend(hi);
        sponge(GAP_DOMAIN, &message)
    }
}

/// The public handle of a set: its type, tree depth and the two Merkle roots. Safe to publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SetCommitment {
    ty: IntType,
    depth: usize,
    members: Digest,
    gaps: Digest,
}

impl SetCommitment {
    pub fn ty(&self) -> IntType {
        self.ty
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub(super) fn members(&self) -> &Digest {
        &self.members
    }

    pub(super) fn gaps(&self) -> &Digest {
        &self.gaps
    }

    /// Canonical text form `set:<type>:<depth>:<128 hex digits>` (member root, then gap root).
    pub fn to_text(&self) -> String {
        let hex: String = self
            .members
            .iter()
            .chain(&self.gaps)
            .map(|d| format!("{d:08x}"))
            .collect();
        format!("set:{}:{}:{hex}", self.ty, self.depth)
    }

    pub fn from_text(text: &str) -> Result<Self> {
        let invalid = || ZkError::Format(format!("`{text}` is not a set commitment"));
        let mut parts = text.splitn(4, ':');
        let (Some("set"), Some(ty), Some(depth), Some(hex)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        let ty: IntType = ty.parse().map_err(|_| invalid())?;
        let depth: usize = depth.parse().map_err(|_| invalid())?;
        if !SET_DEPTHS.contains(&depth) || hex.len() != 16 * DIGEST_ELEMENTS {
            return Err(invalid());
        }
        let words = parse_words(hex).ok_or_else(invalid)?;
        let (members, gaps) = words.split_at(DIGEST_ELEMENTS);
        Ok(Self {
            ty,
            depth,
            members: members.try_into().map_err(|_| invalid())?,
            gaps: gaps.try_into().map_err(|_| invalid())?,
        })
    }
}

/// Field elements from 8-digit hex groups; `None` when one is malformed or not canonical.
pub(super) fn parse_words(hex: &str) -> Option<Vec<u32>> {
    if !hex.is_ascii() {
        return None;
    }
    hex.as_bytes()
        .chunks(8)
        .map(|chunk| {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            (word < FIELD_MODULUS).then_some(word)
        })
        .collect()
}

impl fmt::Display for SetCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl Serialize for SetCommitment {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_text())
    }
}

impl<'de> Deserialize<'de> for SetCommitment {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_text(&text).map_err(serde::de::Error::custom)
    }
}

/// The private path from a leaf to a root: which leaf (`index`), the sibling digests bottom-up,
/// and for an absence claim the interval the value lies in. The index identifies the member, so a
/// path is private to the prover; its `Debug` output is redacted and its contents are overwritten
/// when it is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct SetPath {
    pub(super) index: u64,
    pub(super) siblings: Vec<Digest>,
    pub(super) gap: Option<Gap>,
}

impl Drop for SetPath {
    fn drop(&mut self) {
        self.index.zeroize();
        self.siblings.iter_mut().for_each(Zeroize::zeroize);
    }
}

impl fmt::Debug for SetPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SetPath(depth {}, <redacted>)", self.siblings.len())
    }
}

impl SetPath {
    /// A path to a member leaf: its position and the sibling digests bottom-up.
    pub(super) fn member(index: u64, siblings: Vec<Digest>) -> Self {
        Self {
            index,
            siblings,
            gap: None,
        }
    }

    pub(super) fn siblings_len(&self) -> usize {
        self.siblings.len()
    }

    pub(super) fn root(&self, leaf: Digest) -> Digest {
        self.siblings
            .iter()
            .enumerate()
            .fold(leaf, |node, (level, sibling)| {
                if (self.index >> level) & 1 == 1 {
                    compress(sibling, &node)
                } else {
                    compress(&node, sibling)
                }
            })
    }

    /// The private circuit signals this path feeds: the index bits and sibling digests, plus for an
    /// absence claim the interval ends. Fails when an absence claim has no interval or the path is
    /// the wrong depth.
    pub(super) fn circuit_inputs(
        &self,
        ty: IntType,
        absent: bool,
        depth: usize,
    ) -> Result<Vec<(String, u64)>> {
        if self.siblings.len() != depth {
            return Err(error(format!(
                "the path has {} levels but the set has depth {depth}",
                self.siblings.len()
            )));
        }
        let mut inputs: Vec<(String, u64)> = (0..depth)
            .map(|level| (format!("index_bit[{level}]"), (self.index >> level) & 1))
            .collect();
        for (level, sibling) in self.siblings.iter().enumerate() {
            let base = level * DIGEST_ELEMENTS;
            inputs.extend(
                sibling
                    .iter()
                    .enumerate()
                    .map(|(i, word)| (format!("sibling[{}]", base + i), u64::from(*word))),
            );
        }
        if absent {
            let gap = self
                .gap
                .ok_or_else(|| error("an absence claim needs a path from absence_path"))?;
            inputs.push(("lo_infinite".into(), u64::from(gap.lo.is_none())));
            inputs.push(("hi_infinite".into(), u64::from(gap.hi.is_none())));
            for (name, end) in [("lo", gap.lo), ("hi", gap.hi)] {
                let limbs = ty.limbs(end.unwrap_or(0));
                inputs.extend(
                    limbs
                        .iter()
                        .enumerate()
                        .map(|(i, limb)| (format!("{name}[{i}]"), *limb)),
                );
            }
        }
        Ok(inputs)
    }

    /// Text form for storage or transfer to the prover. Treat it as secret.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&PathText::from(self)).expect("paths always serialize")
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let path: PathText =
            serde_json::from_str(text).map_err(|e| ZkError::Format(e.to_string()))?;
        path.into_path()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PathText {
    index: u64,
    siblings: Vec<String>,
    #[serde(default)]
    gap: Option<GapText>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GapText {
    lo: Option<String>,
    hi: Option<String>,
}

impl From<&SetPath> for PathText {
    fn from(path: &SetPath) -> Self {
        let text = |end: Option<u128>| end.map(|e| e.to_string());
        Self {
            index: path.index,
            siblings: path
                .siblings
                .iter()
                .map(|d| d.iter().map(|w| format!("{w:08x}")).collect())
                .collect(),
            gap: path.gap.map(|gap| GapText {
                lo: text(gap.lo),
                hi: text(gap.hi),
            }),
        }
    }
}

impl PathText {
    pub(super) fn into_path(self) -> Result<SetPath> {
        let invalid = || ZkError::Format("malformed set path".into());
        let end = |text: Option<String>| {
            text.map(|t| t.parse::<u128>().map_err(|_| invalid()))
                .transpose()
        };
        let siblings = self
            .siblings
            .iter()
            .map(|hex| {
                if hex.len() != 8 * DIGEST_ELEMENTS {
                    return Err(invalid());
                }
                parse_words(hex)
                    .and_then(|words| words.try_into().ok())
                    .ok_or_else(invalid)
            })
            .collect::<Result<Vec<Digest>>>()?;
        let gap = self
            .gap
            .map(|gap| -> Result<Gap> {
                Ok(Gap {
                    lo: end(gap.lo)?,
                    hi: end(gap.hi)?,
                })
            })
            .transpose()?;
        Ok(SetPath {
            index: self.index,
            siblings,
            gap,
        })
    }
}

/// A set of integers of one type with both Merkle trees materialised (only the populated part of
/// each level is stored; empty subtrees are the precomputed zero hashes).
pub struct SetTree {
    ty: IntType,
    depth: usize,
    values: Vec<u128>,
    members: Vec<Vec<Digest>>,
    gaps: Vec<Vec<Digest>>,
}

pub(super) fn zero_hashes(depth: usize) -> Vec<Digest> {
    let mut zeros = vec![ZERO];
    for level in 0..depth {
        zeros.push(compress(&zeros[level], &zeros[level]));
    }
    zeros
}

pub(super) fn levels(leaves: Vec<Digest>, zeros: &[Digest]) -> Vec<Vec<Digest>> {
    let mut levels = vec![leaves];
    for zero in &zeros[..zeros.len() - 1] {
        let below = levels.last().expect("levels start non-empty");
        let above = below
            .chunks(2)
            .map(|pair| compress(&pair[0], pair.get(1).unwrap_or(zero)))
            .collect();
        levels.push(above);
    }
    levels
}

pub(super) fn top(levels: &[Vec<Digest>], zeros: &[Digest]) -> Digest {
    levels
        .last()
        .and_then(|root| root.first())
        .copied()
        .unwrap_or(zeros[zeros.len() - 1])
}

fn gaps_of(values: &[u128]) -> Vec<Gap> {
    let mut ends: Vec<Option<u128>> = vec![None];
    ends.extend(values.iter().map(|v| Some(*v)));
    ends.push(None);
    ends.windows(2)
        .map(|pair| Gap {
            lo: pair[0],
            hi: pair[1],
        })
        .collect()
}

/// The smallest approved depth whose tree holds `count` leaves with room to spare.
pub(super) fn fit_depth(count: usize) -> Result<usize> {
    SET_DEPTHS
        .into_iter()
        .find(|depth| count < 1usize << depth)
        .ok_or_else(|| {
            error(format!(
                "{count} entries exceed the largest supported tree (2^{} leaves)",
                SET_DEPTHS[SET_DEPTHS.len() - 1]
            ))
        })
}

/// The sibling digests from leaf `index` of `tree` up to the root of a depth-`depth` tree.
pub(super) fn siblings_of(tree: &[Vec<Digest>], depth: usize, index: usize) -> Vec<Digest> {
    let zeros = zero_hashes(depth);
    (0..depth)
        .map(|level| {
            *tree[level]
                .get((index >> level) ^ 1)
                .unwrap_or(&zeros[level])
        })
        .collect()
}

impl SetTree {
    /// Build the trees for `values` (duplicates are ignored). Fails when a value does not fit `ty`
    /// or the set is too large for the largest approved depth.
    pub fn new(ty: IntType, values: impl IntoIterator<Item = Number>) -> Result<Self> {
        let sorted: BTreeSet<u128> = values
            .into_iter()
            .map(|v| ty.encode(v))
            .collect::<Result<_>>()?;
        let values: Vec<u128> = sorted.into_iter().collect();
        let depth = fit_depth(values.len())?;
        let zeros = zero_hashes(depth);
        let members = levels(values.iter().map(|v| member_leaf(ty, *v)).collect(), &zeros);
        let gaps = levels(
            gaps_of(&values).iter().map(|gap| gap.leaf(ty)).collect(),
            &zeros,
        );
        Ok(Self {
            ty,
            depth,
            values,
            members,
            gaps,
        })
    }

    pub fn commitment(&self) -> SetCommitment {
        let zeros = zero_hashes(self.depth);
        SetCommitment {
            ty: self.ty,
            depth: self.depth,
            members: top(&self.members, &zeros),
            gaps: top(&self.gaps, &zeros),
        }
    }

    /// The path proving `value` is in the set; fails when it is not.
    pub fn member_path(&self, value: impl Into<Number>) -> Result<SetPath> {
        let encoded = self.ty.encode(value.into())?;
        let index = self
            .values
            .binary_search(&encoded)
            .map_err(|_| error("the value is not a member of the set"))?;
        Ok(SetPath {
            index: index as u64,
            siblings: siblings_of(&self.members, self.depth, index),
            gap: None,
        })
    }

    /// The path proving `value` is not in the set; fails when it is a member.
    pub fn absence_path(&self, value: impl Into<Number>) -> Result<SetPath> {
        let encoded = self.ty.encode(value.into())?;
        let index = self
            .values
            .binary_search(&encoded)
            .err()
            .ok_or_else(|| error("the value is a member of the set"))?;
        Ok(SetPath {
            index: index as u64,
            siblings: siblings_of(&self.gaps, self.depth, index),
            gap: Some(gaps_of(&self.values)[index]),
        })
    }
}

/// Why `path` does not prove membership (or, with `absent`, absence) of the value with this
/// encoding in `set`; `Ok(None)` when it does. A missing or wrongly sized path is an error.
pub(super) fn refusal(
    set: &SetCommitment,
    absent: bool,
    encoded: u128,
    path: Option<&SetPath>,
) -> Result<Option<String>> {
    let path = path.ok_or_else(|| {
        error("this claim needs a set path (SetTree::member_path / absence_path)")
    })?;
    if path.siblings.len() != set.depth {
        return Err(error(format!(
            "the path has {} levels but the set has depth {}",
            path.siblings.len(),
            set.depth
        )));
    }
    Ok(if absent {
        absence_refusal(set, encoded, path)
    } else if path.root(member_leaf(set.ty, encoded)) == set.members {
        None
    } else {
        Some(
            "the value is not a member of the set (its path does not reach the published root)"
                .into(),
        )
    })
}

fn absence_refusal(set: &SetCommitment, encoded: u128, path: &SetPath) -> Option<String> {
    let Some(gap) = path.gap else {
        return Some("the path names no interval, so it cannot show absence".into());
    };
    if !gap.contains(encoded) {
        return Some("the value is not inside the interval the path names".into());
    }
    (path.root(gap.leaf(set.ty)) != set.gaps)
        .then(|| "the interval is not in the published set".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(values: &[u64]) -> SetTree {
        SetTree::new(IntType::U64, values.iter().map(|v| Number::from(*v))).unwrap()
    }

    fn refused(set: &SetTree, absent: bool, value: u64, path: &SetPath) -> bool {
        refusal(&set.commitment(), absent, u128::from(value), Some(path))
            .unwrap()
            .is_some()
    }

    #[test]
    fn members_and_absentees_get_paths_to_the_published_roots() {
        let set = tree(&[10, 20, 30, 40, 50]);
        for member in [10u64, 30, 50] {
            let path = set.member_path(member).unwrap();
            assert!(!refused(&set, false, member, &path));
            assert!(refused(&set, true, member, &path));
        }
        for stranger in [0u64, 15, 35, 51, u64::MAX] {
            let path = set.absence_path(stranger).unwrap();
            assert!(!refused(&set, true, stranger, &path));
            assert!(refused(&set, false, stranger, &path));
        }
        assert!(set.member_path(11u64).is_err() && set.absence_path(20u64).is_err());
    }

    #[test]
    fn the_empty_set_and_a_singleton_work() {
        let empty = tree(&[]);
        assert!(!refused(
            &empty,
            true,
            7,
            &empty.absence_path(7u64).unwrap()
        ));
        assert!(empty.member_path(7u64).is_err());
        let one = tree(&[7]);
        assert!(!refused(&one, false, 7, &one.member_path(7u64).unwrap()));
        assert_ne!(empty.commitment(), one.commitment());
    }

    #[test]
    fn a_path_for_another_value_or_set_is_refused() {
        let set = tree(&[1, 2, 3]);
        let other = tree(&[1, 2, 4]);
        let path = set.member_path(2u64).unwrap();
        assert!(refused(&set, false, 3, &path));
        assert!(refused(&other, false, 2, &path));
        assert!(refusal(&set.commitment(), false, 2, None).is_err());
    }

    #[test]
    fn depth_grows_with_the_set_and_duplicates_collapse() {
        assert_eq!(tree(&[5, 5, 5]).commitment(), tree(&[5]).commitment());
        let big = SetTree::new(IntType::U32, (0..300u32).map(Number::from)).unwrap();
        assert_eq!(big.commitment().depth(), 20);
        assert_eq!(tree(&[1]).commitment().depth(), 8);
        assert!(SetTree::new(IntType::U32, [Number::from(-1i32)]).is_err());
    }

    #[test]
    fn signedness_and_width_separate_sets() {
        let unsigned = SetTree::new(IntType::U32, [Number::from(1u8)]).unwrap();
        let signed = SetTree::new(IntType::I32, [Number::from(1u8)]).unwrap();
        assert_ne!(unsigned.commitment().members, signed.commitment().members);
    }

    #[test]
    fn text_and_json_forms_round_trip_and_reject_garbage() {
        let set = tree(&[3, 9]);
        let commitment = set.commitment();
        assert_eq!(
            SetCommitment::from_text(&commitment.to_text()).unwrap(),
            commitment
        );
        for bad in ["", "set:u64:8:00", "set:u64:9:aa", "tree:u64:8:aa"] {
            assert!(SetCommitment::from_text(bad).is_err(), "{bad}");
        }
        let mut shifted = commitment.to_text();
        let end = shifted.len();
        shifted.replace_range(end - 8.., "ffffffff");
        assert!(
            SetCommitment::from_text(&shifted).is_err(),
            "non-canonical field element"
        );
        for path in [
            set.member_path(9u64).unwrap(),
            set.absence_path(5u64).unwrap(),
        ] {
            assert_eq!(SetPath::from_json(&path.to_json()).unwrap(), path);
        }
        assert!(SetPath::from_json("{}").is_err());
        assert!(SetPath::from_json(r#"{"index":0,"siblings":["zz"]}"#).is_err());
    }
}
