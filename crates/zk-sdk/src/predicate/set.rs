//! Sets of integers committed by Merkle roots, for membership and non-membership claims.
//!
//! A [`SetTree`] is built by whoever publishes the set. It yields one public [`SetCommitment`]
//! holding two roots: a *member tree* with a leaf per member, and a *gap tree* whose leaves are the
//! open intervals between consecutive sorted members (unbounded at both ends). A holder of a
//! committed value asks the tree for a [`SetPath`] and proves, against the published roots, that the
//! value is a member (its leaf is in the member tree) or is absent (it lies strictly inside one
//! interval of the gap tree) without revealing the value or which leaf it is. A tree is built for
//! one [`Scheme`] and only proves claims about that scheme's commitments. The hashes are in
//! `hash.rs`; `circuits/predicates/sets.circom` is the circuit.
//!
//! Trust: the roots are only as honest as their publisher. A verifier who does not rebuild the tree
//! from the whole set relies on the publisher having used sorted, duplicate-free values; a
//! dishonestly built gap tree could "prove" absence of a real member.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use zk_groth16::Fr;

use super::hash::{Node, GAP_DOMAIN, LEAF_DOMAIN};
use super::int::{IntType, Number};
use super::scheme::Scheme;
use crate::{Result, ZkError};

/// Tree depths with an approved circuit; a set of `n` members needs `n + 1 <= 2^depth`.
pub const SET_DEPTHS: [usize; 2] = [8, 20];

fn error(message: impl Into<String>) -> ZkError {
    ZkError::Predicate(message.into())
}

fn limb_words(ty: IntType, encoded: u128) -> Vec<u32> {
    ty.limbs(encoded).iter().map(|l| *l as u32).collect()
}

fn member_leaf(scheme: Scheme, ty: IntType, encoded: u128) -> Node {
    let limbs = limb_words(ty, encoded);
    let mut message = vec![u32::from(ty.signed), limbs.len() as u32];
    message.extend(limbs);
    Node::leaf(scheme, LEAF_DOMAIN, &message)
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

    fn leaf(&self, scheme: Scheme, ty: IntType) -> Node {
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
        Node::leaf(scheme, GAP_DOMAIN, &message)
    }
}

/// The public handle of a set: its type, tree depth and the two Merkle roots (whose kind is the
/// set's scheme). Safe to publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SetCommitment {
    ty: IntType,
    depth: usize,
    members: Node,
    gaps: Node,
}

impl SetCommitment {
    pub fn ty(&self) -> IntType {
        self.ty
    }

    pub fn scheme(&self) -> Scheme {
        self.members.scheme()
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub(super) fn members(&self) -> &Node {
        &self.members
    }

    pub(super) fn gaps(&self) -> &Node {
        &self.gaps
    }

    /// Canonical text form `[groth16:]set:<type>:<depth>:<128 hex digits>` (member root, then gap
    /// root).
    pub fn to_text(&self) -> String {
        format!(
            "{}set:{}:{}:{}{}",
            self.scheme().text_prefix(),
            self.ty,
            self.depth,
            self.members.to_hex(),
            self.gaps.to_hex()
        )
    }

    pub fn from_text(text: &str) -> Result<Self> {
        let invalid = || ZkError::Format(format!("`{text}` is not a set commitment"));
        let (scheme, rest) = Scheme::split_text(text);
        let mut parts = rest.splitn(4, ':');
        let (Some("set"), Some(ty), Some(depth), Some(hex)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        let ty: IntType = ty.parse().map_err(|_| invalid())?;
        let depth: usize = depth.parse().map_err(|_| invalid())?;
        if !SET_DEPTHS.contains(&depth) || hex.len() != 128 || !hex.is_ascii() {
            return Err(invalid());
        }
        let (members, gaps) = hex.split_at(64);
        Ok(Self {
            ty,
            depth,
            members: Node::from_hex(scheme, members).ok_or_else(invalid)?,
            gaps: Node::from_hex(scheme, gaps).ok_or_else(invalid)?,
        })
    }
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
/// when it is dropped. Every sibling is of the path's scheme.
#[derive(Clone, PartialEq, Eq)]
pub struct SetPath {
    scheme: Scheme,
    pub(super) index: u64,
    pub(super) siblings: Vec<Node>,
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
    /// A path to a member leaf of a `scheme` tree: its position and the sibling digests bottom-up.
    pub(super) fn member(scheme: Scheme, index: u64, siblings: Vec<Node>) -> Self {
        Self {
            scheme,
            index,
            siblings,
            gap: None,
        }
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Fails unless this path belongs to a `scheme` tree of `depth` levels.
    pub(super) fn check_shape(&self, scheme: Scheme, depth: usize) -> Result<()> {
        if self.scheme != scheme {
            return Err(error(format!(
                "the path is for a {} tree, not a {scheme} one",
                self.scheme
            )));
        }
        if self.siblings.len() != depth {
            return Err(error(format!(
                "the path has {} levels but the tree has depth {depth}",
                self.siblings.len()
            )));
        }
        Ok(())
    }

    /// The root `leaf` reaches; `leaf` is of the path's scheme ([`SetPath::check_shape`]).
    pub(super) fn root(&self, leaf: Node) -> Node {
        self.siblings
            .iter()
            .enumerate()
            .fold(leaf, |node, (level, sibling)| {
                if (self.index >> level) & 1 == 1 {
                    sibling.parent(&node)
                } else {
                    node.parent(sibling)
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
    ) -> Result<Vec<(String, Fr)>> {
        if self.siblings.len() != depth {
            return Err(error(format!(
                "the path has {} levels but the set has depth {depth}",
                self.siblings.len()
            )));
        }
        let mut inputs: Vec<(String, Fr)> = (0..depth)
            .map(|level| {
                let bit = (self.index >> level) & 1;
                (format!("index_bit[{level}]"), Fr::from(bit))
            })
            .collect();
        let elements = self.siblings.iter().flat_map(Node::signals);
        inputs.extend(
            elements
                .enumerate()
                .map(|(i, e)| (format!("sibling[{i}]"), e)),
        );
        if absent {
            let gap = self
                .gap
                .ok_or_else(|| error("an absence claim needs a path from absence_path"))?;
            let flag = |infinite: bool| Fr::from(u64::from(infinite));
            inputs.push(("lo_infinite".into(), flag(gap.lo.is_none())));
            inputs.push(("hi_infinite".into(), flag(gap.hi.is_none())));
            for (name, end) in [("lo", gap.lo), ("hi", gap.hi)] {
                let limbs = ty.limbs(end.unwrap_or(0));
                inputs.extend(
                    limbs
                        .iter()
                        .enumerate()
                        .map(|(i, limb)| (format!("{name}[{i}]"), Fr::from(*limb))),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scheme: Option<String>,
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
            scheme: (path.scheme != Scheme::SpartanWhir).then(|| path.scheme.name().to_owned()),
            index: path.index,
            siblings: path.siblings.iter().map(|node| node.to_hex()).collect(),
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
        let scheme = match &self.scheme {
            Some(name) => name.parse()?,
            None => Scheme::SpartanWhir,
        };
        let siblings = self
            .siblings
            .iter()
            .map(|hex| Node::from_hex(scheme, hex).ok_or_else(invalid))
            .collect::<Result<Vec<Node>>>()?;
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
            scheme,
            index: self.index,
            siblings,
            gap,
        })
    }
}

/// A set of integers of one type with both Merkle trees materialised (only the populated part of
/// each level is stored; empty subtrees are the precomputed zero hashes).
pub struct SetTree {
    scheme: Scheme,
    ty: IntType,
    depth: usize,
    values: Vec<u128>,
    members: Vec<Vec<Node>>,
    gaps: Vec<Vec<Node>>,
}

pub(super) fn zero_hashes(scheme: Scheme, depth: usize) -> Vec<Node> {
    let mut zeros = vec![Node::zero(scheme)];
    for level in 0..depth {
        zeros.push(zeros[level].parent(&zeros[level]));
    }
    zeros
}

pub(super) fn levels(leaves: Vec<Node>, zeros: &[Node]) -> Vec<Vec<Node>> {
    let mut levels = vec![leaves];
    for zero in &zeros[..zeros.len() - 1] {
        let below = levels.last().expect("levels start non-empty");
        let above = below
            .chunks(2)
            .map(|pair| pair[0].parent(pair.get(1).unwrap_or(zero)))
            .collect();
        levels.push(above);
    }
    levels
}

pub(super) fn top(levels: &[Vec<Node>], zeros: &[Node]) -> Node {
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
pub(super) fn siblings_of(
    scheme: Scheme,
    tree: &[Vec<Node>],
    depth: usize,
    index: usize,
) -> Vec<Node> {
    let zeros = zero_hashes(scheme, depth);
    (0..depth)
        .map(|level| {
            *tree[level]
                .get((index >> level) ^ 1)
                .unwrap_or(&zeros[level])
        })
        .collect()
}

impl SetTree {
    /// Build the Spartan-WHIR trees for `values` (duplicates are ignored). Fails when a value does
    /// not fit `ty` or the set is too large for the largest approved depth.
    pub fn new(ty: IntType, values: impl IntoIterator<Item = Number>) -> Result<Self> {
        Self::new_in(Scheme::SpartanWhir, ty, values)
    }

    /// Build the trees for `values` in `scheme`, for claims about that scheme's commitments.
    pub fn new_in(
        scheme: Scheme,
        ty: IntType,
        values: impl IntoIterator<Item = Number>,
    ) -> Result<Self> {
        let sorted: BTreeSet<u128> = values
            .into_iter()
            .map(|v| ty.encode(v))
            .collect::<Result<_>>()?;
        let values: Vec<u128> = sorted.into_iter().collect();
        let depth = fit_depth(values.len())?;
        let zeros = zero_hashes(scheme, depth);
        let members = values.iter().map(|v| member_leaf(scheme, ty, *v)).collect();
        let gaps = gaps_of(&values)
            .iter()
            .map(|gap| gap.leaf(scheme, ty))
            .collect();
        Ok(Self {
            scheme,
            ty,
            depth,
            members: levels(members, &zeros),
            gaps: levels(gaps, &zeros),
            values,
        })
    }

    pub fn commitment(&self) -> SetCommitment {
        let zeros = zero_hashes(self.scheme, self.depth);
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
        Ok(SetPath::member(
            self.scheme,
            index as u64,
            siblings_of(self.scheme, &self.members, self.depth, index),
        ))
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
            scheme: self.scheme,
            index: index as u64,
            siblings: siblings_of(self.scheme, &self.gaps, self.depth, index),
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
    path.check_shape(set.scheme(), set.depth)?;
    Ok(if absent {
        absence_refusal(set, encoded, path)
    } else if path.root(member_leaf(set.scheme(), set.ty, encoded)) == set.members {
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
    (path.root(gap.leaf(set.scheme(), set.ty)) != set.gaps)
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
    fn groth16_trees_prove_their_own_values_and_never_mix_with_spartan_paths() {
        let values = || [3u64, 9, 27].map(Number::from);
        let groth16 = SetTree::new_in(Scheme::Groth16, IntType::U64, values()).unwrap();
        let spartan = SetTree::new(IntType::U64, values()).unwrap();
        let commitment = groth16.commitment();
        assert_eq!(commitment.scheme(), Scheme::Groth16);
        assert!(commitment.to_text().starts_with("groth16:set:u64:8:"));
        assert_eq!(
            SetCommitment::from_text(&commitment.to_text()).unwrap(),
            commitment
        );
        for (absent, value, path) in [
            (false, 9, groth16.member_path(9u64).unwrap()),
            (true, 10, groth16.absence_path(10u64).unwrap()),
        ] {
            assert_eq!(SetPath::from_json(&path.to_json()).unwrap(), path);
            assert_eq!(
                refusal(&commitment, absent, value, Some(&path)).unwrap(),
                None
            );
            assert!(refusal(&spartan.commitment(), absent, value, Some(&path)).is_err());
        }
        let spartan_path = spartan.member_path(9u64).unwrap();
        assert!(refusal(&commitment, false, 9, Some(&spartan_path)).is_err());
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
