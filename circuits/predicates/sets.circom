pragma circom 2.2.0;
include "../lib/opens.circom";
include "merkle.circom";
include "../lib/compare.circom";

// Set membership and non-membership of a committed value against a published Merkle root.
//
// Membership tree: leaf = Sponge(leaf_domain)[signed, L, limb...] of each member, padded with
// all-zero digests. Gap tree: the members sorted ascending, e_1 < ... < e_n, define the n + 1 open
// intervals (-inf, e_1), (e_1, e_2), ..., (e_n, +inf); the leaf of an interval is
// Sponge(gap_domain)[signed, L, lo_infinite, hi_infinite, lo..., hi...], padded the same way. A
// value is absent exactly when it lies strictly inside one interval of the gap tree. The roots are
// trusted to have been built honestly from a sorted, duplicate-free set (docs/PREDICATES.md).
// Values are the unsigned limbs of the biased representation, as everywhere in the library.

template SetMember(L, D) {
    signal input commitment[digest_len()];
    signal input signed;
    signal input root[digest_len()];
    signal input limb[L];
    signal input blinding[blinding_len()];
    signal input index_bit[D];
    signal input sibling[D * digest_len()];
    signed * (signed - 1) === 0;
    component opens = CommitmentOpens(L);
    opens.commitment <== commitment;
    opens.signed <== signed;
    opens.limb <== limb;
    opens.blinding <== blinding;
    component leaf = Sponge(2 + L, leaf_domain());
    leaf.message[0] <== signed;
    leaf.message[1] <== L;
    for (var i = 0; i < L; i++) { leaf.message[2 + i] <== limb[i]; }
    component path = MerkleRoot(D);
    path.leaf <== leaf.digest;
    path.index_bit <== index_bit;
    path.sibling <== sibling;
    for (var i = 0; i < digest_len(); i++) { path.root[i] === root[i]; }
}

template SetAbsent(L, D) {
    signal input commitment[digest_len()];
    signal input signed;
    signal input root[digest_len()];
    signal input limb[L];
    signal input blinding[blinding_len()];
    signal input lo_infinite;
    signal input hi_infinite;
    signal input lo[L];
    signal input hi[L];
    signal input index_bit[D];
    signal input sibling[D * digest_len()];
    signed * (signed - 1) === 0;
    lo_infinite * (lo_infinite - 1) === 0;
    hi_infinite * (hi_infinite - 1) === 0;
    component opens = CommitmentOpens(L);
    opens.commitment <== commitment;
    opens.signed <== signed;
    opens.limb <== limb;
    opens.blinding <== blinding;
    component loRange = RangeCheckLimbs(L);
    loRange.limb <== lo;
    component hiRange = RangeCheckLimbs(L);
    hiRange.limb <== hi;
    component leaf = Sponge(4 + 2 * L, gap_domain());
    leaf.message[0] <== signed;
    leaf.message[1] <== L;
    leaf.message[2] <== lo_infinite;
    leaf.message[3] <== hi_infinite;
    for (var i = 0; i < L; i++) {
        leaf.message[4 + i] <== lo[i];
        leaf.message[4 + L + i] <== hi[i];
    }
    component path = MerkleRoot(D);
    path.leaf <== leaf.digest;
    path.index_bit <== index_bit;
    path.sibling <== sibling;
    for (var i = 0; i < digest_len(); i++) { path.root[i] === root[i]; }
    // lo < value (or no lower end) and value < hi (or no upper end).
    component aboveLo = Compare(L);
    aboveLo.a <== limb;
    aboveLo.b <== lo;
    component belowHi = Compare(L);
    belowHi.a <== limb;
    belowHi.b <== hi;
    signal lo_both;
    signal hi_both;
    lo_both <== lo_infinite * aboveLo.gt;
    hi_both <== hi_infinite * belowHi.lt;
    lo_infinite + aboveLo.gt - lo_both === 1;
    hi_infinite + belowHi.lt - hi_both === 1;
}
