pragma circom 2.2.0;
include "../lib/opens.circom";

// Built-in predicate circuits, compiled for each field (the commitment comes from the field's
// commit.circom; see lib/opens.circom) and parameterised by the limb count L (2, 4, 8 = 32, 64, 128 bits).
// Every statement is about a value committed with `Commit(L)`. Values are the unsigned limbs of the
// biased representation: a signed integer v of width w is committed and compared as v + 2^(w-1),
// which preserves order. `signed` only records which interpretation the commitment was made under.
//
// The public acceptance triple (accept_lt, accept_eq, accept_gt) selects the comparison:
//     lt = (1,0,0)   le = (1,1,0)   gt = (0,0,1)   ge = (0,1,1)   eq = (0,1,0)   ne = (1,0,1)

// Knowledge of an opening: the prover knows (value, blinding) behind the public commitment.
template OpenCommitment(L) {
    signal input commitment[digest_len()];
    signal input signed;
    signal input limb[L];
    signal input blinding[blinding_len()];
    signed * (signed - 1) === 0;
    component opens = CommitmentOpens(L);
    opens.commitment <== commitment;
    opens.signed <== signed;
    opens.limb <== limb;
    opens.blinding <== blinding;
}

// committed value (op) public bound.
template CompareToBound(L) {
    signal input commitment[digest_len()];
    signal input signed;
    signal input accept_lt;
    signal input accept_eq;
    signal input accept_gt;
    signal input bound[L];
    signal input limb[L];
    signal input blinding[blinding_len()];
    signed * (signed - 1) === 0;
    accept_lt * (accept_lt - 1) === 0;
    accept_eq * (accept_eq - 1) === 0;
    accept_gt * (accept_gt - 1) === 0;
    component opens = CommitmentOpens(L);
    opens.commitment <== commitment;
    opens.signed <== signed;
    opens.limb <== limb;
    opens.blinding <== blinding;
    component boundRange = RangeCheckLimbs(L);
    boundRange.limb <== bound;
    component compare = Compare(L);
    compare.a <== limb;
    compare.b <== bound;
    signal lt_hit;
    signal eq_hit;
    signal gt_hit;
    lt_hit <== accept_lt * compare.lt;
    eq_hit <== accept_eq * compare.eq;
    gt_hit <== accept_gt * compare.gt;
    lt_hit + eq_hit + gt_hit === 1;
}

// lo (<|<=) committed value (<|<=) hi; each end is inclusive when its public flag is 1.
template InRange(L) {
    signal input commitment[digest_len()];
    signal input signed;
    signal input lo_inclusive;
    signal input hi_inclusive;
    signal input lo[L];
    signal input hi[L];
    signal input limb[L];
    signal input blinding[blinding_len()];
    signed * (signed - 1) === 0;
    lo_inclusive * (lo_inclusive - 1) === 0;
    hi_inclusive * (hi_inclusive - 1) === 0;
    component opens = CommitmentOpens(L);
    opens.commitment <== commitment;
    opens.signed <== signed;
    opens.limb <== limb;
    opens.blinding <== blinding;
    component loRange = RangeCheckLimbs(L);
    loRange.limb <== lo;
    component hiRange = RangeCheckLimbs(L);
    hiRange.limb <== hi;
    component aboveLo = Compare(L);
    aboveLo.a <== limb;
    aboveLo.b <== lo;
    component belowHi = Compare(L);
    belowHi.a <== limb;
    belowHi.b <== hi;
    signal lo_equal;
    signal hi_equal;
    lo_equal <== lo_inclusive * aboveLo.eq;
    hi_equal <== hi_inclusive * belowHi.eq;
    aboveLo.gt + lo_equal === 1;
    belowHi.lt + hi_equal === 1;
}

// left (op) right for two commitments opened by the SAME prover. This is not a two-party
// protocol: independent secret holders would need a separate secure-input protocol.
template CompareCommitted(L) {
    signal input left[digest_len()];
    signal input right[digest_len()];
    signal input signed;
    signal input accept_lt;
    signal input accept_eq;
    signal input accept_gt;
    signal input left_limb[L];
    signal input left_blinding[blinding_len()];
    signal input right_limb[L];
    signal input right_blinding[blinding_len()];
    signed * (signed - 1) === 0;
    accept_lt * (accept_lt - 1) === 0;
    accept_eq * (accept_eq - 1) === 0;
    accept_gt * (accept_gt - 1) === 0;
    component openLeft = CommitmentOpens(L);
    openLeft.commitment <== left;
    openLeft.signed <== signed;
    openLeft.limb <== left_limb;
    openLeft.blinding <== left_blinding;
    component openRight = CommitmentOpens(L);
    openRight.commitment <== right;
    openRight.signed <== signed;
    openRight.limb <== right_limb;
    openRight.blinding <== right_blinding;
    component compare = Compare(L);
    compare.a <== left_limb;
    compare.b <== right_limb;
    signal lt_hit;
    signal eq_hit;
    signal gt_hit;
    lt_hit <== accept_lt * compare.lt;
    eq_hit <== accept_eq * compare.eq;
    gt_hit <== accept_gt * compare.gt;
    lt_hit + eq_hit + gt_hit === 1;
}
