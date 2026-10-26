pragma circom 2.2.0;
include "../lib/opens.circom";
include "../lib/normalize.circom";
include "../lib/limbs.circom";
include "../lib/operand.circom";

// |a - b| for canonical L-limb integers, exact (never wraps).
//
// a - b + 2^(16L) and b - a + 2^(16L) are normalised over L + 1 limbs; the top limb of the first is
// 1 exactly when a >= b. The low limbs of that sum are then a - b, and otherwise those of the other
// sum are b - a. Offset-binary operands may be passed directly: the offset cancels in a difference.
template AbsDiff(L) {
    signal input a[L];
    signal input b[L];
    signal output d[L];
    component forward = Normalize(L + 1);
    component backward = Normalize(L + 1);
    for (var k = 0; k < L; k++) {
        forward.sum[k] <== a[k] + 65535 - b[k] + (k == 0 ? 1 : 0);
        backward.sum[k] <== b[k] + 65535 - a[k] + (k == 0 ? 1 : 0);
    }
    forward.sum[L] <== 0;
    backward.sum[L] <== 0;
    signal a_at_least_b;
    a_at_least_b <== forward.limb[L];
    signal pick[L];
    for (var k = 0; k < L; k++) {
        pick[k] <== a_at_least_b * (forward.limb[k] - backward.limb[k]);
        d[k] <== backward.limb[k] + pick[k];
    }
}

// Squared Euclidean distance between a committed point (x, y) and a public centre, compared with
// the public radius squared: dist^2 (op) radius^2, with every quantity an exact integer.
//
// dx = |x - center_x| and dy = |y - center_y| are exact L-limb values; dx^2 + dy^2 is formed from
// 8-bit digit products (as in `MulAdd`), normalised over 2L + 1 limbs and compared with
// `radius_sq` (2L limbs, computed by the verifier from the claim). (lt, eq, gt) select the
// comparison like `CompareToBound`.
template Distance(L) {
    signal input x_commitment[8];
    signal input y_commitment[8];
    signal input signed;
    signal input center_x[L];
    signal input center_y[L];
    signal input accept_lt;
    signal input accept_eq;
    signal input accept_gt;
    signal input radius_sq[2 * L];
    signal input x_limb[L];
    signal input x_blinding[8];
    signal input y_limb[L];
    signal input y_blinding[8];
    signed * (signed - 1) === 0;
    accept_lt * (accept_lt - 1) === 0;
    accept_eq * (accept_eq - 1) === 0;
    accept_gt * (accept_gt - 1) === 0;

    component centre_x_ok = RangeCheckLimbs(L);
    centre_x_ok.limb <== center_x;
    component centre_y_ok = RangeCheckLimbs(L);
    centre_y_ok.limb <== center_y;
    component radius_ok = RangeCheckLimbs(2 * L);
    radius_ok.limb <== radius_sq;

    component x = CommitmentOpens(L);
    x.commitment <== x_commitment; x.signed <== signed; x.limb <== x_limb; x.blinding <== x_blinding;
    component y = CommitmentOpens(L);
    y.commitment <== y_commitment; y.signed <== signed; y.limb <== y_limb; y.blinding <== y_blinding;

    component dx = AbsDiff(L);
    dx.a <== x_limb; dx.b <== center_x;
    component dy = AbsDiff(L);
    dy.a <== y_limb; dy.b <== center_y;
    component dxp = LimbParts(L);
    dxp.value <== dx.d;
    component dyp = LimbParts(L);
    dyp.value <== dy.d;

    // Each position sums at most 4L digit products below 2^16 (two squares), and the two weighted
    // digit rows combine to under 2^29, so `Normalize` never wraps.
    signal xx[2 * L][2 * L];
    signal yy[2 * L][2 * L];
    var convolution[4 * L];
    for (var k = 0; k < 4 * L; k++) { convolution[k] = 0; }
    for (var i = 0; i < 2 * L; i++) {
        for (var j = 0; j < 2 * L; j++) {
            xx[i][j] <== dxp.digit[i] * dxp.digit[j];
            yy[i][j] <== dyp.digit[i] * dyp.digit[j];
            convolution[i + j] += xx[i][j] + yy[i][j];
        }
    }
    component distance = Normalize(2 * L + 1);
    for (var m = 0; m < 2 * L; m++) {
        distance.sum[m] <== convolution[2 * m] + 256 * convolution[2 * m + 1];
    }
    distance.sum[2 * L] <== 0;

    signal radius[2 * L + 1];
    for (var m = 0; m < 2 * L; m++) { radius[m] <== radius_sq[m]; }
    radius[2 * L] <== 0;
    component compare = Compare(2 * L + 1);
    compare.a <== distance.limb;
    compare.b <== radius;
    signal lt_hit;
    signal eq_hit;
    signal gt_hit;
    lt_hit <== accept_lt * compare.lt;
    eq_hit <== accept_eq * compare.eq;
    gt_hit <== accept_gt * compare.gt;
    lt_hit + eq_hit + gt_hit === 1;
}
