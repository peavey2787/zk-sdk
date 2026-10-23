pragma circom 2.2.0;
include "../lib/operand.circom";
include "../lib/normalize.circom";
include "../lib/limbs.circom";

// Exact integer arithmetic over committed or public operands. No arithmetic ever wraps: every
// relation is evaluated on unbounded integers and compared limb by limb.
//
// Values are carried offset-binary: encoded e = v + o with o = signed * 2^(w-1) (w = 16L), so a
// signed type is the same unsigned limbs shifted by a public offset. The offset is removed
// algebraically, never by wrapping.

// sum(+ terms) + plus_constant  (op)  sum(- terms) + minus_constant, over up to N committed values.
//
// Slot i is a '+' term when plus[i] = 1, a '-' term when minus[i] = 1 and unused when both are 0
// (its commitment is then not checked and its private limbs are zero). With true values
// v = e - o the relation is  sum_P e + plus_constant + |M| o  (op)  sum_M e + minus_constant + |P| o,
// so the host folds the public offsets into plus_total and minus_total (L + 1 limbs each) and the
// circuit only sums non-negative integers. (lt, eq, gt) select the comparison like `CompareToBound`.
template WeightedSum(L, N) {
    signal input commitment[N * 8];
    signal input signed;
    signal input plus[N];
    signal input minus[N];
    signal input plus_total[L + 1];
    signal input minus_total[L + 1];
    signal input accept_lt;
    signal input accept_eq;
    signal input accept_gt;
    signal input limb[N][L];
    signal input blinding[N][8];
    signed * (signed - 1) === 0;
    accept_lt * (accept_lt - 1) === 0;
    accept_eq * (accept_eq - 1) === 0;
    accept_gt * (accept_gt - 1) === 0;

    component totals_ok[2];
    totals_ok[0] = RangeCheckLimbs(L + 1);
    totals_ok[0].limb <== plus_total;
    totals_ok[1] = RangeCheckLimbs(L + 1);
    totals_ok[1].limb <== minus_total;

    component opens[N];
    signal pos_term[N][L];
    signal neg_term[N][L];
    var pos_sum[L + 1];
    var neg_sum[L + 1];
    for (var k = 0; k <= L; k++) { pos_sum[k] = plus_total[k]; neg_sum[k] = minus_total[k]; }
    for (var i = 0; i < N; i++) {
        plus[i] * (plus[i] - 1) === 0;
        minus[i] * (minus[i] - 1) === 0;
        plus[i] * minus[i] === 0;
        opens[i] = Commit(L);
        opens[i].signed <== signed;
        opens[i].limb <== limb[i];
        opens[i].blinding <== blinding[i];
        for (var j = 0; j < 8; j++) {
            (plus[i] + minus[i]) * (opens[i].digest[j] - commitment[i * 8 + j]) === 0;
        }
        for (var k = 0; k < L; k++) {
            pos_term[i][k] <== plus[i] * limb[i][k];
            neg_term[i][k] <== minus[i] * limb[i][k];
            pos_sum[k] += pos_term[i][k];
            neg_sum[k] += neg_term[i][k];
        }
    }

    component left = Normalize(L + 1);
    component right = Normalize(L + 1);
    for (var k = 0; k <= L; k++) { left.sum[k] <== pos_sum[k]; right.sum[k] <== neg_sum[k]; }
    component compare = Compare(L + 1);
    compare.a <== left.limb;
    compare.b <== right.limb;
    signal lt_hit;
    signal eq_hit;
    signal gt_hit;
    lt_hit <== accept_lt * compare.lt;
    eq_hit <== accept_eq * compare.eq;
    gt_hit <== accept_gt * compare.gt;
    lt_hit + eq_hit + gt_hit === 1;
}

// x * y + z (op) t over four operands, each committed or public, computed exactly on 2L-limb
// products. Signed values: with e = v + o,
//     v_x v_y + v_z  (op)  v_t   <=>   e_x e_y + e_z + o^2  (op)  e_t + o e_x + o e_y
// (add the same non-negative amount to both sides), and o * e = signed * e * 2^(16(L-1) + 15) is a
// shift, formed from each limb's parity and upper 15 bits.
//
// `divide` = 1 turns the relation into Euclidean division of t by y:  t = x*y + z  with y > 0 and
// 0 <= z < y (quotient x, remainder z), all in true (signed) values; the host sets (op) = equality.
template MulAdd(L) {
    signal input x_commitment[8];
    signal input x_is_public;
    signal input x_public[L];
    signal input y_commitment[8];
    signal input y_is_public;
    signal input y_public[L];
    signal input z_commitment[8];
    signal input z_is_public;
    signal input z_public[L];
    signal input t_commitment[8];
    signal input t_is_public;
    signal input t_public[L];
    signal input signed;
    signal input accept_lt;
    signal input accept_eq;
    signal input accept_gt;
    signal input divide;
    signal input x_limb[L];
    signal input x_blinding[8];
    signal input y_limb[L];
    signal input y_blinding[8];
    signal input z_limb[L];
    signal input z_blinding[8];
    signal input t_limb[L];
    signal input t_blinding[8];
    signed * (signed - 1) === 0;
    divide * (divide - 1) === 0;
    accept_lt * (accept_lt - 1) === 0;
    accept_eq * (accept_eq - 1) === 0;
    accept_gt * (accept_gt - 1) === 0;

    component x = Operand(L);
    x.commitment <== x_commitment; x.is_public <== x_is_public; x.public_limb <== x_public;
    x.signed <== signed; x.limb <== x_limb; x.blinding <== x_blinding;
    component y = Operand(L);
    y.commitment <== y_commitment; y.is_public <== y_is_public; y.public_limb <== y_public;
    y.signed <== signed; y.limb <== y_limb; y.blinding <== y_blinding;
    component z = Operand(L);
    z.commitment <== z_commitment; z.is_public <== z_is_public; z.public_limb <== z_public;
    z.signed <== signed; z.limb <== z_limb; z.blinding <== z_blinding;
    component t = Operand(L);
    t.commitment <== t_commitment; t.is_public <== t_is_public; t.public_limb <== t_public;
    t.signed <== signed; t.limb <== t_limb; t.blinding <== t_blinding;

    component xp = LimbParts(L);
    xp.value <== x.value;
    component yp = LimbParts(L);
    yp.value <== y.value;
    component zp = LimbParts(L);
    zp.value <== z.value;
    component tp = LimbParts(L);
    tp.value <== t.value;

    // Exact product x * y from 8-bit digits: every digit product is < 2^16 and each position sums
    // at most 2L of them, so the convolution never approaches the field prime.
    signal digit_product[2 * L][2 * L];
    var convolution[4 * L];
    for (var k = 0; k < 4 * L; k++) { convolution[k] = 0; }
    for (var i = 0; i < 2 * L; i++) {
        for (var j = 0; j < 2 * L; j++) {
            digit_product[i][j] <== xp.digit[i] * yp.digit[j];
            convolution[i + j] += digit_product[i][j];
        }
    }

    // The offset o = signed * 2^(16L - 1) as limbs (only the top limb is non-zero).
    signal offset[L];
    for (var k = 0; k < L - 1; k++) { offset[k] <== 0; }
    offset[L - 1] <== 32768 * signed;

    // o * x and o * y: limb j of v * 2^15 is parity[j] * 2^15 + half[j - 1]; it lands at j + L - 1.
    signal shifted_x[L + 1];
    signal shifted_y[L + 1];
    for (var j = 0; j <= L; j++) {
        if (j == 0) {
            shifted_x[j] <== signed * (32768 * xp.parity[0]);
            shifted_y[j] <== signed * (32768 * yp.parity[0]);
        } else if (j == L) {
            shifted_x[j] <== signed * xp.half[L - 1];
            shifted_y[j] <== signed * yp.half[L - 1];
        } else {
            shifted_x[j] <== signed * (32768 * xp.parity[j] + xp.half[j - 1]);
            shifted_y[j] <== signed * (32768 * yp.parity[j] + yp.half[j - 1]);
        }
    }

    // Left  = e_x e_y + e_z + o^2        (2L + 1 limbs; o^2 = signed * 2^(32L - 2) is limb 2L-1)
    // Right = e_t + o e_x + o e_y
    var left_sum[2 * L + 1];
    var right_sum[2 * L + 1];
    for (var m = 0; m < 2 * L + 1; m++) { left_sum[m] = 0; right_sum[m] = 0; }
    for (var m = 0; m < 2 * L; m++) {
        left_sum[m] += convolution[2 * m] + 256 * convolution[2 * m + 1];
    }
    for (var k = 0; k < L; k++) {
        left_sum[k] += z.value[k];
        right_sum[k] += t.value[k];
    }
    left_sum[2 * L - 1] += 16384 * signed;
    for (var j = 0; j <= L; j++) {
        right_sum[j + L - 1] += shifted_x[j] + shifted_y[j];
    }

    component left = Normalize(2 * L + 1);
    component right = Normalize(2 * L + 1);
    for (var m = 0; m < 2 * L + 1; m++) { left.sum[m] <== left_sum[m]; right.sum[m] <== right_sum[m]; }
    component compare = Compare(2 * L + 1);
    compare.a <== left.limb;
    compare.b <== right.limb;
    signal lt_hit;
    signal eq_hit;
    signal gt_hit;
    lt_hit <== accept_lt * compare.lt;
    eq_hit <== accept_eq * compare.eq;
    gt_hit <== accept_gt * compare.gt;
    lt_hit + eq_hit + gt_hit === 1;

    // Division rules, enforced only when `divide` = 1: divisor > 0, remainder >= 0, remainder < divisor.
    component divisor_positive = Compare(L);
    divisor_positive.a <== y.value;
    divisor_positive.b <== offset;
    component remainder_floor = Compare(L);
    remainder_floor.a <== z.value;
    remainder_floor.b <== offset;
    component remainder_below = Compare(L);
    remainder_below.a <== z.value;
    remainder_below.b <== y.value;
    divide * (1 - divisor_positive.gt) === 0;
    divide * remainder_floor.lt === 0;
    divide * (1 - remainder_below.lt) === 0;
}
