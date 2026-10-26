pragma circom 2.2.0;
include "../lib/opens.circom";
include "../lib/limbs.circom";

// The committed value lies in at least one of four public closed intervals [lo_i, hi_i]. Slot i is
// used when enabled[i] = 1; a disabled slot never matches, so its bounds are ignored (the host
// zeroes them). Which interval matched stays hidden. Intervals may overlap; an interval with
// lo > hi is empty. With `miss[i] = 1 - enabled[i] * inside[i]` the value is in the union exactly
// when the product of all four misses is zero, which needs only quadratic constraints.
template InAnyRange(L) {
    signal input commitment[8];
    signal input signed;
    signal input enabled[4];
    signal input lo[4 * L];
    signal input hi[4 * L];
    signal input limb[L];
    signal input blinding[8];
    signed * (signed - 1) === 0;
    component opens = CommitmentOpens(L);
    opens.commitment <== commitment;
    opens.signed <== signed;
    opens.limb <== limb;
    opens.blinding <== blinding;
    component lo_ok[4];
    component hi_ok[4];
    component above[4];
    component below[4];
    signal inside[4];
    signal hit[4];
    signal miss[4];
    for (var i = 0; i < 4; i++) {
        enabled[i] * (enabled[i] - 1) === 0;
        lo_ok[i] = RangeCheckLimbs(L);
        hi_ok[i] = RangeCheckLimbs(L);
        above[i] = Compare(L);
        below[i] = Compare(L);
        above[i].a <== limb;
        below[i].a <== limb;
        for (var k = 0; k < L; k++) {
            lo_ok[i].limb[k] <== lo[i * L + k];
            hi_ok[i].limb[k] <== hi[i * L + k];
            above[i].b[k] <== lo[i * L + k];
            below[i].b[k] <== hi[i * L + k];
        }
        inside[i] <== (1 - above[i].lt) * (1 - below[i].gt);
        hit[i] <== enabled[i] * inside[i];
        miss[i] <== 1 - hit[i];
    }
    signal miss_low;
    signal miss_high;
    miss_low <== miss[0] * miss[1];
    miss_high <== miss[2] * miss[3];
    miss_low * miss_high === 0;
}
