pragma circom 2.2.0;
include "bits.circom";

// Canonical 16-bit limbs of a non-negative integer given as a vector of limb-position sums.
//
// `sum[i]` is the (field) total contributed to limb position i; the caller guarantees every
// sum[i] < 2^29, which together with the carry (< 2^14) stays below 2^30, far under the 31-bit
// KoalaBear prime, so nothing wraps. Each position is split by ONE 30-bit decomposition of
// sum[i] + carry: the low 16 bits are the canonical limb, the high 14 bits the carry. Canonical
// limbs make the representation of an integer unique, so two normalised vectors are equal exactly
// when the integers are. The carry out of the top position must be zero: the caller sizes M so an
// honest total always fits.
template Normalize(M) {
    signal input sum[M];
    signal output limb[M];
    signal carry[M + 1];
    component split[M];
    carry[0] <== 0;
    for (var i = 0; i < M; i++) {
        split[i] = Num2Bits(30);
        split[i].in <== sum[i] + carry[i];
        var low = 0;
        var high = 0;
        for (var b = 0; b < 16; b++) { low += split[i].out[b] * (1 << b); }
        for (var b = 0; b < 14; b++) { high += split[i].out[16 + b] * (1 << b); }
        limb[i] <== low;
        carry[i + 1] <== high;
    }
    carry[M] === 0;
}
