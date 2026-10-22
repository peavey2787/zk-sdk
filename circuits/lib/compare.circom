pragma circom 2.2.0;
include "bits.circom";

// out = 1 iff a < b. Both inputs are range-checked to n bits, which makes
// the (n+1)-bit decomposition of a + 2^n - b sound. The KoalaBear prime is
// below 2^31, so n must be at most 29 to avoid wrap-around.
template LessThan(n) {
    signal input a;
    signal input b;
    signal output out;
    component rangeA = Num2Bits(n);
    component rangeB = Num2Bits(n);
    component diff = Num2Bits(n + 1);
    rangeA.in <== a;
    rangeB.in <== b;
    diff.in <== a + (1 << n) - b;
    out <== 1 - diff.out[n];
}
