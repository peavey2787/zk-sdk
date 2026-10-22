pragma circom 2.2.0;
include "lib/compare.circom";

// Proves "private age > public threshold" without revealing the age.
template AgeOver() {
    signal input age;
    signal input threshold;
    signal output over;
    component lt = LessThan(8);
    lt.a <== threshold;
    lt.b <== age;
    over <== lt.out;
}
component main { public [threshold] } = AgeOver();
