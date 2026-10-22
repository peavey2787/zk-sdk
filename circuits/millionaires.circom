pragma circom 2.2.0;
include "lib/compare.circom";

// Yao's millionaires: output 1 iff alice's private wealth > bob's.
// Wealth is limited to 29 bits: the KoalaBear field is 31 bits, and LessThan(n)
// needs 2^(n+1) to stay below the field prime.
template Millionaires() {
    signal input alice;
    signal input bob;
    signal output alice_richer;
    component lt = LessThan(29);
    lt.a <== bob;
    lt.b <== alice;
    alice_richer <== lt.out;
}
component main = Millionaires();
