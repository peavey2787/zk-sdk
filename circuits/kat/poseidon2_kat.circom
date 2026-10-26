pragma circom 2.2.0;
include "../lib/koalabear/poseidon2.circom";

// Known-answer harness: exposes the bare permutation for differential testing against Plonky3.
template Poseidon2Kat() {
    signal input in[16];
    signal output out[16];
    component permutation = Poseidon2Permutation();
    permutation.in <== in;
    out <== permutation.out;
}
component main = Poseidon2Kat();
