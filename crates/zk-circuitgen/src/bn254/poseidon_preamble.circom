// x -> x^5, the BN254 Poseidon S-box (5 is coprime to r - 1).
template Pow5() {
    signal input in;
    signal output out;
    signal x2;
    signal x4;
    x2 <== in * in;
    x4 <== x2 * x2;
    out <== x4 * in;
}

