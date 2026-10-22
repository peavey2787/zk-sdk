pragma circom 2.2.0;

// Demonstration of actual full-ZK proving over a private witness.
// Not a cryptographic commitment, game-state proof, or security-reviewed circuit.
template Arithmetic() {
    signal input x;
    signal input secret;
    signal output y;
    signal t0;
    signal t1;
    signal t2;
    t0 <== x * secret;
    t1 <== t0 + x;
    t2 <== t1 * t1;
    y <== t2 + 3;
}
component main { public [x] } = Arithmetic();
