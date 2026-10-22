pragma circom 2.2.0;

// A constrained 7-bit secret. Pedagogical only: existence of a 7-bit value
// without a binding public commitment is a trivial public statement.
template Range7() {
    signal input bits[7];
    signal input claimed_value;
    signal output valid;
    var sum = 0;
    for (var i = 0; i < 7; i++) {
        bits[i] * (bits[i] - 1) === 0;
        sum += bits[i] * (1 << i);
    }
    claimed_value === sum;
    valid <== 1;
}
component main = Range7();
