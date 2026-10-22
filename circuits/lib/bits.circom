pragma circom 2.2.0;

// Constrains `in` to n bits (n <= 30 in the 31-bit KoalaBear field) and returns them little-endian.
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var sum = 0;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        sum += out[i] * (1 << i);
    }
    sum === in;
}
