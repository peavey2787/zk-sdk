pragma circom 2.2.0;

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
