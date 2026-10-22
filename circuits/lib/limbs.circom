pragma circom 2.2.0;
include "bits.circom";

// Unsigned integers are L little-endian 16-bit limbs (L = 2, 4, 8 for 32, 64, 128 bits). Sixteen
// bits per limb keeps every intermediate below the 31-bit KoalaBear prime, so no arithmetic wraps.

// Constrains every limb to [0, 2^16): the representation is canonical and the value never exceeds
// 16 * L bits.
template RangeCheckLimbs(L) {
    signal input limb[L];
    component bits[L];
    for (var i = 0; i < L; i++) {
        bits[i] = Num2Bits(16);
        bits[i].in <== limb[i];
    }
}

// out = 1 iff a < b, for canonical limbs. Subtracts limb by limb with a borrow: each step forms
// a - b - borrow + 2^16, which lies in [1, 2^17), and its bit 16 says whether a borrow was NOT
// needed.
template BorrowChain(L) {
    signal input a[L];
    signal input b[L];
    signal output out;
    signal borrow[L + 1];
    component bits[L];
    borrow[0] <== 0;
    for (var i = 0; i < L; i++) {
        bits[i] = Num2Bits(17);
        bits[i].in <== a[i] - b[i] - borrow[i] + 65536;
        borrow[i + 1] <== 1 - bits[i].out[16];
    }
    out <== borrow[L];
}

// Three-way comparison of canonical limb vectors; exactly one of lt, eq, gt is 1.
template Compare(L) {
    signal input a[L];
    signal input b[L];
    signal output lt;
    signal output eq;
    signal output gt;
    component below = BorrowChain(L);
    component above = BorrowChain(L);
    below.a <== a;
    below.b <== b;
    above.a <== b;
    above.b <== a;
    lt <== below.out;
    gt <== above.out;
    eq <== 1 - lt - gt;
}
