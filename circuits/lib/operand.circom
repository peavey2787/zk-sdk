pragma circom 2.2.0;
include "commit.circom";

// An integer operand that is either PUBLIC (its limbs are a public input) or COMMITTED (its limbs
// are private and bound to a public commitment by opening it). `is_public` selects which. For a
// committed operand the commitment must be the field's commitment (commit.circom) of (signed, limbs, blinding);
// for a public operand the commitment inputs are ignored and the private inputs are all zero.
// `value` is the canonical-limb encoding the rest of the circuit computes with.
template Operand(L) {
    signal input commitment[digest_len()];
    signal input is_public;
    signal input public_limb[L];
    signal input signed;
    signal input limb[L];
    signal input blinding[blinding_len()];
    signal output value[L];
    is_public * (is_public - 1) === 0;
    component opens = Commit(L);
    opens.signed <== signed;
    opens.limb <== limb;
    opens.blinding <== blinding;
    signal committed;
    committed <== 1 - is_public;
    for (var i = 0; i < digest_len(); i++) { committed * (opens.digest[i] - commitment[i]) === 0; }
    signal pick[L];
    for (var k = 0; k < L; k++) {
        pick[k] <== is_public * (public_limb[k] - limb[k]);
        value[k] <== limb[k] + pick[k];
    }
}

// Canonical decomposition of an operand's limbs for exact multiplication and the signed-offset
// correction: 8-bit digits (so a convolution of products stays far below the field prime), and for
// each limb its lowest bit and its upper 15 bits (value = 2 * half + parity).
template LimbParts(L) {
    signal input value[L];
    signal output digit[2 * L];
    signal output parity[L];
    signal output half[L];
    component bits[L];
    for (var k = 0; k < L; k++) {
        bits[k] = Num2Bits(16);
        bits[k].in <== value[k];
        var low = 0;
        var high = 0;
        var upper = 0;
        for (var b = 0; b < 8; b++) {
            low += bits[k].out[b] * (1 << b);
            high += bits[k].out[8 + b] * (1 << b);
        }
        for (var b = 1; b < 16; b++) { upper += bits[k].out[b] * (1 << (b - 1)); }
        digit[2 * k] <== low;
        digit[2 * k + 1] <== high;
        parity[k] <== bits[k].out[0];
        half[k] <== upper;
    }
}
