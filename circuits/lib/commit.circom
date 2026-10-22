pragma circom 2.2.0;
include "poseidon2.circom";
include "limbs.circom";

// Value commitment: a Poseidon2 sponge (rate 8, capacity 8) over
//     [signed, L, limb[0..L), blinding[0..8)]
// zero-padded to whole blocks, with capacity initialised to [COMMIT_DOMAIN, message length, 0 ...].
// The digest is the first 8 state elements. The fixed message length per L plus the length in the
// capacity make the encoding injective; the domain tag separates it from any other use of the
// permutation. The host implementation is `zk_sdk::predicate::commit` and is tested against this
// circuit.
function commit_domain() { return 1514344449; }

template Commit(L) {
    signal input signed;
    signal input limb[L];
    signal input blinding[8];
    signal output digest[8];

    var length = 2 + L + 8;
    var blocks = (length + 7) \ 8;

    component range = RangeCheckLimbs(L);
    range.limb <== limb;

    signal message[blocks * 8];
    for (var i = 0; i < blocks * 8; i++) {
        if (i == 0) { message[i] <== signed; }
        else if (i == 1) { message[i] <== L; }
        else if (i < 2 + L) { message[i] <== limb[i - 2]; }
        else if (i < length) { message[i] <== blinding[i - 2 - L]; }
        else { message[i] <== 0; }
    }

    component permutation[blocks];
    signal state[blocks + 1][16];
    for (var i = 0; i < 16; i++) {
        if (i == 8) { state[0][i] <== commit_domain(); }
        else if (i == 9) { state[0][i] <== length; }
        else { state[0][i] <== 0; }
    }
    for (var b = 0; b < blocks; b++) {
        permutation[b] = Poseidon2Permutation();
        for (var i = 0; i < 16; i++) {
            if (i < 8) { permutation[b].in[i] <== state[b][i] + message[b * 8 + i]; }
            else { permutation[b].in[i] <== state[b][i]; }
        }
        state[b + 1] <== permutation[b].out;
    }
    for (var i = 0; i < 8; i++) { digest[i] <== state[blocks][i]; }
}

// Constrains `commitment` to be the commitment to (signed, limb, blinding).
template CommitmentOpens(L) {
    signal input commitment[8];
    signal input signed;
    signal input limb[L];
    signal input blinding[8];
    component commit = Commit(L);
    commit.signed <== signed;
    commit.limb <== limb;
    commit.blinding <== blinding;
    for (var i = 0; i < 8; i++) { commit.digest[i] === commitment[i]; }
}
