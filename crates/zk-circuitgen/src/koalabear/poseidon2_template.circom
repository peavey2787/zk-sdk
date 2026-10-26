// x -> x^3, the KoalaBear Poseidon2 S-box (3 is coprime to p - 1).
template Cube() {
    signal input in;
    signal output out;
    signal square;
    square <== in * in;
    out <== square * in;
}

// Width-16 Poseidon2 permutation: initial linear layer, 4 full rounds, 20 partial rounds,
// 4 full rounds. Differentially tested against Plonky3's `default_koalabear_poseidon2_16`.
template Poseidon2Permutation() {
    signal input in[16];
    signal output out[16];

    var external[16][16] = p2_external_matrix();
    var internal[16][16] = p2_internal_matrix();
    var initial[4][16] = p2_rc_initial();
    var terminal[4][16] = p2_rc_final();
    var partial[20] = p2_rc_internal();

    // state[layer][i]: layer 0 is after the initial linear layer, 1..4 after the first full
    // rounds, 5..24 after the partial rounds, 25..28 after the last full rounds.
    signal state[29][16];
    component fullInitial[4][16];
    component partialBox[20];
    component fullFinal[4][16];

    var acc;
    for (var i = 0; i < 16; i++) {
        acc = 0;
        for (var j = 0; j < 16; j++) { acc += external[i][j] * in[j]; }
        state[0][i] <== acc;
    }

    for (var r = 0; r < 4; r++) {
        for (var i = 0; i < 16; i++) {
            fullInitial[r][i] = Cube();
            fullInitial[r][i].in <== state[r][i] + initial[r][i];
        }
        for (var i = 0; i < 16; i++) {
            acc = 0;
            for (var j = 0; j < 16; j++) { acc += external[i][j] * fullInitial[r][j].out; }
            state[r + 1][i] <== acc;
        }
    }

    for (var r = 0; r < 20; r++) {
        partialBox[r] = Cube();
        partialBox[r].in <== state[4 + r][0] + partial[r];
        for (var i = 0; i < 16; i++) {
            acc = 0;
            for (var j = 0; j < 16; j++) {
                if (j == 0) { acc += internal[i][0] * partialBox[r].out; }
                else { acc += internal[i][j] * state[4 + r][j]; }
            }
            state[5 + r][i] <== acc;
        }
    }

    for (var r = 0; r < 4; r++) {
        for (var i = 0; i < 16; i++) {
            fullFinal[r][i] = Cube();
            fullFinal[r][i].in <== state[24 + r][i] + terminal[r][i];
        }
        for (var i = 0; i < 16; i++) {
            acc = 0;
            for (var j = 0; j < 16; j++) { acc += external[i][j] * fullFinal[r][j].out; }
            if (r == 3) { out[i] <== acc; } else { state[25 + r][i] <== acc; }
        }
    }
}
