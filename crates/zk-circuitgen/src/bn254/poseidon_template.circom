// Poseidon hash of {N} inputs: width {T}, state [0, in...], {RF} full and {RP} partial rounds of
// (add round constants, S-box, MDS mix); the digest is state[0]. Differentially tested against
// `light_poseidon::Poseidon::new_circom({N})`.
template Poseidon{N}() {
    signal input in[{N}];
    signal output out;

    var ark[{ARKS}] = poseidon_ark_{T}();
    var mds[{T}][{T}] = poseidon_mds_{T}();
    var state[{T}];
    state[0] = 0;
    for (var i = 0; i < {N}; i++) { state[i + 1] = in[i]; }

    component sbox[{SBOXES}];
    var used = 0;
    for (var r = 0; r < {RF} + {RP}; r++) {
        var full = r < {RF} / 2 || r >= {RF} / 2 + {RP};
        for (var i = 0; i < {T}; i++) {
            state[i] += ark[r * {T} + i];
            if (full == 1 || i == 0) {
                sbox[used] = Pow5();
                sbox[used].in <== state[i];
                state[i] = sbox[used].out;
                used++;
            }
        }
        var mixed[{T}];
        for (var i = 0; i < {T}; i++) {
            mixed[i] = 0;
            for (var j = 0; j < {T}; j++) { mixed[i] += mds[i][j] * state[j]; }
        }
        for (var i = 0; i < {T}; i++) { state[i] = mixed[i]; }
    }
    out <== state[0];
}

