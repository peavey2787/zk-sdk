pragma circom 2.2.0;
include "poseidon2.circom";

// Domain tags for every Poseidon2 use in the predicate library. They are field elements placed in
// the sponge capacity, so a digest made for one purpose can never be replayed as another.
function commit_domain() { return 1514344449; }
function leaf_domain() { return 1514344450; }
function gap_domain() { return 1514344451; }

// Poseidon2 sponge (rate 8, capacity 8) over a message of M field elements, zero-padded to whole
// blocks, with capacity initialised to [DOMAIN, M, 0 ...]. The digest is the first 8 state
// elements. The fixed message length per use plus the length in the capacity make the encoding
// injective. The host implementation is `zk_sdk::predicate::hash::sponge`.
template Sponge(M, DOMAIN) {
    signal input message[M];
    signal output digest[8];

    var blocks = (M + 7) \ 8;
    signal padded[blocks * 8];
    for (var i = 0; i < blocks * 8; i++) {
        if (i < M) { padded[i] <== message[i]; }
        else { padded[i] <== 0; }
    }

    component permutation[blocks];
    signal state[blocks + 1][16];
    for (var i = 0; i < 16; i++) {
        if (i == 8) { state[0][i] <== DOMAIN; }
        else if (i == 9) { state[0][i] <== M; }
        else { state[0][i] <== 0; }
    }
    for (var b = 0; b < blocks; b++) {
        permutation[b] = Poseidon2Permutation();
        for (var i = 0; i < 16; i++) {
            if (i < 8) { permutation[b].in[i] <== state[b][i] + padded[b * 8 + i]; }
            else { permutation[b].in[i] <== state[b][i]; }
        }
        state[b + 1] <== permutation[b].out;
    }
    for (var i = 0; i < 8; i++) { digest[i] <== state[blocks][i]; }
}

// Two-to-one compression of Merkle nodes: permute (left, right) and add `left` back so the map is
// not invertible. The host implementation is `zk_sdk::predicate::hash::compress`.
template Compress() {
    signal input left[8];
    signal input right[8];
    signal output digest[8];
    component permutation = Poseidon2Permutation();
    for (var i = 0; i < 8; i++) {
        permutation.in[i] <== left[i];
        permutation.in[8 + i] <== right[i];
    }
    for (var i = 0; i < 8; i++) { digest[i] <== permutation.out[i] + left[i]; }
}
