pragma circom 2.2.0;
include "poseidon.circom";

// BN254 hashing for Merkle sets and credentials, the counterpart of lib/koalabear/merkle.circom and
// sponge.circom: one-element digests (digest_len() in commit.circom), every hash a Poseidon5 call.
// The host implementation is `zk_groth16::sponge` / `zk_groth16::compress`.
function leaf_domain() { return 1514344450; }
function gap_domain() { return 1514344451; }
function credential_domain() { return 1514344452; }
function node_domain() { return 1514344453; }

// Fixed-length sponge over M elements: h = Poseidon5(DOMAIN, M, 0, 0, 0), then
// h = Poseidon5(h, m[4b], .., m[4b + 3]) per block of four (zero-padded). The length is fixed per
// use and bound in the first call, so the encoding is injective.
template Sponge(M, DOMAIN) {
    signal input message[M];
    signal output digest[1];

    var blocks = (M + 3) \ 4;
    component hash[blocks + 1];
    hash[0] = Poseidon5();
    hash[0].in[0] <== DOMAIN;
    hash[0].in[1] <== M;
    for (var i = 2; i < 5; i++) { hash[0].in[i] <== 0; }
    for (var b = 0; b < blocks; b++) {
        hash[b + 1] = Poseidon5();
        hash[b + 1].in[0] <== hash[b].out;
        for (var i = 0; i < 4; i++) {
            if (4 * b + i < M) { hash[b + 1].in[1 + i] <== message[4 * b + i]; }
            else { hash[b + 1].in[1 + i] <== 0; }
        }
    }
    digest[0] <== hash[blocks].out;
}

// Merkle node: Poseidon5(node_domain(), left, right, 0, 0).
template Compress() {
    signal input left[1];
    signal input right[1];
    signal output digest[1];
    component hash = Poseidon5();
    hash.in[0] <== node_domain();
    hash.in[1] <== left[0];
    hash.in[2] <== right[0];
    hash.in[3] <== 0;
    hash.in[4] <== 0;
    digest[0] <== hash.out;
}

// Root of a depth-D binary Merkle tree reached from `leaf`; `index_bit[d]` is 1 when the node at
// level d is a right child and `sibling` holds the D sibling digests bottom-up. Both are private.
template MerkleRoot(D) {
    signal input leaf[1];
    signal input index_bit[D];
    signal input sibling[D];
    signal output root[1];

    signal level[D + 1];
    signal delta[D];
    component node[D];
    level[0] <== leaf[0];
    for (var d = 0; d < D; d++) {
        index_bit[d] * (index_bit[d] - 1) === 0;
        delta[d] <== index_bit[d] * (sibling[d] - level[d]);
        node[d] = Compress();
        node[d].left[0] <== level[d] + delta[d];
        node[d].right[0] <== sibling[d] - delta[d];
        level[d + 1] <== node[d].digest[0];
    }
    root[0] <== level[D];
}
