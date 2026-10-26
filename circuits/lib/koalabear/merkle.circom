pragma circom 2.2.0;
include "sponge.circom";

// Root of a depth-D binary Merkle tree reached from `leaf`. `index_bit[d]` is 1 when the node at
// level d is a right child, and `sibling` holds the D sibling digests bottom-up, 8 elements each.
// Both are private; only the root is public.
template MerkleRoot(D) {
    signal input leaf[8];
    signal input index_bit[D];
    signal input sibling[D * 8];
    signal output root[8];

    signal level[D + 1][8];
    signal delta[D][8];
    signal left[D][8];
    signal right[D][8];
    component node[D];
    for (var i = 0; i < 8; i++) { level[0][i] <== leaf[i]; }
    for (var d = 0; d < D; d++) {
        index_bit[d] * (index_bit[d] - 1) === 0;
        node[d] = Compress();
        for (var i = 0; i < 8; i++) {
            delta[d][i] <== index_bit[d] * (sibling[d * 8 + i] - level[d][i]);
            left[d][i] <== level[d][i] + delta[d][i];
            right[d][i] <== sibling[d * 8 + i] - delta[d][i];
            node[d].left[i] <== left[d][i];
            node[d].right[i] <== right[d][i];
        }
        for (var i = 0; i < 8; i++) { level[d + 1][i] <== node[d].digest[i]; }
    }
    for (var i = 0; i < 8; i++) { root[i] <== level[D][i]; }
}
