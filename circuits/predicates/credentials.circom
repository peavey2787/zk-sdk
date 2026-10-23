pragma circom 2.2.0;
include "../lib/commit.circom";
include "../lib/merkle.circom";
include "../lib/limbs.circom";

// An issuer-backed credential. The issuer publishes the root of a Merkle tree whose leaf for each
// credential is Sponge(credential_domain)[signed, L, attribute limbs, serial limbs, expiry limbs]
// (serial and expiry are unsigned 64-bit, four 16-bit limbs each). The holder proves, without
// revealing which leaf, that the attribute, serial and expiry committed in the three public
// commitments are those of a leaf under the root, and that expiry >= now, where `now` is public and
// chosen by the verifier. The leaf domain differs from every other tree and from commitments, so a
// credential can never be confused with set membership or with knowledge of a committed secret.
// Revocation is a separate claim over the committed serial (absence from the issuer's revocation set),
// bound to this one by sharing the serial commitment.
template Credential(L, D) {
    signal input a_commitment[8];
    signal input s_commitment[8];
    signal input e_commitment[8];
    signal input signed;
    signal input root[8];
    signal input now[4];
    signal input a_limb[L];
    signal input a_blinding[8];
    signal input s_limb[4];
    signal input s_blinding[8];
    signal input e_limb[4];
    signal input e_blinding[8];
    signal input index_bit[D];
    signal input sibling[D * 8];
    signed * (signed - 1) === 0;
    component attribute = CommitmentOpens(L);
    attribute.commitment <== a_commitment;
    attribute.signed <== signed;
    attribute.limb <== a_limb;
    attribute.blinding <== a_blinding;
    component serial = CommitmentOpens(4);
    serial.commitment <== s_commitment;
    serial.signed <== 0;
    serial.limb <== s_limb;
    serial.blinding <== s_blinding;
    component expiry = CommitmentOpens(4);
    expiry.commitment <== e_commitment;
    expiry.signed <== 0;
    expiry.limb <== e_limb;
    expiry.blinding <== e_blinding;
    component leaf = Sponge(2 + L + 8, credential_domain());
    leaf.message[0] <== signed;
    leaf.message[1] <== L;
    for (var i = 0; i < L; i++) { leaf.message[2 + i] <== a_limb[i]; }
    for (var i = 0; i < 4; i++) {
        leaf.message[2 + L + i] <== s_limb[i];
        leaf.message[6 + L + i] <== e_limb[i];
    }
    component path = MerkleRoot(D);
    path.leaf <== leaf.digest;
    path.index_bit <== index_bit;
    path.sibling <== sibling;
    for (var i = 0; i < 8; i++) { path.root[i] === root[i]; }
    component notExpired = Compare(4);
    notExpired.a <== e_limb;
    notExpired.b <== now;
    notExpired.lt === 0;
}
