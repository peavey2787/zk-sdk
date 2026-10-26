pragma circom 2.2.0;
// "commit.circom" is the field's commitment (lib/koalabear or lib/bn254), chosen by the compiler's
// -l search path. It defines Commit(L), digest_len() and blinding_len().
include "commit.circom";

// Constrains `commitment` to be the commitment to (signed, limb, blinding).
template CommitmentOpens(L) {
    signal input commitment[digest_len()];
    signal input signed;
    signal input limb[L];
    signal input blinding[blinding_len()];
    component commit = Commit(L);
    commit.signed <== signed;
    commit.limb <== limb;
    commit.blinding <== blinding;
    for (var i = 0; i < digest_len(); i++) { commit.digest[i] === commitment[i]; }
}
