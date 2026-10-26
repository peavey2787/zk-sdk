pragma circom 2.2.0;
include "sponge.circom";
include "../limbs.circom";

// Commitment shape shared with lib/opens.circom: 8-element digests and blindings.
function digest_len() { return 8; }
function blinding_len() { return 8; }

// Value commitment: the Sponge (see sponge.circom) under commit_domain() over
//     [signed, L, limb[0..L), blinding[0..8)]
// The digest is the first 8 state elements. The host implementation is
// `zk_sdk::predicate::commit` and is tested against this circuit.
template Commit(L) {
    signal input signed;
    signal input limb[L];
    signal input blinding[8];
    signal output digest[8];

    component range = RangeCheckLimbs(L);
    range.limb <== limb;

    component sponge = Sponge(2 + L + 8, commit_domain());
    sponge.message[0] <== signed;
    sponge.message[1] <== L;
    for (var i = 0; i < L; i++) { sponge.message[2 + i] <== limb[i]; }
    for (var i = 0; i < 8; i++) { sponge.message[2 + L + i] <== blinding[i]; }
    for (var i = 0; i < 8; i++) { digest[i] <== sponge.digest[i]; }
}
