pragma circom 2.2.0;
include "poseidon.circom";
include "../limbs.circom";

// BN254 commitment shape for lib/opens.circom: one-element digests and blindings. A blinding is a
// uniformly random scalar (~254 bits), so the commitment hides the value.
function digest_len() { return 1; }
function blinding_len() { return 1; }

// Domain tag, the first hash input, so a commitment digest is never valid for another purpose.
function commit_domain() { return 1514344449; }

// Value commitment: Poseidon5(commit_domain(), signed, L, value, blinding) with
// value = sum(limb[i] * 2^(16 i)). The limbs are range-checked, so value < 2^(16 L) <= 2^128 is
// below the field modulus and the packing is injective. The host implementation is
// `zk_groth16::commit` and is tested against this circuit.
template Commit(L) {
    signal input signed;
    signal input limb[L];
    signal input blinding[1];
    signal output digest[1];

    component range = RangeCheckLimbs(L);
    range.limb <== limb;

    var value = 0;
    for (var i = 0; i < L; i++) { value += limb[i] * (1 << (16 * i)); }

    component hash = Poseidon5();
    hash.in[0] <== commit_domain();
    hash.in[1] <== signed;
    hash.in[2] <== L;
    hash.in[3] <== value;
    hash.in[4] <== blinding[0];
    digest[0] <== hash.out;
}
