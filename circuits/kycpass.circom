pragma circom 2.1.9;

include "poseidon.circom";
include "switcher.circom";

/// MerkleInclusion
///
/// Proves that `leaf` sits at the position described by `pathIndices` under
/// `root`, given the `pathElements` siblings. Each level hashes the (left,
/// right) pair with Poseidon(2); `pathIndices[i]` selects whether the running
/// hash is the left (0) or right (1) input at level i, and is constrained
/// boolean so a prover cannot smuggle a non-bit selector.
template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component hashers[depth];
    component switchers[depth];

    // levelHashes[0] is the leaf; levelHashes[depth] is the computed root.
    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // pathIndices[i] ∈ {0,1}.
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Order the (running hash, sibling) pair by the path bit.
        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== levelHashes[i];
        switchers[i].R <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[depth];
}

/// KYCPass
///
/// Privacy-preserving proof that the holder possesses a valid KYC credential
/// issued by an approved issuer, WITHOUT revealing which issuer, the holder's
/// secret, or the leaf's position in the tree.
///
/// A credential leaf is Poseidon(holderSecret, expiry, issuerId). The issuer
/// publishes a Merkle root over all outstanding leaves. A holder proves:
///   (1) their leaf is included under `root` (Poseidon Merkle, depth 16);
///   (2) the `nullifier` is Poseidon(holderSecret, root) — one-time spend per
///       root, so a redemption cannot be replayed;
///   (3) `holderAddr` is bound into the proof (anti-theft address binding) — the
///       contract feeds msg.sender as this public input, so a stolen proof
///       submitted from any other address fails verification;
///   (4) `expiry` is surfaced as a public signal (the contract enforces
///       freshness against block.timestamp; the circuit binds it into the leaf
///       so it cannot be forged).
///
/// Public signals, in circom's ordering (main-component OUTPUTS first, then the
/// signals listed as public, in declaration order):
///
///   [0] nullifier   — output, Poseidon(holderSecret, root)
///   [1] root        — input,  the issuer's published Merkle root
///   [2] holderAddr  — input,  the address permitted to spend this proof
///   [3] expiry      — input,  the credential's expiry (unix seconds)
///
/// Private witness: holderSecret, issuerId, pathElements[16], pathIndices[16].
template KYCPass(depth) {
    // Private witness.
    signal input holderSecret;
    signal input issuerId;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Public inputs.
    signal input root;
    signal input holderAddr;
    signal input expiry;

    // Public output.
    signal output nullifier;

    // leaf == Poseidon(holderSecret, expiry, issuerId)
    component leafHash = Poseidon(3);
    leafHash.inputs[0] <== holderSecret;
    leafHash.inputs[1] <== expiry;
    leafHash.inputs[2] <== issuerId;

    // Merkle inclusion of the leaf under the published root.
    component inclusion = MerkleInclusion(depth);
    inclusion.leaf <== leafHash.out;
    for (var i = 0; i < depth; i++) {
        inclusion.pathElements[i] <== pathElements[i];
        inclusion.pathIndices[i] <== pathIndices[i];
    }
    inclusion.root === root;

    // nullifier == Poseidon(holderSecret, root). Binding to the root scopes the
    // one-time spend to the current issuer epoch: a rotation mints fresh
    // nullifiers, so a holder still present in the new tree may re-verify, while
    // any spend within an epoch can never replay.
    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== holderSecret;
    nullifierHash.inputs[1] <== root;
    nullifier <== nullifierHash.out;

    // Address binding (anti-theft). holderAddr is a public input, so Groth16
    // already binds it into proof validity; squaring it forces it into the
    // constraint system explicitly (Semaphore's signal-binding idiom) so no
    // optimizer pass can drop the otherwise-unused public signal.
    signal addrSquared;
    addrSquared <== holderAddr * holderAddr;
}

component main {public [root, holderAddr, expiry]} = KYCPass(16);
