# Security model — zk-kyc-pass

This document is for a reviewer. It states what the system defends against, how,
and — just as important — what it deliberately does **not** defend against. The
demo targets Base Sepolia; several properties are demo-grade by design and are
called out as such.

## What the system is

A privacy-preserving KYC gate for a tokenized real-world asset. An approved
issuer publishes a Merkle root over credential leaves. A holder proves, in zero
knowledge, that they hold a leaf under that root — without revealing which leaf,
which issuer, or any identifying data — and becomes verified until their
credential's expiry. The `KYCToken` consults `ZKComplianceRegistry.isVerified`
on every mint and transfer, exactly as it would a plain whitelist.

A credential leaf is `Poseidon(holderSecret, expiry, issuerId)`. The circuit
(`circuits/kycpass.circom`, Groth16, depth-16 Poseidon Merkle) proves:

1. the leaf is included under the published root;
2. `nullifier == Poseidon(holderSecret, root)`;
3. `holderAddr` is bound into the proof;
4. `expiry` is surfaced as a public signal.

Public signals, in order: `[nullifier, root, holderAddr, expiry]`.

## Threats defended

### Proof theft / front-running — address binding

`holderAddr` is a public input to the proof. `redeemProof` requires
`pubSignals[holderAddr] == uint256(uint160(msg.sender))`. Because Groth16 binds
every public input into proof validity, a proof generated for address A cannot be
re-used from address B: an attacker who observes A's proof in the mempool and
front-runs it from their own address is rejected with `AddressMismatch` before the
verifier is even consulted. The proof is worthless to anyone but its bound holder.
Covered end-to-end against a real proof in `test/RealProof.t.sol`
(`test_RealProof_RejectedFromOtherAddress`) and in-circuit in
`test/circuit/kycpass.test.mjs` ("proof bound to address A is rejected … B").

### Replay — nullifiers

`nullifier == Poseidon(holderSecret, root)`. On redemption the contract records
`spentNullifiers[nullifier] = true`, and a second redemption of the same nullifier
reverts with `NullifierAlreadySpent`. `spentNullifiers` is a **global** mapping:
a nullifier integer spends exactly once, ever. Because the nullifier is derived
from the root, a rotation produces a *different* nullifier for the same holder,
which is what makes legitimate cross-epoch re-verification possible (see below)
without ever letting a single epoch's redemption replay. Covered in the invariant
suite (`echidna_nullifier_never_reused`, 100k+ calls) and against a real proof
(`test_RealProof_NullifierCannotReplay`).

### Root rotation semantics

`setRoot(newRoot)` (owner-only) is the revocation lever for the credential *set*:
proofs against the old root stop redeeming (`RootMismatch`). This is the tool for
re-issuing after adding or removing credentials.

**Tradeoff (documented, by design):** rotating the root does **not** retroactively
un-verify addresses that already redeemed under the old root — their
`verifiedUntil` persists until their credential expiry. Root rotation gates
*future* redemptions, not *past* verifications. To pull a specific address's
verification immediately, use `revoke` (see below). This is the deliberate split
between "stop issuing against this set" (rotation) and "kill this holder now"
(revocation).

### Expiry semantics

`expiry` is bound into the leaf (so the issuer, not the holder, controls it) and
surfaced as a public signal. `redeemProof` rejects an already-expired credential
(`CredentialExpired`), and `isVerified(addr)` returns `verifiedUntil[addr] >
block.timestamp` — so verification **lapses automatically** at expiry with no
transaction required. A holder whose credential lapses can no longer send or
receive tokens (both sides of a transfer are checked), though any balance they
already hold is frozen in place, not seized. This automatic lapse is a feature,
not a gap; the Slither `timestamp` detector is excluded for exactly this reason
(`docs/slither-exclusions.md`) — a ~15-second miner skew is immaterial against
expiries measured in days.

### Emergency revocation

`revoke(addr)` (agent-only) sets `verifiedUntil[addr] = 0`, taking effect
immediately. This is the per-address complement to root rotation.

### Compliance gate integrity

`KYCToken` gates every acquisition: `mint` requires the recipient verified;
`transfer`/`transferFrom` require **both** parties verified. There is no burn or
redemption path, so total supply only ever grows via `mint` and is conserved
across transfers. The invariant suite proves an unverified address can never be
minted to, send, or receive (`echidna_unverified_never_holds_or_moves`) and that
supply is conserved (`echidna_supply_conserved`), each over 100k+ Echidna calls
and 256×64 Foundry invariant sequences with zero reverts.

## Trusted setup provenance

Groth16 needs a trusted setup. It has two phases:

- **Phase 1 (powers of tau) — real.** We reuse the Hermez `powersOfTau28_hez_final`
  perpetual ceremony, power 14, whose transcript is the product of many
  independent contributors and is not controlled by any single party. The exact
  file is pinned by sha256 in `scripts/build-circuit.sh`
  (`489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d`, from
  `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau`),
  and the build refuses to proceed on a mismatch.

- **Phase 2 (circuit-specific) — DEMO-GRADE.** The phase-2 contribution is
  generated locally, on one machine, with entropy the build script supplies.
  Whoever ran it therefore knows that contribution's toxic waste and could forge
  proofs for this circuit. **This is acceptable for a Base Sepolia demo and
  unacceptable for real value.** A production deployment needs independent phase-2
  contributors so no single participant sees all the randomness.

All setup artifacts (`.r1cs`, witness `.wasm`, final `.zkey`,
`verification_key.json`, and the generated `src/Verifier.sol`) are checked in, so
anyone can re-verify a proof or re-derive the on-chain verifier.

## Non-goals / explicit assumptions

- **The issuer is trusted.** The system proves a holder is in the issuer's tree;
  it says nothing about whether the issuer vetted them correctly. Garbage in the
  tree is garbage verified. Approving issuers and auditing their KYC process is
  out of scope.
- **One issuer root at a time.** The registry tracks a single `currentRoot`. A
  multi-issuer deployment (a set of approved roots, or a root-of-roots) is a
  natural extension but not built here — the demo's story is a single approved
  issuer whose identity the proof hides among its members.
- **Phase-2 ceremony is mock** (see above).
- **No key rotation for the verifier.** The verifier address is immutable in the
  registry. Upgrading the circuit means deploying a fresh registry.
- **Front-running the *first* redemption is harmless.** Address binding means a
  proof only helps its bound holder, so there is nothing to gain by ordering
  around it.

## Reporting

This is a demonstration project. For issues in the composed production systems,
follow those projects' disclosure channels.
