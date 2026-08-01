# Slither exclusions

**The exclusion list is no longer kept here.** Since this repo adopted the
[PIGFOX SOLIDITY PIPELINE v1](https://github.com/pigfox/solidity-pipeline) there
is exactly one Slither configuration in the estate, and every detector it
excludes is justified in one place:

→ **[lib/solidity-pipeline/docs/slither-exclusions.md](../lib/solidity-pipeline/docs/slither-exclusions.md)**

The gate is still `fail_on: low`, and a full run over `src/` still reports **zero
findings**. Nothing else is suppressed: a new finding in our own code is a red
build.

## What this repo contributed to the shared list

`timestamp` was already excluded here, and the reasoning moved across with the
specifics intact, because in this repo the detector fires on the product itself:

- `ZKComplianceRegistry.redeemProof`:
  `if (expiry <= block.timestamp) revert CredentialExpired(expiry);`
- `ZKComplianceRegistry.isVerified`:
  `return verifiedUntil[account] > block.timestamp;`

A KYC credential has an expiry and verification lapses when it passes — the whole
freshness guarantee **is** a timestamp comparison. The detector warns that a
validator can nudge `block.timestamp` by a few seconds; credential expiries are
measured in days to months, so that skew cannot gain or deny verification in any
meaningful window. The semantics are specified in the brief and in
[`SECURITY.md`](../SECURITY.md) under "Expiry semantics".

## The coverage exclusion

Separate from Slither, and equally documented: `src/Verifier.sol` is excluded
from the 100% coverage gate **by name**, not hidden inside a percentage. It is
generated verbatim by `snarkjs zkey export solidityverifier` (see
`scripts/build-circuit.sh`) and never hand-edited; its residual uncovered lines
are the inline-assembly early exits taken when the BN254 precompiles themselves
report failure, which cannot be provoked from a test. Inputs that are merely
wrong are rejected by the reachable `checkField` branch, which *is* covered.

The verifier is still exercised end-to-end by real Groth16 proofs in
`test/RealProof.t.sol`, and the pipeline's coverage gate prints the exclusion as
`SKIP` on every run — and fails the build if it ever stops matching a real file.

## The fuzz exclusion

`src/Verifier.sol` is **not driven by Echidna or Medusa**. `test/Properties.sol`
substitutes `test/mocks/MockVerifier.sol`, so the engines can reach the state
behind verification rather than spending an entire campaign on proofs that can
never verify — a valid Groth16 proof is not something a fuzzer can produce.

That substitution was undocumented until PF-S134, which is the same failure as
the one recorded above it: an exclusion nobody argued in writing is
indistinguishable from one nobody noticed. The shared reasoning, and a table of
exactly which tools do and do not reach the file, is in the pipeline's
[`docs/PROPERTIES.md`](https://github.com/pigfox/solidity-pipeline/blob/main/docs/PROPERTIES.md).

What holds it up **in this repo** is `test/RealProof.t.sol`, which drives the
real verifier with a checked-in fixture proof: the accepting case, the
address-binding rejection, the rotated-root rejection, the nullifier replay, an
out-of-range public signal at each of the four `checkField` call sites, an
off-curve point, and a zero proof. Without those the exclusion would be
undefended rather than documented.
