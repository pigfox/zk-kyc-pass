# Slither exclusions

Slither runs in CI with `fail_on: low` — any finding at low severity or above
fails the build. The detectors below are excluded in `slither.config.json`, each
for a documented reason. Nothing else is suppressed: a new finding in our own
code is a red build.

## Excluded detectors

### `timestamp` — block-timestamp comparisons (medium)

Two comparisons in `ZKComplianceRegistry` read `block.timestamp`:

- `redeemProof`: `if (expiry <= block.timestamp) revert CredentialExpired(expiry);`
- `isVerified`: `return verifiedUntil[account] > block.timestamp;`

This is the **core design**, not an oversight. A KYC credential has an expiry,
and verification lapses when it passes — the contract's whole freshness guarantee
is a timestamp comparison. The block-timestamp detector warns that a miner can
nudge `block.timestamp` by a few seconds; credential expiries are measured in
days to months, so a ~15-second skew is immaterial and cannot be used to gain or
deny verification in any meaningful window. Excluding the detector is correct
here; the semantics are specified in the brief and documented in SECURITY.md
("Expiry semantics").

### `naming-convention` (informational)

The contracts follow the RWA-house convention (`decimals`, `identityRegistry`,
`verifier` in lower/mixedCase for public constants and immutables) to stay
byte-consistent with the rwa-tokenization-demo they compose with. Renaming to
`SCREAMING_SNAKE_CASE` would diverge from the sibling repo for no security gain.

### `too-many-digits` (informational)

Large literal field elements and wei amounts appear in tests and are inherent to
the domain.

### `solc-version` (informational)

The pragma is pinned to exactly `0.8.28` across the whole tree; the detector's
generic "use a recent, fixed version" advice is already satisfied.

### `assembly`, `incorrect-return-in-assembly` (informational/low)

Only `src/Verifier.sol` uses inline assembly. It is generated verbatim by
`snarkjs zkey export solidityverifier` and is never hand-edited (see
`scripts/build-circuit.sh`). Its assembly is the standard BN254 pairing check.

### `missing-inheritance` (informational)

Slither occasionally suggests a contract "should inherit" an interface it merely
resembles; not applicable to our explicit interface implementations.

### `low-level-calls` (informational)

Only the test `Actor` forwarder uses a low-level `call`, by design — it needs to
forward arbitrary calldata and surface reverts as a boolean rather than bubbling
them. Test-only; `filter_paths` already drops `test/`, this is belt-and-suspenders.
