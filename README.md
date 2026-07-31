# zk-kyc-pass

[![CI](https://github.com/pigfox/zk-kyc-pass/actions/workflows/ci.yml/badge.svg)](https://github.com/pigfox/zk-kyc-pass/actions/workflows/ci.yml)

**Privacy-preserving KYC for tokenized real-world assets.** Prove you hold a valid
credential from an approved issuer — without revealing which one, who you are, or
anything else — and become eligible to hold and transfer a compliance-gated
security token. Groth16 credential proofs on Base Sepolia.

This is the third of a trilogy that composes into a full private-compliance
tokenization stack:

| # | Project | What it proves |
|---|---------|----------------|
| 1 | [zk-escrow](https://github.com/pigfox/zk-escrow) | Settle an escrow by proving knowledge of a delivery secret, in zero knowledge. |
| 2 | [rwa-tokenization-demo](https://github.com/pigfox/rwa-tokenization-demo) | An ERC-3643-style RWA token whose transfers are gated on a KYC whitelist. |
| 3 | **zk-kyc-pass** (this repo) | Replace the plaintext whitelist with a **zero-knowledge** credential proof — the compliance gate, made private. |

zk-kyc-pass reuses the zk-escrow Groth16 toolchain (circom + snarkjs) and the
rwa-tokenization compliance model (`IIdentityRegistry` + a hand-rolled ERC-20),
and swaps the identity list for a Merkle root of credential commitments. Nothing
identifying is ever written on chain.

## How it works

```
  Issuer                         Holder                        Chain
  ------                         ------                        -----
  vet holder off-chain
  leaf = Poseidon(               holderSecret (kept secret)
      holderSecret,
      expiry, issuerId)
  append leaf to tree
  publish root  ───────────────────────────────────────────►  setRoot(root)
                                 build Groth16 proof:
                                   - leaf ∈ tree (root)
                                   - nullifier=Poseidon(secret,root)
                                   - bound to holderAddr
                                   - expiry public
                                 redeemProof(π, signals) ────►  ZKComplianceRegistry
                                                                  verify π, checks:
                                                                   root == currentRoot
                                                                   holderAddr == msg.sender
                                                                   expiry > now
                                                                   nullifier unspent
                                                                  ⇒ verifiedUntil[holder]=expiry
  ─────────────────────────────────────────────────────────────────────────────
  agent mints ──────────────────────────────────────────────►  KYCToken.mint (recipient verified)
                                 transfer ─────────────────►    KYCToken.transfer (both verified)
```

On-chain state is only: the current Merkle root, the set of spent nullifiers, and
per-address expiries. **There is no identity list to enumerate.**

### The circuit (`circuits/kycpass.circom`)

- **Private inputs:** `holderSecret`, `issuerId`, Merkle `pathElements[16]` + `pathIndices[16]`.
- **Public signals:** `[nullifier, root, holderAddr, expiry]`.
- **Constraints:** (1) depth-16 Poseidon Merkle inclusion of
  `leaf = Poseidon(holderSecret, expiry, issuerId)` under `root`; (2) `nullifier ==
  Poseidon(holderSecret, root)`; (3) `holderAddr` bound into the proof (anti-theft
  address binding); (4) `expiry` surfaced publicly (contract enforces freshness).

### The contracts (`src/`)

- **`Groth16Verifier`** (`Verifier.sol`) — generated verbatim by snarkjs from the
  final zkey. Never hand-edited.
- **`ZKComplianceRegistry`** — `redeemProof`, `isVerified`, `setRoot` (owner),
  `revoke` (agent). Implements `IIdentityRegistry`.
- **`KYCToken`** — a fractional ERC-20 gated on `isVerified` for every mint and
  transfer. Adapted from rwa-tokenization's `RWAToken`; no burn/redemption path.
- **`Roles`** — the shared owner/agent access control.

See [`SECURITY.md`](./SECURITY.md) for the full threat model (address binding,
replay, root rotation vs. revocation, expiry semantics, trusted-setup provenance,
and non-goals).

## Quickstart

```bash
# 1. Dependencies
npm install                      # circom toolchain (circomlib, snarkjs)
forge install                    # forge-std

# 2. Build the circuit + trusted setup (fetches the pinned published ptau)
./scripts/build-circuit.sh
#   → src/Verifier.sol, circuits/build/{kycpass.r1cs,kycpass_final.zkey,
#     verification_key.json,kycpass_js/kycpass.wasm}   (all checked in)

# 3. Contracts
git submodule update --init --recursive   # brings in lib/solidity-pipeline
forge build
forge test                       # 62 tests: units, real-proof integration, invariants
lib/solidity-pipeline/scripts/coverage.sh    # 100% on src/ (Verifier.sol excluded, by name)
node --test test/circuit/        # circuit tests via snarkjs

# 4. Static analysis + property fuzzing (both engines)
slither . --ignore-compile --fail-low \
  --config-file lib/solidity-pipeline/slither.config.json         # 0 findings
echidna . --contract Properties --config echidna.yaml             # 4/4, 100k calls
medusa fuzz --config medusa.json                                  # 4/4, 100k calls
```

## Verification

Verified by the
[**PIGFOX SOLIDITY PIPELINE v1**](https://github.com/pigfox/solidity-pipeline) —
the estate's single definition of green, consumed rather than copied. The
pipeline is vendored at `lib/solidity-pipeline`, so the gates that run in CI are
the same bytes you run locally.

| Gate | Result |
|---|---|
| `forge test` | **62 tests**, 5 suites, 4 invariants, 0 reverts |
| Coverage | **100%** lines / statements / branches / functions on `src/`, one named exclusion |
| Slither | 0 findings at `fail-on: low` |
| Echidna | **4/4** properties over 100,000 calls |
| Medusa | **4/4** properties over 100,000 calls |
| Circuit | circom compile + snarkjs proof/rejection tests |
| `kycctl` | `go vet`, gofmt, 100.0% statement coverage |

Medusa and the CI property-fuzzing job are **new**. This repo carried an
`echidna.yaml` that no CI job ever ran, so the property fuzzing was opt-in on a
laptop; both engines now run on every push, and each asserts the *number* of
properties it registered so a predicate that silently stops being picked up fails
the build rather than reporting a smaller green run.

One harness, `test/Properties.sol`, is driven by all three engines. The four
properties: a nullifier spends exactly once, an unverified address never holds or
moves tokens, supply is conserved, and the harness's own success counters never
outrun the opportunities that produced them.

The single coverage exclusion — `src/Verifier.sol`, generated verbatim by snarkjs
— is excluded **by name** and printed as `SKIP` on every run, never hidden inside
a percentage. See [`docs/slither-exclusions.md`](docs/slither-exclusions.md).

## Issuer / prover CLI (`cmd/kycctl`)

The Go CLI is the issuer + prover side. Its tree management and snarkjs wrapper are
circuit-agnostic (paths/config injected), so the toolchain is reusable for other
circuits — see the `DeliveryConfig` stub pointing at zk-escrow.

```bash
go build ./cmd/kycctl

# issue a credential (prints holderSecret ONCE — save it)
./kycctl issue --addr 0xYourHolder --expiry 4102444800 --issuer 42

# the root to publish via setRoot
./kycctl root

# generate a redemption proof (calldata for redeemProof)
./kycctl prove --addr 0xYourHolder --secret <printed-secret> --expiry 4102444800 --issuer 42

# verify a proof off-chain
./kycctl verify --proof <dir>
```

## Trusted setup

Phase 1 reuses the real Hermez `powersOfTau28_hez_final_14` ceremony (pinned by
sha256). Phase 2 is a **demo-grade** local contribution — fine for Base Sepolia,
not for real value. See [`SECURITY.md`](./SECURITY.md#trusted-setup-provenance).

## Deployment

Live on Base Sepolia (chain id `84532`), deployed **2026-07-31** at block
**44880416**:

| Contract | Address |
|---|---|
| ZKComplianceRegistry | [`0x83D45db94F12bb8ec3744Ce5C4eAbC5Ed06648bE`](https://sepolia.basescan.org/address/0x83D45db94F12bb8ec3744Ce5C4eAbC5Ed06648bE) |
| KYCToken (ACME) | [`0x33785A54bC58A8349E71b1424003fb5AC7c42c7D`](https://sepolia.basescan.org/address/0x33785A54bC58A8349E71b1424003fb5AC7c42c7D) |
| Groth16Verifier | [`0x64c474f7005bD5C52c89c97700D1E495B5288e7c`](https://sepolia.basescan.org/address/0x64c474f7005bD5C52c89c97700D1E495B5288e7c) |

`deployments/base-sepolia.json` records the live addresses, the issuer root, and
the seed-narrative transaction hashes. Deploy + seed are local-only (they read
`.env`, never CI); see `.env.example`. CI builds the circuit, builds/tests the
contracts to 100% coverage, and runs Slither — with no secrets.

### v1 deployment (retired 2026-07-26)

An earlier deployment ran from 2026-07-22 and is **retired**: its contracts are
still on chain and keep their own history, but nothing here reads them and none
of the numbers above belong to them. They are listed because the honest way to
retire a deployment is to say where it went, not to delete it.

| Contract | Retired address |
|---|---|
| ZKComplianceRegistry | [`0xF27e733d05F7BB4105b867C9b4Da201688e64e65`](https://sepolia.basescan.org/address/0xF27e733d05F7BB4105b867C9b4Da201688e64e65) |
| KYCToken (ACME) | [`0x882BA887fDF70e4206600060161eb8B23903668D`](https://sepolia.basescan.org/address/0x882BA887fDF70e4206600060161eb8B23903668D) |
| Groth16Verifier | [`0x754b372030DfbC42058E040db1A46cB27fDA8a22`](https://sepolia.basescan.org/address/0x754b372030DfbC42058E040db1A46cB27fDA8a22) |

Deployed at block 44557573, under a different issuer root. Its Investor A was
[`0x1aA17B67…`](https://sepolia.basescan.org/address/0x1aA17B67bE685BaBbe9DfE7abA44940b247756D6)
and its never-verified Investor B
[`0xaF83046d…`](https://sepolia.basescan.org/address/0xaF83046d1B3FDDCF894E05Bc293E7f9dE26ee3ec).
The rotation that replaced every key and redeployed from scratch is recorded in
`pigfox2-repos/KEYS.md`.

## Layout

```
circuits/        kycpass.circom + build artifacts (committed)
src/             Roles, ZKComplianceRegistry, KYCToken, Verifier (generated), interfaces
test/            forge units + RealProof integration + Properties/Invariants + circuit/ (snarkjs)
cmd/kycctl/      Go issuer/prover CLI          internal/  its circuit-agnostic packages
scripts/         build-circuit.sh, coverage.sh, poseidon.js
docs/            slither-exclusions.md
```

## License

MIT. Circuit artifacts and the generated verifier carry their snarkjs-emitted
GPL-3.0 header where applicable.
