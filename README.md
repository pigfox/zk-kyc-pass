# zk-kyc-pass

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
forge build
forge test                       # 60 tests: units, real-proof integration, invariants
./scripts/coverage.sh            # 100% on src/ (Verifier.sol excluded, documented)
node --test test/circuit/        # circuit tests via snarkjs

# 4. Static analysis + property fuzzing
slither . --ignore-compile --config-file slither.config.json      # 0 findings
echidna . --contract Properties --config echidna.yaml             # 100k calls
```

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

`deployments/base-sepolia.json` records the live addresses and the seed-narrative
transaction hashes. Deploy + seed are local-only (they read `.env`, never CI); see
`.env.example`. CI builds the circuit, builds/tests the contracts to 100% coverage,
and runs Slither — with no secrets.

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
