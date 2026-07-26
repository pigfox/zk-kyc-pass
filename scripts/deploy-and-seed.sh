#!/usr/bin/env bash
#
# Deploy + seed the zk-kyc-pass stack on Base Sepolia, then write
# deployments/base-sepolia.json. Run ONCE — chain state is the ground truth
# forever, and the recorded transaction hashes are what the demo page reads back.
#
# Sources .env (secrets never hit the command line or stdout), verifies the chain
# and that each key derives to its expected address before spending gas, issues
# the two demo credentials, deploys with the issuer's published root, redeems both
# holders, mints to Investor A, performs the compliant transfer, and forces the
# showcase compliance-blocked transfer to Investor B (which reverts on chain).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '\033[0;36m[seed]\033[0m %s\n' "$*"; }
die() {
    printf '\033[0;31m[seed] %s\033[0m\n' "$*" >&2
    exit 1
}

# The public RPC is load-balanced, so a read issued right after a write can land
# on a replica that has not yet seen the new state. Every read-after-write goes
# through this poll (first field only — cast annotates big uints as "N [1e21]").
poll_eq() { # $1=description  $2=expected  $3=cast-call-command-string
    local i got
    for i in $(seq 1 40); do
        got="$(eval "$3" 2>/dev/null | awk '{print $1}')"
        [ "$got" = "$2" ] && return 0
        sleep 3
    done
    die "$1: got '$got', expected '$2'"
}

[ -f .env ] || die "no .env — see .env.example"
set -a
# shellcheck disable=SC1091
. ./.env
set +a

: "${DEMO_DEPLOYER_PK:?}" "${DEMO_DEPLOYER_ADDR:?}" "${DEMO_INVESTOR_A_PK:?}" "${DEMO_INVESTOR_A_ADDR:?}" "${DEMO_INVESTOR_B_ADDR:?}"
# DEMO_RPC_URL wins when set. sepolia.base.org rate-limits a host that has been
# running the chain suites and then fails as a bare "fetch failed" rather than a
# 429; the chain-id assertion below is what actually guarantees the network.
RPC="${DEMO_RPC_URL:-${BASE_SEPOLIA_RPC_URL:-https://sepolia.base.org}}"
ISSUER_ID="42"
EXPIRY="4102444800" # 2100-01-01
export KYC_TREE_STATE="${KYC_TREE_STATE:-./kycctl-state/tree.json}"

# --- pre-flight (never-assume-verify) -----------------------------------------
chain_id="$(cast chain-id --rpc-url "$RPC")"
[ "$chain_id" = "84532" ] || die "RPC chain id $chain_id, expected 84532 (Base Sepolia)"

dep_derived="$(cast wallet address --private-key "$DEMO_DEPLOYER_PK")"
[ "${dep_derived,,}" = "${DEMO_DEPLOYER_ADDR,,}" ] || die "DEPLOYER key derives to $dep_derived, not $DEMO_DEPLOYER_ADDR"
a_derived="$(cast wallet address --private-key "$DEMO_INVESTOR_A_PK")"
[ "${a_derived,,}" = "${DEMO_INVESTOR_A_ADDR,,}" ] || die "INVESTOR_A key derives to $a_derived, not $DEMO_INVESTOR_A_ADDR"

log "Deployer $DEMO_DEPLOYER_ADDR balance $(cast balance "$DEMO_DEPLOYER_ADDR" --rpc-url "$RPC" --ether) ETH"
log "InvestorA $DEMO_INVESTOR_A_ADDR balance $(cast balance "$DEMO_INVESTOR_A_ADDR" --rpc-url "$RPC" --ether) ETH"

# --- build the issuer/prover CLI ----------------------------------------------
KYCCTL="$(mktemp -d)/kycctl"
go build -o "$KYCCTL" ./cmd/kycctl
log "built kycctl"

# --- issue the two demo credentials (ephemeral secrets; verification persists
#     on chain after redemption, so the secrets are never needed again) ---------
rm -rf "$(dirname "$KYC_TREE_STATE")"
SEC_DEP="$(python3 -c "print(int('$(openssl rand -hex 30)',16))")"
SEC_A="$(python3 -c "print(int('$(openssl rand -hex 30)',16))")"

log "issuing deployer credential (leaf 0)"
"$KYCCTL" issue --addr "$DEMO_DEPLOYER_ADDR" --expiry "$EXPIRY" --issuer "$ISSUER_ID" --secret "$SEC_DEP" >/dev/null
log "issuing Investor A credential (leaf 1)"
"$KYCCTL" issue --addr "$DEMO_INVESTOR_A_ADDR" --expiry "$EXPIRY" --issuer "$ISSUER_ID" --secret "$SEC_A" >/dev/null

ROOT_DEC="$("$KYCCTL" root | awk '/^root:/ {print $2}')"
[ -n "$ROOT_DEC" ] || die "failed to read issuer root"
log "issuer root $ROOT_DEC"

# --- deploy --------------------------------------------------------------------
# Deploy WITHOUT --verify: Basescan verification can lag or flake, and we never
# want that to abort the run after the contracts are already on chain. Source
# verification runs after the seed (below), non-fatally.
log "deploying Verifier + Registry(root) + Token to Base Sepolia..."
KYC_INITIAL_ROOT="$ROOT_DEC" NODE_OPTIONS=--dns-result-order=ipv4first \
    forge script script/Deploy.s.sol:Deploy \
    --rpc-url "$RPC" \
    --broadcast \
    -vvv

RUN="broadcast/Deploy.s.sol/84532/run-latest.json"
[ -f "$RUN" ] || die "no broadcast artifact at $RUN"
VERIFIER="$(jq -r '.transactions[] | select(.contractName=="Groth16Verifier") | .contractAddress' "$RUN" | head -1)"
REGISTRY="$(jq -r '.transactions[] | select(.contractName=="ZKComplianceRegistry") | .contractAddress' "$RUN" | head -1)"
TOKEN="$(jq -r '.transactions[] | select(.contractName=="KYCToken") | .contractAddress' "$RUN" | head -1)"
VERIFIER="$(cast to-checksum "$VERIFIER")"
REGISTRY="$(cast to-checksum "$REGISTRY")"
TOKEN="$(cast to-checksum "$TOKEN")"

# The public RPC is load-balanced; a just-mined contract can be invisible on the
# replica the next read lands on for a few seconds. Poll until every contract's
# code has propagated before touching them, so no downstream call races the node.
wait_for_code() { # $1=addr $2=label
    local i
    for i in $(seq 1 40); do
        [ "$(cast code "$1" --rpc-url "$RPC" 2>/dev/null)" != "0x" ] && return 0
        sleep 3
    done
    die "$2 code never propagated at $1"
}
wait_for_code "$VERIFIER" "verifier"
wait_for_code "$REGISTRY" "registry"
wait_for_code "$TOKEN" "token"
log "VERIFIER $VERIFIER"
log "REGISTRY $REGISTRY"
log "TOKEN    $TOKEN"

# on-chain root must equal what we published.
poll_eq "on-chain root" "$ROOT_DEC" "cast call $REGISTRY 'currentRoot()(uint256)' --rpc-url $RPC"

# --- helper: prove for an address and split snarkjs calldata into 4 cast args --
prove_args() { # $1=addr $2=secret  -> writes 4 lines to $3
    local addr="$1" secret="$2" out="$3"
    "$KYCCTL" prove --addr "$addr" --secret "$secret" --expiry "$EXPIRY" --issuer "$ISSUER_ID" 2>/dev/null \
        | grep -m1 '^\[' | tr -d '" ' \
        | awk '{d=0;g="";for(i=1;i<=length($0);i++){c=substr($0,i,1);if(c=="["){d++}else if(c=="]"){d--}if(c==","&&d==0){print g;g="";continue}g=g c}print g}' \
        > "$out"
    [ "$(wc -l < "$out")" = "4" ] || die "prove for $addr did not yield 4 calldata groups"
}

REDEEM_SIG="redeemProof(uint256[2],uint256[2][2],uint256[2],uint256[4])"

redeem() { # $1=label $2=addr $3=secret $4=pk  -> echoes tx hash
    local args
    args="$(mktemp)"
    prove_args "$2" "$3" "$args"
    mapfile -t G < "$args"
    cast send "$REGISTRY" "$REDEEM_SIG" "${G[0]}" "${G[1]}" "${G[2]}" "${G[3]}" \
        --private-key "$4" --rpc-url "$RPC" --json | jq -r '.transactionHash'
}

log "redeeming deployer proof..."
TX_REDEEM_DEP="$(redeem deployer "$DEMO_DEPLOYER_ADDR" "$SEC_DEP" "$DEMO_DEPLOYER_PK")"
log "redeeming Investor A proof..."
TX_REDEEM_A="$(redeem investorA "$DEMO_INVESTOR_A_ADDR" "$SEC_A" "$DEMO_INVESTOR_A_PK")"

poll_eq "deployer verified" "true" "cast call $REGISTRY 'isVerified(address)(bool)' $DEMO_DEPLOYER_ADDR --rpc-url $RPC"
poll_eq "Investor A verified" "true" "cast call $REGISTRY 'isVerified(address)(bool)' $DEMO_INVESTOR_A_ADDR --rpc-url $RPC"
log "both holders verified on chain"

# --- mint + compliant transfer + the showcase revert --------------------------
MINT_AMT="5000000000000000000000"   # 5,000 ACME
XFER_OK_AMT="1000000000000000000000" # 1,000 ACME
XFER_REVERT_AMT="500000000000000000000" # 500 ACME

log "minting 5,000 ACME to Investor A..."
TX_MINT="$(cast send "$TOKEN" "mint(address,uint256)" "$DEMO_INVESTOR_A_ADDR" "$MINT_AMT" \
    --private-key "$DEMO_DEPLOYER_PK" --rpc-url "$RPC" --json | jq -r '.transactionHash')"
poll_eq "mint balance" "$MINT_AMT" "cast call $TOKEN 'balanceOf(address)(uint256)' $DEMO_INVESTOR_A_ADDR --rpc-url $RPC"

log "compliant transfer: Investor A -> deployer, 1,000 ACME..."
TX_XFER_OK="$(cast send "$TOKEN" "transfer(address,uint256)" "$DEMO_DEPLOYER_ADDR" "$XFER_OK_AMT" \
    --private-key "$DEMO_INVESTOR_A_PK" --rpc-url "$RPC" --json | jq -r '.transactionHash')"
poll_eq "deployer received transfer" "$XFER_OK_AMT" "cast call $TOKEN 'balanceOf(address)(uint256)' $DEMO_DEPLOYER_ADDR --rpc-url $RPC"

log "SHOWCASE: Investor A -> Investor B, 500 ACME (must REVERT — B is unverified)..."
# --gas-limit skips estimation (which would abort a reverting tx before broadcast)
# so the reverting transaction actually lands on chain; --async returns its hash
# without cast erroring on the status-0 receipt.
TX_XFER_REVERT="$(cast send "$TOKEN" "transfer(address,uint256)" "$DEMO_INVESTOR_B_ADDR" "$XFER_REVERT_AMT" \
    --private-key "$DEMO_INVESTOR_A_PK" --rpc-url "$RPC" --gas-limit 120000 --async)"
log "revert tx broadcast: $TX_XFER_REVERT — waiting for receipt..."
# poll until mined
for _ in $(seq 1 30); do
    st="$(cast receipt "$TX_XFER_REVERT" status --rpc-url "$RPC" 2>/dev/null || true)"
    [ -n "$st" ] && break
    sleep 3
done
REVERT_STATUS="$(cast receipt "$TX_XFER_REVERT" status --rpc-url "$RPC" | awk '{print $1}')"
case "$REVERT_STATUS" in
    0 | 0x0 | false) log "confirmed: showcase transfer reverted on chain (status $REVERT_STATUS)" ;;
    *) die "showcase transfer did NOT revert (status $REVERT_STATUS) — B must be unverified" ;;
esac

# balances after the story
BAL_A="$(cast call "$TOKEN" "balanceOf(address)(uint256)" "$DEMO_INVESTOR_A_ADDR" --rpc-url "$RPC" | awk '{print $1}')"
BAL_DEP="$(cast call "$TOKEN" "balanceOf(address)(uint256)" "$DEMO_DEPLOYER_ADDR" --rpc-url "$RPC" | awk '{print $1}')"
SUPPLY="$(cast call "$TOKEN" "totalSupply()(uint256)" --rpc-url "$RPC" | awk '{print $1}')"

# --- write deployments/base-sepolia.json --------------------------------------
DEPLOY_BLOCK="$(cast receipt "$TX_MINT" blockNumber --rpc-url "$RPC" 2>/dev/null || echo 0)"
mkdir -p deployments
cat > deployments/base-sepolia.json <<JSON
{
  "chainId": 84532,
  "network": "base-sepolia",
  "explorer": "https://sepolia.basescan.org",
  "issuerRoot": "$ROOT_DEC",
  "contracts": {
    "Groth16Verifier": "$VERIFIER",
    "ZKComplianceRegistry": "$REGISTRY",
    "KYCToken": "$TOKEN"
  },
  "actors": {
    "deployer": "$DEMO_DEPLOYER_ADDR",
    "investorA": "$DEMO_INVESTOR_A_ADDR",
    "investorB": "$DEMO_INVESTOR_B_ADDR"
  },
  "token": { "name": "ACME RWA Share", "symbol": "ACME", "decimals": 18, "totalSupply": "$SUPPLY" },
  "seedNarrative": [
    { "step": "redeem-deployer", "tx": "$TX_REDEEM_DEP", "status": "success", "label": "Deployer redeems a ZK credential proof and becomes verified" },
    { "step": "redeem-investorA", "tx": "$TX_REDEEM_A", "status": "success", "label": "Investor A redeems a ZK credential proof and becomes verified" },
    { "step": "mint", "tx": "$TX_MINT", "status": "success", "label": "Mint 5,000 ACME to KYC-verified Investor A" },
    { "step": "transfer-compliant", "tx": "$TX_XFER_OK", "status": "success", "label": "Investor A to deployer, 1,000 ACME: both parties verified" },
    { "step": "transfer-revert", "tx": "$TX_XFER_REVERT", "status": "reverted", "label": "Investor A to Investor B, 500 ACME: reverts, recipient not verified" }
  ]
}
JSON

log "wrote deployments/base-sepolia.json"

# --- Basescan source verification (non-fatal; deploy + seed already durable) ---
CHAIN="84532"
V=(--chain "$CHAIN" --etherscan-api-key "${BASESCAN_API_KEY:?}" --verifier etherscan --watch)
log "verifying Groth16Verifier on Basescan..."
forge verify-contract "$VERIFIER" src/Verifier.sol:Groth16Verifier "${V[@]}" \
    || log "WARN: verify Groth16Verifier failed — retry manually"
log "verifying ZKComplianceRegistry on Basescan..."
forge verify-contract "$REGISTRY" src/ZKComplianceRegistry.sol:ZKComplianceRegistry "${V[@]}" \
    --constructor-args "$(cast abi-encode 'constructor(address,uint256,address)' "$VERIFIER" "$ROOT_DEC" "$DEMO_DEPLOYER_ADDR")" \
    || log "WARN: verify ZKComplianceRegistry failed — retry manually"
log "verifying KYCToken on Basescan..."
forge verify-contract "$TOKEN" src/KYCToken.sol:KYCToken "${V[@]}" \
    --constructor-args "$(cast abi-encode 'constructor(string,string,address,address)' 'ACME RWA Share' 'ACME' "$REGISTRY" "$DEMO_DEPLOYER_ADDR")" \
    || log "WARN: verify KYCToken failed — retry manually"

log "DONE. balances: A=$BAL_A deployer=$BAL_DEP supply=$SUPPLY"
