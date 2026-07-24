#!/usr/bin/env bash
#
# Compiles circuits/kycpass.circom and runs a Groth16 trusted setup on top of a
# PUBLISHED powers-of-tau, then exports and CHECKS IN every artifact a verifier
# or prover needs:
#
#   src/Verifier.sol                       — on-chain verifier (checked in)
#   circuits/build/kycpass.r1cs            — constraint system (checked in)
#   circuits/build/kycpass_js/kycpass.wasm — witness calculator (checked in)
#   circuits/build/kycpass_final.zkey      — proving key (checked in)
#   circuits/build/verification_key.json   — off-chain verifying key (checked in)
#
# Doctrine learned from zk-escrow: artifacts never stay laptop-only. Everything
# a third party needs to re-prove or re-verify is committed in the same phase it
# is produced. Only the reproducible intermediates (the .ptau, the pre-phase-2
# zkey) are gitignored.
#
# ############################################################################
# # TRUSTED SETUP — PHASE 1 IS REAL, PHASE 2 IS DEMO-GRADE.                   #
# #                                                                          #
# # Phase 1 (the powers-of-tau) reuses the Hermez `powersOfTau28_hez_final`  #
# # perpetual ceremony — a real multi-party ceremony whose transcript no     #
# # single participant controls. Its integrity is pinned by sha256 below.    #
# #                                                                          #
# # Phase 2 (the circuit-specific contribution) is generated locally, on one #
# # machine, with entropy this script supplies. Whoever runs it therefore    #
# # knows that contribution's toxic waste and could forge proofs for this    #
# # circuit. That is fine for a Base Sepolia demo and unacceptable for real  #
# # value — production needs independent phase-2 contributors. See           #
# # SECURITY.md, "Trusted setup provenance".                                 #
# ############################################################################
#
# NOTE: re-running this performs a FRESH phase-2 contribution, producing a
# different verification key and therefore a different src/Verifier.sol and
# kycpass_final.zkey. Any proof generated against the old key stops verifying.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CIRCUIT_NAME="kycpass"
CIRCUIT_SRC="circuits/${CIRCUIT_NAME}.circom"
BUILD_DIR="circuits/build"

# Published powers-of-tau. Power 14 (2^14 = 16384 constraints) comfortably
# covers the circuit's ~9.5k constraints. Source and integrity are pinned:
#   https://github.com/iden3/snarkjs#7-prepare-phase-2  (canonical index)
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau"
PTAU_FILE="$BUILD_DIR/powersOfTau28_hez_final_14.ptau"
PTAU_SHA256="489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d"

CIRCOMLIB_DIR="node_modules/circomlib/circuits"
SNARKJS="npx --no-install snarkjs"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v circom >/dev/null 2>&1 || die "circom not found. https://docs.circom.io/getting-started/installation/"
command -v npx >/dev/null 2>&1 || die "npx not found. Install Node.js 20+."
[ -d "$CIRCOMLIB_DIR" ] || die "circomlib missing. Run: npm install"
[ -f "$CIRCUIT_SRC" ] || die "circuit source not found at $CIRCUIT_SRC"

mkdir -p "$BUILD_DIR"

log "Compiling $CIRCUIT_SRC"
circom "$CIRCUIT_SRC" \
    --r1cs --wasm --sym \
    -l "$CIRCOMLIB_DIR" \
    -o "$BUILD_DIR"

log "Circuit info"
$SNARKJS r1cs info "$BUILD_DIR/${CIRCUIT_NAME}.r1cs"

# --- Phase 1: published powers-of-tau (fetch if missing, verify integrity) ----
if [ ! -f "$PTAU_FILE" ]; then
    log "Fetching published powers-of-tau"
    curl -sSL -o "$PTAU_FILE" "$PTAU_URL"
fi

log "Verifying powers-of-tau integrity (sha256)"
ACTUAL_SHA="$(sha256sum "$PTAU_FILE" | cut -d' ' -f1)"
[ "$ACTUAL_SHA" = "$PTAU_SHA256" ] || die "ptau sha256 mismatch: got $ACTUAL_SHA, pinned $PTAU_SHA256"

# The sha256 pin above IS the integrity guarantee: these exact bytes are the
# published Hermez power-14 file. A full `snarkjs powersoftau verify` re-walks
# the entire transcript (several minutes) and adds nothing once the bytes are
# pinned, so it is left as an opt-in manual check rather than a build-hot-path
# cost:  npx snarkjs powersoftau verify "$PTAU_FILE"
# The `zkey verify` below still validates that OUR setup is consistent with this
# ptau and the r1cs, which is the part that actually depends on this run.

# --- Phase 2: circuit-specific contribution (DEMO ENTROPY — see header) --------
log "Groth16 setup"
$SNARKJS groth16 setup \
    "$BUILD_DIR/${CIRCUIT_NAME}.r1cs" \
    "$PTAU_FILE" \
    "$BUILD_DIR/${CIRCUIT_NAME}_0000.zkey"

log "Phase 2 contribution (DEMO ENTROPY — see header)"
$SNARKJS zkey contribute \
    "$BUILD_DIR/${CIRCUIT_NAME}_0000.zkey" \
    "$BUILD_DIR/${CIRCUIT_NAME}_final.zkey" \
    --name="zk-kyc-pass demo phase2" -v \
    -e="zk-kyc-pass demo phase2 entropy, not a real ceremony"

log "Verifying final zkey against the ptau"
$SNARKJS zkey verify \
    "$BUILD_DIR/${CIRCUIT_NAME}.r1cs" \
    "$PTAU_FILE" \
    "$BUILD_DIR/${CIRCUIT_NAME}_final.zkey"

log "Exporting verification key"
$SNARKJS zkey export verificationkey \
    "$BUILD_DIR/${CIRCUIT_NAME}_final.zkey" \
    "$BUILD_DIR/verification_key.json"

log "Exporting src/Verifier.sol"
$SNARKJS zkey export solidityverifier \
    "$BUILD_DIR/${CIRCUIT_NAME}_final.zkey" \
    "$BUILD_DIR/Verifier.sol"

# snarkjs emits a floating pragma and no SPDX tag. Pin both so the contract
# builds under the same solc as the rest of src/ and Slither stays quiet.
{
    echo "// SPDX-License-Identifier: GPL-3.0"
    echo "// AUTOGENERATED BY scripts/build-circuit.sh — DO NOT EDIT BY HAND."
    echo "// Regenerate with: ./scripts/build-circuit.sh"
    sed -e 's|^// SPDX-License-Identifier:.*$||' \
        -e 's|^pragma solidity .*;$|pragma solidity 0.8.28;|' \
        "$BUILD_DIR/Verifier.sol"
} > src/Verifier.sol

log "Done."
echo
echo "  Checked in:  src/Verifier.sol"
echo "               $BUILD_DIR/${CIRCUIT_NAME}.r1cs"
echo "               $BUILD_DIR/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm"
echo "               $BUILD_DIR/${CIRCUIT_NAME}_final.zkey"
echo "               $BUILD_DIR/verification_key.json"
echo "  Gitignored:  $PTAU_FILE (rederivable from the pinned URL + sha256)"
echo "               $BUILD_DIR/${CIRCUIT_NAME}_0000.zkey"
echo
echo "  Next: node scripts/poseidon.js  (tree/leaf/nullifier helper)"
