#!/usr/bin/env bash
#
# Solidity coverage gate.
#
# Requires 100% line, statement, branch AND function coverage on every file
# under src/, with exactly one documented exclusion:
#
#   src/Verifier.sol — generated verbatim by snarkjs from the proving key.
#     Its residual uncovered lines are the inline-assembly early-exit paths
#     taken when the BN254 ecAdd / ecMul / pairing precompiles themselves report
#     failure. Those cannot be made to fail from a test: inputs that are merely
#     wrong (off-curve points, out-of-range field elements) are rejected by the
#     reachable checkField branch. Reaching the rest would require a broken EVM,
#     not a broken proof.
#
#     The verifier is still exercised end-to-end — see test/RealProof.t.sol,
#     which drives a real Groth16 proof through it, including address-binding
#     rejection and nullifier replay rejection.
#
# Coverage here is a hard gate, not a report. Any shortfall exits non-zero.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXCLUDED_FILE="src/Verifier.sol"
REPORT="${COVERAGE_REPORT:-coverage-summary.txt}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

if [ "${COVERAGE_SKIP_RUN:-0}" = "1" ]; then
    log "Reusing existing report at $REPORT"
else
    log "Running forge coverage"
    forge coverage \
        --no-match-coverage '(script|test)/' \
        --report summary \
        | tee "$REPORT"
fi

echo
log "Enforcing 100% coverage on src/ (excluding $EXCLUDED_FILE)"

awk -v excluded="$EXCLUDED_FILE" '
    /^\| *src\// {
        n = split($0, cells, "|")
        file = cells[2]
        gsub(/^[ \t]+|[ \t]+$/, "", file)

        if (file == excluded) {
            printf "  SKIP  %-36s (documented exclusion)\n", file
            skipped++
            next
        }

        seen++
        bad = 0
        for (i = 3; i <= 6; i++) {
            pct = cells[i]
            gsub(/^[ \t]+/, "", pct)
            sub(/%.*/, "", pct)
            if (pct + 0 < 100) bad = 1
        }

        if (bad) {
            printf "  FAIL  %-36s %s\n", file, $0
            failures++
        } else {
            printf "  OK    %-36s 100%% lines / statements / branches / functions\n", file
        }
    }
    END {
        if (seen == 0) {
            print "\nERROR: no src/ rows found in the coverage summary."
            print "The report format may have changed; refusing to pass by default."
            exit 1
        }
        if (failures > 0) {
            printf "\nFAILED: %d file(s) under 100%% coverage.\n", failures
            exit 1
        }
        printf "\nPASSED: %d file(s) at 100%% on all four metrics", seen
        if (skipped > 0) printf " (%d documented exclusion)", skipped
        printf ".\n"
    }
' "$REPORT"
