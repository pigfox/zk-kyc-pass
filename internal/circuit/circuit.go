// Package circuit holds circuit configuration: the paths and geometry a snarkjs
// wrapper needs, kept out of the generic plumbing so the tree and prover stay
// circuit-agnostic. Configs live here in one place. KYCPassConfig wires the
// kycpass circuit; DeliveryConfig is a documented stub demonstrating that the
// exact same generic prover/tree code is reusable for a different circuit.
package circuit

import (
	"path/filepath"

	"github.com/pigfox/zk-kyc-pass/internal/consts"
)

// Config describes one Groth16 circuit's on-disk build artifacts.
type Config struct {
	Name     string // circuit name, e.g. "kycpass".
	Depth    int    // Merkle depth the circuit expects.
	BuildDir string // directory containing the build artifacts.
	Wasm     string // witness-calculator wasm.
	Zkey     string // proving key (final).
	Vkey     string // verification key JSON.
}

// kycpass build-artifact names, fixed by the circuit's build.
const (
	kycpassName    = "kycpass"
	buildDirName   = "build"
	circuitsDir    = "circuits"
	kycpassWasm    = "kycpass.wasm"
	kycpassJSDir   = "kycpass_js"         //nolint:gosec // G101 false positive: a build-output directory name, not a credential
	kycpassZkey    = "kycpass_final.zkey" //nolint:gosec // G101 false positive: a proving-key filename, not a credential
	verificationVK = "verification_key.json"
)

// KYCPassConfig returns the Config for the kycpass circuit, rooted at repoRoot.
// Artifacts live under <repoRoot>/circuits/build.
func KYCPassConfig(repoRoot string) Config {
	build := filepath.Join(repoRoot, circuitsDir, buildDirName)
	return Config{
		Name:     kycpassName,
		Depth:    consts.TreeDepth,
		BuildDir: build,
		Wasm:     filepath.Join(build, kycpassJSDir, kycpassWasm),
		Zkey:     filepath.Join(build, kycpassZkey),
		Vkey:     filepath.Join(build, verificationVK),
	}
}

// delivery build-artifact names. These mirror kycpass's layout for the sibling
// zk-escrow delivery.circom circuit.
const (
	deliveryName    = "delivery"
	deliveryWasm    = "delivery.wasm"
	deliveryJSDir   = "delivery_js"
	deliveryZkey    = "delivery_final.zkey"
	deliveryDepth   = consts.TreeDepth
	deliveryCircuit = circuitsDir
)

// DeliveryConfig is a documented stub proving the plumbing is circuit-agnostic.
//
// It targets the delivery.circom circuit that lives in the sibling zk-escrow
// repository (a separate future session reuses this exact tree + prover code
// for it). Only kycpass is wired into the CLI today; this stub exists so the
// generic prover/tree can be pointed at delivery without touching their code.
func DeliveryConfig(repoRoot string) Config {
	build := filepath.Join(repoRoot, deliveryCircuit, buildDirName)
	return Config{
		Name:     deliveryName,
		Depth:    deliveryDepth,
		BuildDir: build,
		Wasm:     filepath.Join(build, deliveryJSDir, deliveryWasm),
		Zkey:     filepath.Join(build, deliveryZkey),
		Vkey:     filepath.Join(build, verificationVK),
	}
}
