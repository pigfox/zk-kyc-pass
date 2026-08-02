// Package prover is a generic, circuit-agnostic snarkjs wrapper. The circuit is
// injected as a circuit.Config and the process launcher as a Runner, so the
// same code proves any Groth16 circuit and tests can simulate snarkjs without
// spending a real proof.
package prover

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/pigfox/zk-kyc-pass/internal/circuit"
	"github.com/pigfox/zk-kyc-pass/internal/consts"
)

// verifyOKMarker is the substring snarkjs prints for a valid proof.
const verifyOKMarker = "OK!"

// Runner launches an external command and returns its combined output. It takes
// a context so a long-running proof can be canceled with the command that
// produced it.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// OSRunner is the production Runner; it executes the command and captures
// stdout+stderr together. Canceling ctx kills the process.
func OSRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	// G204 false positive: launching a named process is this function's entire
	// contract. Every call site passes consts.NpxBin as name and package
	// constants plus internally-derived paths as args — none of it is shell
	// input, and exec.CommandContext does not spawn a shell, so there is
	// nothing to inject into.
	return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: constant binary, no shell, args built in-package
}

// Prover wraps snarkjs for a specific circuit.
type Prover struct {
	cfg    circuit.Config
	runner Runner
}

// New builds a Prover for cfg using runner.
func New(cfg circuit.Config, runner Runner) *Prover {
	return &Prover{cfg: cfg, runner: runner}
}

// run invokes `npx --no-install snarkjs <sub...>` through the injected runner.
func (p *Prover) run(ctx context.Context, sub ...string) ([]byte, error) {
	args := make([]string, 0, len(sub)+2)
	args = append(args, consts.NpxNoInstall, consts.SnarkjsBin)
	args = append(args, sub...)
	return p.runner(ctx, consts.NpxBin, args...)
}

// Witness computes the witness from the circuit wasm and an input JSON file.
func (p *Prover) Witness(ctx context.Context, inputPath, witnessPath string) error {
	out, err := p.run(ctx, consts.WtnsCmd, consts.CalculateCmd, p.cfg.Wasm, inputPath, witnessPath)
	if err != nil {
		return fmt.Errorf("snarkjs witness: %w: %s", err, out)
	}
	return nil
}

// Prove produces a Groth16 proof and its public signals from the witness.
func (p *Prover) Prove(ctx context.Context, witnessPath, proofPath, publicPath string) error {
	out, err := p.run(ctx, consts.Groth16Cmd, consts.ProveCmd, p.cfg.Zkey, witnessPath, proofPath, publicPath)
	if err != nil {
		return fmt.Errorf("snarkjs prove: %w: %s", err, out)
	}
	return nil
}

// Verify checks a proof against the circuit verification key. It returns
// (true,nil) for a valid proof, (false,nil) for a proof snarkjs reports invalid,
// and (false,err) when the runner itself fails without an OK verdict.
func (p *Prover) Verify(ctx context.Context, publicPath, proofPath string) (bool, error) {
	out, err := p.run(ctx, consts.Groth16Cmd, consts.VerifyCmd, p.cfg.Vkey, publicPath, proofPath)
	if bytes.Contains(out, []byte(verifyOKMarker)) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("snarkjs verify: %w: %s", err, out)
	}
	return false, nil
}

// Calldata exports the Solidity calldata (pA, pB, pC, pubSignals) for the proof.
func (p *Prover) Calldata(ctx context.Context, publicPath, proofPath string) (string, error) {
	out, err := p.run(ctx, consts.ZkeyCmd, consts.ExportCmd, consts.SolidityCalldataCmd, publicPath, proofPath)
	if err != nil {
		return "", fmt.Errorf("snarkjs calldata: %w: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}
