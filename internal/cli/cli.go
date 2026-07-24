// Package cli implements the kycctl command dispatch. Run is a thin, fully
// table-testable wrapper: writers, environment lookup, the process runner, and
// the working-directory factory are all injected or seam-swappable, so every
// branch (including snarkjs error paths) is reachable without spending a proof.
package cli

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pigfox/zk-kyc-pass/internal/circuit"
	"github.com/pigfox/zk-kyc-pass/internal/consts"
	"github.com/pigfox/zk-kyc-pass/internal/hash"
	"github.com/pigfox/zk-kyc-pass/internal/kyc"
	"github.com/pigfox/zk-kyc-pass/internal/prover"
)

// Exit codes returned by Run.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// Seams for tests. runnerFactory yields the process launcher; makeWorkDir
// creates the per-proof scratch directory. Production values shell out and use
// a real temp dir; tests swap them to simulate snarkjs and force error paths.
var (
	runnerFactory = func() prover.Runner { return prover.OSRunner }
	makeWorkDir   = func() (string, error) { return os.MkdirTemp("", "kycctl-prove-*") }
)

// out writes to w, deliberately ignoring terminal write errors.
func out(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

// Run dispatches a kycctl invocation and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		out(stderr, "usage: kycctl <issue|root|prove|verify> [flags]\n")
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "issue":
		return cmdIssue(rest, stdout, stderr, getenv)
	case "root":
		return cmdRoot(rest, stdout, stderr, getenv)
	case "prove":
		return cmdProve(rest, stdout, stderr, getenv)
	case "verify":
		return cmdVerify(rest, stdout, stderr, getenv)
	default:
		out(stderr, "unknown command %q; want issue|root|prove|verify\n", cmd)
		return exitUsage
	}
}

// statePath resolves the tree state file from the environment.
func statePath(getenv func(string) string) string {
	if p := getenv(consts.EnvTreeState); p != "" {
		return p
	}
	return consts.DefaultStatePath
}

// repoRoot resolves the repository root (where circuits/build lives).
func repoRoot(getenv func(string) string) string {
	if r := getenv(consts.EnvRepoRoot); r != "" {
		return r
	}
	return consts.DefaultRepoRoot
}

func cmdIssue(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "", "holder ethereum address (0x-hex)")
	expiry := fs.String("expiry", "", "credential expiry, unix seconds")
	issuer := fs.String("issuer", "", "issuer id (decimal)")
	secret := fs.String("secret", "", "holder secret (decimal); random if omitted")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *addr == "" || *expiry == "" || *issuer == "" {
		out(stderr, "issue: --addr, --expiry and --issuer are required\n")
		return exitUsage
	}
	res, err := kyc.Issue(hash.PoseidonHasher{}, rand.Reader, statePath(getenv), kyc.IssueParams{
		Addr:   *addr,
		Secret: *secret,
		Expiry: *expiry,
		Issuer: *issuer,
	})
	if err != nil {
		out(stderr, "issue: %v\n", err)
		return exitError
	}
	out(stdout, "SAVE THIS — printed once\n")
	out(stdout, "holderSecret: %s\n", res.Secret.String())
	out(stdout, "leafIndex: %d\n", res.Index)
	out(stdout, "root: %s\n", res.RootDec)
	out(stdout, "root (hex): %s\n", res.RootHex)
	return exitOK
}

func cmdRoot(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("root", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	dec, hexStr, err := kyc.Root(hash.PoseidonHasher{}, statePath(getenv))
	if err != nil {
		out(stderr, "root: %v\n", err)
		return exitError
	}
	out(stdout, "root: %s\n", dec)
	out(stdout, "root (hex): %s\n", hexStr)
	return exitOK
}

func cmdProve(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("prove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "", "holder ethereum address (0x-hex)")
	secret := fs.String("secret", "", "holder secret (decimal)")
	expiry := fs.String("expiry", "", "credential expiry, unix seconds")
	issuer := fs.String("issuer", "", "issuer id (decimal)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *addr == "" || *secret == "" || *expiry == "" || *issuer == "" {
		out(stderr, "prove: --addr, --secret, --expiry and --issuer are required\n")
		return exitUsage
	}
	input, nullifier, err := kyc.BuildProof(hash.PoseidonHasher{}, statePath(getenv), kyc.ProveParams{
		Addr:   *addr,
		Secret: *secret,
		Expiry: *expiry,
		Issuer: *issuer,
	})
	if err != nil {
		out(stderr, "prove: %v\n", err)
		return exitError
	}
	workDir, err := makeWorkDir()
	if err != nil {
		out(stderr, "prove: work dir: %v\n", err)
		return exitError
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	inputPath := filepath.Join(workDir, consts.InputFileName)
	if err := kyc.WriteInput(inputPath, input); err != nil {
		out(stderr, "prove: %v\n", err)
		return exitError
	}

	p := prover.New(circuit.KYCPassConfig(repoRoot(getenv)), runnerFactory())
	witnessPath := filepath.Join(workDir, consts.WitnessFileName)
	if err := p.Witness(inputPath, witnessPath); err != nil {
		out(stderr, "prove: %v\n", err)
		return exitError
	}
	proofPath := filepath.Join(workDir, consts.ProofFileName)
	publicPath := filepath.Join(workDir, consts.PublicFileName)
	if err := p.Prove(witnessPath, proofPath, publicPath); err != nil {
		out(stderr, "prove: %v\n", err)
		return exitError
	}
	ok, err := p.Verify(publicPath, proofPath)
	if err != nil {
		out(stderr, "prove: %v\n", err)
		return exitError
	}
	if !ok {
		out(stderr, "prove: local verification failed\n")
		return exitError
	}
	calldata, err := p.Calldata(publicPath, proofPath)
	if err != nil {
		out(stderr, "prove: %v\n", err)
		return exitError
	}
	out(stdout, "nullifier: %s\n", nullifier)
	out(stdout, "local verification: OK\n")
	out(stdout, "calldata (pA, pB, pC, pubSignals):\n%s\n", calldata)
	return exitOK
}

func cmdVerify(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	proofDir := fs.String("proof", "", "directory containing proof.json and public.json")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *proofDir == "" {
		out(stderr, "verify: --proof is required\n")
		return exitUsage
	}
	proofPath := filepath.Join(*proofDir, consts.ProofFileName)
	publicPath := filepath.Join(*proofDir, consts.PublicFileName)
	p := prover.New(circuit.KYCPassConfig(repoRoot(getenv)), runnerFactory())
	ok, err := p.Verify(publicPath, proofPath)
	if err != nil {
		out(stderr, "verify: %v\n", err)
		return exitError
	}
	if !ok {
		out(stdout, "FAIL\n")
		return exitError
	}
	out(stdout, "OK\n")
	return exitOK
}
