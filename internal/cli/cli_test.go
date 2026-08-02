package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pigfox/zk-kyc-pass/internal/consts"
	"github.com/pigfox/zk-kyc-pass/internal/prover"
)

var errRun = errors.New("runner failed")

// fakeSnarkjs simulates snarkjs, keyed on the sub-command present in the args.
type fakeSnarkjs struct {
	witnessErr  bool
	proveErr    bool
	verifyOut   string // "OK!", "INVALID", ""
	verifyErr   bool
	calldataOut string
	calldataErr bool
}

func (f fakeSnarkjs) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	// args == ["--no-install", "snarkjs", <sub>, ...]; classify on the token
	// position, not a substring scan (the temp dir name contains "prove").
	sub := args[2]
	switch {
	case sub == consts.ZkeyCmd: // zkey export soliditycalldata
		if f.calldataErr {
			return nil, errRun
		}
		return []byte(f.calldataOut), nil
	case sub == consts.Groth16Cmd && args[3] == consts.VerifyCmd:
		if f.verifyErr {
			return []byte("crash"), errRun
		}
		return []byte(f.verifyOut), nil
	case sub == consts.Groth16Cmd && args[3] == consts.ProveCmd:
		if f.proveErr {
			return nil, errRun
		}
		return nil, nil
	default: // wtns calculate
		if f.witnessErr {
			return nil, errRun
		}
		return nil, nil
	}
}

// setRunner installs fake snarkjs and returns a restore func.
func setRunner(f fakeSnarkjs) func() {
	prev := runnerFactory
	runnerFactory = func() prover.Runner { return f.run }
	return func() { runnerFactory = prev }
}

func setWorkDir(fn func() (string, error)) func() {
	prev := makeWorkDir
	makeWorkDir = fn
	return func() { makeWorkDir = prev }
}

// envMap turns a map into a getenv function.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func runCLI(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, &stdout, &stderr, envMap(env))
	return code, stdout.String(), stderr.String()
}

// issueOne seeds a state file with one credential and returns its state path.
func issueOne(t *testing.T) (string, map[string]string) {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "tree.json")
	env := map[string]string{consts.EnvTreeState: statePath}
	code, out, errOut := runCLI(t, env, "issue",
		"--addr", "0x00000000000000000000000000000000000000AA",
		"--expiry", "4102444800", "--issuer", "42", "--secret", "987654321098765")
	if code != exitOK {
		t.Fatalf("seed issue failed: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "holderSecret:") {
		t.Fatalf("issue output missing secret label: %s", out)
	}
	return statePath, env
}

// missingRoot is an absolute path that cannot exist, used to force the
// work-dir failure branch without touching the filesystem.
const missingRoot = "/no-such-zzz"

func TestRepoRootAndDefaultRunner(t *testing.T) {
	if got := repoRoot(envMap(map[string]string{consts.EnvRepoRoot: "/custom"})); got != "/custom" {
		t.Fatalf("repoRoot = %q, want /custom", got)
	}
	if runnerFactory() == nil {
		t.Fatalf("default runnerFactory returned nil runner")
	}
}

func TestRunUsage(t *testing.T) {
	if code, _, errOut := runCLI(t, nil); code != exitUsage || !strings.Contains(errOut, "usage") {
		t.Fatalf("no-args = (%d,%q)", code, errOut)
	}
	if code, _, errOut := runCLI(t, nil, "bogus"); code != exitUsage || !strings.Contains(errOut, "unknown") {
		t.Fatalf("unknown = (%d,%q)", code, errOut)
	}
}

func TestIssueCommand(t *testing.T) {
	statePath, env := issueOne(t)
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state not written: %v", err)
	}
	// Missing required flags.
	if code, _, _ := runCLI(t, env, "issue", "--addr", "0x00000000000000000000000000000000000000AA"); code != exitUsage {
		t.Fatalf("missing flags code = %d", code)
	}
	// Bad flag → parse error.
	if code, _, _ := runCLI(t, env, "issue", "--nope"); code != exitUsage {
		t.Fatalf("bad flag code = %d", code)
	}
	// Domain error (bad address).
	if code, _, errOut := runCLI(t, env, "issue", "--addr", "bad", "--expiry", "1", "--issuer", "2"); code != exitError || !strings.Contains(errOut, "issue:") {
		t.Fatalf("issue error = (%d,%q)", code, errOut)
	}
	// Default state path branch (no env set): use a temp cwd.
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(prev); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	}()
	if code, _, errOut := runCLI(t, map[string]string{}, "issue",
		"--addr", "0x00000000000000000000000000000000000000AA", "--expiry", "1", "--issuer", "2"); code != exitOK {
		t.Fatalf("default-path issue = (%d,%q)", code, errOut)
	}
}

func TestRootCommand(t *testing.T) {
	statePath, env := issueOne(t)
	code, out, errOut := runCLI(t, env, "root")
	if code != exitOK || !strings.Contains(out, "root:") || !strings.Contains(out, "0x") {
		t.Fatalf("root = (%d,%q,%q)", code, out, errOut)
	}
	// Error: missing state.
	missing := map[string]string{consts.EnvTreeState: filepath.Join(t.TempDir(), "none.json")}
	if code, _, _ := runCLI(t, missing, "root"); code != exitError {
		t.Fatalf("root missing state code = %d", code)
	}
	_ = statePath
	// Bad flag.
	if code, _, _ := runCLI(t, env, "root", "--nope"); code != exitUsage {
		t.Fatalf("root bad flag code = %d", code)
	}
}

func proveArgs() []string {
	return []string{"prove",
		"--addr", "0x00000000000000000000000000000000000000AA",
		"--secret", "987654321098765", "--expiry", "4102444800", "--issuer", "42"}
}

func TestProveHappyPath(t *testing.T) {
	_, env := issueOne(t)
	restore := setRunner(fakeSnarkjs{verifyOut: "OK!", calldataOut: "[\"0x1\"]"})
	defer restore()
	code, out, errOut := runCLI(t, env, proveArgs()...)
	if code != exitOK {
		t.Fatalf("prove happy = (%d,%q)", code, errOut)
	}
	for _, want := range []string{"nullifier:", "local verification: OK", "calldata"} {
		if !strings.Contains(out, want) {
			t.Fatalf("prove output missing %q: %s", want, out)
		}
	}
}

func TestProveFlagErrors(t *testing.T) {
	_, env := issueOne(t)
	if code, _, _ := runCLI(t, env, "prove", "--addr", "0x00000000000000000000000000000000000000AA"); code != exitUsage {
		t.Fatalf("prove missing flags code = %d", code)
	}
	if code, _, _ := runCLI(t, env, "prove", "--nope"); code != exitUsage {
		t.Fatalf("prove bad flag code = %d", code)
	}
}

func TestProveBuildProofError(t *testing.T) {
	// State missing → BuildProof fails before any snarkjs call.
	env := map[string]string{consts.EnvTreeState: filepath.Join(t.TempDir(), "none.json")}
	if code, _, errOut := runCLI(t, env, proveArgs()...); code != exitError || !strings.Contains(errOut, "prove:") {
		t.Fatalf("prove build error = (%d,%q)", code, errOut)
	}
}

func TestProveWorkDirError(t *testing.T) {
	_, env := issueOne(t)
	restore := setWorkDir(func() (string, error) { return "", errRun })
	defer restore()
	if code, _, errOut := runCLI(t, env, proveArgs()...); code != exitError || !strings.Contains(errOut, "work dir") {
		t.Fatalf("prove workdir error = (%d,%q)", code, errOut)
	}
}

func TestProveWriteInputError(t *testing.T) {
	_, env := issueOne(t)
	// Non-existent work dir makes WriteInput fail.
	restore := setWorkDir(func() (string, error) { return filepath.Join(missingRoot, "wd"), nil })
	defer restore()
	if code, _, _ := runCLI(t, env, proveArgs()...); code != exitError {
		t.Fatalf("prove writeinput error code = %d", code)
	}
}

func TestProveSnarkjsErrors(t *testing.T) {
	_, env := issueOne(t)
	cases := []struct {
		name string
		f    fakeSnarkjs
	}{
		{"witness", fakeSnarkjs{witnessErr: true}},
		{"prove", fakeSnarkjs{proveErr: true}},
		{"verifyErr", fakeSnarkjs{verifyErr: true}},
		{"verifyInvalid", fakeSnarkjs{verifyOut: "INVALID"}},
		{"calldata", fakeSnarkjs{verifyOut: "OK!", calldataErr: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore := setRunner(tc.f)
			defer restore()
			if code, _, errOut := runCLI(t, env, proveArgs()...); code != exitError || !strings.Contains(errOut, "prove:") {
				t.Fatalf("%s = (%d,%q)", tc.name, code, errOut)
			}
		})
	}
}

func TestVerifyCommand(t *testing.T) {
	env := map[string]string{}
	dir := t.TempDir()

	restore := setRunner(fakeSnarkjs{verifyOut: "OK!"})
	if code, out, _ := runCLI(t, env, "verify", "--proof", dir); code != exitOK || !strings.Contains(out, "OK") {
		restore()
		t.Fatalf("verify OK = (%d,%q)", code, out)
	}
	restore()

	restore = setRunner(fakeSnarkjs{verifyOut: "INVALID"})
	if code, out, _ := runCLI(t, env, "verify", "--proof", dir); code != exitError || !strings.Contains(out, "FAIL") {
		restore()
		t.Fatalf("verify FAIL = (%d,%q)", code, out)
	}
	restore()

	restore = setRunner(fakeSnarkjs{verifyErr: true})
	if code, _, errOut := runCLI(t, env, "verify", "--proof", dir); code != exitError || !strings.Contains(errOut, "verify:") {
		restore()
		t.Fatalf("verify err = (%d,%q)", code, errOut)
	}
	restore()

	// Missing --proof.
	if code, _, _ := runCLI(t, env, "verify"); code != exitUsage {
		t.Fatalf("verify missing proof code = %d", code)
	}
	// Bad flag.
	if code, _, _ := runCLI(t, env, "verify", "--nope"); code != exitUsage {
		t.Fatalf("verify bad flag code = %d", code)
	}
}

// failingWriter reports an error on every write, standing in for a closed pipe
// or a full disk on the command's own output stream.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("stream closed")
}

// TestOutDropsWriteErrors pins the contract of out: a command whose output
// stream has failed has nowhere left to report that, so out must swallow the
// error rather than panic or propagate it. Run must still return its normal
// exit code when every write fails.
func TestOutDropsWriteErrors(t *testing.T) {
	out(failingWriter{}, "%s\n", "discarded")

	if code := Run(context.Background(), nil, failingWriter{}, failingWriter{}, envMap(nil)); code != exitUsage {
		t.Errorf("Run with a dead stderr: exit code = %d, want %d", code, exitUsage)
	}
}

// TestProveCleanupError covers the branch where removing the per-proof scratch
// directory fails: prove reports the cleanup failure on stderr instead of
// discarding it.
//
// The failure is induced with a work-dir path ending in ".". os.RemoveAll
// rejects that with EINVAL from its endsWithDot guard, which runs before it
// issues any syscall — so the error does not depend on ownership, on the
// filesystem, or on whether the process is root. A read-only parent directory
// would have been the obvious alternative and is the wrong choice: root ignores
// the permission bits, so in a CI container that arrangement would quietly stop
// inducing the failure and leave this branch uncovered while the test still
// passed. The premise is asserted below rather than assumed.
func TestProveCleanupError(t *testing.T) {
	_, env := issueOne(t)

	// The parent is deliberately never created, so WriteInput fails and prove
	// returns before it needs a runner; the deferred cleanup still runs.
	workDir := filepath.Join(t.TempDir(), "wd") + string(filepath.Separator) + "."
	if err := os.RemoveAll(workDir); err == nil {
		t.Skip("os.RemoveAll accepted a trailing-dot path here; the cleanup branch cannot be induced")
	}

	restore := setWorkDir(func() (string, error) { return workDir, nil })
	defer restore()

	code, _, errOut := runCLI(t, env, proveArgs()...)
	if code != exitError {
		t.Fatalf("prove cleanup: code = %d, want %d (stderr=%q)", code, exitError, errOut)
	}
	if !strings.Contains(errOut, "cleanup") {
		t.Fatalf("prove cleanup: stderr does not report the cleanup failure: %q", errOut)
	}
}
