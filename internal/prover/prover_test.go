package prover

import (
	"context"
	"errors"
	"testing"

	"github.com/pigfox/zk-kyc-pass/internal/circuit"
)

var errRun = errors.New("runner failed")

// fakeRunner returns canned output/err keyed by the snarkjs subcommand seen in
// the arg list.
type fakeRunner struct {
	lastName string
	lastArgs []string
	out      []byte
	err      error
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.lastName = name
	f.lastArgs = args
	return f.out, f.err
}

func newProver(out []byte, err error) (*Prover, *fakeRunner) {
	fr := &fakeRunner{out: out, err: err}
	return New(circuit.KYCPassConfig("/repo"), fr.run), fr
}

func TestOSRunnerSuccess(t *testing.T) {
	out, err := OSRunner(context.Background(), "echo", "hello")
	if err != nil {
		t.Fatalf("OSRunner echo: %v", err)
	}
	if string(out) != "hello\n" {
		t.Fatalf("OSRunner echo out = %q", out)
	}
}

func TestOSRunnerError(t *testing.T) {
	if _, err := OSRunner(context.Background(), "kycctl-no-such-binary-zzz"); err == nil {
		t.Fatalf("OSRunner missing binary: want error")
	}
}

func TestWitness(t *testing.T) {
	p, fr := newProver(nil, nil)
	if err := p.Witness(context.Background(), "in.json", "w.wtns"); err != nil {
		t.Fatalf("Witness: %v", err)
	}
	if fr.lastName != "npx" {
		t.Fatalf("runner name = %q", fr.lastName)
	}
	p2, _ := newProver([]byte("nope"), errRun)
	if err := p2.Witness(context.Background(), "in.json", "w.wtns"); !errors.Is(err, errRun) {
		t.Fatalf("Witness err = %v, want errRun", err)
	}
}

func TestProve(t *testing.T) {
	p, _ := newProver(nil, nil)
	if err := p.Prove(context.Background(), "w.wtns", "proof.json", "public.json"); err != nil {
		t.Fatalf("Prove: %v", err)
	}
	p2, _ := newProver(nil, errRun)
	if err := p2.Prove(context.Background(), "w.wtns", "proof.json", "public.json"); !errors.Is(err, errRun) {
		t.Fatalf("Prove err = %v", err)
	}
}

func TestVerify(t *testing.T) {
	// Valid: OK! present even alongside a runner error.
	p, _ := newProver([]byte("[INFO] snarkJS: OK!"), errRun)
	ok, err := p.Verify(context.Background(), "public.json", "proof.json")
	if err != nil || !ok {
		t.Fatalf("Verify valid = (%v,%v)", ok, err)
	}
	// Invalid: no OK, no error.
	p2, _ := newProver([]byte("snarkJS: INVALID"), nil)
	ok, err = p2.Verify(context.Background(), "public.json", "proof.json")
	if err != nil || ok {
		t.Fatalf("Verify invalid = (%v,%v)", ok, err)
	}
	// Runner error with no OK marker.
	p3, _ := newProver([]byte("crash"), errRun)
	ok, err = p3.Verify(context.Background(), "public.json", "proof.json")
	if ok || !errors.Is(err, errRun) {
		t.Fatalf("Verify error = (%v,%v)", ok, err)
	}
}

func TestCalldata(t *testing.T) {
	p, _ := newProver([]byte("  [\"0x1\"]  \n"), nil)
	got, err := p.Calldata(context.Background(), "public.json", "proof.json")
	if err != nil {
		t.Fatalf("Calldata: %v", err)
	}
	if got != "[\"0x1\"]" {
		t.Fatalf("Calldata = %q", got)
	}
	p2, _ := newProver(nil, errRun)
	if _, err := p2.Calldata(context.Background(), "public.json", "proof.json"); !errors.Is(err, errRun) {
		t.Fatalf("Calldata err = %v", err)
	}
}
