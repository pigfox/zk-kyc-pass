package tree

import (
	"errors"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pigfox/zk-kyc-pass/internal/hash"
)

// errBoom is the failure the fake hasher injects.
var errBoom = errors.New("boom")

// fakeHasher is a deterministic hasher that can fail on and after a chosen call.
type fakeHasher struct {
	calls  int
	failAt int // 1-based first failing call; 0 disables failure.
}

func (f *fakeHasher) Hash(inputs ...*big.Int) (*big.Int, error) {
	f.calls++
	if f.failAt > 0 && f.calls >= f.failAt {
		return nil, errBoom
	}
	sum := big.NewInt(0)
	for _, x := range inputs {
		sum.Add(sum, x)
	}
	return sum, nil
}

func realTree(t *testing.T, depth int) *Tree {
	t.Helper()
	tr, err := New(depth, hash.PoseidonHasher{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tr
}

func TestNewInvalidDepth(t *testing.T) {
	if _, err := New(0, hash.PoseidonHasher{}); !errors.Is(err, ErrInvalidDepth) {
		t.Fatalf("New(0) err = %v, want ErrInvalidDepth", err)
	}
}

func TestNewHasherError(t *testing.T) {
	if _, err := New(2, &fakeHasher{failAt: 1}); !errors.Is(err, errBoom) {
		t.Fatalf("New err = %v, want errBoom", err)
	}
}

func TestDepthAndLen(t *testing.T) {
	tr := realTree(t, 4)
	if tr.Depth() != 4 {
		t.Fatalf("Depth = %d, want 4", tr.Depth())
	}
	if tr.Len() != 0 {
		t.Fatalf("Len = %d, want 0", tr.Len())
	}
	tr.Append(big.NewInt(7))
	if tr.Len() != 1 {
		t.Fatalf("Len = %d, want 1", tr.Len())
	}
}

// TestEmptyRootIsZeroLadder checks the empty tree collapses to the zero ladder
// top, exercising nextLevel's empty-propagation branch.
func TestEmptyRootIsZeroLadder(t *testing.T) {
	const depth = 4
	tr := realTree(t, depth)
	got, err := tr.Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	// Recompute zeros[depth] independently.
	z := big.NewInt(0)
	for k := 1; k <= depth; k++ {
		z, err = poseidon.Hash([]*big.Int{z, z})
		if err != nil {
			t.Fatalf("poseidon: %v", err)
		}
	}
	if got.Cmp(z) != 0 {
		t.Fatalf("empty root = %s, want %s", got, z)
	}
}

// TestProofReconstructsRoot builds several trees and folds each proof back to
// the root, validating the sibling/bit ordering against real Poseidon.
func TestProofReconstructsRoot(t *testing.T) {
	const depth = 5
	for _, n := range []int{1, 2, 3, 5, 8} {
		tr := realTree(t, depth)
		leaves := make([]*big.Int, n)
		for i := 0; i < n; i++ {
			leaves[i] = big.NewInt(int64(100 + i))
			tr.Append(leaves[i])
		}
		root, err := tr.Root()
		if err != nil {
			t.Fatalf("Root: %v", err)
		}
		for i := 0; i < n; i++ {
			pe, pi, proot, err := tr.Proof(i)
			if err != nil {
				t.Fatalf("Proof(%d): %v", i, err)
			}
			if proot.Cmp(root) != 0 {
				t.Fatalf("Proof root mismatch: %s vs %s", proot, root)
			}
			if len(pe) != depth || len(pi) != depth {
				t.Fatalf("path length = %d/%d, want %d", len(pe), len(pi), depth)
			}
			h := new(big.Int).Set(leaves[i])
			for lvl := 0; lvl < depth; lvl++ {
				var pair []*big.Int
				if pi[lvl] == 0 {
					pair = []*big.Int{h, pe[lvl]}
				} else {
					pair = []*big.Int{pe[lvl], h}
				}
				h, err = poseidon.Hash(pair)
				if err != nil {
					t.Fatalf("poseidon: %v", err)
				}
			}
			if h.Cmp(root) != 0 {
				t.Fatalf("n=%d i=%d reconstructed %s, want root %s", n, i, h, root)
			}
		}
	}
}

func TestProofOutOfRange(t *testing.T) {
	tr := realTree(t, 4)
	tr.Append(big.NewInt(1))
	if _, _, _, err := tr.Proof(-1); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("Proof(-1) err = %v, want ErrIndexOutOfRange", err)
	}
	if _, _, _, err := tr.Proof(1); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("Proof(1) err = %v, want ErrIndexOutOfRange", err)
	}
}

func TestRootHasherError(t *testing.T) {
	const depth = 2
	fh := &fakeHasher{failAt: depth + 1} // succeed for New, fail in layers.
	tr, err := New(depth, fh)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr.Append(big.NewInt(3))
	if _, err := tr.Root(); !errors.Is(err, errBoom) {
		t.Fatalf("Root err = %v, want errBoom", err)
	}
}

func TestProofHasherError(t *testing.T) {
	const depth = 2
	fh := &fakeHasher{failAt: depth + 1}
	tr, err := New(depth, fh)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr.Append(big.NewInt(3))
	if _, _, _, err := tr.Proof(0); !errors.Is(err, errBoom) {
		t.Fatalf("Proof err = %v, want errBoom", err)
	}
}
