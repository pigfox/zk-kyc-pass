// Package tree implements a generic, circuit-agnostic append-only dense Merkle
// tree of fixed depth. The hash function is injected via hash.Hasher so the
// same tree serves any Poseidon-style circuit (kycpass today, delivery
// tomorrow); the circuit-specific leaf formula lives in the domain layer, never
// here.
//
// Layout: leaves are appended at indices 0,1,2,...; every internal node hashes
// its (left,right) children; empty right subtrees collapse to precomputed zero
// hashes where zeros[0]=0 and zeros[k]=Hash(zeros[k-1],zeros[k-1]). A path
// index bit of 0 means the running hash is the LEFT input at that level.
package tree

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/pigfox/zk-kyc-pass/internal/hash"
)

// ErrInvalidDepth is returned when a tree is constructed with a non-positive
// depth.
var ErrInvalidDepth = errors.New("tree: depth must be positive")

// ErrIndexOutOfRange is returned by Proof when the requested leaf index is not
// present in the tree.
var ErrIndexOutOfRange = errors.New("tree: leaf index out of range")

// Tree is a fixed-depth append-only Merkle tree over an injected Hasher.
type Tree struct {
	depth  int
	hasher hash.Hasher
	leaves []*big.Int
	zeros  []*big.Int // zeros[k] is the empty-subtree hash at level k.
}

// New constructs an empty Tree of the given depth, precomputing the zero-hash
// ladder. It returns an error for a non-positive depth or if the hasher fails
// while building the ladder.
func New(depth int, hasher hash.Hasher) (*Tree, error) {
	if depth <= 0 {
		return nil, ErrInvalidDepth
	}
	zeros := make([]*big.Int, depth+1)
	zeros[0] = big.NewInt(0)
	for k := 1; k <= depth; k++ {
		z, err := hasher.Hash(zeros[k-1], zeros[k-1])
		if err != nil {
			return nil, fmt.Errorf("tree: precompute zero at level %d: %w", k, err)
		}
		zeros[k] = z
	}
	return &Tree{depth: depth, hasher: hasher, zeros: zeros}, nil
}

// Depth reports the tree depth.
func (t *Tree) Depth() int { return t.depth }

// Len reports the number of leaves currently in the tree.
func (t *Tree) Len() int { return len(t.leaves) }

// Append adds a leaf at the next free index and returns that index.
func (t *Tree) Append(leaf *big.Int) int {
	t.leaves = append(t.leaves, new(big.Int).Set(leaf))
	return len(t.leaves) - 1
}

// nextLevel folds one level of the tree into the next, substituting the level's
// zero hash for any missing right sibling.
func (t *Tree) nextLevel(current []*big.Int, level int) ([]*big.Int, error) {
	next := make([]*big.Int, 0, (len(current)+1)/2)
	for i := 0; i < len(current); i += 2 {
		left := current[i]
		var right *big.Int
		if i+1 < len(current) {
			right = current[i+1]
		} else {
			right = t.zeros[level]
		}
		h, err := t.hasher.Hash(left, right)
		if err != nil {
			return nil, fmt.Errorf("tree: hash level %d: %w", level, err)
		}
		next = append(next, h)
	}
	if len(next) == 0 {
		// Empty tree: the parent of an empty level is the next zero hash.
		next = append(next, t.zeros[level+1])
	}
	return next, nil
}

// layers builds every level from the leaves (layers[0]) up to the root layer
// (layers[depth], always length 1).
func (t *Tree) layers() ([][]*big.Int, error) {
	all := make([][]*big.Int, t.depth+1)
	current := make([]*big.Int, len(t.leaves))
	copy(current, t.leaves)
	all[0] = current
	for level := range t.depth {
		next, err := t.nextLevel(current, level)
		if err != nil {
			return nil, err
		}
		all[level+1] = next
		current = next
	}
	return all, nil
}

// Root computes the current Merkle root.
func (t *Tree) Root() (*big.Int, error) {
	all, err := t.layers()
	if err != nil {
		return nil, err
	}
	return all[t.depth][0], nil
}

// Proof returns the Merkle authentication path for the leaf at index: the
// sibling at each level (pathElements), the boolean position bits (pathIndices,
// 0 = running hash is the left input), and the resulting root. Returning the
// root here means callers compute the layers exactly once.
func (t *Tree) Proof(index int) (pathElements []*big.Int, pathIndices []int, root *big.Int, err error) {
	if index < 0 || index >= len(t.leaves) {
		return nil, nil, nil, ErrIndexOutOfRange
	}
	all, err := t.layers()
	if err != nil {
		return nil, nil, nil, err
	}
	pathElements = make([]*big.Int, t.depth)
	pathIndices = make([]int, t.depth)
	idx := index
	for level := range t.depth {
		layer := all[level]
		if idx%2 == 0 {
			pathIndices[level] = 0
			if idx+1 < len(layer) {
				pathElements[level] = layer[idx+1]
			} else {
				pathElements[level] = t.zeros[level]
			}
		} else {
			pathIndices[level] = 1
			pathElements[level] = layer[idx-1]
		}
		idx /= 2
	}
	return pathElements, pathIndices, all[t.depth][0], nil
}
