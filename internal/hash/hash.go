// Package hash defines the Hasher seam used by the generic Merkle tree and the
// production Poseidon implementation. Injecting Hasher keeps the tree logic
// unit-testable (a fake hasher can force error paths) while the real
// PoseidonHasher is exercised against a known circomlibjs vector.
package hash

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// Hasher hashes an ordered list of field elements into a single field element.
type Hasher interface {
	Hash(inputs ...*big.Int) (*big.Int, error)
}

// PoseidonHasher is the production Hasher. It delegates to go-iden3-crypto's
// Poseidon, which is byte-identical to the circuit's circomlibjs Poseidon.
type PoseidonHasher struct{}

// Hash implements Hasher using Poseidon over the BN254 scalar field.
func (PoseidonHasher) Hash(inputs ...*big.Int) (*big.Int, error) {
	return poseidon.Hash(inputs)
}
