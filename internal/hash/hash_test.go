package hash

import (
	"math/big"
	"testing"
)

// TestPoseidonKnownVector pins PoseidonHasher to the circomlibjs reference value
// Poseidon(1,2,3), guaranteeing byte-identity with the circuit.
func TestPoseidonKnownVector(t *testing.T) {
	const want = "6542985608222806190361240322586112750744169038454362455181422643027100751666"
	got, err := PoseidonHasher{}.Hash(big.NewInt(1), big.NewInt(2), big.NewInt(3))
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if got.String() != want {
		t.Fatalf("Poseidon(1,2,3) = %s, want %s", got.String(), want)
	}
}

// TestPoseidonTwoInputs exercises the 2-input arity used for Merkle nodes.
func TestPoseidonTwoInputs(t *testing.T) {
	got, err := PoseidonHasher{}.Hash(big.NewInt(0), big.NewInt(0))
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if got.Sign() == 0 {
		t.Fatalf("Poseidon(0,0) unexpectedly zero")
	}
}
