// Package kyc holds the circuit-SPECIFIC domain logic for kycpass: the
// credential leaf formula Poseidon(holderSecret, expiry, issuerId), the
// nullifier Poseidon(holderSecret, root), the Ethereum-address-to-field
// mapping, persisted tree state, and the issue/root/prove orchestration. The
// generic tree and snarkjs plumbing live in sibling packages and know nothing
// about these formulae.
package kyc

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pigfox/zk-kyc-pass/internal/consts"
	"github.com/pigfox/zk-kyc-pass/internal/hash"
	"github.com/pigfox/zk-kyc-pass/internal/tree"
)

// addrHexLen is the number of hex digits in a 20-byte Ethereum address.
const addrHexLen = 40

// Sentinel errors for domain-level failures.
var (
	ErrInvalidAddr      = errors.New("kyc: invalid ethereum address")
	ErrInvalidField     = errors.New("kyc: invalid field element")
	ErrSecretOutOfRange = errors.New("kyc: holder secret out of field range")
	ErrLeafNotFound     = errors.New("kyc: leaf not found in tree state")
)

// fieldModulus is the BN254 scalar field order; a holder secret must be below it.
var fieldModulus, _ = new(big.Int).SetString(consts.FieldModulusDecimal, 10)

// marshalJSON is a seam over json.Marshal so tests can exercise marshal-error
// branches (the concrete state/input types never actually fail to marshal).
var marshalJSON = json.Marshal

// State is the persisted, append-only tree contents. Only leaf hashes are
// stored (as decimal strings); the holder secret is NEVER persisted.
type State struct {
	Leaves []string `json:"leaves"`
}

// CircuitInput is the kycpass input.json, all field elements as decimal strings.
type CircuitInput struct {
	HolderSecret string   `json:"holderSecret"`
	IssuerID     string   `json:"issuerId"`
	PathElements []string `json:"pathElements"`
	PathIndices  []string `json:"pathIndices"`
	Root         string   `json:"root"`
	HolderAddr   string   `json:"holderAddr"`
	Expiry       string   `json:"expiry"`
}

// IssueParams are the inputs to Issue.
type IssueParams struct {
	Addr   string // holder address (validated; not part of the leaf).
	Secret string // decimal holder secret; empty means "generate one".
	Expiry string // unix seconds, decimal.
	Issuer string // issuer id, decimal.
}

// IssueResult is what Issue returns to the CLI for printing.
type IssueResult struct {
	Secret  *big.Int
	Index   int
	RootDec string
	RootHex string
}

// ProveParams are the inputs to BuildProof.
type ProveParams struct {
	Addr   string
	Secret string
	Expiry string
	Issuer string
}

// AddrToField maps a hex Ethereum address to its field element uint256(uint160).
func AddrToField(addr string) (*big.Int, error) {
	s := strings.TrimPrefix(addr, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s) != addrHexLen {
		return nil, fmt.Errorf("%w: want %d hex digits, got %d", ErrInvalidAddr, addrHexLen, len(s))
	}
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidAddr, addr)
	}
	return x, nil
}

// Leaf computes the credential leaf Poseidon(secret, expiry, issuer).
func Leaf(h hash.Hasher, secret, expiry, issuer *big.Int) (*big.Int, error) {
	leaf, err := h.Hash(secret, expiry, issuer)
	if err != nil {
		return nil, fmt.Errorf("kyc: leaf hash: %w", err)
	}
	return leaf, nil
}

// Nullifier computes Poseidon(secret, root).
func Nullifier(h hash.Hasher, secret, root *big.Int) (*big.Int, error) {
	n, err := h.Hash(secret, root)
	if err != nil {
		return nil, fmt.Errorf("kyc: nullifier hash: %w", err)
	}
	return n, nil
}

// RandomSecret draws a uniform field element from r (crypto/rand.Reader in
// production).
func RandomSecret(r io.Reader) (*big.Int, error) {
	x, err := rand.Int(r, fieldModulus)
	if err != nil {
		return nil, fmt.Errorf("kyc: random secret: %w", err)
	}
	return x, nil
}

// HexField renders a field element as 0x-prefixed hex.
func HexField(x *big.Int) string {
	return "0x" + x.Text(16)
}

// parseField parses a non-negative decimal field element.
func parseField(s string) (*big.Int, error) {
	x, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidField, s)
	}
	return x, nil
}

// parseSecret parses a decimal secret and checks it lies in [0, fieldModulus).
func parseSecret(s string) (*big.Int, error) {
	x, err := parseField(s)
	if err != nil {
		return nil, err
	}
	if x.Sign() < 0 || x.Cmp(fieldModulus) >= 0 {
		return nil, fmt.Errorf("%w: %q", ErrSecretOutOfRange, s)
	}
	return x, nil
}

// resolveSecret returns the provided secret, or a fresh random one when empty.
func resolveSecret(secret string, r io.Reader) (*big.Int, error) {
	if secret != "" {
		return parseSecret(secret)
	}
	return RandomSecret(r)
}

// LoadState reads and decodes a state file.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kyc: read state %q: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("kyc: parse state %q: %w", path, err)
	}
	return &s, nil
}

// LoadOrCreateState loads a state file, returning an empty state when the file
// does not yet exist.
func LoadOrCreateState(path string) (*State, error) {
	s, err := LoadState(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &State{}, nil
		}
		return nil, err
	}
	return s, nil
}

// SaveState marshals and writes state, creating the parent directory as needed.
func SaveState(path string, s *State) error {
	data, err := marshalJSON(s)
	if err != nil {
		return fmt.Errorf("kyc: marshal state: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("kyc: mkdir %q: %w", dir, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("kyc: write state %q: %w", path, err)
	}
	return nil
}

// WriteInput marshals and writes a circuit input.json to an existing directory.
func WriteInput(path string, input CircuitInput) error {
	data, err := marshalJSON(input)
	if err != nil {
		return fmt.Errorf("kyc: marshal input: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("kyc: write input %q: %w", path, err)
	}
	return nil
}

// Tree rebuilds the Merkle tree from the persisted leaves.
func (s *State) Tree(depth int, h hash.Hasher) (*tree.Tree, error) {
	t, err := tree.New(depth, h)
	if err != nil {
		return nil, err
	}
	for _, ls := range s.Leaves {
		leaf, ok := new(big.Int).SetString(ls, 10)
		if !ok {
			return nil, fmt.Errorf("%w: leaf %q", ErrInvalidField, ls)
		}
		t.Append(leaf)
	}
	return t, nil
}

// indexOf returns the position of target in leaves, or -1.
func indexOf(leaves []string, target string) int {
	for i, l := range leaves {
		if l == target {
			return i
		}
	}
	return -1
}

// bigStrings renders field elements as decimal strings.
func bigStrings(xs []*big.Int) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.String()
	}
	return out
}

// intStrings renders path-index bits as decimal strings.
func intStrings(xs []int) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(x)
	}
	return out
}

// Issue appends a new credential leaf to the tree state and returns the secret,
// assigned index, and new root. The secret is never written to disk.
func Issue(h hash.Hasher, r io.Reader, statePath string, p IssueParams) (IssueResult, error) {
	return issue(h, r, consts.TreeDepth, statePath, p)
}

func issue(h hash.Hasher, r io.Reader, depth int, statePath string, p IssueParams) (IssueResult, error) {
	var res IssueResult
	if _, err := AddrToField(p.Addr); err != nil {
		return res, err
	}
	secret, err := resolveSecret(p.Secret, r)
	if err != nil {
		return res, err
	}
	expiry, err := parseField(p.Expiry)
	if err != nil {
		return res, err
	}
	issuer, err := parseField(p.Issuer)
	if err != nil {
		return res, err
	}
	leaf, err := Leaf(h, secret, expiry, issuer)
	if err != nil {
		return res, err
	}
	state, err := LoadOrCreateState(statePath)
	if err != nil {
		return res, err
	}
	index := len(state.Leaves)
	state.Leaves = append(state.Leaves, leaf.String())
	t, err := state.Tree(depth, h)
	if err != nil {
		return res, err
	}
	root, err := t.Root()
	if err != nil {
		return res, err
	}
	if err := SaveState(statePath, state); err != nil {
		return res, err
	}
	return IssueResult{Secret: secret, Index: index, RootDec: root.String(), RootHex: HexField(root)}, nil
}

// Root loads the state and returns the current root in decimal and hex.
func Root(h hash.Hasher, statePath string) (dec, hexStr string, err error) {
	return rootStrings(h, consts.TreeDepth, statePath)
}

func rootStrings(h hash.Hasher, depth int, statePath string) (dec, hexStr string, err error) {
	state, err := LoadState(statePath)
	if err != nil {
		return "", "", err
	}
	t, err := state.Tree(depth, h)
	if err != nil {
		return "", "", err
	}
	root, err := t.Root()
	if err != nil {
		return "", "", err
	}
	return root.String(), HexField(root), nil
}

// BuildProof reconstructs the leaf, locates it in the persisted tree, builds the
// Merkle path, and assembles the circuit input plus the derived nullifier.
func BuildProof(h hash.Hasher, statePath string, p ProveParams) (CircuitInput, string, error) {
	return buildProof(h, consts.TreeDepth, statePath, p)
}

func buildProof(h hash.Hasher, depth int, statePath string, p ProveParams) (CircuitInput, string, error) {
	var empty CircuitInput
	addrField, err := AddrToField(p.Addr)
	if err != nil {
		return empty, "", err
	}
	secret, err := parseSecret(p.Secret)
	if err != nil {
		return empty, "", err
	}
	expiry, err := parseField(p.Expiry)
	if err != nil {
		return empty, "", err
	}
	issuer, err := parseField(p.Issuer)
	if err != nil {
		return empty, "", err
	}
	leaf, err := Leaf(h, secret, expiry, issuer)
	if err != nil {
		return empty, "", err
	}
	state, err := LoadState(statePath)
	if err != nil {
		return empty, "", err
	}
	index := indexOf(state.Leaves, leaf.String())
	if index < 0 {
		return empty, "", fmt.Errorf("%w: index %d", ErrLeafNotFound, index)
	}
	t, err := state.Tree(depth, h)
	if err != nil {
		return empty, "", err
	}
	pathElements, pathIndices, root, err := t.Proof(index)
	if err != nil {
		return empty, "", err
	}
	nullifier, err := Nullifier(h, secret, root)
	if err != nil {
		return empty, "", err
	}
	input := CircuitInput{
		HolderSecret: secret.String(),
		IssuerID:     issuer.String(),
		PathElements: bigStrings(pathElements),
		PathIndices:  intStrings(pathIndices),
		Root:         root.String(),
		HolderAddr:   addrField.String(),
		Expiry:       expiry.String(),
	}
	return input, nullifier.String(), nil
}
