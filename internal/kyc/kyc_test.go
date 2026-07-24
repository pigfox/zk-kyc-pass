package kyc

import (
	"crypto/rand"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/pigfox/zk-kyc-pass/internal/hash"
)

var errBoom = errors.New("boom")

// fakeHasher is deterministic (sum of inputs) and can fail on and after a chosen
// call, so every hash-dependent error branch is reachable.
type fakeHasher struct {
	calls  int
	failAt int
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

// errReader always fails, to drive RandomSecret's error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }

const validAddr = "0x00000000000000000000000000000000000000AA"

func tmpState(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state.json")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

func TestAddrToField(t *testing.T) {
	got, err := AddrToField(validAddr)
	if err != nil {
		t.Fatalf("AddrToField: %v", err)
	}
	if got.Cmp(big.NewInt(0xAA)) != 0 {
		t.Fatalf("addr field = %s, want 170", got)
	}
	if _, err := AddrToField("0X00000000000000000000000000000000000000ab"); err != nil {
		t.Fatalf("uppercase prefix: %v", err)
	}
	if _, err := AddrToField("0x1234"); !errors.Is(err, ErrInvalidAddr) {
		t.Fatalf("short addr err = %v", err)
	}
	if _, err := AddrToField("0xzz00000000000000000000000000000000000000"); !errors.Is(err, ErrInvalidAddr) {
		t.Fatalf("bad hex err = %v", err)
	}
}

func TestLeafAndNullifier(t *testing.T) {
	h := hash.PoseidonHasher{}
	leaf, err := Leaf(h, big.NewInt(5), big.NewInt(10), big.NewInt(3))
	if err != nil || leaf == nil {
		t.Fatalf("Leaf: %v", err)
	}
	n, err := Nullifier(h, big.NewInt(5), big.NewInt(99))
	if err != nil || n == nil {
		t.Fatalf("Nullifier: %v", err)
	}
	if _, err := Leaf(&fakeHasher{failAt: 1}, big.NewInt(1), big.NewInt(2), big.NewInt(3)); !errors.Is(err, errBoom) {
		t.Fatalf("Leaf error = %v", err)
	}
	if _, err := Nullifier(&fakeHasher{failAt: 1}, big.NewInt(1), big.NewInt(2)); !errors.Is(err, errBoom) {
		t.Fatalf("Nullifier error = %v", err)
	}
}

func TestRandomSecret(t *testing.T) {
	s, err := RandomSecret(rand.Reader)
	if err != nil {
		t.Fatalf("RandomSecret: %v", err)
	}
	if s.Sign() < 0 || s.Cmp(fieldModulus) >= 0 {
		t.Fatalf("secret out of range: %s", s)
	}
	if _, err := RandomSecret(errReader{}); !errors.Is(err, errBoom) {
		t.Fatalf("RandomSecret error = %v", err)
	}
}

func TestHexField(t *testing.T) {
	if got := HexField(big.NewInt(255)); got != "0xff" {
		t.Fatalf("HexField = %q", got)
	}
}

func TestParseHelpers(t *testing.T) {
	if _, err := parseField("123"); err != nil {
		t.Fatalf("parseField: %v", err)
	}
	if _, err := parseField("abc"); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("parseField bad = %v", err)
	}
	if _, err := parseSecret("42"); err != nil {
		t.Fatalf("parseSecret: %v", err)
	}
	if _, err := parseSecret("nope"); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("parseSecret invalid = %v", err)
	}
	if _, err := parseSecret("-1"); !errors.Is(err, ErrSecretOutOfRange) {
		t.Fatalf("parseSecret negative = %v", err)
	}
	if _, err := parseSecret(fieldModulus.String()); !errors.Is(err, ErrSecretOutOfRange) {
		t.Fatalf("parseSecret modulus = %v", err)
	}
}

func TestResolveSecret(t *testing.T) {
	got, err := resolveSecret("7", nil)
	if err != nil || got.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("resolveSecret provided = (%v,%v)", got, err)
	}
	rnd, err := resolveSecret("", rand.Reader)
	if err != nil || rnd == nil {
		t.Fatalf("resolveSecret random = (%v,%v)", rnd, err)
	}
	if _, err := resolveSecret("", errReader{}); !errors.Is(err, errBoom) {
		t.Fatalf("resolveSecret random error = %v", err)
	}
}

func TestLoadState(t *testing.T) {
	path := tmpState(t)
	if _, err := LoadState(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadState missing = %v", err)
	}
	writeFile(t, path, "{ not json")
	if _, err := LoadState(path); err == nil {
		t.Fatalf("LoadState bad json: want error")
	}
	writeFile(t, path, `{"leaves":["1","2"]}`)
	s, err := LoadState(path)
	if err != nil || len(s.Leaves) != 2 {
		t.Fatalf("LoadState good = (%v,%v)", s, err)
	}
}

func TestLoadOrCreateState(t *testing.T) {
	path := tmpState(t)
	s, err := LoadOrCreateState(path)
	if err != nil || len(s.Leaves) != 0 {
		t.Fatalf("LoadOrCreate missing = (%v,%v)", s, err)
	}
	writeFile(t, path, "{ bad")
	if _, err := LoadOrCreateState(path); err == nil {
		t.Fatalf("LoadOrCreate bad json: want error")
	}
	writeFile(t, path, `{"leaves":["9"]}`)
	s, err = LoadOrCreateState(path)
	if err != nil || len(s.Leaves) != 1 {
		t.Fatalf("LoadOrCreate good = (%v,%v)", s, err)
	}
}

func TestSaveState(t *testing.T) {
	path := tmpState(t)
	if err := SaveState(path, &State{Leaves: []string{"3"}}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	got, err := LoadState(path)
	if err != nil || len(got.Leaves) != 1 || got.Leaves[0] != "3" {
		t.Fatalf("round-trip = (%v,%v)", got, err)
	}

	// Marshal error via seam.
	restore := marshalJSON
	marshalJSON = func(any) ([]byte, error) { return nil, errBoom }
	err = SaveState(path, &State{})
	marshalJSON = restore
	if !errors.Is(err, errBoom) {
		t.Fatalf("SaveState marshal err = %v", err)
	}

	// MkdirAll error: a regular file stands where a parent dir is needed.
	fileAsDir := filepath.Join(t.TempDir(), "afile")
	writeFile(t, fileAsDir, "x")
	if err := SaveState(filepath.Join(fileAsDir, "sub", "s.json"), &State{}); err == nil {
		t.Fatalf("SaveState mkdir: want error")
	}

	// WriteFile error: the target path is an existing directory.
	if err := SaveState(t.TempDir(), &State{}); err == nil {
		t.Fatalf("SaveState write-to-dir: want error")
	}
}

func TestWriteInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	in := CircuitInput{HolderSecret: "1", PathIndices: []string{"0"}}
	if err := WriteInput(path, in); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}
	restore := marshalJSON
	marshalJSON = func(any) ([]byte, error) { return nil, errBoom }
	err := WriteInput(path, in)
	marshalJSON = restore
	if !errors.Is(err, errBoom) {
		t.Fatalf("WriteInput marshal err = %v", err)
	}
	if err := WriteInput(filepath.Join("/no-such-dir-zzz", "input.json"), in); err == nil {
		t.Fatalf("WriteInput bad dir: want error")
	}
}

func TestStateTree(t *testing.T) {
	s := &State{Leaves: []string{"1", "2", "3"}}
	tr, err := s.Tree(4, hash.PoseidonHasher{})
	if err != nil || tr.Len() != 3 {
		t.Fatalf("Tree good = (%v,%v)", tr, err)
	}
	if _, err := (&State{Leaves: []string{"notnum"}}).Tree(4, hash.PoseidonHasher{}); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("Tree bad leaf = %v", err)
	}
	if _, err := (&State{}).Tree(2, &fakeHasher{failAt: 1}); !errors.Is(err, errBoom) {
		t.Fatalf("Tree hasher err = %v", err)
	}
}

func TestIndexOf(t *testing.T) {
	xs := []string{"a", "b", "c"}
	if indexOf(xs, "b") != 1 {
		t.Fatalf("indexOf found wrong")
	}
	if indexOf(xs, "z") != -1 {
		t.Fatalf("indexOf missing wrong")
	}
}

// TestExportedHappyPath runs Issue -> Root -> BuildProof at the real depth with
// real Poseidon, covering the thin exported wrappers.
func TestExportedHappyPath(t *testing.T) {
	h := hash.PoseidonHasher{}
	path := tmpState(t)
	p := IssueParams{Addr: validAddr, Secret: "987654321098765", Expiry: "4102444800", Issuer: "42"}
	res, err := Issue(h, rand.Reader, path, p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.Index != 0 || res.RootDec == "" || res.RootHex[:2] != "0x" {
		t.Fatalf("Issue result = %+v", res)
	}
	// Secret must not be persisted.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if want := res.Secret.String(); len(want) > 0 && containsStr(string(raw), want) {
		t.Fatalf("secret leaked into state file")
	}

	dec, hexStr, err := Root(h, path)
	if err != nil || dec != res.RootDec || hexStr != res.RootHex {
		t.Fatalf("Root = (%s,%s,%v)", dec, hexStr, err)
	}

	input, nullifier, err := BuildProof(h, path, ProveParams{Addr: validAddr, Secret: "987654321098765", Expiry: "4102444800", Issuer: "42"})
	if err != nil {
		t.Fatalf("BuildProof: %v", err)
	}
	if len(input.PathElements) != 16 || len(input.PathIndices) != 16 {
		t.Fatalf("path lengths = %d/%d", len(input.PathElements), len(input.PathIndices))
	}
	if input.Root != res.RootDec || input.HolderAddr != "170" || input.Expiry != "4102444800" || input.IssuerID != "42" {
		t.Fatalf("input = %+v", input)
	}
	if nullifier == "" {
		t.Fatalf("empty nullifier")
	}

	// A second issue advances the index.
	res2, err := Issue(h, rand.Reader, path, IssueParams{Addr: validAddr, Secret: "111", Expiry: "1", Issuer: "2"})
	if err != nil || res2.Index != 1 {
		t.Fatalf("second issue = (%+v,%v)", res2, err)
	}
}

func containsStr(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && indexOfSub(hay, needle) >= 0
}

func indexOfSub(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestIssueErrorBranches(t *testing.T) {
	h := hash.PoseidonHasher{}
	base := IssueParams{Addr: validAddr, Secret: "5", Expiry: "10", Issuer: "3"}

	// Bad address.
	if _, err := issue(h, nil, 4, tmpState(t), IssueParams{Addr: "bad"}); !errors.Is(err, ErrInvalidAddr) {
		t.Fatalf("issue addr err = %v", err)
	}
	// Bad secret.
	bad := base
	bad.Secret = "-1"
	if _, err := issue(h, nil, 4, tmpState(t), bad); !errors.Is(err, ErrSecretOutOfRange) {
		t.Fatalf("issue secret err = %v", err)
	}
	// Bad expiry.
	bad = base
	bad.Expiry = "x"
	if _, err := issue(h, nil, 4, tmpState(t), bad); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("issue expiry err = %v", err)
	}
	// Bad issuer.
	bad = base
	bad.Issuer = "y"
	if _, err := issue(h, nil, 4, tmpState(t), bad); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("issue issuer err = %v", err)
	}
	// Leaf hash error.
	if _, err := issue(&fakeHasher{failAt: 1}, nil, 2, tmpState(t), base); !errors.Is(err, errBoom) {
		t.Fatalf("issue leaf err = %v", err)
	}
	// LoadOrCreateState error (existing bad-JSON file, not "not exist").
	badState := tmpState(t)
	writeFile(t, badState, "{ bad")
	if _, err := issue(h, nil, 4, badState, base); err == nil {
		t.Fatalf("issue load err: want error")
	}
	// state.Tree error: Leaf ok (call 1), New fails (call 2).
	if _, err := issue(&fakeHasher{failAt: 2}, nil, 2, tmpState(t), base); !errors.Is(err, errBoom) {
		t.Fatalf("issue tree err = %v", err)
	}
	// Root error: Leaf(1) + New(2,3) ok, layers fails (call 4).
	if _, err := issue(&fakeHasher{failAt: 4}, nil, 2, tmpState(t), base); !errors.Is(err, errBoom) {
		t.Fatalf("issue root err = %v", err)
	}
	// SaveState error via marshal seam.
	restore := marshalJSON
	marshalJSON = func(any) ([]byte, error) { return nil, errBoom }
	_, err := issue(h, nil, 4, tmpState(t), base)
	marshalJSON = restore
	if !errors.Is(err, errBoom) {
		t.Fatalf("issue save err = %v", err)
	}
}

func TestRootStringsErrorBranches(t *testing.T) {
	// LoadState error.
	if _, _, err := rootStrings(hash.PoseidonHasher{}, 4, tmpState(t)); err == nil {
		t.Fatalf("rootStrings missing state: want error")
	}
	// state.Tree parse error.
	badLeaf := tmpState(t)
	writeFile(t, badLeaf, `{"leaves":["notnum"]}`)
	if _, _, err := rootStrings(hash.PoseidonHasher{}, 4, badLeaf); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("rootStrings bad leaf = %v", err)
	}
	// Root hash error: New(1,2) ok, layers fails (call 3).
	oneLeaf := tmpState(t)
	writeFile(t, oneLeaf, `{"leaves":["1"]}`)
	if _, _, err := rootStrings(&fakeHasher{failAt: 3}, 2, oneLeaf); !errors.Is(err, errBoom) {
		t.Fatalf("rootStrings root err = %v", err)
	}
}

func TestBuildProofErrorBranches(t *testing.T) {
	h := hash.PoseidonHasher{}
	base := ProveParams{Addr: validAddr, Secret: "5", Expiry: "10", Issuer: "3"}

	// Bad address.
	if _, _, err := buildProof(h, 4, tmpState(t), ProveParams{Addr: "bad"}); !errors.Is(err, ErrInvalidAddr) {
		t.Fatalf("buildProof addr err = %v", err)
	}
	// Bad secret.
	bad := base
	bad.Secret = "-1"
	if _, _, err := buildProof(h, 4, tmpState(t), bad); !errors.Is(err, ErrSecretOutOfRange) {
		t.Fatalf("buildProof secret err = %v", err)
	}
	// Bad expiry.
	bad = base
	bad.Expiry = "x"
	if _, _, err := buildProof(h, 4, tmpState(t), bad); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("buildProof expiry err = %v", err)
	}
	// Bad issuer.
	bad = base
	bad.Issuer = "y"
	if _, _, err := buildProof(h, 4, tmpState(t), bad); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("buildProof issuer err = %v", err)
	}
	// Leaf hash error.
	if _, _, err := buildProof(&fakeHasher{failAt: 1}, 2, tmpState(t), base); !errors.Is(err, errBoom) {
		t.Fatalf("buildProof leaf err = %v", err)
	}
	// LoadState error (missing file).
	if _, _, err := buildProof(h, 4, tmpState(t), base); err == nil {
		t.Fatalf("buildProof load err: want error")
	}
	// Leaf not found: state present but without this leaf.
	noLeaf := tmpState(t)
	writeFile(t, noLeaf, `{"leaves":["999999"]}`)
	if _, _, err := buildProof(h, 4, noLeaf, base); !errors.Is(err, ErrLeafNotFound) {
		t.Fatalf("buildProof not found = %v", err)
	}

	// For the fake-hasher paths the leaf value is sum(secret,expiry,issuer)=18.
	sumState := tmpState(t)
	writeFile(t, sumState, `{"leaves":["18"]}`)
	// state.Tree error: Leaf(1) ok, New fails (call 2).
	if _, _, err := buildProof(&fakeHasher{failAt: 2}, 2, sumState, base); !errors.Is(err, errBoom) {
		t.Fatalf("buildProof tree err = %v", err)
	}
	// Proof error: Leaf(1)+New(2,3) ok, layers fails (call 4).
	if _, _, err := buildProof(&fakeHasher{failAt: 4}, 2, sumState, base); !errors.Is(err, errBoom) {
		t.Fatalf("buildProof proof err = %v", err)
	}
	// Nullifier error: Leaf(1)+New(2,3)+layers(4,5) ok, nullifier fails (call 6).
	if _, _, err := buildProof(&fakeHasher{failAt: 6}, 2, sumState, base); !errors.Is(err, errBoom) {
		t.Fatalf("buildProof nullifier err = %v", err)
	}
}
