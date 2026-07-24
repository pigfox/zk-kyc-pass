// Package consts centralises every magic literal used by the kycctl CLI and its
// supporting packages: tree geometry, environment keys, default paths, the
// BN254 scalar field modulus, snarkjs sub-command tokens, and the generic
// per-proof file names. Keeping them here satisfies the project's
// no-magic-literals rule and gives one place to audit the fixed domain facts.
package consts

const (
	// TreeDepth is the fixed Merkle depth mandated by kycpass.circom.
	TreeDepth = 16

	// EnvTreeState names the environment variable that overrides the tree
	// state file location; DefaultStatePath is used when it is unset.
	EnvTreeState     = "KYC_TREE_STATE"
	DefaultStatePath = "./kycctl-state/tree.json"

	// EnvRepoRoot names the environment variable that points at the repo root
	// (where circuits/build lives); DefaultRepoRoot is the current directory.
	EnvRepoRoot     = "KYC_REPO_ROOT"
	DefaultRepoRoot = "."

	// FieldModulusDecimal is the BN254 scalar field order. A holderSecret must
	// be a field element strictly below this value.
	FieldModulusDecimal = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
)

// Generic per-proof artefact file names (circuit-agnostic).
const (
	InputFileName   = "input.json"
	WitnessFileName = "witness.wtns"
	ProofFileName   = "proof.json"
	PublicFileName  = "public.json"
)

// snarkjs invocation tokens. The wrapper builds commands of the shape
// `npx --no-install snarkjs <sub...>`.
const (
	NpxBin       = "npx"
	NpxNoInstall = "--no-install"
	SnarkjsBin   = "snarkjs"

	WtnsCmd             = "wtns"
	CalculateCmd        = "calculate"
	Groth16Cmd          = "groth16"
	ProveCmd            = "prove"
	VerifyCmd           = "verify"
	ZkeyCmd             = "zkey"
	ExportCmd           = "export"
	SolidityCalldataCmd = "soliditycalldata"
)
