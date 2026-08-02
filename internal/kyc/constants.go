package kyc

// hexBase is the radix used for the 0x-prefixed field encodings this package
// reads and writes. Field elements cross the circuit boundary as hex, so the
// parse and the render side must always agree on it.
const hexBase = 16

// File modes for the artifacts this package persists.
//
//	stateDirPerm  parent directory of a state file. This is the historical
//	              0o755 and is under review: gosec's G301 wants 0o750 or less,
//	              and nothing in this process needs the world bits. Note that
//	              naming the mode here is enough to stop G301 flagging it — the
//	              check only reads literals at the MkdirAll call site — so the
//	              clean lint result is not an endorsement of this value.
//	stateFilePerm state and circuit-input files: owner only. They carry the
//	              identity secret, so the group bit is not granted here.
const (
	stateDirPerm  = 0o755
	stateFilePerm = 0o600
)
