package kyc

// hexBase is the radix used for the 0x-prefixed field encodings this package
// reads and writes. Field elements cross the circuit boundary as hex, so the
// parse and the render side must always agree on it.
const hexBase = 16

// File modes for the artifacts this package persists.
//
//	stateDirPerm  parent directory of a state file. 0o750, narrowed from the
//	              historical 0o755 on the merits: this directory is written and
//	              read by one process, and nothing outside it needs the world
//	              bits. The linter did not drive this. Naming the mode here is
//	              by itself enough to silence gosec's G301, because that check
//	              only reads literals at the MkdirAll call site — so a clean
//	              lint run says nothing about which value is correct, and would
//	              have stayed just as clean had 0o755 been left in place. The
//	              choice was made by looking at who needs access, not by
//	              chasing a finding.
//	stateFilePerm state and circuit-input files: owner only. They carry the
//	              identity secret, so the group bit is not granted here.
const (
	stateDirPerm  = 0o750
	stateFilePerm = 0o600
)
