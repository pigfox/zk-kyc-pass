// Command kycctl is the issuer/prover CLI for the zk-kyc-pass circuit. All logic
// lives in internal/cli.Run; main is a one-line wrapper so the CLI stays fully
// table-testable. It also owns the process-wide root context, which is threaded
// down to the prover so a canceled run kills the snarkjs subprocess with it.
package main

import (
	"context"
	"os"

	"github.com/pigfox/zk-kyc-pass/internal/cli"
)

// osExit is a seam so main is fully coverable without terminating the test
// process.
var osExit = os.Exit

func main() {
	osExit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}
