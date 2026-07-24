package main

import (
	"os"
	"testing"
)

// TestMainDispatch runs main() with a stubbed exit so the wrapper is covered.
func TestMainDispatch(t *testing.T) {
	oldArgs := os.Args
	oldExit := osExit
	defer func() {
		os.Args = oldArgs
		osExit = oldExit
	}()

	var got int
	osExit = func(code int) { got = code }
	os.Args = []string{"kycctl"} // no subcommand → usage exit code 2.
	main()
	if got != 2 {
		t.Fatalf("main exit code = %d, want 2", got)
	}
}
