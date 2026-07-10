package main

import "testing"

// TestIntegrationCmd_CleanSweepExitsZero: the subcommand returns nil (exit 0) only when every
// integration clean-sweeps — so it is a valid CI gate.
func TestIntegrationCmd_CleanSweepExitsZero(t *testing.T) {
	if err := integrationCmd([]string{"--json"}); err != nil {
		t.Fatalf("integration coverage must be a clean sweep, got: %v", err)
	}
}
