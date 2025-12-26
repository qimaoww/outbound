package testutil

import (
	"os"
	"testing"
)

// RequireE2E skips flaky network-dependent tests unless OUTBOUND_E2E=1.
func RequireE2E(tb testing.TB) {
	tb.Helper()
	if os.Getenv("OUTBOUND_E2E") != "1" {
		tb.Skip("set OUTBOUND_E2E=1 to run outbound e2e tests")
	}
}
