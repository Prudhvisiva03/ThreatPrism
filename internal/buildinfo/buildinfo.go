// Package buildinfo exposes version metadata injected at build time via
// -ldflags (see the Makefile).
package buildinfo

import "fmt"

var (
	// Version is the semantic version or git describe output.
	Version = "dev"
	// Commit is the short git commit hash.
	Commit = "none"
	// Date is the RFC3339 build timestamp.
	Date = "unknown"
)

// String returns a one-line human-readable build identifier.
func String() string {
	return fmt.Sprintf("threatprism %s (commit %s, built %s)", Version, Commit, Date)
}
