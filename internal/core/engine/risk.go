package engine

import (
	"fmt"

	"github.com/threatprism/threatprism/pkg/models"
)

// ComputeRisk derives an aggregate 0-100 risk score for a result. It blends the
// severity of findings, exposed secrets, and sensitive files, then normalizes
// so that a handful of critical issues approaches (but never guarantees) 100.
func ComputeRisk(r *models.Result) int {
	var raw int
	for _, f := range r.Findings {
		raw += f.Severity.Score()
	}
	for _, s := range r.Secrets {
		raw += s.Severity.Score()
	}
	for _, sf := range r.SensitiveFiles {
		raw += sf.Severity.Score()
	}
	// Small additive pressure from exposed surface area.
	raw += len(r.LoginPages) * 3
	raw += len(r.APIEndpoints)

	// Diminishing-returns normalization: map raw onto 0-100.
	// score = 100 * raw / (raw + k) with k tuned so ~300 raw => ~75.
	const k = 100
	if raw <= 0 {
		return 0
	}
	score := 100 * raw / (raw + k)
	if score > 100 {
		score = 100
	}
	return score
}

// errorf is a tiny fmt.Errorf alias kept package-local so engine.go reads
// cleanly without importing fmt directly for a single call site.
func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
