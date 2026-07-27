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

// EstimateBountyPayout calculates estimated HackerOne/Bugcrowd bounty rewards based on finding severity and category.
func EstimateBountyPayout(f models.Finding) (string, string) {
	t := f.Type
	sev := f.Severity

	switch sev {
	case models.SeverityCritical:
		if t == "rce" || t == "sqli" || t == "auth_bypass" {
			return "$1,500 – $3,000", "Critical Vulnerability (RCE/SQLi/Auth Bypass)"
		}
		return "$1,500+", "Critical Impact"
	case models.SeverityHigh:
		if t == "ssrf" || t == "account_takeover" || t == "idor" {
			return "$750 – $1,500", "High Severity (SSRF/ATO/IDOR)"
		}
		return "$750 – $1,000", "High Impact"
	case models.SeverityMedium:
		if t == "xss" || t == "logic_bypass" {
			return "$150 – $400", "Medium Severity (XSS/Logic)"
		}
		return "$150 – $300", "Medium Impact"
	case models.SeverityLow:
		if t == "subdomain_takeover" {
			return "$50 – $100", "Low Severity (Subdomain Takeover)"
		}
		return "$50", "Low Impact"
	default:
		return "$0 (Informative)", "Out of Scope / No Direct Impact"
	}
}

// IsOutOfScopeNoise checks if a finding type is typically excluded by bug bounty programs (e.g. SPF/DKIM, Clickjacking, Self-XSS).
func IsOutOfScopeNoise(f models.Finding) bool {
	t := f.Type
	switch t {
	case "spf_dmarc_issue", "clickjacking", "self_xss", "tls_version_warning", "missing_csrf_without_impact":
		return true
	default:
		return false
	}
}

// errorf is a tiny fmt.Errorf alias kept package-local so engine.go reads
// cleanly without importing fmt directly for a single call site.
func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

