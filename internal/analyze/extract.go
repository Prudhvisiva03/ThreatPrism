// Package analyze provides shared, dependency-light extraction helpers used by
// the JavaScript, API, and parameter intelligence modules: secret detection,
// endpoint/URL/parameter extraction, and simple entity scraping (emails, IPs).
//
// Detection is regex-based and tuned to minimize false positives while
// surfacing the high-signal credential formats that matter in recon.
package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/threatprism/threatprism/pkg/models"
)

// secretRule pairs a named pattern with the severity of a match.
type secretRule struct {
	name     string
	re       *regexp.Regexp
	severity models.Severity
}

var secretRules = []secretRule{
	{"aws_access_key", regexp.MustCompile(`\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`), models.SeverityCritical},
	{"aws_secret_key", regexp.MustCompile(`(?i)aws(.{0,20})?(secret|access).{0,20}?['"][0-9a-zA-Z/+]{40}['"]`), models.SeverityCritical},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), models.SeverityHigh},
	{"google_oauth", regexp.MustCompile(`\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`), models.SeverityMedium},
	{"firebase", regexp.MustCompile(`\b[a-z0-9-]+\.firebaseio\.com\b`), models.SeverityMedium},
	{"stripe_secret", regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`), models.SeverityCritical},
	{"stripe_pub", regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{24,}\b`), models.SeverityLow},
	{"twilio_sid", regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`), models.SeverityHigh},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`), models.SeverityHigh},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}\b`), models.SeverityCritical},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`), models.SeverityMedium},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----`), models.SeverityCritical},
	{"generic_secret", regexp.MustCompile(`(?i)(api[_-]?key|secret|passwd|password|token)['"\s:=]{1,5}['"][0-9a-zA-Z\-_@#$%!]{12,}['"]`), models.SeverityMedium},
}

var (
	reURL      = regexp.MustCompile(`https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[^\s"'<>()]*)?`)
	reEndpoint = regexp.MustCompile(`["'\` + "`" + `](/[a-zA-Z0-9_\-/.]{2,}(?:\?[^"'\` + "`" + `]*)?)["'\` + "`" + `]`)
	reEmail    = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	reIP       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reS3       = regexp.MustCompile(`\b[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com\b|\bs3://[a-z0-9.\-]+`)
	reParamQS  = regexp.MustCompile(`[?&]([a-zA-Z0-9_\-\[\]]{1,40})=`)
	reParamJS  = regexp.MustCompile(`(?:params|data|body|query)\s*[:=]\s*\{([^}]{0,300})\}`)
	reKeyish   = regexp.MustCompile(`["']([a-zA-Z_][a-zA-Z0-9_]{1,40})["']\s*:`)
)

// DetectSecrets scans text and returns any secrets found, tagged with source.
func DetectSecrets(text, source string) []models.Secret {
	var out []models.Secret
	seen := map[string]bool{}
	for _, rule := range secretRules {
		for _, m := range rule.re.FindAllString(text, -1) {
			key := rule.name + "|" + m
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, models.Secret{
				Type:     rule.name,
				Value:    m,
				Redacted: Redact(m),
				Source:   source,
				Severity: rule.severity,
			})
		}
	}
	return out
}

// Redact masks the middle of a secret so reports never leak the full value.
func Redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

// ExtractURLs returns absolute http(s) URLs found in text.
func ExtractURLs(text string) []string {
	return dedup(reURL.FindAllString(text, -1))
}

// ExtractEndpoints returns relative path endpoints referenced in quoted
// strings (common in JS/API clients).
func ExtractEndpoints(text string) []string {
	var out []string
	for _, m := range reEndpoint.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			out = append(out, m[1])
		}
	}
	return dedup(out)
}

// ExtractParams returns parameter names found in query strings and inline JS
// object/property positions.
func ExtractParams(text string) []string {
	var out []string
	for _, m := range reParamQS.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	for _, block := range reParamJS.FindAllStringSubmatch(text, -1) {
		for _, kv := range reKeyish.FindAllStringSubmatch(block[1], -1) {
			out = append(out, kv[1])
		}
	}
	return dedup(out)
}

// ExtractParamsFromURL returns the query parameter names of a URL.
func ExtractParamsFromURL(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []string
	for k := range u.Query() {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ExtractEmails returns email addresses found in text.
func ExtractEmails(text string) []string { return dedup(reEmail.FindAllString(text, -1)) }

// ExtractIPs returns IPv4 addresses found in text.
func ExtractIPs(text string) []string { return dedup(reIP.FindAllString(text, -1)) }

// ExtractS3Buckets returns S3 bucket references found in text.
func ExtractS3Buckets(text string) []string { return dedup(reS3.FindAllString(text, -1)) }

// Hash returns a short content hash used to de-duplicate JS files.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16]
}

// InterestingParam reports whether a parameter name is commonly linked to
// vulnerabilities and therefore worth highlighting.
func InterestingParam(name string) bool {
	n := strings.ToLower(name)
	for _, k := range interestingParams {
		if n == k || strings.Contains(n, k) {
			return true
		}
	}
	return false
}

var interestingParams = []string{
	"redirect", "url", "next", "return", "callback", "file", "path", "dir",
	"page", "id", "user", "admin", "token", "key", "cmd", "exec", "query",
	"search", "q", "debug", "test", "template", "include", "load", "dest",
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Fingerprint is a compact, quoted representation used in log lines.
func Fingerprint(v any) string { return fmt.Sprintf("%v", v) }

// StaticExtensions lists file extensions considered non-dynamic noise in recon.
var StaticExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".css": true, ".woff": true, ".woff2": true, ".ttf": true, ".ico": true,
	".eot": true, ".mp4": true, ".mp3": true, ".webp": true, ".pdf": true,
}

// IsStaticNoise checks if a URL points to a static media or font file.
func IsStaticNoise(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for ext := range StaticExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// FilterPassiveData deduplicates, filters static noise, and clusters URLs into dynamic patterns.
func FilterPassiveData(urls []models.URLEntry) []models.URLEntry {
	seenPatterns := make(map[string]bool)
	var filtered []models.URLEntry

	for _, entry := range urls {
		if IsStaticNoise(entry.URL) {
			continue
		}
		u, err := url.Parse(entry.URL)
		if err != nil {
			continue
		}

		// Normalize query params for pattern matching (e.g. /item?id=123 -> /item?id={param})
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		patternKey := u.Host + u.Path + "?" + strings.Join(keys, "&")

		if seenPatterns[patternKey] {
			continue
		}
		seenPatterns[patternKey] = true
		filtered = append(filtered, entry)
	}

	return filtered
}

