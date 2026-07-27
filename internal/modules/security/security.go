// Package security implements Security Analysis: it inspects HTTP security
// headers, cookies, CORS, and TLS/certificate posture, then produces graded
// findings and an overall risk contribution.
package security

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements security analysis.
type Module struct{ module.Meta }

// New returns a configured security module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "security",
		ModName:     "Security Analysis",
		ModDesc:     "Analyzes security headers, cookies, CORS, and TLS posture",
		ModCategory: "analysis",
		ModModes:    []models.Mode{models.ModeQuick, models.ModeStandard, models.ModeDeep},
	}}
}

// expectedHeaders lists security headers and the severity of their absence.
var expectedHeaders = []struct {
	name     string
	missing  models.Severity
}{
	{"Strict-Transport-Security", models.SeverityMedium},
	{"Content-Security-Policy", models.SeverityMedium},
	{"X-Frame-Options", models.SeverityLow},
	{"X-Content-Type-Options", models.SeverityLow},
	{"Referrer-Policy", models.SeverityInfo},
	{"Permissions-Policy", models.SeverityInfo},
}

// Run analyzes the target's security posture.
func (m *Module) Run(rc *module.RunContext) error {
	resp, err := rc.HTTP.Get(rc.Ctx, rc.Target.URL)
	if err != nil {
		return err
	}
	rc.Progress.Stepf("analyzing security headers and TLS")

	var headers []models.SecurityHeader
	var findings []models.Finding

	for _, eh := range expectedHeaders {
		val := resp.Header.Get(eh.name)
		present := val != ""
		headers = append(headers, models.SecurityHeader{Name: eh.name, Value: val, Present: present})
		if !present {
			findings = append(findings, models.Finding{
				Module: m.Slug(), Type: "missing_header", Severity: eh.missing, Confidence: 95,
				Title:       "Missing security header: " + eh.name,
				Description: "The " + eh.name + " response header is not set",
				URL:         resp.FinalURL, Tags: []string{"header", "hardening"}, FoundAt: time.Now(),
			})
		}
	}

	// Cookie flags.
	for _, c := range readCookies(resp.Header) {
		if !c.Secure || !c.HttpOnly {
			findings = append(findings, models.Finding{
				Module: m.Slug(), Type: "cookie", Severity: models.SeverityLow, Confidence: 80,
				Title:       "Cookie missing security flags: " + c.Name,
				Description: flagDesc(c),
				URL:         resp.FinalURL, Tags: []string{"cookie"}, FoundAt: time.Now(),
			})
		}
	}

	// CORS.
	if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao == "*" {
		findings = append(findings, models.Finding{
			Module: m.Slug(), Type: "cors", Severity: models.SeverityMedium, Confidence: 85,
			Title:       "Permissive CORS policy",
			Description: "Access-Control-Allow-Origin is set to '*'",
			URL:         resp.FinalURL, Tags: []string{"cors"}, FoundAt: time.Now(),
		})
	}

	// TLS inspection (only for https).
	var tlsInfo *models.TLSInfo
	if rc.Target.Scheme == "https" {
		tlsInfo = m.inspectTLS(rc)
		if tlsInfo != nil {
			if tlsInfo.Expired {
				findings = append(findings, models.Finding{
					Module: m.Slug(), Type: "tls", Severity: models.SeverityHigh, Confidence: 95,
					Title: "Expired TLS certificate", Description: "The server certificate has expired",
					URL: rc.Target.URL, Tags: []string{"tls"}, FoundAt: time.Now(),
				})
			}
			if tlsInfo.SelfSigned {
				findings = append(findings, models.Finding{
					Module: m.Slug(), Type: "tls", Severity: models.SeverityMedium, Confidence: 80,
					Title: "Self-signed TLS certificate", Description: "The certificate is self-signed",
					URL: rc.Target.URL, Tags: []string{"tls"}, FoundAt: time.Now(),
				})
			}
		}
	}

	rc.Update(func(r *models.Result) {
		r.SecurityHeaders = append(r.SecurityHeaders, headers...)
		r.Findings = append(r.Findings, findings...)
		if tlsInfo != nil {
			r.TLS = tlsInfo
		}
	})

	rc.Progress.Stepf("security analysis produced %d findings", len(findings))
	if rc.Workspace != nil {
		_, _ = rc.Workspace.WriteJSON("11_headers", "security.json", map[string]any{
			"headers": headers, "tls": tlsInfo, "findings": findings,
		})
	}
	return nil
}

func (m *Module) inspectTLS(rc *module.RunContext) *models.TLSInfo {
	host := rc.Target.Host
	port := rc.Target.Port
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // inspection only, never trust-decision
		ServerName:         host,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info := &models.TLSInfo{Version: tlsVersion(state.Version)}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Issuer = cert.Issuer.String()
		info.Subject = cert.Subject.String()
		info.NotBefore = cert.NotBefore
		info.NotAfter = cert.NotAfter
		info.DNSNames = cert.DNSNames
		info.Expired = time.Now().After(cert.NotAfter)
		info.SelfSigned = cert.Issuer.String() == cert.Subject.String()
	}
	return info
}

type cookie struct {
	Name     string
	Secure   bool
	HttpOnly bool
	SameSite bool
}

func readCookies(h http.Header) []cookie {
	var out []cookie
	for _, sc := range h.Values("Set-Cookie") {
		parts := strings.Split(sc, ";")
		if len(parts) == 0 {
			continue
		}
		name := strings.TrimSpace(strings.SplitN(parts[0], "=", 2)[0])
		c := cookie{Name: name}
		for _, p := range parts[1:] {
			switch strings.ToLower(strings.TrimSpace(p)) {
			case "secure":
				c.Secure = true
			case "httponly":
				c.HttpOnly = true
			}
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(p)), "samesite") {
				c.SameSite = true
			}
		}
		out = append(out, c)
	}
	return out
}

func flagDesc(c cookie) string {
	var missing []string
	if !c.Secure {
		missing = append(missing, "Secure")
	}
	if !c.HttpOnly {
		missing = append(missing, "HttpOnly")
	}
	return "Missing flags: " + strings.Join(missing, ", ")
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}
