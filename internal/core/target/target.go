// Package target parses and normalizes user-supplied reconnaissance targets
// into a canonical models.Target.
package target

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/threatprism/threatprism/pkg/models"
)

// Parse normalizes a raw target string (a URL, host, host:port, or IP) into a
// models.Target. It defaults to https when no scheme is supplied.
func Parse(raw string) (models.Target, error) {
	t := models.Target{Raw: strings.TrimSpace(raw)}
	if t.Raw == "" {
		return t, fmt.Errorf("empty target")
	}

	s := t.Raw
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return t, fmt.Errorf("invalid target %q: %w", raw, err)
	}
	if u.Hostname() == "" {
		return t, fmt.Errorf("target %q has no host", raw)
	}

	t.Scheme = u.Scheme
	t.Host = u.Hostname()
	t.Port = u.Port()
	t.IsIP = net.ParseIP(t.Host) != nil

	if t.Port == "" {
		if t.Scheme == "http" {
			t.Port = "80"
		} else {
			t.Port = "443"
		}
	}

	// Rebuild a clean normalized URL preserving path.
	nu := &url.URL{Scheme: t.Scheme, Host: u.Host, Path: u.Path}
	if nu.Path == "" {
		nu.Path = "/"
	}
	t.URL = nu.String()

	if !t.IsIP {
		t.Apex = apexOf(t.Host)
	}
	return t, nil
}

// apexOf derives a best-effort registrable/apex domain from a host. It does not
// consult the public suffix list (kept dependency-free); it returns the last
// two labels, which is correct for the common single-suffix TLDs and a safe
// grouping key otherwise.
func apexOf(host string) string {
	host = strings.TrimSuffix(host, ".")
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// InScope reports whether candidate belongs to the same apex domain as the
// target (or is the target host itself). Used to keep crawling on-scope.
func InScope(t models.Target, candidate string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	if candidate == "" {
		return false
	}
	if h, err := hostOnly(candidate); err == nil {
		candidate = h
	}
	if candidate == strings.ToLower(t.Host) {
		return true
	}
	if t.Apex == "" {
		return false
	}
	return candidate == t.Apex || strings.HasSuffix(candidate, "."+t.Apex)
}

func hostOnly(s string) (string, error) {
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	return strings.ToLower(u.Hostname()), nil
}
