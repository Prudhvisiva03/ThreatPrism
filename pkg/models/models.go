// Package models defines the shared domain types used across every ThreatPrism
// module, the persistence layer, the reporting engine, and the TUI.
//
// These types are deliberately dependency-free so that modules, plugins, and
// report renderers can all agree on a single representation of the attack
// surface without importing each other.
package models

import "time"

// Severity classifies the risk weight of a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Score returns a numeric weight for a severity, useful for risk aggregation.
func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 70
	case SeverityMedium:
		return 40
	case SeverityLow:
		return 15
	default:
		return 1
	}
}

// Target represents a normalized reconnaissance target.
type Target struct {
	Raw    string `json:"raw"`    // exactly what the user supplied
	Scheme string `json:"scheme"` // http / https
	Host   string `json:"host"`   // hostname or IP
	Port   string `json:"port"`   // explicit or scheme default
	URL    string `json:"url"`    // normalized absolute URL
	IsIP   bool   `json:"is_ip"`
	Apex   string `json:"apex"` // registrable/apex domain when derivable
}

// Finding is a generic, prioritizable observation produced by any module.
type Finding struct {
	ID          int64             `json:"id"`
	Module      string            `json:"module"`
	Type        string            `json:"type"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Confidence  int               `json:"confidence"` // 0-100
	URL         string            `json:"url,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	FoundAt     time.Time         `json:"found_at"`
}

// Subdomain is a discovered subdomain and its resolution state.
type Subdomain struct {
	Name    string   `json:"name"`
	Sources []string `json:"sources,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	Alive   bool     `json:"alive"`
	CNAME   string   `json:"cname,omitempty"`
}

// Host is an alive host with basic HTTP metadata.
type Host struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	Title         string `json:"title,omitempty"`
	ContentLength int64  `json:"content_length"`
	Server        string `json:"server,omitempty"`
	IP            string `json:"ip,omitempty"`
	CDN           string `json:"cdn,omitempty"`
	Scheme        string `json:"scheme,omitempty"`
}

// DNSRecord is a single resolved DNS record.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // A, AAAA, CNAME, MX, TXT, NS, ...
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// URLEntry is a discovered URL along with where it came from.
type URLEntry struct {
	URL        string   `json:"url"`
	Source     string   `json:"source"` // wayback, crawl, sitemap, robots, js, ...
	StatusCode int      `json:"status_code,omitempty"`
	Params     []string `json:"params,omitempty"`
}

// JSFile is a discovered JavaScript file plus extracted intelligence.
type JSFile struct {
	URL        string   `json:"url"`
	Size       int64    `json:"size"`
	Hash       string   `json:"hash,omitempty"`
	Endpoints  []string `json:"endpoints,omitempty"`
	URLs       []string `json:"urls,omitempty"`
	Params     []string `json:"params,omitempty"`
	Secrets    []Secret `json:"secrets,omitempty"`
	Libraries  []string `json:"libraries,omitempty"`
	Frameworks []string `json:"frameworks,omitempty"`
	SourceMap  string   `json:"source_map,omitempty"`
}

// Secret is a detected credential, key, or token.
type Secret struct {
	Type     string   `json:"type"` // aws_key, jwt, stripe, google, ...
	Value    string   `json:"value"`
	Redacted string   `json:"redacted"`
	Source   string   `json:"source"`
	Severity Severity `json:"severity"`
}

// APIEndpoint is a discovered API surface.
type APIEndpoint struct {
	URL      string   `json:"url"`
	Method   string   `json:"method,omitempty"`
	Kind     string   `json:"kind"` // rest, graphql, soap, swagger, openapi, postman
	Auth     string   `json:"auth,omitempty"`
	Params   []string `json:"params,omitempty"`
	Source   string   `json:"source,omitempty"`
}

// LoginPage is an identified authentication surface.
type LoginPage struct {
	URL        string   `json:"url"`
	Kind       string   `json:"kind"` // login, admin, dashboard, portal
	AuthType   string   `json:"auth_type,omitempty"`
	HasCaptcha bool     `json:"has_captcha"`
	HasOAuth   bool     `json:"has_oauth"`
	HasCSRF    bool     `json:"has_csrf"`
	Screenshot string   `json:"screenshot,omitempty"`
	Tech       []string `json:"tech,omitempty"`
}

// Technology is a fingerprinted technology.
type Technology struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Category   string   `json:"category"` // server, language, framework, cms, cdn, waf, js
	Confidence int      `json:"confidence"`
	CVEs       []string `json:"cves,omitempty"`
	Source     string   `json:"source,omitempty"`
}

// DirEntry is a result from directory/content discovery.
type DirEntry struct {
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Size       int64    `json:"size"`
	Title      string   `json:"title,omitempty"`
	Tech       []string `json:"tech,omitempty"`
	Class      string   `json:"class"` // ok, redirect, forbidden, error, ...
}

// SensitiveFile is a discovered file of security interest.
type SensitiveFile struct {
	URL        string   `json:"url"`
	Path       string   `json:"path"`
	StatusCode int      `json:"status_code"`
	Size       int64    `json:"size"`
	Severity   Severity `json:"severity"`
}

// Parameter is a discovered request parameter.
type Parameter struct {
	Name        string   `json:"name"`
	Sources     []string `json:"sources,omitempty"`
	Interesting bool     `json:"interesting"`
	Example     string   `json:"example,omitempty"`
}

// Screenshot references a captured screenshot stored in the workspace.
type Screenshot struct {
	URL   string `json:"url"`
	Path  string `json:"path"`
	Kind  string `json:"kind"`
	Title string `json:"title,omitempty"`
}

// SecurityHeader captures the state of one security-relevant HTTP header.
type SecurityHeader struct {
	Name    string `json:"name"`
	Value   string `json:"value,omitempty"`
	Present bool   `json:"present"`
	Grade   string `json:"grade,omitempty"`
}

// TLSInfo summarizes the TLS/certificate posture of a host.
type TLSInfo struct {
	Version    string    `json:"version,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	NotBefore  time.Time `json:"not_before,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	Expired    bool      `json:"expired"`
	SelfSigned bool      `json:"self_signed"`
}

// Note represents an investigation notebook entry attached to an asset.
type Note struct {
	ID        int64     `json:"id"`
	Target    string    `json:"target"`
	AssetURL  string    `json:"asset_url"`
	Text      string    `json:"text"`
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// AssetRating represents AI 5-star scoring and rationale for an asset.
type AssetRating struct {
	AssetURL string   `json:"asset_url"`
	Stars    int      `json:"stars"` // 1 to 5
	Reason   string   `json:"reason"`
	Tags     []string `json:"tags,omitempty"`
}

// TimelineEvent represents a historical change event across scans.
type TimelineEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Summary   string    `json:"summary"`
	Category  string    `json:"category"` // js, api, login, header, tech
	Delta     string    `json:"delta"`
}

