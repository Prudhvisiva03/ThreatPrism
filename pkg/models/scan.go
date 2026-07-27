package models

import "time"

// Mode identifies a reconnaissance depth profile.
type Mode string

const (
	ModeQuick    Mode = "quick"
	ModeStandard Mode = "standard"
	ModeDeep     Mode = "deep"
	ModeCustom   Mode = "custom"
)

// AllModes lists the selectable recon modes in order of increasing depth.
func AllModes() []Mode { return []Mode{ModeQuick, ModeStandard, ModeDeep, ModeCustom} }

// Describe returns a human-readable summary of a mode.
func (m Mode) Describe() string {
	switch m {
	case ModeQuick:
		return "Fast reconnaissance — the essentials, quickly."
	case ModeStandard:
		return "Everything required for bug bounty."
	case ModeDeep:
		return "Complete attack surface discovery."
	case ModeCustom:
		return "User selects the exact modules to run."
	default:
		return string(m)
	}
}

// Valid reports whether m is a recognized mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeQuick, ModeStandard, ModeDeep, ModeCustom:
		return true
	}
	return false
}

// ScanStatus is the lifecycle state of a scan.
type ScanStatus string

const (
	ScanPending   ScanStatus = "pending"
	ScanRunning   ScanStatus = "running"
	ScanPaused    ScanStatus = "paused"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCanceled  ScanStatus = "canceled"
)

// Scan is a single reconnaissance run against a target.
type Scan struct {
	ID        int64      `json:"id"`
	Workspace string     `json:"workspace"`
	Target    string     `json:"target"`
	Mode      Mode       `json:"mode"`
	Modules   []string   `json:"modules"`
	Status    ScanStatus `json:"status"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   time.Time  `json:"ended_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// Duration returns how long the scan ran (or has been running).
func (s Scan) Duration() time.Duration {
	end := s.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(s.StartedAt)
}

// ModuleStat captures per-module execution accounting for a scan.
type ModuleStat struct {
	Module   string        `json:"module"`
	Status   string        `json:"status"`
	Findings int           `json:"findings"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
}

// Result is the complete aggregated attack-surface picture for a scan.
// Modules append to the collections they own; the engine assembles the whole.
type Result struct {
	Target          Target           `json:"target"`
	Mode            Mode             `json:"mode"`
	Subdomains      []Subdomain      `json:"subdomains,omitempty"`
	Hosts           []Host           `json:"hosts,omitempty"`
	DNSRecords      []DNSRecord      `json:"dns_records,omitempty"`
	URLs            []URLEntry       `json:"urls,omitempty"`
	JSFiles         []JSFile         `json:"js_files,omitempty"`
	APIEndpoints    []APIEndpoint    `json:"api_endpoints,omitempty"`
	LoginPages      []LoginPage      `json:"login_pages,omitempty"`
	Technologies    []Technology     `json:"technologies,omitempty"`
	Directories     []DirEntry       `json:"directories,omitempty"`
	SensitiveFiles  []SensitiveFile  `json:"sensitive_files,omitempty"`
	Parameters      []Parameter      `json:"parameters,omitempty"`
	Secrets         []Secret         `json:"secrets,omitempty"`
	Screenshots     []Screenshot     `json:"screenshots,omitempty"`
	SecurityHeaders []SecurityHeader `json:"security_headers,omitempty"`
	TLS             *TLSInfo         `json:"tls,omitempty"`
	Findings        []Finding        `json:"findings,omitempty"`
	ModuleStats     []ModuleStat     `json:"module_stats,omitempty"`
	RiskScore       int              `json:"risk_score"`
	StartedAt       time.Time        `json:"started_at"`
	EndedAt         time.Time        `json:"ended_at"`
}

// RiskLevel maps the aggregate RiskScore to a coarse label.
func (r *Result) RiskLevel() string {
	switch {
	case r.RiskScore >= 80:
		return "critical"
	case r.RiskScore >= 60:
		return "high"
	case r.RiskScore >= 35:
		return "medium"
	case r.RiskScore >= 10:
		return "low"
	default:
		return "minimal"
	}
}
