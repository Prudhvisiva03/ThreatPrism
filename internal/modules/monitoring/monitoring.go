// Package monitoring implements the Monitoring Engine: it diffs the current
// scan result against the most recent prior result for the same target and
// surfaces changes as findings (new subdomains, JS files, APIs, login pages,
// technology changes, header changes).
package monitoring

import (
	"fmt"
	"time"

	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements the monitoring / change-detection engine.
type Module struct{ module.Meta }

// New returns a configured monitoring module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "monitoring",
		ModName:     "Monitoring Engine",
		ModDesc:     "Diffs current scan against the previous baseline and surfaces changes",
		ModCategory: "analysis",
		ModModes:    []models.Mode{models.ModeStandard, models.ModeDeep},
	}}
}

// Run compares the current result to the previous stored result.
func (m *Module) Run(rc *module.RunContext) error {
	if rc.Store == nil {
		rc.Progress.Stepf("no store available; skipping monitoring diff")
		return nil
	}

	// Find the most recent completed scan for this target.
	scans, err := rc.Store.ListScans(rc.Target.URL)
	if err != nil || len(scans) == 0 {
		rc.Progress.Stepf("no prior scan found; this is the baseline")
		return nil
	}
	// The current scan is the newest; we want the one before it.
	if len(scans) < 2 {
		rc.Progress.Stepf("no prior completed scan to diff against")
		return nil
	}
	prev, err := rc.Store.Result(scans[1].ID)
	if err != nil || prev == nil {
		rc.Progress.Stepf("could not load prior result; skipping diff")
		return nil
	}

	rc.Progress.Stepf("diffing against scan from %s", scans[1].StartedAt.Format("2006-01-02 15:04"))

	var findings []models.Finding
	curr := rc.Result()

	// New subdomains.
	oldSubs := setOf(func() []string {
		out := make([]string, len(prev.Subdomains))
		for i, s := range prev.Subdomains {
			out[i] = s.Name
		}
		return out
	}())
	for _, s := range curr.Subdomains {
		if !oldSubs[s.Name] {
			findings = append(findings, change("subdomain", "New subdomain discovered: "+s.Name, s.Name, models.SeverityMedium))
		}
	}

	// New JS files.
	oldJS := setOf(urlsOf(func() []string {
		out := make([]string, len(prev.JSFiles))
		for i, j := range prev.JSFiles {
			out[i] = j.URL
		}
		return out
	}()))
	for _, js := range curr.JSFiles {
		if !oldJS[js.URL] {
			findings = append(findings, change("new_js", "New JavaScript file: "+js.URL, js.URL, models.SeverityLow))
		}
	}

	// New API endpoints.
	oldAPI := setOf(func() []string {
		out := make([]string, len(prev.APIEndpoints))
		for i, e := range prev.APIEndpoints {
			out[i] = e.URL
		}
		return out
	}())
	for _, ep := range curr.APIEndpoints {
		if !oldAPI[ep.URL] {
			findings = append(findings, change("new_api", "New API endpoint: "+ep.URL, ep.URL, models.SeverityMedium))
		}
	}

	// New login pages.
	oldLogin := setOf(func() []string {
		out := make([]string, len(prev.LoginPages))
		for i, lp := range prev.LoginPages {
			out[i] = lp.URL
		}
		return out
	}())
	for _, lp := range curr.LoginPages {
		if !oldLogin[lp.URL] {
			findings = append(findings, change("new_login", "New login surface: "+lp.URL, lp.URL, models.SeverityMedium))
		}
	}

	// Technology changes.
	oldTech := map[string]string{}
	for _, t := range prev.Technologies {
		oldTech[t.Name] = t.Version
	}
	for _, t := range curr.Technologies {
		if v, ok := oldTech[t.Name]; ok && v != t.Version && t.Version != "" {
			findings = append(findings, change("tech_change",
				fmt.Sprintf("Technology version changed: %s %s → %s", t.Name, v, t.Version),
				"", models.SeverityLow))
		}
	}

	rc.Update(func(r *models.Result) { r.Findings = append(r.Findings, findings...) })
	rc.Progress.Stepf("monitoring diff produced %d change findings", len(findings))

	if rc.Workspace != nil && len(findings) > 0 {
		_, _ = rc.Workspace.WriteJSON("17_ai", "changes.json", findings)
	}
	return nil
}

func change(typ, title, url string, sev models.Severity) models.Finding {
	return models.Finding{
		Module: "monitoring", Type: typ, Title: title, Severity: sev,
		Confidence: 90, URL: url, Tags: []string{"change", "monitoring"}, FoundAt: time.Now(),
	}
}

func setOf(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func urlsOf(ss []string) []string { return ss }
