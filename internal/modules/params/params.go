// Package params implements Parameter Discovery: it aggregates parameters from
// historical URLs, JavaScript, forms, API definitions, robots.txt, and the
// crawler, deduplicates them, and flags interesting ones.
package params

import (
	"sort"
	"time"

	"github.com/threatprism/threatprism/internal/analyze"
	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements parameter discovery.
type Module struct{ module.Meta }

// New returns a configured params module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "params",
		ModName:     "Parameter Discovery",
		ModDesc:     "Aggregates and classifies request parameters from all sources",
		ModCategory: "intelligence",
		ModModes:    []models.Mode{models.ModeStandard, models.ModeDeep},
		ModRequires: []string{"crawler", "jsintel"},
	}}
}

// Run aggregates parameters from all prior module outputs.
func (m *Module) Run(rc *module.RunContext) error {
	seen := map[string]*models.Parameter{}

	add := func(name, source string) {
		name = normalize(name)
		if name == "" {
			return
		}
		if p, ok := seen[name]; ok {
			p.Sources = appendUnique(p.Sources, source)
		} else {
			seen[name] = &models.Parameter{
				Name:        name,
				Sources:     []string{source},
				Interesting: analyze.InterestingParam(name),
			}
		}
	}

	rc.Update(func(r *models.Result) {
		// From URLs (query strings).
		for _, u := range r.URLs {
			for _, p := range u.Params {
				add(p, "url:"+u.Source)
			}
		}
		// From JavaScript.
		for _, js := range r.JSFiles {
			for _, p := range js.Params {
				add(p, "js")
			}
		}
		// From API endpoints.
		for _, ep := range r.APIEndpoints {
			for _, p := range ep.Params {
				add(p, "api")
			}
		}
	})

	params := make([]models.Parameter, 0, len(seen))
	for _, p := range seen {
		params = append(params, *p)
	}
	sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })

	var interesting []models.Parameter
	for _, p := range params {
		if p.Interesting {
			interesting = append(interesting, p)
		}
	}

	rc.Update(func(r *models.Result) {
		r.Parameters = params
		if len(interesting) > 0 {
			r.Findings = append(r.Findings, models.Finding{
				Module: m.Slug(), Type: "params", Severity: models.SeverityLow, Confidence: 70,
				Title:       "Interesting parameters discovered",
				Description: "Parameters commonly associated with injection, redirect, or IDOR vulnerabilities",
				Tags:        []string{"params", "interesting"}, FoundAt: time.Now(),
				Metadata: map[string]string{"count": itoa(len(interesting))},
			})
		}
	})

	rc.Progress.Stepf("discovered %d unique parameters (%d interesting)", len(params), len(interesting))
	if rc.Workspace != nil && len(params) > 0 {
		_, _ = rc.Workspace.WriteJSON("12_parameters", "parameters.json", params)
	}
	return nil
}

func normalize(s string) string {
	if len(s) == 0 || len(s) > 80 {
		return ""
	}
	return s
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
