// Package jsintel implements JavaScript Intelligence: for every discovered JS
// file it extracts endpoints, URLs, parameters, secrets, and library/framework
// hints, and records source-map references. It consumes the JS files surfaced
// by the crawler and discovery modules.
package jsintel

import (
	"strings"
	"sync"
	"time"

	"github.com/threatprism/threatprism/internal/analyze"
	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements JavaScript Intelligence.
type Module struct{ module.Meta }

// New returns a configured jsintel module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "jsintel",
		ModName:     "JavaScript Intelligence",
		ModDesc:     "Extracts endpoints, secrets, parameters, and libraries from JavaScript",
		ModCategory: "intelligence",
		ModModes:    []models.Mode{models.ModeStandard, models.ModeDeep},
		ModRequires: []string{"crawler"},
	}}
}

var libSignatures = map[string]string{
	"jquery":       "jQuery",
	"react":        "React",
	"angular":      "Angular",
	"vue":          "Vue.js",
	"backbone":     "Backbone.js",
	"ember":        "Ember.js",
	"lodash":       "Lodash",
	"moment":       "Moment.js",
	"axios":        "Axios",
	"bootstrap":    "Bootstrap",
	"d3":           "D3.js",
	"webpack":      "Webpack",
	"next":         "Next.js",
	"nuxt":         "Nuxt.js",
	"svelte":       "Svelte",
	"graphql":      "GraphQL",
}

// Run analyzes all JS files in the shared result.
func (m *Module) Run(rc *module.RunContext) error {
	// Collect JS URLs already known plus any .js URLs from crawling/wayback.
	seen := map[string]bool{}
	var targets []string
	rc.Update(func(r *models.Result) {
		for _, js := range r.JSFiles {
			if !seen[js.URL] {
				seen[js.URL] = true
				targets = append(targets, js.URL)
			}
		}
		for _, u := range r.URLs {
			if strings.Contains(strings.ToLower(u.URL), ".js") && !seen[u.URL] {
				seen[u.URL] = true
				targets = append(targets, u.URL)
			}
		}
	})

	if len(targets) == 0 {
		rc.Progress.Stepf("no JavaScript files to analyze")
		return nil
	}
	rc.Progress.Stepf("analyzing %d JavaScript files", len(targets))

	var mu sync.Mutex
	var wg sync.WaitGroup
	analyzed := make(map[string]models.JSFile)
	var allSecrets []models.Secret
	sem := make(chan struct{}, 20)

	for _, u := range targets {
		u := u
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			jf, secrets := m.analyzeOne(rc, u)
			mu.Lock()
			analyzed[u] = jf
			allSecrets = append(allSecrets, secrets...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	var files []models.JSFile
	for _, jf := range analyzed {
		files = append(files, jf)
	}

	rc.Update(func(r *models.Result) {
		r.JSFiles = mergeJS(r.JSFiles, files)
		r.Secrets = append(r.Secrets, allSecrets...)
		for _, s := range allSecrets {
			r.Findings = append(r.Findings, models.Finding{
				Module: m.Slug(), Type: "secret", Severity: s.Severity, Confidence: 70,
				Title:       "Potential " + s.Type + " exposed in JavaScript",
				Description: "Matched a high-signal credential pattern in a JS file",
				URL:         s.Source, Evidence: s.Redacted, Tags: []string{"secret", s.Type},
				FoundAt: time.Now(),
			})
		}
	})

	rc.Progress.Stepf("found %d secrets across JavaScript files", len(allSecrets))
	if rc.Workspace != nil {
		_, _ = rc.Workspace.WriteJSON("06_js", "javascript.json", files)
	}
	return nil
}

func (m *Module) analyzeOne(rc *module.RunContext, u string) (models.JSFile, []models.Secret) {
	jf := models.JSFile{URL: u}
	resp, err := rc.HTTP.Get(rc.Ctx, u)
	if err != nil || resp.StatusCode != 200 {
		return jf, nil
	}
	body := string(resp.Body)
	jf.Size = int64(len(resp.Body))
	jf.Hash = analyze.Hash(resp.Body)
	jf.Endpoints = analyze.ExtractEndpoints(body)
	jf.URLs = analyze.ExtractURLs(body)
	jf.Params = analyze.ExtractParams(body)
	secrets := analyze.DetectSecrets(body, u)
	jf.Secrets = secrets

	// Library / framework detection.
	low := strings.ToLower(body)
	for sig, name := range libSignatures {
		if strings.Contains(low, sig) {
			jf.Libraries = append(jf.Libraries, name)
		}
	}
	// Source map reference.
	if i := strings.LastIndex(body, "sourceMappingURL="); i >= 0 {
		rest := body[i+len("sourceMappingURL="):]
		if j := strings.IndexAny(rest, "\n\r "); j >= 0 {
			rest = rest[:j]
		}
		jf.SourceMap = strings.TrimSpace(rest)
	}
	return jf, secrets
}

// mergeJS merges freshly analyzed files into the existing slice by URL,
// preferring the analyzed (richer) entry.
func mergeJS(existing, analyzed []models.JSFile) []models.JSFile {
	idx := make(map[string]int, len(existing))
	for i, e := range existing {
		idx[e.URL] = i
	}
	for _, a := range analyzed {
		if i, ok := idx[a.URL]; ok {
			existing[i] = a
		} else {
			existing = append(existing, a)
		}
	}
	return existing
}
