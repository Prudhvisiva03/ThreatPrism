// Package apiintel implements API Intelligence: it discovers REST, GraphQL,
// Swagger/OpenAPI, SOAP, and Postman surfaces from crawled URLs, JavaScript
// endpoints, and probes for well-known API definition paths.
package apiintel

import (
	"strings"
	"sync"
	"time"

	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements API Intelligence.
type Module struct{ module.Meta }

// New returns a configured apiintel module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "apiintel",
		ModName:     "API Intelligence",
		ModDesc:     "Discovers REST, GraphQL, Swagger/OpenAPI, and SOAP surfaces",
		ModCategory: "intelligence",
		ModModes:    []models.Mode{models.ModeStandard, models.ModeDeep},
		ModRequires: []string{"crawler"},
	}}
}

// wellKnown are common API definition/entry paths worth probing directly.
var wellKnown = []struct {
	path string
	kind string
}{
	{"/swagger.json", "swagger"},
	{"/swagger/v1/swagger.json", "swagger"},
	{"/api-docs", "swagger"},
	{"/v2/api-docs", "swagger"},
	{"/openapi.json", "openapi"},
	{"/openapi.yaml", "openapi"},
	{"/graphql", "graphql"},
	{"/graphiql", "graphql"},
	{"/api", "rest"},
	{"/api/v1", "rest"},
	{"/api/v2", "rest"},
	{"/rest", "rest"},
	{"/.well-known/openapi.json", "openapi"},
}

// Run discovers API surfaces.
func (m *Module) Run(rc *module.RunContext) error {
	base := strings.TrimSuffix(rc.Target.Scheme+"://"+rc.Target.Host, "/")

	found := map[string]models.APIEndpoint{}
	var mu sync.Mutex
	addEndpoint := func(e models.APIEndpoint) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := found[e.URL]; !ok {
			found[e.URL] = e
		}
	}

	// 1. Harvest API-looking URLs from prior modules.
	rc.Update(func(r *models.Result) {
		for _, u := range r.URLs {
			if kind, ok := classify(u.URL); ok {
				addEndpoint(models.APIEndpoint{URL: u.URL, Kind: kind, Source: u.Source, Params: u.Params})
			}
		}
		for _, js := range r.JSFiles {
			for _, ep := range js.Endpoints {
				full := base + ep
				if kind, ok := classify(ep); ok {
					addEndpoint(models.APIEndpoint{URL: full, Kind: kind, Source: "js:" + js.URL})
				}
			}
		}
	})

	// 2. Actively probe well-known definition paths.
	rc.Progress.Stepf("probing %d well-known API paths", len(wellKnown))
	var wg sync.WaitGroup
	for _, wk := range wellKnown {
		wk := wk
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := base + wk.path
			resp, err := rc.HTTP.Get(rc.Ctx, u)
			if err != nil || resp.StatusCode >= 400 {
				return
			}
			ct := resp.ContentType()
			if wk.kind == "graphql" || strings.Contains(ct, "json") || strings.Contains(ct, "yaml") || looksLikeSwagger(resp.Body) {
				addEndpoint(models.APIEndpoint{URL: resp.FinalURL, Kind: wk.kind, Method: "GET", Source: "probe"})
			}
		}()
	}
	wg.Wait()

	var endpoints []models.APIEndpoint
	for _, e := range found {
		endpoints = append(endpoints, e)
	}

	rc.Update(func(r *models.Result) {
		r.APIEndpoints = append(r.APIEndpoints, endpoints...)
		for _, e := range endpoints {
			if e.Source == "probe" {
				sev := models.SeverityLow
				if e.Kind == "swagger" || e.Kind == "openapi" || e.Kind == "graphql" {
					sev = models.SeverityMedium
				}
				r.Findings = append(r.Findings, models.Finding{
					Module: m.Slug(), Type: "api", Severity: sev, Confidence: 85,
					Title:       "Exposed " + strings.ToUpper(e.Kind) + " endpoint",
					Description: "An API definition or entry point is publicly reachable",
					URL:         e.URL, Tags: []string{"api", e.Kind}, FoundAt: time.Now(),
				})
			}
		}
	})

	rc.Progress.Stepf("identified %d API endpoints", len(endpoints))
	if rc.Workspace != nil && len(endpoints) > 0 {
		_, _ = rc.Workspace.WriteJSON("07_api", "endpoints.json", endpoints)
	}
	return nil
}

func classify(u string) (string, bool) {
	l := strings.ToLower(u)
	switch {
	case strings.Contains(l, "graphql"):
		return "graphql", true
	case strings.Contains(l, "swagger"):
		return "swagger", true
	case strings.Contains(l, "openapi"):
		return "openapi", true
	case strings.Contains(l, ".asmx") || strings.Contains(l, "?wsdl") || strings.Contains(l, "soap"):
		return "soap", true
	case strings.Contains(l, "/api/") || strings.HasSuffix(l, "/api") || strings.Contains(l, "/rest/"):
		return "rest", true
	}
	return "", false
}

func looksLikeSwagger(body []byte) bool {
	s := string(body[:min(len(body), 2048)])
	return strings.Contains(s, "\"swagger\"") || strings.Contains(s, "\"openapi\"") || strings.Contains(s, "\"paths\"")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
