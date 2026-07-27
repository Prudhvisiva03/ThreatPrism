// Package loginintel implements Login Intelligence: it identifies login pages,
// admin panels, dashboards, and portals, then collects metadata about each
// authentication surface (auth type, CSRF, OAuth, captcha, cookies, forms).
package loginintel

import (
	"strings"
	"sync"
	"time"

	"github.com/threatprism/threatprism/internal/analyze"
	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements login intelligence.
type Module struct{ module.Meta }

// New returns a configured loginintel module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "loginintel",
		ModName:     "Login Intelligence",
		ModDesc:     "Identifies login pages, admin panels, and authentication surfaces",
		ModCategory: "intelligence",
		ModModes:    []models.Mode{models.ModeStandard, models.ModeDeep},
		ModRequires: []string{"crawler"},
	}}
}

// loginSignal pairs a URL keyword with the kind of auth surface it suggests.
var loginSignals = []struct {
	keyword string
	kind    string
}{
	{"login", "login"}, {"signin", "login"}, {"sign-in", "login"},
	{"admin", "admin"}, {"administrator", "admin"}, {"wp-admin", "admin"},
	{"dashboard", "dashboard"}, {"panel", "dashboard"}, {"console", "dashboard"},
	{"portal", "portal"}, {"employee", "portal"}, {"staff", "portal"},
	{"student", "portal"}, {"partner", "portal"}, {"client", "portal"},
	{"auth", "login"}, {"account", "login"}, {"user/login", "login"},
	{"grafana", "dashboard"}, {"kibana", "dashboard"}, {"jenkins", "dashboard"},
}

// Run identifies login surfaces from crawled URLs and probes them.
func (m *Module) Run(rc *module.RunContext) error {
	candidates := map[string]string{} // url -> kind

	rc.Update(func(r *models.Result) {
		for _, u := range r.URLs {
			if kind := loginKind(u.URL); kind != "" {
				candidates[u.URL] = kind
			}
		}
		for _, h := range r.Hosts {
			if kind := loginKind(h.URL); kind != "" {
				candidates[h.URL] = kind
			}
		}
	})

	// Also probe common paths directly.
	base := strings.TrimSuffix(rc.Target.Scheme+"://"+rc.Target.Host, "/")
	for _, sig := range loginSignals {
		u := base + "/" + sig.keyword
		if _, ok := candidates[u]; !ok {
			candidates[u] = sig.kind
		}
	}

	rc.Progress.Stepf("probing %d potential login surfaces", len(candidates))

	var mu sync.Mutex
	var pages []models.LoginPage
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	for u, kind := range candidates {
		u, kind := u, kind
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			resp, err := rc.HTTP.Get(rc.Ctx, u)
			if err != nil || resp.StatusCode == 404 {
				return
			}
			page := analyze.ParsePage(resp.FinalURL, resp.Body)
			lp := models.LoginPage{
				URL:  resp.FinalURL,
				Kind: kind,
			}
			for _, f := range page.Forms {
				if f.HasPass {
					lp.AuthType = "form"
				}
				for _, inp := range f.Inputs {
					if strings.Contains(strings.ToLower(inp.Name), "csrf") ||
						strings.Contains(strings.ToLower(inp.Name), "_token") {
						lp.HasCSRF = true
					}
				}
			}
			body := strings.ToLower(string(resp.Body))
			lp.HasOAuth = strings.Contains(body, "oauth") || strings.Contains(body, "google-signin") || strings.Contains(body, "sign in with")
			lp.HasCaptcha = strings.Contains(body, "recaptcha") || strings.Contains(body, "hcaptcha") || strings.Contains(body, "captcha")
			if lp.AuthType == "" {
				if strings.Contains(body, "bearer") || strings.Contains(body, "authorization") {
					lp.AuthType = "token"
				} else if lp.HasOAuth {
					lp.AuthType = "oauth"
				}
			}
			mu.Lock()
			pages = append(pages, lp)
			mu.Unlock()
		}()
	}
	wg.Wait()

	rc.Update(func(r *models.Result) {
		r.LoginPages = append(r.LoginPages, pages...)
		for _, lp := range pages {
			sev := models.SeverityInfo
			if lp.Kind == "admin" {
				sev = models.SeverityMedium
			}
			r.Findings = append(r.Findings, models.Finding{
				Module: m.Slug(), Type: "login", Severity: sev, Confidence: 80,
				Title:       strings.Title(lp.Kind) + " surface identified",
				Description: "Authentication surface at " + lp.URL,
				URL:         lp.URL, Tags: []string{"login", lp.Kind}, FoundAt: time.Now(),
			})
		}
	})

	rc.Progress.Stepf("identified %d login/admin surfaces", len(pages))
	if rc.Workspace != nil && len(pages) > 0 {
		_, _ = rc.Workspace.WriteJSON("08_login", "login_pages.json", pages)
	}
	return nil
}

func loginKind(u string) string {
	l := strings.ToLower(u)
	for _, sig := range loginSignals {
		if strings.Contains(l, sig.keyword) {
			return sig.kind
		}
	}
	return ""
}
