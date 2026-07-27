// Package dirdisco implements Directory Discovery: a built-in, concurrency-safe
// content brute-forcer that classifies responses by status code and records
// size, title, and detected technologies.
package dirdisco

import (
	"strings"
	"sync"
	"time"

	"github.com/threatprism/threatprism/internal/analyze"
	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements directory discovery.
type Module struct{ module.Meta }

// New returns a configured dirdisco module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "dirdisco",
		ModName:     "Directory Discovery",
		ModDesc:     "Smart content brute-force with response classification",
		ModCategory: "discovery",
		ModModes:    []models.Mode{models.ModeDeep},
	}}
}

// builtinWordlist is a compact, high-signal default list. Users can supply a
// larger custom wordlist via config.
var builtinWordlist = []string{
	"admin", "administrator", "login", "dashboard", "api", "api/v1", "api/v2",
	"app", "assets", "backup", "backups", "config", "console", "css", "data",
	"db", "debug", "dev", "docs", "download", "files", "images", "img", "js",
	"logs", "old", "panel", "private", "public", "scripts", "server-status",
	"static", "test", "tmp", "upload", "uploads", "user", "users", "wp-admin",
	"wp-content", "wp-login.php", ".git", ".env", "phpinfo.php", "status",
	"health", "metrics", "actuator", "swagger", "graphql", "robots.txt",
}

// Run brute-forces directories under the target root.
func (m *Module) Run(rc *module.RunContext) error {
	base := strings.TrimSuffix(rc.Target.Scheme+"://"+rc.Target.Host, "/")

	words := builtinWordlist
	exts := []string{""}
	conc := 40
	if rc.Config != nil {
		if len(rc.Config.Dirs.Extensions) > 0 {
			exts = rc.Config.Dirs.Extensions
		}
		if rc.Config.Dirs.Concurrency > 0 {
			conc = rc.Config.Dirs.Concurrency
		}
	}

	// Build candidate paths.
	var candidates []string
	for _, w := range words {
		for _, e := range exts {
			p := w
			if e != "" && !strings.Contains(w, ".") {
				p = w + "." + e
			}
			candidates = append(candidates, base+"/"+p)
		}
	}

	rc.Progress.Stepf("testing %d paths", len(candidates))

	var mu sync.Mutex
	var entries []models.DirEntry
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for _, u := range candidates {
		u := u
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			resp, err := rc.HTTP.Get(rc.Ctx, u)
			if err != nil {
				return
			}
			// Skip vanilla 404s (the common negative case).
			if resp.StatusCode == 404 {
				return
			}
			e := models.DirEntry{
				URL:        resp.FinalURL,
				StatusCode: resp.StatusCode,
				Size:       int64(len(resp.Body)),
				Title:      analyze.Title(resp.Body),
				Class:      classify(resp.StatusCode),
			}
			mu.Lock()
			entries = append(entries, e)
			mu.Unlock()
		}()
	}
	wg.Wait()

	rc.Update(func(r *models.Result) {
		r.Directories = append(r.Directories, entries...)
		for _, e := range entries {
			if e.StatusCode == 200 || e.StatusCode == 401 || e.StatusCode == 403 {
				sev := models.SeverityInfo
				if e.StatusCode == 401 || e.StatusCode == 403 {
					sev = models.SeverityLow
				}
				r.Findings = append(r.Findings, models.Finding{
					Module: m.Slug(), Type: "directory", Severity: sev, Confidence: 75,
					Title:       itoa(e.StatusCode) + " " + e.URL,
					Description: "Discovered content path (" + e.Class + ")",
					URL:         e.URL, FoundAt: time.Now(),
				})
			}
		}
	})

	rc.Progress.Stepf("found %d interesting paths", len(entries))
	if rc.Workspace != nil && len(entries) > 0 {
		_, _ = rc.Workspace.WriteJSON("01_overview", "directories.json", entries)
	}
	return nil
}

func classify(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "ok"
	case code >= 300 && code < 400:
		return "redirect"
	case code == 401 || code == 403:
		return "forbidden"
	case code >= 400 && code < 500:
		return "client-error"
	case code >= 500:
		return "server-error"
	default:
		return "other"
	}
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
