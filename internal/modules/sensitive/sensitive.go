// Package sensitive implements Sensitive File Discovery: it probes for
// well-known files that should never be publicly accessible.
package sensitive

import (
	"strings"
	"sync"
	"time"

	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements sensitive file discovery.
type Module struct{ module.Meta }

// New returns a configured sensitive module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "sensitive",
		ModName:     "Sensitive File Discovery",
		ModDesc:     "Probes for exposed credentials, configs, backups, and source files",
		ModCategory: "discovery",
		ModModes:    []models.Mode{models.ModeStandard, models.ModeDeep},
	}}
}

type probe struct {
	path     string
	severity models.Severity
}

var probes = []probe{
	{"/.env", models.SeverityCritical},
	{"/.env.local", models.SeverityCritical},
	{"/.env.production", models.SeverityCritical},
	{"/.env.backup", models.SeverityCritical},
	{"/.git/config", models.SeverityCritical},
	{"/.git/HEAD", models.SeverityHigh},
	{"/.svn/entries", models.SeverityHigh},
	{"/.hg/hgrc", models.SeverityHigh},
	{"/backup.zip", models.SeverityHigh},
	{"/backup.tar.gz", models.SeverityHigh},
	{"/db.sql", models.SeverityCritical},
	{"/database.sql", models.SeverityCritical},
	{"/dump.sql", models.SeverityCritical},
	{"/config.php", models.SeverityHigh},
	{"/config.json", models.SeverityHigh},
	{"/config.yaml", models.SeverityHigh},
	{"/config.yml", models.SeverityHigh},
	{"/docker-compose.yml", models.SeverityMedium},
	{"/Dockerfile", models.SeverityLow},
	{"/package.json", models.SeverityLow},
	{"/package-lock.json", models.SeverityLow},
	{"/composer.json", models.SeverityLow},
	{"/composer.lock", models.SeverityLow},
	{"/README.md", models.SeverityInfo},
	{"/CHANGELOG.md", models.SeverityInfo},
	{"/robots.txt", models.SeverityInfo},
	{"/sitemap.xml", models.SeverityInfo},
	{"/swagger.json", models.SeverityMedium},
	{"/openapi.json", models.SeverityMedium},
	{"/phpinfo.php", models.SeverityHigh},
	{"/server-status", models.SeverityMedium},
	{"/server-info", models.SeverityMedium},
	{"/.DS_Store", models.SeverityLow},
	{"/web.config", models.SeverityMedium},
	{"/wp-config.php", models.SeverityCritical},
	{"/wp-config.php.bak", models.SeverityCritical},
	{"/.htpasswd", models.SeverityCritical},
	{"/.htaccess", models.SeverityLow},
	{"/id_rsa", models.SeverityCritical},
	{"/id_rsa.pub", models.SeverityMedium},
	{"/authorized_keys", models.SeverityHigh},
}

// Run probes for sensitive files.
func (m *Module) Run(rc *module.RunContext) error {
	base := strings.TrimSuffix(rc.Target.Scheme+"://"+rc.Target.Host, "/")
	rc.Progress.Stepf("probing %d sensitive file paths", len(probes))

	var mu sync.Mutex
	var found []models.SensitiveFile
	sem := make(chan struct{}, 30)
	var wg sync.WaitGroup

	for _, p := range probes {
		p := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			u := base + p.path
			resp, err := rc.HTTP.Get(rc.Ctx, u)
			if err != nil || resp.StatusCode == 404 || resp.StatusCode == 0 {
				return
			}
			// Treat 200, 403 (exists but forbidden), and 500 as hits.
			if resp.StatusCode != 200 && resp.StatusCode != 403 && resp.StatusCode < 500 {
				return
			}
			sf := models.SensitiveFile{
				URL:        resp.FinalURL,
				Path:       p.path,
				StatusCode: resp.StatusCode,
				Size:       int64(len(resp.Body)),
				Severity:   p.severity,
			}
			mu.Lock()
			found = append(found, sf)
			mu.Unlock()
		}()
	}
	wg.Wait()

	rc.Update(func(r *models.Result) {
		r.SensitiveFiles = append(r.SensitiveFiles, found...)
		for _, sf := range found {
			r.Findings = append(r.Findings, models.Finding{
				Module: m.Slug(), Type: "sensitive_file", Severity: sf.Severity, Confidence: 85,
				Title:       "Sensitive file exposed: " + sf.Path,
				Description: "HTTP " + itoa(sf.StatusCode) + " — file should not be publicly accessible",
				URL:         sf.URL, Tags: []string{"sensitive", "exposure"}, FoundAt: time.Now(),
			})
		}
	})

	rc.Progress.Stepf("found %d sensitive files", len(found))
	if rc.Workspace != nil && len(found) > 0 {
		_, _ = rc.Workspace.WriteJSON("13_sensitive_files", "sensitive.json", found)
	}
	return nil
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
