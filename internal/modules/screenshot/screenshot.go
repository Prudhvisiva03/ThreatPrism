// Package screenshot implements the Screenshot Engine. It captures screenshots
// of interesting pages (homepage, login/admin panels, dashboards, exposed
// tooling) by driving a locally installed headless Chrome/Chromium. When no
// browser is available it degrades gracefully, recording the intended targets
// so the rest of the scan is unaffected.
package screenshot

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/internal/workspace"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements the screenshot engine.
type Module struct{ module.Meta }

// New returns a configured screenshot module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "screenshot",
		ModName:     "Screenshot Engine",
		ModDesc:     "Captures screenshots of interesting pages via headless Chrome",
		ModCategory: "analysis",
		ModModes:    []models.Mode{models.ModeDeep},
		ModRequires: []string{"loginintel"},
	}}
}

// Run captures screenshots of interesting URLs.
func (m *Module) Run(rc *module.RunContext) error {
	browser := findBrowser()
	if browser == "" {
		rc.Progress.Stepf("no headless browser found; skipping screenshots")
		rc.Log.Info("screenshot: no chrome/chromium found on PATH; skipping")
		return nil
	}

	// Build the target list: homepage + login/admin/dashboard pages.
	type shot struct {
		url  string
		kind string
	}
	shots := []shot{{rc.Target.URL, "homepage"}}
	rc.Update(func(r *models.Result) {
		for _, lp := range r.LoginPages {
			shots = append(shots, shot{lp.URL, lp.Kind})
		}
	})

	dir := workspace.DirScreenshots
	if rc.Workspace == nil {
		rc.Progress.Stepf("no workspace; skipping screenshots")
		return nil
	}
	outDir := rc.Workspace.ScreenshotsDir()

	rc.Progress.Stepf("capturing %d screenshots via %s", len(shots), filepath.Base(browser))

	var mu sync.Mutex
	var captured []models.Screenshot
	sem := make(chan struct{}, 3) // browsers are heavy; keep it modest
	var wg sync.WaitGroup

	for i, s := range shots {
		i, s := i, s
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			name := sanitize(s.kind) + "_" + itoa(i) + ".png"
			out := filepath.Join(outDir, name)
			if err := capture(rc.Ctx, browser, s.url, out); err != nil {
				rc.Log.Debug("screenshot failed", "url", s.url, "err", err)
				return
			}
			mu.Lock()
			captured = append(captured, models.Screenshot{
				URL: s.url, Path: filepath.Join(dir, name), Kind: s.kind,
			})
			mu.Unlock()
		}()
	}
	wg.Wait()

	rc.Update(func(r *models.Result) { r.Screenshots = append(r.Screenshots, captured...) })
	rc.Progress.Stepf("captured %d screenshots", len(captured))
	return nil
}

// capture drives headless Chrome to screenshot url into outPath.
func capture(ctx context.Context, browser, url, outPath string) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--hide-scrollbars",
		"--window-size=1440,900",
		"--screenshot=" + outPath,
		"--virtual-time-budget=5000",
		"--ignore-certificate-errors",
		url,
	}
	cmd := exec.CommandContext(cctx, browser, args...)
	return cmd.Run()
}

// findBrowser locates a Chrome/Chromium/Edge binary across platforms.
func findBrowser() string {
	candidates := []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	// Well-known install paths.
	var paths []string
	switch runtime.GOOS {
	case "windows":
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		paths = []string{
			filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
		}
	case "darwin":
		paths = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	default:
		paths = []string{"/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium"}
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "page"
	}
	return b.String()
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
