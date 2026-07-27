// Package crawler implements the Active Crawling engine: recursive in-scope
// crawling with HTML, robots.txt, and sitemap parsing; link, asset, form, and
// JavaScript-file extraction. Its output feeds the JavaScript, API, and
// parameter intelligence modules.
package crawler

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/threatprism/threatprism/internal/analyze"
	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/internal/core/target"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements the crawling engine.
type Module struct{ module.Meta }

// New returns a configured crawler module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "crawler",
		ModName:     "Crawling Engine",
		ModDesc:     "Recursive in-scope crawling with robots/sitemap parsing and asset extraction",
		ModCategory: "discovery",
		ModModes:    []models.Mode{models.ModeQuick, models.ModeStandard, models.ModeDeep},
	}}
}

// Run crawls the target starting from its root URL.
func (m *Module) Run(rc *module.RunContext) error {
	maxDepth, maxPages := 2, 100
	crawlJS := true
	if rc.Config != nil {
		maxDepth = rc.Config.Crawler.MaxDepth
		maxPages = rc.Config.Crawler.MaxPages
		crawlJS = rc.Config.Crawler.CrawlJS
	}
	if rc.Mode == models.ModeQuick {
		maxDepth, maxPages = 1, 30
	}

	c := &crawl{
		rc:       rc,
		maxDepth: maxDepth,
		maxPages: maxPages,
		visited:  map[string]bool{},
		jsSeen:   map[string]bool{},
	}

	// Seed frontier with robots + sitemap discoveries plus the root.
	seeds := []string{rc.Target.URL}
	if rc.Config == nil || rc.Config.Crawler.ParseRobots {
		seeds = append(seeds, c.robots()...)
	}
	if rc.Config == nil || rc.Config.Crawler.ParseSitemap {
		seeds = append(seeds, c.sitemap()...)
	}

	rc.Progress.Stepf("crawling from %d seed URLs (depth %d, max %d pages)", len(seeds), maxDepth, maxPages)
	for _, s := range seeds {
		c.enqueue(s, 0)
	}
	c.process()

	rc.Progress.Stepf("crawled %d pages, found %d JS files, %d forms", len(c.pages), len(c.jsFiles), len(c.forms))

	rc.Update(func(r *models.Result) {
		r.URLs = append(r.URLs, c.pages...)
		for _, js := range c.jsFiles {
			if crawlJS {
				r.JSFiles = append(r.JSFiles, models.JSFile{URL: js})
			}
		}
		if len(c.forms) > 0 {
			r.Findings = append(r.Findings, models.Finding{
				Module: m.Slug(), Type: "forms", Severity: models.SeverityInfo, Confidence: 80,
				Title:       "HTML forms discovered",
				Description: "Interactive input surfaces that may accept user data",
				Metadata:    map[string]string{"count": itoa(len(c.forms))},
				FoundAt:     time.Now(),
			})
		}
	})

	if rc.Workspace != nil {
		_, _ = rc.Workspace.WriteJSON("05_urls", "crawled.json", c.pages)
		if len(c.forms) > 0 {
			_, _ = rc.Workspace.WriteJSON("12_parameters", "forms.json", c.forms)
		}
	}
	return nil
}

type crawl struct {
	rc       *module.RunContext
	maxDepth int
	maxPages int

	mu      sync.Mutex
	visited map[string]bool
	jsSeen  map[string]bool
	pages   []models.URLEntry
	jsFiles []string
	forms   []analyze.Form

	frontier []queued
}

type queued struct {
	url   string
	depth int
}

func (c *crawl) enqueue(u string, depth int) {
	u = strings.TrimSpace(u)
	if u == "" || depth > c.maxDepth {
		return
	}
	if !target.InScope(c.rc.Target, u) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visited[u] {
		return
	}
	c.visited[u] = true
	c.frontier = append(c.frontier, queued{u, depth})
}

// process crawls the frontier breadth-first, one depth level at a time, with
// bounded concurrency per level via the shared HTTP client.
func (c *crawl) process() {
	for len(c.frontier) > 0 {
		c.mu.Lock()
		batch := c.frontier
		c.frontier = nil
		c.mu.Unlock()

		var wg sync.WaitGroup
		for _, item := range batch {
			c.mu.Lock()
			over := len(c.pages) >= c.maxPages
			c.mu.Unlock()
			if over {
				return
			}
			wg.Add(1)
			go func(q queued) {
				defer wg.Done()
				c.fetch(q)
			}(item)
		}
		wg.Wait()
	}
}

func (c *crawl) fetch(q queued) {
	resp, err := c.rc.HTTP.Get(c.rc.Ctx, q.url)
	if err != nil {
		return
	}
	entry := models.URLEntry{
		URL:        resp.FinalURL,
		Source:     "crawl",
		StatusCode: resp.StatusCode,
		Params:     analyze.ExtractParamsFromURL(resp.FinalURL),
	}
	c.mu.Lock()
	c.pages = append(c.pages, entry)
	c.mu.Unlock()

	if !strings.Contains(resp.ContentType(), "html") {
		return
	}
	page := analyze.ParsePage(resp.FinalURL, resp.Body)

	c.mu.Lock()
	for _, f := range page.Forms {
		c.forms = append(c.forms, f)
	}
	for _, js := range page.Scripts {
		if !c.jsSeen[js] {
			c.jsSeen[js] = true
			c.jsFiles = append(c.jsFiles, js)
		}
	}
	c.mu.Unlock()

	for _, link := range page.Links {
		c.enqueue(link, q.depth+1)
	}
}

func (c *crawl) robots() []string {
	return c.fetchList("/robots.txt", func(body string) []string {
		var out []string
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			for _, pfx := range []string{"Allow:", "Disallow:", "Sitemap:"} {
				if strings.HasPrefix(line, pfx) {
					val := strings.TrimSpace(strings.TrimPrefix(line, pfx))
					if val != "" && val != "/" {
						out = append(out, c.abs(val))
					}
				}
			}
		}
		return out
	})
}

func (c *crawl) sitemap() []string {
	return c.fetchList("/sitemap.xml", func(body string) []string {
		var out []string
		for _, part := range strings.Split(body, "<loc>") {
			if i := strings.Index(part, "</loc>"); i > 0 {
				out = append(out, strings.TrimSpace(part[:i]))
			}
		}
		return out
	})
}

func (c *crawl) fetchList(path string, parse func(string) []string) []string {
	ctx, cancel := context.WithTimeout(c.rc.Ctx, 10*time.Second)
	defer cancel()
	resp, err := c.rc.HTTP.Get(ctx, c.abs(path))
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	return parse(string(resp.Body))
}

func (c *crawl) abs(p string) string {
	if strings.HasPrefix(p, "http") {
		return p
	}
	base := strings.TrimSuffix(c.rc.Target.Scheme+"://"+c.rc.Target.Host, "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
