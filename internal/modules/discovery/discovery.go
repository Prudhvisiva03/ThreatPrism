// Package discovery implements the Discovery Engine: passive subdomain
// enumeration from multiple providers, DNS resolution, alive-host probing, and
// historical URL collection. It is the foundation other modules build on.
package discovery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/threatprism/threatprism/internal/analyze"
	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements the Discovery Engine.
type Module struct{ module.Meta }

// New returns a configured Discovery module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "discovery",
		ModName:     "Discovery Engine",
		ModDesc:     "Passive subdomains, DNS records, alive hosts, and historical URLs",
		ModCategory: "discovery",
		ModModes:    []models.Mode{models.ModeQuick, models.ModeStandard, models.ModeDeep},
	}}
}

// Run performs discovery against the target host.
func (m *Module) Run(rc *module.RunContext) error {
	domain := rc.Target.Host
	rc.Progress.Stepf("enumerating subdomains for %s", domain)

	subs := m.enumerate(rc, domain)
	rc.Progress.Stepf("found %d unique subdomains", len(subs))

	// Resolve + probe alive concurrently.
	if rc.Config == nil || rc.Config.Discovery.ResolveDNS {
		m.resolve(rc, subs)
	}

	var hosts []models.Host
	if rc.Config == nil || rc.Config.Discovery.ProbeAlive {
		hosts = m.probe(rc, subs)
	}

	// Historical URLs (wayback) for standard/deep modes.
	var urls []models.URLEntry
	if m.waybackEnabled(rc) {
		rc.Progress.Stepf("collecting historical URLs from Wayback Machine")
		urls = m.wayback(rc, domain)
		rc.Progress.Stepf("collected %d historical URLs", len(urls))
	}

	subList := make([]models.Subdomain, 0, len(subs))
	for _, s := range subs {
		subList = append(subList, *s)
	}
	sort.Slice(subList, func(i, j int) bool { return subList[i].Name < subList[j].Name })

	rc.Update(func(r *models.Result) {
		r.Subdomains = append(r.Subdomains, subList...)
		r.Hosts = append(r.Hosts, hosts...)
		r.URLs = append(r.URLs, urls...)
		if len(subList) > 0 {
			r.Findings = append(r.Findings, models.Finding{
				Module: m.Slug(), Type: "subdomains", Severity: models.SeverityInfo,
				Confidence: 90, Title: fmt.Sprintf("%d subdomains discovered", len(subList)),
				Description: fmt.Sprintf("%d alive of %d resolved", countAlive(subList), len(subList)),
				FoundAt:     time.Now(),
			})
		}
	})

	// Persist artifacts to the workspace.
	if rc.Workspace != nil {
		_, _ = rc.Workspace.WriteJSON("02_subdomains", "subdomains.json", subList)
		if len(hosts) > 0 {
			_, _ = rc.Workspace.WriteJSON("03_alive", "hosts.json", hosts)
		}
		if len(urls) > 0 {
			_, _ = rc.Workspace.WriteJSON("05_urls", "wayback.json", urls)
		}
	}
	return nil
}

// enumerate gathers subdomains from all enabled passive sources.
func (m *Module) enumerate(rc *module.RunContext, domain string) map[string]*models.Subdomain {
	sources := []string{"crtsh", "hackertarget", "rapiddns"}
	if rc.Config != nil && len(rc.Config.Discovery.PassiveSources) > 0 {
		sources = rc.Config.Discovery.PassiveSources
	}

	result := make(map[string]*models.Subdomain)
	var mu sync.Mutex
	var wg sync.WaitGroup

	add := func(name, src string) {
		name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
		if name == "" || !strings.HasSuffix(name, domain) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if s, ok := result[name]; ok {
			s.Sources = appendUnique(s.Sources, src)
		} else {
			result[name] = &models.Subdomain{Name: name, Sources: []string{src}}
		}
	}
	// Always include the apex itself.
	add(domain, "seed")

	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			names := m.querySource(rc.Ctx, rc, src, domain)
			for _, n := range names {
				add(n, src)
			}
		}()
	}
	wg.Wait()
	return result
}

// querySource fetches subdomains from a single provider.
func (m *Module) querySource(ctx context.Context, rc *module.RunContext, src, domain string) []string {
	switch src {
	case "crtsh":
		return m.crtsh(ctx, rc, domain)
	case "hackertarget":
		return m.hackertarget(ctx, rc, domain)
	case "rapiddns":
		return m.rapiddns(ctx, rc, domain)
	case "wayback":
		return nil // handled separately as URLs
	default:
		return nil
	}
}

func (m *Module) crtsh(ctx context.Context, rc *module.RunContext, domain string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := rc.HTTP.Get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(resp.Body, &entries); err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			out = append(out, line)
		}
	}
	return out
}

func (m *Module) hackertarget(ctx context.Context, rc *module.RunContext, domain string) []string {
	url := "https://api.hackertarget.com/hostsearch/?q=" + domain
	resp, err := rc.HTTP.Get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(resp.Body))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ','); i > 0 {
			out = append(out, line[:i])
		}
	}
	return out
}

func (m *Module) rapiddns(ctx context.Context, rc *module.RunContext, domain string) []string {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
	resp, err := rc.HTTP.Get(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	// RapidDNS returns HTML; harvest anything ending in the domain.
	page := analyze.ParsePage(url, resp.Body)
	set := map[string]bool{}
	var out []string
	for _, l := range page.Links {
		if strings.Contains(l, domain) {
			if h := hostOf(l); h != "" && strings.HasSuffix(h, domain) && !set[h] {
				set[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// resolve fills in IPs for each subdomain via DNS.
func (m *Module) resolve(rc *module.RunContext, subs map[string]*models.Subdomain) {
	names := keys(subs)
	work := make(chan string, len(names))
	var wg sync.WaitGroup
	resolver := &net.Resolver{}

	workers := 20
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range work {
				ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
				ips, err := resolver.LookupHost(ctx, name)
				cancel()
				if err == nil && len(ips) > 0 {
					subs[name].IPs = ips
				}
				if cname, err := resolver.LookupCNAME(rc.Ctx, name); err == nil {
					subs[name].CNAME = strings.TrimSuffix(cname, ".")
				}
			}
		}()
	}
	for _, n := range names {
		work <- n
	}
	close(work)
	wg.Wait()
}

// probe checks which hosts respond over HTTP(S).
func (m *Module) probe(rc *module.RunContext, subs map[string]*models.Subdomain) []models.Host {
	names := keys(subs)
	var mu sync.Mutex
	var hosts []models.Host
	work := make(chan string, len(names))
	var wg sync.WaitGroup

	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range work {
				for _, scheme := range []string{"https", "http"} {
					u := scheme + "://" + name
					resp, err := rc.HTTP.Get(rc.Ctx, u)
					if err != nil {
						continue
					}
					mu.Lock()
					subs[name].Alive = true
					hosts = append(hosts, models.Host{
						URL:           resp.FinalURL,
						StatusCode:    resp.StatusCode,
						Title:         analyze.Title(resp.Body),
						ContentLength: int64(len(resp.Body)),
						Server:        resp.Header.Get("Server"),
						Scheme:        scheme,
					})
					mu.Unlock()
					break // one working scheme is enough
				}
			}
		}()
	}
	for _, n := range names {
		work <- n
	}
	close(work)
	wg.Wait()

	sort.Slice(hosts, func(i, j int) bool { return hosts[i].URL < hosts[j].URL })
	return hosts
}

func (m *Module) waybackEnabled(rc *module.RunContext) bool {
	if rc.Mode == models.ModeQuick {
		return false
	}
	if rc.Config != nil {
		return rc.Config.Discovery.Wayback
	}
	return true
}

func (m *Module) wayback(rc *module.RunContext, domain string) []models.URLEntry {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=5000", domain)
	resp, err := rc.HTTP.Get(rc.Ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	var rows [][]string
	if err := json.Unmarshal(resp.Body, &rows); err != nil {
		return nil
	}
	var out []models.URLEntry
	for i, row := range rows {
		if i == 0 || len(row) == 0 { // skip header row
			continue
		}
		out = append(out, models.URLEntry{
			URL:    row[0],
			Source: "wayback",
			Params: analyze.ExtractParamsFromURL(row[0]),
		})
	}
	return out
}

// ---- helpers ----

func countAlive(subs []models.Subdomain) int {
	n := 0
	for _, s := range subs {
		if s.Alive {
			n++
		}
	}
	return n
}

func keys(m map[string]*models.Subdomain) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if i := strings.IndexAny(raw, "/:?#"); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(raw)
}
