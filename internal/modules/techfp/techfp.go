// Package techfp implements Technology Fingerprinting: it identifies web
// servers, languages, frameworks, CMSs, JS frameworks, CDNs, and WAFs from HTTP
// response headers, cookies, and body markers.
package techfp

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements technology fingerprinting.
type Module struct{ module.Meta }

// New returns a configured techfp module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "techfp",
		ModName:     "Technology Fingerprinting",
		ModDesc:     "Detects servers, frameworks, CMSs, CDNs, and WAFs",
		ModCategory: "intelligence",
		ModModes:    []models.Mode{models.ModeQuick, models.ModeStandard, models.ModeDeep},
	}}
}

type sig struct {
	name     string
	category string
	header   string         // header to inspect ("" = any/body)
	contains string         // simple substring match
	re       *regexp.Regexp // optional regex to also extract a version (group 1)
}

var signatures = []sig{
	{"Nginx", "server", "Server", "nginx", regexp.MustCompile(`nginx/([\d.]+)`)},
	{"Apache", "server", "Server", "apache", regexp.MustCompile(`Apache/([\d.]+)`)},
	{"Microsoft IIS", "server", "Server", "iis", regexp.MustCompile(`IIS/([\d.]+)`)},
	{"LiteSpeed", "server", "Server", "litespeed", nil},
	{"PHP", "language", "X-Powered-By", "php", regexp.MustCompile(`PHP/([\d.]+)`)},
	{"ASP.NET", "language", "X-Powered-By", "asp.net", nil},
	{"ASP.NET", "language", "X-AspNet-Version", "", regexp.MustCompile(`([\d.]+)`)},
	{"Express", "framework", "X-Powered-By", "express", nil},
	{"Node.js", "language", "X-Powered-By", "node", nil},
	{"WordPress", "cms", "", "wp-content", regexp.MustCompile(`wordpress ?([\d.]+)?`)},
	{"Drupal", "cms", "X-Generator", "drupal", nil},
	{"Joomla", "cms", "", "joomla", nil},
	{"Cloudflare", "cdn", "Server", "cloudflare", nil},
	{"Cloudflare", "waf", "CF-RAY", "", nil},
	{"Akamai", "cdn", "", "akamai", nil},
	{"Fastly", "cdn", "X-Served-By", "fastly", nil},
	{"Amazon CloudFront", "cdn", "Via", "cloudfront", nil},
	{"AWS S3", "cloud", "Server", "amazons3", nil},
	{"Sucuri WAF", "waf", "Server", "sucuri", nil},
	{"Imperva/Incapsula", "waf", "X-Iinfo", "", nil},
	{"React", "js", "", "react", nil},
	{"Vue.js", "js", "", "vue", nil},
	{"Angular", "js", "", "ng-version", nil},
	{"Next.js", "framework", "X-Powered-By", "next.js", nil},
	{"jQuery", "js", "", "jquery", nil},
	{"Varnish", "cache", "Via", "varnish", nil},
}

// Run fingerprints the target's root response.
func (m *Module) Run(rc *module.RunContext) error {
	resp, err := rc.HTTP.Get(rc.Ctx, rc.Target.URL)
	if err != nil {
		return err
	}
	rc.Progress.Stepf("fingerprinting %s (HTTP %d)", rc.Target.Host, resp.StatusCode)

	body := strings.ToLower(string(resp.Body))
	seen := map[string]bool{}
	var techs []models.Technology

	for _, s := range signatures {
		var hay string
		if s.header != "" {
			hay = strings.ToLower(resp.Header.Get(s.header))
			if hay == "" && s.contains == "" && resp.Header.Get(s.header) == "" {
				continue // header-presence signal absent
			}
		} else {
			hay = body
		}
		matched := false
		switch {
		case s.header != "" && s.contains == "":
			matched = resp.Header.Get(s.header) != ""
		case s.contains != "":
			matched = strings.Contains(hay, s.contains)
		}
		if !matched {
			continue
		}
		key := s.name + "|" + s.category
		if seen[key] {
			continue
		}
		seen[key] = true

		t := models.Technology{Name: s.name, Category: s.category, Confidence: 80, Source: "headers/body"}
		if s.re != nil {
			src := hay
			if s.header == "" {
				src = body
			}
			if mm := s.re.FindStringSubmatch(src); len(mm) > 1 && mm[1] != "" {
				t.Version = mm[1]
				t.Confidence = 90
			}
		}
		techs = append(techs, t)
	}

	headers := collectSecurityHeaders(resp.Header)

	rc.Update(func(r *models.Result) {
		r.Technologies = append(r.Technologies, techs...)
		r.Hosts = upsertHost(r.Hosts, models.Host{
			URL: resp.FinalURL, StatusCode: resp.StatusCode,
			Server: resp.Header.Get("Server"), ContentLength: int64(len(resp.Body)),
		})
		if len(techs) > 0 {
			r.Findings = append(r.Findings, models.Finding{
				Module: m.Slug(), Type: "technology", Severity: models.SeverityInfo, Confidence: 85,
				Title:       "Technology stack fingerprinted",
				Description: summarize(techs), FoundAt: time.Now(),
			})
		}
	})

	rc.Progress.Stepf("detected %d technologies", len(techs))
	if rc.Workspace != nil {
		_, _ = rc.Workspace.WriteJSON("10_technology", "technologies.json", techs)
		_, _ = rc.Workspace.WriteJSON("11_headers", "headers.json", map[string]any{
			"all":       headerMap(resp.Header),
			"interesting": headers,
		})
	}
	return nil
}

func collectSecurityHeaders(h http.Header) []string {
	var out []string
	for _, name := range []string{"Server", "X-Powered-By", "Via", "X-AspNet-Version"} {
		if v := h.Get(name); v != "" {
			out = append(out, name+": "+v)
		}
	}
	return out
}

func headerMap(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k := range h {
		out[k] = h.Get(k)
	}
	return out
}

func summarize(techs []models.Technology) string {
	names := make([]string, 0, len(techs))
	for _, t := range techs {
		if t.Version != "" {
			names = append(names, t.Name+" "+t.Version)
		} else {
			names = append(names, t.Name)
		}
	}
	return strings.Join(names, ", ")
}

func upsertHost(hosts []models.Host, h models.Host) []models.Host {
	for i := range hosts {
		if hosts[i].URL == h.URL {
			if hosts[i].Server == "" {
				hosts[i].Server = h.Server
			}
			return hosts
		}
	}
	return append(hosts, h)
}
