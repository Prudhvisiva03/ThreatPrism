// Package plugin implements ThreatPrism's external plugin system. Plugins are
// external tools (e.g. nuclei, amass, or user scripts) described by a YAML
// manifest, so new capabilities can be added without modifying or recompiling
// the core application.
//
// Layout:
//
//	plugins/
//	  nuclei/plugin.yaml
//	  amass/plugin.yaml
//	  custom/plugin.yaml
//
// Each manifest declares how to invoke the tool and how to interpret its
// output. Plugins run as a bridge into the same Module interface, so they slot
// into scans exactly like built-in modules.
package plugin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/pkg/models"
)

// Manifest describes an external tool plugin.
type Manifest struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Category    string   `yaml:"category"`
	Command     string   `yaml:"command"`  // executable name or path
	Args        []string `yaml:"args"`     // supports {{target}} {{host}} {{url}} {{output}} templating
	Modes       []string `yaml:"modes"`    // recon modes this plugin participates in
	OutputType  string   `yaml:"output"`   // lines | json | ignore
	Severity    string   `yaml:"severity"` // default severity for produced findings
	Timeout     int      `yaml:"timeout"`  // seconds; 0 = 300
	Enabled     bool     `yaml:"enabled"`
}

// Load reads every plugin manifest under dir.
func Load(dir string) ([]*Manifest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Manifest
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifestPath := filepath.Join(dir, e.Name(), "plugin.yaml")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var m Manifest
		if err := yaml.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("plugin %s: %w", e.Name(), err)
		}
		if m.Name == "" {
			m.Name = e.Name()
		}
		out = append(out, &m)
	}
	return out, nil
}

// Plugin adapts a Manifest to the module.Module interface.
type Plugin struct {
	module.Meta
	m *Manifest
}

// NewModule wraps a manifest as a runnable module.
func NewModule(m *Manifest) *Plugin {
	modes := make([]models.Mode, 0, len(m.Modes))
	for _, s := range m.Modes {
		modes = append(modes, models.Mode(s))
	}
	if len(modes) == 0 {
		modes = []models.Mode{models.ModeDeep}
	}
	cat := m.Category
	if cat == "" {
		cat = "plugin"
	}
	return &Plugin{
		Meta: module.Meta{
			ModSlug:     "plugin:" + m.Name,
			ModName:     "Plugin: " + m.Name,
			ModDesc:     m.Description,
			ModCategory: cat,
			ModModes:    modes,
		},
		m: m,
	}
}

// Available reports whether the plugin's command is present on the system.
func (p *Plugin) Available() bool {
	_, err := exec.LookPath(p.m.Command)
	return err == nil
}

// Run executes the external tool and ingests its output as findings.
func (p *Plugin) Run(rc *module.RunContext) error {
	if !p.Available() {
		rc.Progress.Stepf("plugin %s: command %q not found; skipping", p.m.Name, p.m.Command)
		return nil
	}

	timeout := time.Duration(p.m.Timeout) * time.Second
	if timeout == 0 {
		timeout = 300 * time.Second
	}
	ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
	defer cancel()

	var outputFile string
	if rc.Workspace != nil {
		outputFile = filepath.Join(rc.Workspace.Dir("01_overview"), sanitize(p.m.Name)+".out")
	}

	args := make([]string, len(p.m.Args))
	for i, a := range p.m.Args {
		args[i] = expand(a, rc.Target, outputFile)
	}

	rc.Progress.Stepf("running plugin %s: %s %s", p.m.Name, p.m.Command, strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, p.m.Command, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	err := cmd.Run()
	if err != nil && ctx.Err() == nil {
		rc.Log.Warn("plugin exited with error", "plugin", p.m.Name, "err", err)
	}

	out := stdout.String()
	if outputFile != "" {
		_ = os.WriteFile(outputFile, []byte(out), 0o644)
	}

	if p.m.OutputType == "ignore" {
		return nil
	}

	sev := models.Severity(p.m.Severity)
	if sev == "" {
		sev = models.SeverityInfo
	}
	var findings []models.Finding
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		findings = append(findings, models.Finding{
			Module: p.Slug(), Type: "plugin", Severity: sev, Confidence: 60,
			Title:   truncate(line, 120),
			Evidence: line, Tags: []string{"plugin", p.m.Name}, FoundAt: time.Now(),
		})
		if len(findings) >= 1000 {
			break
		}
	}

	rc.Update(func(r *models.Result) { r.Findings = append(r.Findings, findings...) })
	rc.Progress.Stepf("plugin %s produced %d findings", p.m.Name, len(findings))
	return nil
}

func expand(arg string, t models.Target, output string) string {
	r := strings.NewReplacer(
		"{{target}}", t.Raw,
		"{{host}}", t.Host,
		"{{url}}", t.URL,
		"{{output}}", output,
	)
	return r.Replace(arg)
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
