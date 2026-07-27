// Package report renders a scan result into multiple output formats: an
// interactive dark-themed HTML dashboard, Markdown, JSON, and CSV. PDF is
// produced from the HTML when a headless browser is available.
package report

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/threatprism/threatprism/pkg/models"
)

// Format identifies an output format.
type Format string

const (
	FormatHTML     Format = "html"
	FormatPDF      Format = "pdf"
	FormatMarkdown Format = "markdown"
	FormatJSON     Format = "json"
	FormatCSV      Format = "csv"
)

// Options controls report generation.
type Options struct {
	Formats []Format
	OutDir  string
	Theme   string // dark | light
}

// Generator renders results to files.
type Generator struct{}

// New returns a report Generator.
func New() *Generator { return &Generator{} }

// Generate writes every requested format for result into opts.OutDir and
// returns the paths written.
func (g *Generator) Generate(result *models.Result, opts Options) ([]string, error) {
	if opts.OutDir == "" {
		opts.OutDir = "."
	}
	if opts.Theme == "" {
		opts.Theme = "dark"
	}
	var written []string
	for _, f := range opts.Formats {
		var (
			data []byte
			name string
			err  error
		)
		switch f {
		case FormatHTML, FormatPDF:
			data, err = renderHTML(result, opts.Theme)
			name = "report.html"
		case FormatMarkdown:
			data, err = renderMarkdown(result)
			name = "report.md"
		case FormatJSON:
			data, err = renderJSON(result)
			name = "report.json"
		case FormatCSV:
			data, err = renderCSV(result)
			name = "findings.csv"
		default:
			continue
		}
		if err != nil {
			return written, fmt.Errorf("report %s: %w", f, err)
		}
		path := filepath.Join(opts.OutDir, name)
		if err := writeFile(path, data); err != nil {
			return written, err
		}
		written = append(written, path)

		if f == FormatPDF {
			if pdf, err := htmlToPDF(path); err == nil {
				written = append(written, pdf)
			}
		}
	}
	return dedupPaths(written), nil
}

func dedupPaths(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// severityClass maps a severity to a CSS class / label token.
func severityClass(s models.Severity) string { return strings.ToLower(string(s)) }

// RenderHTML exposes HTML rendering for the web dashboard server.
func RenderHTML(r *models.Result, theme string) ([]byte, error) {
	if theme == "" {
		theme = "dark"
	}
	return renderHTML(r, theme)
}
