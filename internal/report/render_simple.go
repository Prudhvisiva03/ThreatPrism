package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/threatprism/threatprism/pkg/models"
)

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func renderJSON(r *models.Result) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func renderCSV(r *models.Result) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"module", "type", "severity", "confidence", "title", "url", "description"})
	for _, f := range r.Findings {
		_ = w.Write([]string{
			f.Module, f.Type, string(f.Severity), fmt.Sprintf("%d", f.Confidence),
			f.Title, f.URL, strings.ReplaceAll(f.Description, "\n", " "),
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func renderMarkdown(r *models.Result) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# ThreatPrism Report — %s\n\n", r.Target.URL)
	fmt.Fprintf(&b, "- **Mode:** %s\n", r.Mode)
	fmt.Fprintf(&b, "- **Risk Score:** %d/100 (%s)\n", r.RiskScore, r.RiskLevel())
	fmt.Fprintf(&b, "- **Scanned:** %s\n", r.StartedAt.Format(time.RFC1123))
	fmt.Fprintf(&b, "- **Duration:** %s\n\n", r.EndedAt.Sub(r.StartedAt).Round(time.Second))

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Asset | Count |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Subdomains | %d |\n", len(r.Subdomains))
	fmt.Fprintf(&b, "| Alive Hosts | %d |\n", len(r.Hosts))
	fmt.Fprintf(&b, "| URLs | %d |\n", len(r.URLs))
	fmt.Fprintf(&b, "| JavaScript Files | %d |\n", len(r.JSFiles))
	fmt.Fprintf(&b, "| API Endpoints | %d |\n", len(r.APIEndpoints))
	fmt.Fprintf(&b, "| Login Pages | %d |\n", len(r.LoginPages))
	fmt.Fprintf(&b, "| Technologies | %d |\n", len(r.Technologies))
	fmt.Fprintf(&b, "| Sensitive Files | %d |\n", len(r.SensitiveFiles))
	fmt.Fprintf(&b, "| Secrets | %d |\n", len(r.Secrets))
	fmt.Fprintf(&b, "| Parameters | %d |\n\n", len(r.Parameters))

	if len(r.Findings) > 0 {
		fmt.Fprintf(&b, "## Findings\n\n")
		fmt.Fprintf(&b, "| Severity | Module | Title | URL |\n|---|---|---|---|\n")
		for _, f := range sortFindings(r.Findings) {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				strings.ToUpper(string(f.Severity)), f.Module, mdEscape(f.Title), f.URL)
		}
		b.WriteString("\n")
	}

	if len(r.Technologies) > 0 {
		fmt.Fprintf(&b, "## Technologies\n\n")
		for _, t := range r.Technologies {
			v := t.Version
			if v == "" {
				v = "?"
			}
			fmt.Fprintf(&b, "- **%s** (%s) — v%s\n", t.Name, t.Category, v)
		}
		b.WriteString("\n")
	}

	return []byte(b.String()), nil
}

func mdEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

// htmlToPDF converts an HTML report to PDF using a headless browser if one is
// available. Returns an error (ignored by the caller) when no browser exists.
func htmlToPDF(htmlPath string) (string, error) {
	browser := findBrowser()
	if browser == "" {
		return "", fmt.Errorf("no headless browser available for PDF export")
	}
	pdfPath := strings.TrimSuffix(htmlPath, ".html") + ".pdf"
	abs, _ := filepath.Abs(htmlPath)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, browser,
		"--headless=new", "--disable-gpu", "--no-sandbox",
		"--print-to-pdf="+pdfPath, "--no-pdf-header-footer",
		"file://"+filepath.ToSlash(abs),
	)
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return pdfPath, nil
}

func findBrowser() string {
	for _, c := range []string{"google-chrome", "chromium", "chromium-browser", "chrome", "msedge"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}
