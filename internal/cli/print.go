package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/threatprism/threatprism/pkg/models"
)

// Output styles for non-interactive command output.
var (
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff4d6d")).Bold(true)
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#5eead4"))
	headerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#5b8cff")).Bold(true)
	mutedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#8b93a7"))
	valueStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#e6e9ef")).Bold(true)
)

func severityStyle(sev models.Severity) lipgloss.Style {
	switch strings.ToLower(string(sev)) {
	case "critical":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#ff4d6d")).Bold(true)
	case "high":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#ff8c42")).Bold(true)
	case "medium":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#ffd166"))
	case "low":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#4cc9f0"))
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#5eead4"))
	}
}

// cliProgress implements module.Progress by streaming human-readable lines to
// stderr, keeping stdout clean for structured output.
type cliProgress struct{ quiet bool }

func (p cliProgress) Stage(slug, name string) {
	if p.quiet {
		return
	}
	fmt.Fprintln(os.Stderr, headerStyle.Render("▶ "+name))
}

func (p cliProgress) Stepf(format string, args ...any) {
	if p.quiet {
		return
	}
	fmt.Fprintln(os.Stderr, mutedStyle.Render("  "+fmt.Sprintf(format, args...)))
}

func (p cliProgress) Done(slug string, findings int) {
	if p.quiet {
		return
	}
	fmt.Fprintln(os.Stderr, okStyle.Render(fmt.Sprintf("  ✓ %s (%d findings)", slug, findings)))
}

// printResult renders a compact scan summary to stdout.
func printResult(r *models.Result) {
	fmt.Println()
	fmt.Println(headerStyle.Render("ThreatPrism — Results for " + r.Target.Host))
	fmt.Println(mutedStyle.Render(strings.Repeat("─", 52)))

	level := r.RiskLevel()
	badge := severityStyle(models.Severity(strings.ToLower(level))).Render(" " + strings.ToUpper(level) + " ")
	fmt.Printf("%s %s   %s\n\n",
		mutedStyle.Render("Risk Score"),
		valueStyle.Render(fmt.Sprintf("%d/100", r.RiskScore)),
		badge)

	stats := [][2]string{
		{"Subdomains", itoa(len(r.Subdomains))},
		{"Alive Hosts", itoa(len(r.Hosts))},
		{"JS Files", itoa(len(r.JSFiles))},
		{"API Endpoints", itoa(len(r.APIEndpoints))},
		{"Login Pages", itoa(len(r.LoginPages))},
		{"Technologies", itoa(len(r.Technologies))},
		{"Sensitive Files", itoa(len(r.SensitiveFiles))},
		{"Secrets", itoa(len(r.Secrets))},
		{"Parameters", itoa(len(r.Parameters))},
		{"Findings", itoa(len(r.Findings))},
	}
	for _, s := range stats {
		fmt.Printf("  %s %s\n", mutedStyle.Render(padRight(s[0], 16)), valueStyle.Render(s[1]))
	}

	if len(r.Findings) > 0 {
		fmt.Println("\n" + headerStyle.Render("Top Findings"))
		for i, f := range topFindings(r.Findings) {
			if i >= 10 {
				fmt.Println(mutedStyle.Render(fmt.Sprintf("  … and %d more", len(r.Findings)-10)))
				break
			}
			sv := severityStyle(f.Severity).Render(padRight(strings.ToUpper(string(f.Severity)), 8))
			fmt.Printf("  %s %s\n", sv, f.Title)
		}
	}
	fmt.Println()
}

func topFindings(fs []models.Finding) []models.Finding {
	out := make([]models.Finding, len(fs))
	copy(out, fs)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Severity.Score() > out[j].Severity.Score()
	})
	return out
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
