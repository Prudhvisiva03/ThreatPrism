// Package tui implements ThreatPrism's interactive terminal dashboard using
// BubbleTea and LipGloss: a main menu, target input, recon-mode selection,
// live scan progress, and a results summary.
package tui

import "github.com/charmbracelet/lipgloss"

// Color palette shared across the TUI, mirroring the HTML dashboard.
var (
	colBg      = lipgloss.Color("#0b0e14")
	colText    = lipgloss.Color("#e6e9ef")
	colMuted   = lipgloss.Color("#8b93a7")
	colAccent  = lipgloss.Color("#5b8cff")
	colAccent2 = lipgloss.Color("#22d3ee")
	colCrit    = lipgloss.Color("#ff4d6d")
	colHigh    = lipgloss.Color("#ff8c42")
	colMed     = lipgloss.Color("#ffd166")
	colLow     = lipgloss.Color("#4cc9f0")
	colOK      = lipgloss.Color("#5eead4")
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).Foreground(colText).
			Background(colAccent).Padding(0, 2).MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().Foreground(colMuted).MarginBottom(1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#242c3d")).
			Padding(1, 2)

	menuItemStyle    = lipgloss.NewStyle().Foreground(colText).Padding(0, 1)
	menuSelStyle     = lipgloss.NewStyle().Foreground(colBg).Background(colAccent).Bold(true).Padding(0, 1)
	menuNumStyle     = lipgloss.NewStyle().Foreground(colAccent2).Bold(true)
	menuSelNumStyle  = lipgloss.NewStyle().Foreground(colBg).Bold(true)
	menuDescStyle    = lipgloss.NewStyle().Foreground(colMuted)

	helpStyle   = lipgloss.NewStyle().Foreground(colMuted).MarginTop(1)
	accentStyle = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	okStyle     = lipgloss.NewStyle().Foreground(colOK)
	errStyle    = lipgloss.NewStyle().Foreground(colCrit).Bold(true)
	labelStyle  = lipgloss.NewStyle().Foreground(colMuted)
	valueStyle  = lipgloss.NewStyle().Foreground(colText).Bold(true)
)

// severityStyle returns a style colored for a severity token.
func severityStyle(sev string) lipgloss.Style {
	switch sev {
	case "critical":
		return lipgloss.NewStyle().Foreground(colCrit).Bold(true)
	case "high":
		return lipgloss.NewStyle().Foreground(colHigh).Bold(true)
	case "medium":
		return lipgloss.NewStyle().Foreground(colMed)
	case "low":
		return lipgloss.NewStyle().Foreground(colLow)
	default:
		return lipgloss.NewStyle().Foreground(colOK)
	}
}
