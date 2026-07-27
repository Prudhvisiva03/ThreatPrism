package tui

import (
	"sort"
	"strconv"
	"strings"

	"github.com/threatprism/threatprism/pkg/models"
)

// pad right-pads s with spaces to width n (never truncates).
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func itoa(n int) string { return strconv.Itoa(n) }

// riskLine renders the overall risk score and level as a colored badge.
func riskLine(r *models.Result) string {
	level := r.RiskLevel()
	style := severityStyle(strings.ToLower(level))
	return labelStyle.Render("Risk Score ") +
		valueStyle.Render(itoa(r.RiskScore)+"/100") + "  " +
		style.Render(" "+strings.ToUpper(level)+" ")
}

// topFindings returns findings sorted by descending severity score.
func topFindings(fs []models.Finding) []models.Finding {
	out := make([]models.Finding, len(fs))
	copy(out, fs)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Severity.Score() > out[j].Severity.Score()
	})
	return out
}
