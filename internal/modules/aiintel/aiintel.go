// Package aiintel implements the AI Intelligence module: it calls the
// configured AI provider to summarize findings, score risk, and suggest next
// recon steps. It never performs exploitation — it only explains and advises.
package aiintel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/threatprism/threatprism/internal/core/module"
	"github.com/threatprism/threatprism/internal/ai"
	"github.com/threatprism/threatprism/pkg/models"
)

// Module implements AI Intelligence.
type Module struct{ module.Meta }

// New returns a configured aiintel module.
func New() *Module {
	return &Module{Meta: module.Meta{
		ModSlug:     "aiintel",
		ModName:     "AI Intelligence",
		ModDesc:     "Summarizes findings, scores risk, and suggests next steps via AI",
		ModCategory: "intelligence",
		ModModes:    []models.Mode{models.ModeDeep},
	}}
}

// Run calls the AI provider to analyze the current result.
func (m *Module) Run(rc *module.RunContext) error {
	if rc.Config == nil || !rc.Config.AI.Enabled {
		rc.Progress.Stepf("AI disabled; skipping AI intelligence")
		return nil
	}

	provider, err := ai.NewProvider(rc.Config.AI)
	if err != nil {
		rc.Log.Warn("aiintel: could not initialize AI provider", "err", err)
		return nil
	}

	result := rc.Result()
	prompt := buildPrompt(result, rc.Config.AI.Mode)

	rc.Progress.Stepf("querying AI provider (%s / %s)", rc.Config.AI.Provider, rc.Config.AI.Model)
	ctx, cancel := context.WithTimeout(rc.Ctx, 120*time.Second)
	defer cancel()

	summary, err := provider.Complete(ctx, prompt)
	if err != nil {
		rc.Log.Warn("aiintel: AI query failed", "err", err)
		return nil
	}

	rc.Update(func(r *models.Result) {
		r.Findings = append(r.Findings, models.Finding{
			Module: m.Slug(), Type: "ai_summary", Severity: models.SeverityInfo, Confidence: 60,
			Title:       "AI Reconnaissance Summary",
			Description: summary,
			Tags:        []string{"ai", "summary"}, FoundAt: time.Now(),
		})
	})

	if rc.Workspace != nil {
		_, _ = rc.Workspace.WriteFile("17_ai", "summary.md", []byte(summary))
	}
	rc.Progress.Stepf("AI summary generated (%d chars)", len(summary))
	return nil
}

func buildPrompt(r *models.Result, mode string) string {
	var sb strings.Builder
	if mode == "beginner" {
		sb.WriteString("You are a friendly security mentor. Explain the following reconnaissance findings in simple terms a beginner can understand. Focus on what each finding means and why it matters.\n\n")
	} else {
		sb.WriteString("You are an expert penetration tester. Analyze the following reconnaissance findings professionally. Provide a risk summary, prioritized attack surface observations, and suggested next investigation steps. Do NOT suggest exploitation — only further reconnaissance and investigation.\n\n")
	}
	sb.WriteString(fmt.Sprintf("Target: %s\n", r.Target.URL))
	sb.WriteString(fmt.Sprintf("Risk Score: %d/100 (%s)\n", r.RiskScore, r.RiskLevel()))
	sb.WriteString(fmt.Sprintf("Subdomains: %d | Hosts: %d | JS Files: %d | APIs: %d | Login Pages: %d\n",
		len(r.Subdomains), len(r.Hosts), len(r.JSFiles), len(r.APIEndpoints), len(r.LoginPages)))
	sb.WriteString(fmt.Sprintf("Sensitive Files: %d | Secrets: %d | Parameters: %d\n",
		len(r.SensitiveFiles), len(r.Secrets), len(r.Parameters)))
	sb.WriteString("\nKey Findings:\n")
	count := 0
	for _, f := range r.Findings {
		if f.Severity == models.SeverityInfo || count >= 20 {
			continue
		}
		sb.WriteString(fmt.Sprintf("- [%s] %s: %s\n", strings.ToUpper(string(f.Severity)), f.Module, f.Title))
		count++
	}
	sb.WriteString("\nTechnologies: ")
	techs := make([]string, 0, len(r.Technologies))
	for _, t := range r.Technologies {
		if t.Version != "" {
			techs = append(techs, t.Name+" "+t.Version)
		} else {
			techs = append(techs, t.Name)
		}
	}
	sb.WriteString(strings.Join(techs, ", "))
	sb.WriteString("\n\nProvide your analysis:")
	return sb.String()
}
