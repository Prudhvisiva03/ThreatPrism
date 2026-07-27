// Package ai provides a pluggable AI provider abstraction for the AI Assistant.
// It supports OpenAI, Gemini, OpenRouter, and Ollama behind a single interface
// so the rest of ThreatPrism is provider-agnostic.
//
// The assistant is strictly advisory: prompts are constructed to explain,
// summarize, prioritize, and suggest reconnaissance — never to exploit.
package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/threatprism/threatprism/internal/config"
)

// Provider is implemented by every supported AI backend.
type Provider interface {
	// Name returns the provider identifier.
	Name() string
	// Complete sends a single prompt and returns the model's text response.
	Complete(ctx context.Context, prompt string) (string, error)
}

// NewProvider constructs a Provider from AI configuration.
func NewProvider(cfg config.AIConfig) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "openai":
		return newOpenAI(cfg), nil
	case "gemini":
		return newGemini(cfg), nil
	case "openrouter":
		return newOpenRouter(cfg), nil
	case "ollama", "":
		return newOllama(cfg), nil
	default:
		return nil, fmt.Errorf("ai: unknown provider %q", cfg.Provider)
	}
}

// System prompts tailored for different AI modes.
const (
	SystemGuardBeginner = "You are ThreatPrism's AI Assistant in Beginner Mode. " +
		"Explain security reconnaissance findings using simple, clear, non-jargon language. " +
		"Focus on explaining WHAT was found and WHY it matters in plain English. " +
		"Never provide exploit code, attack payloads, or instructions to gain unauthorized access."

	SystemGuardProfessional = "You are ThreatPrism's AI Assistant in Professional Mode. " +
		"Provide technical triage of reconnaissance findings, asset exposure analysis, risk weights, and actionable next recon steps. " +
		"Never provide exploit code, attack payloads, or instructions to gain unauthorized access."

	SystemGuardEnterprise = "You are ThreatPrism's AI Assistant in Enterprise Mode. " +
		"Focus on attack surface management, asset inventory classification, risk score impact, executive summary, and high-level compliance/remediation priorities. " +
		"Never provide exploit code, attack payloads, or instructions to gain unauthorized access."
)

// PromptForMode returns the appropriate system prompt based on the configured AI mode.
func PromptForMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "beginner":
		return SystemGuardBeginner
	case "enterprise":
		return SystemGuardEnterprise
	default:
		return SystemGuardProfessional
	}
}

