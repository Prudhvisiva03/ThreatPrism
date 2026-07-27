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

// systemGuard is prepended to every prompt to enforce the advisory-only policy.
const systemGuard = "You are ThreatPrism's AI assistant for security reconnaissance. " +
	"You only explain findings, summarize scans, score and prioritize risk, and suggest further reconnaissance. " +
	"You never provide exploit code, payloads, or instructions to attack, compromise, or gain unauthorized access to systems."
