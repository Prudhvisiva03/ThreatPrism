package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/threatprism/threatprism/internal/config"
)

// gemini implements Google's Generative Language API.
type gemini struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

func newGemini(cfg config.AIConfig) *gemini {
	base := cfg.BaseURL
	if base == "" {
		base = "https://generativelanguage.googleapis.com/v1beta"
	}
	model := cfg.Model
	if model == "" {
		model = "gemini-1.5-flash"
	}
	return &gemini{
		apiKey:  cfg.APIKey,
		model:   model,
		baseURL: base,
		client:  &http.Client{Timeout: 120 * time.Second},
	}
}

func (g *gemini) Name() string { return "gemini" }

type geminiPart struct {
	Text string `json:"text"`
}
type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}
type geminiRequest struct {
	Contents          []geminiContent `json:"contents"`
	SystemInstruction *geminiContent  `json:"systemInstruction,omitempty"`
}
type geminiResponse struct {
	Candidates []struct {
		Content geminiContent `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (g *gemini) Complete(ctx context.Context, prompt string) (string, error) {
	if g.apiKey == "" {
		return "", fmt.Errorf("gemini: missing API key (set THREATPRISM_AI_API_KEY)")
	}
	reqBody := geminiRequest{
		SystemInstruction: &geminiContent{Parts: []geminiPart{{Text: systemGuard}}},
		Contents:          []geminiContent{{Role: "user", Parts: []geminiPart{{Text: prompt}}}},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", g.baseURL, g.model, g.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var gr geminiResponse
	if err := json.Unmarshal(body, &gr); err != nil {
		return "", fmt.Errorf("gemini: decode response: %w", err)
	}
	if gr.Error != nil {
		return "", fmt.Errorf("gemini: %s", gr.Error.Message)
	}
	if len(gr.Candidates) == 0 || len(gr.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini: empty response")
	}
	return gr.Candidates[0].Content.Parts[0].Text, nil
}
