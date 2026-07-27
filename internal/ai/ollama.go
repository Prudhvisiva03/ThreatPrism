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

// ollama implements the local Ollama generate API. It requires no API key,
// making it the privacy-friendly default for offline use.
type ollama struct {
	model   string
	baseURL string
	client  *http.Client
}

func newOllama(cfg config.AIConfig) *ollama {
	base := cfg.BaseURL
	if base == "" {
		base = "http://localhost:11434"
	}
	model := cfg.Model
	if model == "" {
		model = "llama3.1"
	}
	return &ollama{
		model:   model,
		baseURL: base,
		client:  &http.Client{Timeout: 180 * time.Second},
	}
}

func (o *ollama) Name() string { return "ollama" }

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	System string `json:"system"`
	Stream bool   `json:"stream"`
}
type ollamaResponse struct {
	Response string `json:"response"`
	Error    string `json:"error"`
}

func (o *ollama) Complete(ctx context.Context, prompt string) (string, error) {
	reqBody := ollamaRequest{
		Model:  o.model,
		Prompt: prompt,
		System: PromptForMode(o.model),
		Stream: false,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/api/generate", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama: %w (is ollama running at %s?)", err, o.baseURL)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var or ollamaResponse
	if err := json.Unmarshal(body, &or); err != nil {
		return "", fmt.Errorf("ollama: decode response: %w", err)
	}
	if or.Error != "" {
		return "", fmt.Errorf("ollama: %s", or.Error)
	}
	return or.Response, nil
}
