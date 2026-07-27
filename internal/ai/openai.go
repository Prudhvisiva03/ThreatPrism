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

// openaiChat implements the OpenAI-compatible Chat Completions API. OpenRouter
// reuses the same wire format, so it embeds this type.
type openaiChat struct {
	name    string
	apiKey  string
	model   string
	baseURL string
	extraHeaders map[string]string
	client  *http.Client
}

func newOpenAI(cfg config.AIConfig) *openaiChat {
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	model := cfg.Model
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &openaiChat{
		name:    "openai",
		apiKey:  cfg.APIKey,
		model:   model,
		baseURL: base,
		client:  &http.Client{Timeout: 120 * time.Second},
	}
}

func newOpenRouter(cfg config.AIConfig) *openaiChat {
	base := cfg.BaseURL
	if base == "" {
		base = "https://openrouter.ai/api/v1"
	}
	model := cfg.Model
	if model == "" {
		model = "openai/gpt-4o-mini"
	}
	return &openaiChat{
		name:    "openrouter",
		apiKey:  cfg.APIKey,
		model:   model,
		baseURL: base,
		extraHeaders: map[string]string{
			"HTTP-Referer": "https://github.com/threatprism/threatprism",
			"X-Title":      "ThreatPrism",
		},
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

func (o *openaiChat) Name() string { return o.name }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (o *openaiChat) Complete(ctx context.Context, prompt string) (string, error) {
	if o.apiKey == "" {
		return "", fmt.Errorf("%s: missing API key (set THREATPRISM_AI_API_KEY)", o.name)
	}
	reqBody := chatRequest{
		Model:       o.model,
		Temperature: 0.3,
		Messages: []chatMessage{
			{Role: "system", Content: systemGuard},
			{Role: "user", Content: prompt},
		},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)
	for k, v := range o.extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var cr chatResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return "", fmt.Errorf("%s: decode response: %w", o.name, err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("%s: %s", o.name, cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("%s: empty response", o.name)
	}
	return cr.Choices[0].Message.Content, nil
}
