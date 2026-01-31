package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an OpenAI-compatible API client
type Client struct {
	APIKey     string
	Endpoint   string
	Model      string
	HTTPClient *http.Client
}

// NewClient creates a new AI client
func NewClient(apiKey, endpoint, model string) *Client {
	return &Client{
		APIKey:   apiKey,
		Endpoint: endpoint,
		Model:    model,
		HTTPClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// ChatMessage represents a message in the chat completion API
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionRequest represents the request body for chat completions
type ChatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	Temperature float64       `json:"temperature,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

// ChatCompletionResponse represents the response from chat completions
type ChatCompletionResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int         `json:"index"`
		Message      ChatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *APIError `json:"error,omitempty"`
}

// APIError represents an error from the API
type APIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// Complete sends a chat completion request and returns the response text
func (c *Client) Complete(ctx context.Context, messages []ChatMessage) (string, error) {
	if c.APIKey == "" {
		return "", fmt.Errorf("AI API key not configured")
	}

	reqBody := ChatCompletionRequest{
		Model:       c.Model,
		Messages:    messages,
		Temperature: 0.3,
		MaxTokens:   2000,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1"
	}
	url := endpoint + "/chat/completions"

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ChatCompletionResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != nil {
			return "", fmt.Errorf("API error: %s", errResp.Error.Message)
		}
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result ChatCompletionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no completion choices returned")
	}

	return result.Choices[0].Message.Content, nil
}

// GenerateVEXJustification generates a VEX justification for a vulnerability
func (c *Client) GenerateVEXJustification(ctx context.Context, vulnID, pkgName, description, modWhyOutput string) (string, error) {
	systemPrompt := `You are a security expert helping to create VEX (Vulnerability Exploitability eXchange) documents.
Your task is to analyze vulnerabilities and determine if they are exploitable in the context of how the package is used.

Respond with a JSON object in OpenVEX format containing:
- "status": one of "not_affected", "affected", "fixed", or "under_investigation"
- "justification": if status is "not_affected", one of: "component_not_present", "vulnerable_code_not_reachable", "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"
- "impact_statement": a brief explanation of why this status was chosen

Only respond with the JSON object, no additional text.`

	userPrompt := fmt.Sprintf(`Analyze this vulnerability:

Vulnerability ID: %s
Package: %s
Description: %s

Dependency chain (from 'go mod why'):
%s

Based on how this dependency is used (as shown in the dependency chain), determine if the vulnerability is likely exploitable.
If you cannot determine exploitability, use "under_investigation" status.`, vulnID, pkgName, description, modWhyOutput)

	messages := []ChatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	return c.Complete(ctx, messages)
}
