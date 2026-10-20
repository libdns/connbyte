package connbyte

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.connbyte.com"

type apiStatus struct {
	Code    int    `json:"code"`
	Title   string `json:"title"`
	Message string `json:"message"`
	ID      string `json:"id"`
	LogID   string `json:"logId"`
	Path    string `json:"path"`
}

type apiResponse[T any] struct {
	Status apiStatus           `json:"status"`
	Data   T                   `json:"data"`
	Field  []map[string]string `json:"field"`
}

// APIError is returned when the ConnByte API answers with a non-2xx status.
type APIError struct {
	Status apiStatus
	Field  []map[string]string
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "connbyte: %d %s: %s", e.Status.Code, e.Status.Title, e.Status.Message)
	for _, f := range e.Field {
		for k, v := range f {
			fmt.Fprintf(&b, " [%s: %s]", k, v)
		}
	}
	if e.Status.LogID != "" {
		fmt.Fprintf(&b, " (logId %s)", e.Status.LogID)
	}
	return b.String()
}

type apiZone struct {
	ID        string `json:"id"`
	ProjectID string `json:"projectId"`
	Zone      string `json:"zone"`
}

type apiRecord struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority"`
	Disabled int    `json:"disabled"`
}

type recordInput struct {
	ZoneID   string `json:"zoneId"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority"`
	Disabled bool   `json:"disabled"`
}

type recordCreated struct {
	ID     int64  `json:"id"`
	Record string `json:"record"`
}

func (p *Provider) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (p *Provider) baseURL() string {
	if p.BaseURL != "" {
		return strings.TrimRight(p.BaseURL, "/")
	}
	return defaultBaseURL
}

// call sends a POST request with a JSON body to the given API path and decodes the "data" member into out.
func call[T any](ctx context.Context, p *Provider, path string, payload any, out *T) error {
	if p.APIToken == "" {
		return fmt.Errorf("connbyte: api_token is empty")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("connbyte: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("connbyte: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("User-Agent", "libdns-connbyte")

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("connbyte: %s: %w", path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return fmt.Errorf("connbyte: %s: read response: %w", path, err)
	}

	var result apiResponse[T]
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("connbyte: %s: HTTP %d: decode response: %w", path, resp.StatusCode, err)
	}

	if resp.StatusCode/100 != 2 || (result.Status.Code != 0 && result.Status.Code/100 != 2) {
		if result.Status.Code == 0 {
			result.Status.Code = resp.StatusCode
		}
		return &APIError{Status: result.Status, Field: result.Field}
	}

	if out != nil {
		*out = result.Data
	}
	return nil
}
