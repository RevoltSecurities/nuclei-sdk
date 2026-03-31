package nucleisdk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"gopkg.in/yaml.v3"
)

// TemplateInfo contains parsed metadata from a nuclei template.
type TemplateInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Author      string   `json:"author"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
}

// templateMetadata is used for lightweight YAML parsing.
type templateMetadata struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string      `yaml:"name"`
		Author      interface{} `yaml:"author"`
		Severity    string      `yaml:"severity"`
		Tags        interface{} `yaml:"tags"`
		Description string      `yaml:"description"`
	} `yaml:"info"`
}

// FetchTemplateFromURL downloads a template from a URL and returns the YAML bytes.
func FetchTemplateFromURL(ctx context.Context, templateURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, templateURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching template: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return data, nil
}

// ValidateTemplate parses raw YAML bytes and validates them as a valid nuclei template.
// Returns the template ID and any validation error.
func ValidateTemplate(data []byte) (string, error) {
	var meta templateMetadata
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return "", fmt.Errorf("invalid YAML: %w", err)
	}

	if meta.ID == "" {
		return "", fmt.Errorf("template missing required 'id' field")
	}
	if meta.Info.Name == "" {
		return "", fmt.Errorf("template missing required 'info.name' field")
	}

	return meta.ID, nil
}

// ParseTemplateInfo extracts metadata from raw YAML template bytes
// without creating a full nuclei engine.
func ParseTemplateInfo(data []byte) (*TemplateInfo, error) {
	var meta templateMetadata
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	if meta.ID == "" {
		return nil, fmt.Errorf("template missing required 'id' field")
	}

	info := &TemplateInfo{
		ID:          meta.ID,
		Name:        meta.Info.Name,
		Severity:    meta.Info.Severity,
		Description: meta.Info.Description,
	}

	// Parse author (can be string or []string)
	switch v := meta.Info.Author.(type) {
	case string:
		info.Author = v
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok {
				if info.Author != "" {
					info.Author += ","
				}
				info.Author += s
			}
		}
	}

	// Parse tags (can be string or []string)
	switch v := meta.Info.Tags.(type) {
	case string:
		for _, tag := range splitCSV(v) {
			if tag != "" {
				info.Tags = append(info.Tags, tag)
			}
		}
	case []interface{}:
		for _, t := range v {
			if s, ok := t.(string); ok {
				info.Tags = append(info.Tags, s)
			}
		}
	}

	return info, nil
}

// splitCSV splits a comma-separated string and trims whitespace.
func splitCSV(s string) []string {
	var parts []string
	for _, p := range splitString(s, ',') {
		p = trimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitString(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
