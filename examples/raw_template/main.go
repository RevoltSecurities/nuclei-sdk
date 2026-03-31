package main

import (
	"context"
	"fmt"
	"log"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

func main() {
	// Define a template as raw YAML bytes
	customTemplate := []byte(`
id: custom-header-check

info:
  name: Custom Security Header Check
  author: nuclei-sdk
  severity: info
  tags: headers,security

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "X-Frame-Options"
          - "X-Content-Type-Options"
          - "Content-Security-Policy"
        part: header
        negative: true
`)

	// Create scanner with raw YAML bytes
	scanner, err := nucleisdk.NewScanner(
		// Load from raw YAML bytes
		nucleisdk.WithTemplateBytes("custom-header-check", customTemplate),

		// Or fetch from URL
		// nucleisdk.WithTemplateURL("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/misconfiguration/missing-csp.yaml"),

		// Set targets
		nucleisdk.WithTargets("https://example.com", "https://httpbin.org"),

		// Concurrency
		nucleisdk.WithThreads(10),
		nucleisdk.WithRateLimit(20),

		// Silent mode (less output from nuclei engine)
		nucleisdk.WithSilent(),
	)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	results, err := scanner.Run(ctx)
	if err != nil {
		log.Fatalf("Failed to start scan: %v", err)
	}

	for result := range results {
		fmt.Printf("[%s] %s - %s\n", result.Severity, result.TemplateID, result.MatchedURL)
		fmt.Println(result.JSONPretty())
	}
}
