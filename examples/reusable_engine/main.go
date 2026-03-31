package main

import (
	"context"
	"fmt"
	"log"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

func main() {
	// Create a reusable scan engine with shared base configuration.
	engine, err := nucleisdk.NewScanEngine(
		nucleisdk.WithRateLimit(100),
		nucleisdk.WithTimeout(10),
		nucleisdk.WithRetries(2),
		nucleisdk.WithNoInteractsh(),
		nucleisdk.WithSilent(),
	)
	if err != nil {
		log.Fatalf("Failed to create scan engine: %v", err)
	}

	// One-time heavy init: loads ALL templates, sets up global resources.
	if err := engine.Setup(); err != nil {
		log.Fatalf("Failed to set up engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// --- Phase 1: HTTP vulnerability scan ---
	// Each Scan() is lightweight: creates only a core.Engine (~5 fields),
	// filters templates at runtime, and builds a SimpleInputProvider.
	fmt.Println("=== Phase 1: HTTP Scan ===")
	httpResults, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
		ProtocolTypes: "http",
		Targets:       []string{"https://example.com"},
	})
	if err != nil {
		log.Fatalf("HTTP scan failed: %v", err)
	}
	for result := range httpResults {
		fmt.Printf("[HTTP] [%s] %s - %s\n", result.Severity, result.TemplateID, result.MatchedURL)
	}

	// --- Phase 2: DNS enumeration scan ---
	fmt.Println("\n=== Phase 2: DNS Scan ===")
	dnsResults, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
		ProtocolTypes: "dns",
		Tags:          []string{"dns", "cname", "takeover"},
		Targets:       []string{"example.com", "target2.com"},
	})
	if err != nil {
		log.Fatalf("DNS scan failed: %v", err)
	}
	for result := range dnsResults {
		fmt.Printf("[DNS] [%s] %s - %s\n", result.Severity, result.TemplateID, result.Host)
	}

	// --- Phase 3: SSL/TLS scan ---
	fmt.Println("\n=== Phase 3: SSL/TLS Scan ===")
	sslResults, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
		ProtocolTypes: "ssl",
		Targets:       []string{"example.com:443", "target2.com:443"},
	})
	if err != nil {
		log.Fatalf("SSL scan failed: %v", err)
	}
	for result := range sslResults {
		fmt.Printf("[SSL] [%s] %s - %s\n", result.Severity, result.TemplateID, result.Host)
	}

	// --- Phase 4: Custom raw template scan ---
	fmt.Println("\n=== Phase 4: Custom Template Scan ===")
	customTemplate := nucleisdk.TemplateBytes("custom-header", []byte(`
id: custom-header-check
info:
  name: Custom Header Check
  severity: info
  author: scanner
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "X-Custom-Header"
        part: header
`))
	customResults, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
		TemplateBytes: []nucleisdk.TemplateBytesEntry{customTemplate},
		Targets:       []string{"https://example.com"},
	})
	if err != nil {
		log.Fatalf("Custom scan failed: %v", err)
	}
	for result := range customResults {
		fmt.Printf("[Custom] [%s] %s - %s\n", result.Severity, result.TemplateID, result.MatchedURL)
	}

	fmt.Println("\nAll scan phases completed.")
}
