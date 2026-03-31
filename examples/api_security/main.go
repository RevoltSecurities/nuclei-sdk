package main

import (
	"context"
	"fmt"
	"log"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

func main() {
	// Create an API Security scanner with OpenAPI spec and bearer auth
	scanner, err := nucleisdk.NewAPISecurityScanner(
		// Load from OpenAPI specification
		nucleisdk.WithOpenAPISpec("/path/to/openapi.yaml"),

		// Or scan specific API targets
		// nucleisdk.WithTargets("https://api.example.com"),

		// Add authentication
		nucleisdk.WithAuth(nucleisdk.BearerToken("your-api-token-here", "api.example.com")),

		// Or use API key header
		// nucleisdk.WithAuth(nucleisdk.APIKeyHeader("X-API-Key", "your-key", "api.example.com")),

		// Custom headers for all requests
		nucleisdk.WithHeader("Accept", "application/json"),

		// Proxy for debugging
		// nucleisdk.WithProxy("http://127.0.0.1:8080"),

		// Rate limit to avoid overwhelming the API
		nucleisdk.WithRateLimit(30),
	)
	if err != nil {
		log.Fatalf("Failed to create API scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	results, err := scanner.Run(ctx)
	if err != nil {
		log.Fatalf("Failed to start scan: %v", err)
	}

	var findings int
	for result := range results {
		findings++
		fmt.Printf("[%s] %s - %s\n", result.Severity, result.TemplateID, result.MatchedURL)

		if result.IsFuzzingResult {
			fmt.Printf("  Fuzzing: method=%s param=%s\n", result.FuzzingMethod, result.FuzzingParameter)
		}

		if len(result.ExtractedResults) > 0 {
			fmt.Printf("  Extracted: %v\n", result.ExtractedResults)
		}

		// Get JSON for reporting
		// fmt.Println(result.JSONPretty())
	}

	fmt.Printf("\nScan complete: %d findings\n", findings)
}
