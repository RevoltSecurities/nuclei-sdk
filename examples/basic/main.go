package main

import (
	"context"
	"fmt"
	"log"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

func main() {
	// Create a scanner with default nuclei-templates and targets
	scanner, err := nucleisdk.NewScanner(
		// No WithTemplateDir needed — nuclei loads from ~/.local/nuclei-templates/ by default

		// Set targets to scan
		nucleisdk.WithTargets("https://example.com"),

		// Filter by tags (not protocol types — "wordpress" is a tag)
		nucleisdk.WithTags("wordpress"),

		// Concurrency settings
		nucleisdk.WithThreads(25),
		nucleisdk.WithRateLimit(100),
	)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	// Run scan and consume results from channel
	ctx := context.Background()
	results, err := scanner.Run(ctx)
	if err != nil {
		log.Fatalf("Failed to start scan: %v", err)
	}

	for result := range results {
		fmt.Printf("[%s] [%s] %s - %s\n",
			result.Severity,
			result.TemplateID,
			result.MatchedURL,
			result.TemplateName,
		)

		// Access JSON output
		// fmt.Println(result.JSONPretty())

		// Check severity
		if result.IsHighOrAbove() {
			fmt.Printf("  HIGH/CRITICAL FINDING: %s\n", result.Description)
		}
	}
}
