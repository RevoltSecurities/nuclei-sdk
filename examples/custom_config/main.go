package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

func main() {
	// Full configuration example showing all major options
	scanner, err := nucleisdk.NewScanner(
		// Templates: directory + individual files
		nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
		nucleisdk.WithTemplateFiles(
			"/path/to/custom-template-1.yaml",
			"/path/to/custom-template-2.yaml",
		),

		// Template filters
		nucleisdk.WithTags("cve", "exposure", "misconfig"),
		nucleisdk.WithExcludeTags("dos"),
		nucleisdk.WithSeverityFilter("medium", "high", "critical"),

		// Targets from multiple sources
		nucleisdk.WithTargets("https://target1.com", "https://target2.com"),
		// nucleisdk.WithTargetFile("/path/to/targets.txt"),

		// Proxy configuration (e.g., Burp Suite)
		nucleisdk.WithProxy("http://127.0.0.1:8080"),
		nucleisdk.WithProxyInternal(false),

		// Concurrency tuning
		nucleisdk.WithThreads(50),
		nucleisdk.WithHostConcurrency(25),
		nucleisdk.WithRateLimit(100),
		nucleisdk.WithPayloadConcurrency(10),

		// Timeouts
		nucleisdk.WithTimeout(15),
		nucleisdk.WithRetries(2),

		// Custom headers for all requests
		nucleisdk.WithHeader("User-Agent", "NucleiSDK/1.0"),
		nucleisdk.WithHeader("X-Custom-Header", "scanner"),

		// Custom variables available in templates
		nucleisdk.WithVar("api_key", "test-key-123"),
		nucleisdk.WithVar("username", "admin"),

		// Authentication
		nucleisdk.WithAuth(nucleisdk.BearerToken("your-jwt-token", "target1.com")),
		nucleisdk.WithAuth(nucleisdk.BasicAuth("admin", "pass", "target2.com")),

		// Scan strategy
		nucleisdk.WithScanStrategy(nucleisdk.StrategyTemplateSpray),

		// Verbosity
		nucleisdk.WithSilent(),
	)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	// Run and collect all results
	ctx := context.Background()
	results, err := scanner.Run(ctx)
	if err != nil {
		log.Fatalf("Failed to start scan: %v", err)
	}

	// Collect all results and write as JSON array to file
	var allResults []*nucleisdk.ScanResult
	for result := range results {
		allResults = append(allResults, result)
		fmt.Printf("[%s] [%s] %s\n", result.Severity, result.TemplateID, result.MatchedURL)
	}

	// Write results to JSON file
	if len(allResults) > 0 {
		jsonData, err := json.MarshalIndent(allResults, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal results: %v", err)
		}
		if err := os.WriteFile("scan-results.json", jsonData, 0644); err != nil {
			log.Fatalf("Failed to write results: %v", err)
		}
		fmt.Printf("\nWrote %d results to scan-results.json\n", len(allResults))
	} else {
		fmt.Println("\nNo vulnerabilities found")
	}
}
