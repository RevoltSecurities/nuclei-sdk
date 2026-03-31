package main

import (
	"context"
	"fmt"
	"log"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

func main() {
	// Create a WordPress scanner
	scanner, err := nucleisdk.NewWordPressScanner(
		nucleisdk.WithTargets("https://wordpress-site.example.com"),

		// Template directory with WordPress templates
		nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),

		// Optional: add authentication for wp-admin checks
		nucleisdk.WithAuth(nucleisdk.BasicAuth("admin", "password", "wordpress-site.example.com")),

		// Filter for high/critical findings only
		nucleisdk.WithResultSeverityFilter("high", "critical"),
	)
	if err != nil {
		log.Fatalf("Failed to create WordPress scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()

	// Use callback style instead of channel
	err = scanner.RunWithCallback(ctx, func(result *nucleisdk.ScanResult) {
		fmt.Printf("[%s] [%s] %s\n", result.Severity, result.TemplateID, result.MatchedURL)

		if len(result.CVEID) > 0 {
			fmt.Printf("  CVE: %v\n", result.CVEID)
		}
		if result.CVSSScore > 0 {
			fmt.Printf("  CVSS: %.1f\n", result.CVSSScore)
		}
		if result.Remediation != "" {
			fmt.Printf("  Fix: %s\n", result.Remediation)
		}
	})
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}
}
