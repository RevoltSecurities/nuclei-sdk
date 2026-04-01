package main

import (
	"context"
	"fmt"
	"log"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

func main() {
	// Create a scan engine with shared base configuration.
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

	// One-time heavy init: protocol state, template loading, global resources.
	// After this, all Scan() calls are lightweight.
	if err := engine.Setup(); err != nil {
		log.Fatalf("Failed to set up engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// RunParallel launches multiple concurrent lightweight scans.
	// Each scan gets its own core.Engine (~5 fields) and filtered templates,
	// but shares global resources (template store, interactsh, rate limiter, etc.).
	//
	// This is far more efficient than running N separate engines concurrently.
	results, err := engine.RunParallel(ctx,
		// Job 1: HTTP high/critical CVEs against web targets
		nucleisdk.ConcurrentScan{
			Label: "http-cves",
			Options: []nucleisdk.Option{
				nucleisdk.WithProtocolTypes("http"),
				nucleisdk.WithTags("cve", "exposure", "misconfig"),
				nucleisdk.WithSeverityFilter("high", "critical"),
				nucleisdk.WithTargets("https://example.com"),
			},
		},

		// Job 2: DNS reconnaissance on domains
		nucleisdk.ConcurrentScan{
			Label: "dns",
			Options: []nucleisdk.Option{
				nucleisdk.WithProtocolTypes("dns"),
				nucleisdk.WithTags("dns", "cname", "takeover"),
				nucleisdk.WithTargets("example.com"),
			},
		},

		// Job 3: SSL/TLS certificate checks
		nucleisdk.ConcurrentScan{
			Label: "ssl",
			Options: []nucleisdk.Option{
				nucleisdk.WithProtocolTypes("ssl"),
				nucleisdk.WithTargets("example.com:443"),
			},
		},

		// Job 4: WordPress-specific scan against a different target
		nucleisdk.ConcurrentScan{
			Label: "wordpress",
			Options: []nucleisdk.Option{
				nucleisdk.WithProtocolTypes("http"),
				nucleisdk.WithTags("http"),
				nucleisdk.WithTargets("https://example.com"),
			},
		},
	)
	if err != nil {
		log.Fatalf("Failed to start parallel scan: %v", err)
	}

	// All results come through a single channel, tagged with their job label.
	counts := make(map[string]int)
	for lr := range results {
		if lr.Error != "" {
			fmt.Printf("[%s] ERROR: %s\n", lr.Label, lr.Error)
			continue
		}

		counts[lr.Label]++
		fmt.Printf("[%s] [%s] [%s] %s - %s\n",
			lr.Label, lr.Severity, lr.TemplateID, lr.Host, lr.TemplateName)
	}

	fmt.Println("\n--- Summary ---")
	total := 0
	for label, count := range counts {
		fmt.Printf("  %s: %d findings\n", label, count)
		total += count
	}
	fmt.Printf("  Total: %d findings\n", total)
}
