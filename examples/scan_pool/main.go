package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

// Simulates a vulnerability intelligence feed that delivers
// (target, CVE template) pairs over time — e.g., from an API,
// message queue, or webhook.
type vulnFeedItem struct {
	Target       string
	CVEID        string
	TemplateYAML []byte
}

func main() {
	// 1. Create and set up a shared engine ONCE.
	engine, err := nucleisdk.NewScanEngine(
		nucleisdk.WithRateLimit(100),
		nucleisdk.WithTimeout(10),
		nucleisdk.WithNoInteractsh(),
		nucleisdk.WithSilent(),
	)
	if err != nil {
		log.Fatalf("Failed to create engine: %v", err)
	}
	if err := engine.Setup(); err != nil {
		log.Fatalf("Failed to setup engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// 2. Create a scan pool with 5 concurrent workers.
	//    Each worker picks jobs from a shared queue and calls engine.Scan().
	pool := engine.NewScanPool(ctx, 5)

	// 3. Consume results in a separate goroutine.
	//    The Results() channel is closed after Close() + all workers drain.
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for r := range pool.Results() {
			if r.Error != "" {
				fmt.Printf("[%s] ERROR: %s\n", r.Label, r.Error)
				continue
			}
			fmt.Printf("[%s] [%s] %s — %s\n",
				r.Label, r.Severity, r.TemplateID, r.MatchedURL)
		}
	}()

	// 4. Simulate: vulnerability feed delivers items over time.
	feed := []vulnFeedItem{
		{
			Target: "https://target-a.example.com",
			CVEID:  "CVE-2024-1234",
			TemplateYAML: []byte(`
id: CVE-2024-1234
info:
  name: Example RCE in Login Endpoint
  severity: critical
  author: scanner
  tags: cve,rce
http:
  - method: POST
    path:
      - "{{BaseURL}}/api/login"
    body: '{"user":"{{randstr}}"}'
    matchers:
      - type: word
        words:
          - "stack trace"
        part: body
`),
		},
		{
			Target: "https://target-b.example.com",
			CVEID:  "CVE-2024-5678",
			TemplateYAML: []byte(`
id: CVE-2024-5678
info:
  name: Example SSRF in Webhook Handler
  severity: high
  author: scanner
  tags: cve,ssrf
http:
  - method: GET
    path:
      - "{{BaseURL}}/webhook?url=http://169.254.169.254"
    matchers:
      - type: word
        words:
          - "ami-id"
        part: body
`),
		},
		{
			Target: "https://target-c.example.com",
			CVEID:  "CVE-2024-9012",
			TemplateYAML: []byte(`
id: CVE-2024-9012
info:
  name: Example SQLi in Search
  severity: critical
  author: scanner
  tags: cve,sqli
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=1'OR'1'='1"
    matchers:
      - type: word
        words:
          - "SQL syntax"
        part: body
`),
		},
	}

	// Submit each feed item as a targeted scan job.
	for _, item := range feed {
		if err := pool.Submit(item.CVEID, &nucleisdk.ScanOptions{
			Targets: []string{item.Target},
			TemplateBytes: []nucleisdk.TemplateBytesEntry{
				nucleisdk.TemplateBytes(item.CVEID, item.TemplateYAML),
			},
		}); err != nil {
			log.Printf("Failed to submit %s: %v", item.CVEID, err)
		}
		// Simulate staggered arrival
		time.Sleep(100 * time.Millisecond)
	}

	// 5. You can also submit filter-based scans (using the global template store).
	_ = pool.Submit("wordpress-scan", &nucleisdk.ScanOptions{
		Targets:       []string{"https://wordpress.example.com"},
		Tags:          []string{"wordpress", "wp-plugin"},
		ProtocolTypes: "http",
	})

	_ = pool.Submit("ssl-check", &nucleisdk.ScanOptions{
		Targets:       []string{"example.com:443"},
		ProtocolTypes: "ssl",
	})

	// 6. Signal no more jobs and wait for all scans to finish.
	pool.Close()

	// Wait for result consumer to finish
	resultWg.Wait()

	// 7. Print stats.
	stats := pool.Stats()
	fmt.Printf("\n--- Pool Stats ---\n")
	fmt.Printf("  Submitted: %d\n", stats.Submitted)
	fmt.Printf("  Completed: %d\n", stats.Completed)
	fmt.Printf("  Failed:    %d\n", stats.Failed)
	fmt.Printf("  Pending:   %d\n", stats.Pending)
}
