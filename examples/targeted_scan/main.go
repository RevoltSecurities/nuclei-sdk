package main

import (
	"context"
	"fmt"
	"log"
	"sync"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

// Simulates an API response that returns vulnerability info per target.
// In practice, this could come from a vulnerability database, CMDB, or prior scan results.
type targetVuln struct {
	Target       string
	TemplateYAML []byte // raw YAML from API
	Label        string
}

func main() {
	// 1. Create engine and initialize global resources ONCE.
	//    Templates, parser, interactsh, rate limiter — all shared.
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

	// 2. Simulate: your scanner/API tells you which targets have which vulns.
	vulns := []targetVuln{
		{
			Target: "https://target-a.example.com",
			Label:  "CVE-2024-1234",
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
			Label:  "CVE-2024-5678",
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
	}

	// 3. Launch concurrent targeted scans — each with its OWN template + target.
	//    Each Scan() creates only a lightweight core.Engine (~5 fields).
	//    All scans share the global resources from Setup().
	var wg sync.WaitGroup
	for _, v := range vulns {
		wg.Add(1)
		go func(v targetVuln) {
			defer wg.Done()

			results, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
				Targets: []string{v.Target},
				TemplateBytes: []nucleisdk.TemplateBytesEntry{
					nucleisdk.TemplateBytes(v.Label, v.TemplateYAML),
				},
			})
			if err != nil {
				fmt.Printf("[%s] scan error: %v\n", v.Label, err)
				return
			}

			for r := range results {
				if r.Error != "" {
					fmt.Printf("[%s] %s: ERROR %s\n", v.Label, v.Target, r.Error)
				} else {
					fmt.Printf("[%s] [%s] %s — %s\n", v.Label, r.Severity, r.TemplateID, r.MatchedURL)
				}
			}
			fmt.Printf("[%s] %s — scan complete\n", v.Label, v.Target)
		}(v)
	}

	// 4. You can also scan with a template FILE or DIRECTORY.
	wg.Add(1)
	go func() {
		defer wg.Done()

		results, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
			Targets: []string{"https://target-c.example.com"},
			// Point to specific template files on disk
			TemplateFiles: []string{
				"/path/to/nuclei-templates/cves/2024/CVE-2024-9999.yaml",
			},
		})
		if err != nil {
			fmt.Printf("[file-scan] error: %v\n", err)
			return
		}
		for r := range results {
			fmt.Printf("[file-scan] [%s] %s — %s\n", r.Severity, r.TemplateID, r.MatchedURL)
		}
	}()

	// 5. Or scan with a whole template directory
	wg.Add(1)
	go func() {
		defer wg.Done()

		results, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
			Targets:      []string{"https://wordpress-site.example.com"},
			TemplateDirs: []string{"/path/to/nuclei-templates/technologies/wordpress/"},
		})
		if err != nil {
			fmt.Printf("[dir-scan] error: %v\n", err)
			return
		}
		for r := range results {
			fmt.Printf("[dir-scan] [%s] %s — %s\n", r.Severity, r.TemplateID, r.MatchedURL)
		}
	}()

	wg.Wait()
	fmt.Println("\nAll targeted scans completed.")
}
