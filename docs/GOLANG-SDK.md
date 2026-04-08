# Go SDK Documentation

Comprehensive documentation for the nuclei-sdk Go library — build custom security scanners, automated workflows, and vulnerability management platforms in Go.

**Developed by [RevoltSecurities](https://github.com/RevoltSecurities)**

---

## Table of Contents

- [Installation](#installation)
- [Architecture](#architecture)
- [Scanner — Simple One-Shot Scanning](#scanner--simple-one-shot-scanning)
- [ScanEngine — High-Performance Reusable Engine](#scanengine--high-performance-reusable-engine)
  - [Setup and Lifecycle](#setup-and-lifecycle)
  - [Single Scan](#single-scan)
  - [Callback-Based Scanning](#callback-based-scanning)
  - [Concurrent Parallel Scans](#concurrent-parallel-scans)
  - [Runtime Engine — Custom Templates per Scan](#runtime-engine--custom-templates-per-scan)
  - [ScanPool — Continuous Dynamic Scanning](#scanpool--continuous-dynamic-scanning)
  - [Advanced: NucleiOptions()](#advanced-nucleioptions)
  - [GetLoadedTemplates()](#getloadedtemplates)
- [Template Loading and Filtering](#template-loading-and-filtering)
  - [How It Works](#how-it-works)
  - [Single Scan — Tags at Setup](#single-scan--tags-at-setup)
  - [Concurrent Scans — No Tags at Setup](#concurrent-scans--no-tags-at-setup)
  - [Direct Templates — Always Work](#direct-templates--always-work)
- [Preset Scanners](#preset-scanners)
  - [API Security Scanner](#api-security-scanner)
  - [WordPress Scanner](#wordpress-scanner)
  - [Web Scanner](#web-scanner)
  - [Network Scanner](#network-scanner)
- [Configuration Reference](#configuration-reference)
  - [Template Options](#template-options)
  - [Template Filter Options](#template-filter-options)
  - [Target Options](#target-options)
  - [HTTP Probing Options](#http-probing-options)
  - [Network Options](#network-options)
  - [Concurrency Options](#concurrency-options)
  - [Authentication Options](#authentication-options)
  - [Header and Variable Options](#header-and-variable-options)
  - [Feature Options](#feature-options)
  - [Verbosity Options](#verbosity-options)
  - [Interactsh Options](#interactsh-options)
  - [Template Execution Options](#template-execution-options)
  - [Response Options](#response-options)
  - [Sandbox Options](#sandbox-options)
  - [Execution Control Options](#execution-control-options)
  - [Advanced Network Options](#advanced-network-options)
  - [Result Filtering Options](#result-filtering-options)
- [Authentication](#authentication)
  - [Basic Auth](#basic-auth)
  - [Bearer Token](#bearer-token)
  - [API Key Header](#api-key-header)
  - [Custom Headers](#custom-headers)
  - [Cookie Auth](#cookie-auth)
  - [Query Parameter Auth](#query-parameter-auth)
  - [Multiple Auth Configs](#multiple-auth-configs)
  - [Secrets File](#secrets-file)
- [ScanOptions Reference](#scanoptions-reference)
- [ScanResult Reference](#scanresult-reference)
  - [Fields](#scanresult-fields)
  - [Methods](#scanresult-methods)
- [Target Utilities](#target-utilities)
- [Template Utilities](#template-utilities)
- [Building Custom Workflows](#building-custom-workflows)
  - [CI/CD Pipeline Scanner](#cicd-pipeline-scanner)
  - [Continuous Vulnerability Monitoring](#continuous-vulnerability-monitoring)
  - [Multi-Tenant Security Platform](#multi-tenant-security-platform)
  - [CVE Verification Service](#cve-verification-service)
  - [Asset Discovery and Scanning](#asset-discovery-and-scanning)
  - [Target File — Scanning from a File](#target-file--scanning-from-a-file)
  - [HTTP Probing — Scanning Raw Hosts/IPs](#http-probing--scanning-raw-hostsips)
  - [Webhook-Driven Scanning](#webhook-driven-scanning)
- [Error Handling](#error-handling)
- [Performance Tips](#performance-tips)

---

## Installation

```bash
go get github.com/RevoltSecurities/nuclei-sdk
```

Import:

```go
import nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
```

---

## Architecture

The SDK provides two main APIs:

```
nuclei-sdk
├── Scanner           Simple, one-shot scanning (creates engine per run)
└── ScanEngine        Reusable engine with shared global resources
    ├── Scan()            Lightweight per-scan execution
    ├── RunParallel()     Multiple concurrent labeled scans
    └── NewScanPool()     Worker pool for dynamic job submission
```

**ScanEngine** is the recommended API for production use. It separates heavy initialization (done once in `Setup()`) from lightweight per-scan execution:

```
Setup() — One-time heavy initialization:
  Template Store, Parser, Catalog, Output Writer,
  Interactsh Client, Rate Limiter, Browser, Host Error Cache

Scan() — Lightweight per-scan (very fast):
  core.Engine (~5 fields), ExecutorOptions copy,
  SimpleInputProvider, Filtered template list
```

---

## Scanner — Simple One-Shot Scanning

`Scanner` is the simplest API — configure everything upfront, run once, get results. It creates and destroys the engine per run, so it's not suitable for repeated scanning.

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

func main() {
    scanner, err := nucleisdk.NewScanner(
        nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
        nucleisdk.WithTargets("https://example.com"),
        nucleisdk.WithSeverityFilter("high", "critical"),
        nucleisdk.WithThreads(25),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer scanner.Close()

    results, err := scanner.Run(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    for result := range results {
        fmt.Printf("[%s] %s - %s\n", result.Severity, result.TemplateID, result.MatchedURL)
    }
}
```

### Callback-Based

```go
scanner, _ := nucleisdk.NewScanner(
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
    nucleisdk.WithTargets("https://example.com"),
    nucleisdk.WithTags("cve"),
)
defer scanner.Close()

err := scanner.RunWithCallback(context.Background(), func(result *nucleisdk.ScanResult) {
    fmt.Printf("[%s] %s\n", result.Severity, result.TemplateID)
})
```

### Scanner API

| Method | Description |
|--------|-------------|
| `NewScanner(opts ...Option) (*Scanner, error)` | Create scanner with configuration |
| `Run(ctx context.Context) (<-chan *ScanResult, error)` | Execute scan, return results channel |
| `RunWithCallback(ctx context.Context, cb func(*ScanResult)) error` | Execute scan with callback per result |
| `Close() error` | Release all resources |

---

## ScanEngine — High-Performance Reusable Engine

`ScanEngine` is the production API. Heavy resources are initialized once in `Setup()`, and each `Scan()` call creates only lightweight per-scan objects.

### Setup and Lifecycle

```go
// 1. Create engine with configuration
engine, err := nucleisdk.NewScanEngine(
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
    nucleisdk.WithRateLimit(100),
    nucleisdk.WithTimeout(10),
    nucleisdk.WithNoInteractsh(),
    nucleisdk.WithSilent(),
)
if err != nil {
    log.Fatal(err)
}

// 2. One-time heavy initialization
if err := engine.Setup(); err != nil {
    log.Fatal(err)
}

// 3. Use engine for many scans...

// 4. Clean up when done
engine.Close()
```

### Single Scan

```go
engine, _ := nucleisdk.NewScanEngine(
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
    nucleisdk.WithRateLimit(100),
    nucleisdk.WithSilent(),
)
engine.Setup()
defer engine.Close()

ctx := context.Background()

results, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
    Targets:       []string{"https://example.com"},
    Tags:          []string{"cve", "exposure"},
    Severities:    []string{"high", "critical"},
    ProtocolTypes: "http",
})
if err != nil {
    log.Fatal(err)
}

for r := range results {
    fmt.Printf("[%s] %s - %s\n", r.Severity, r.TemplateID, r.MatchedURL)
}
```

### Callback-Based Scanning

```go
err := engine.ScanWithCallback(ctx, &nucleisdk.ScanOptions{
    Targets: []string{"https://example.com"},
    Tags:    []string{"cve"},
}, func(r *nucleisdk.ScanResult) {
    fmt.Printf("[%s] %s\n", r.Severity, r.TemplateID)
})
```

### Concurrent Parallel Scans

Run multiple scan types concurrently with labeled results using `RunParallel()`:

```go
results, err := engine.RunParallel(ctx,
    nucleisdk.ConcurrentScan{
        Label: "http-cves",
        Options: []nucleisdk.Option{
            nucleisdk.WithProtocolTypes("http"),
            nucleisdk.WithTags("cve", "exposure"),
            nucleisdk.WithSeverityFilter("high", "critical"),
            nucleisdk.WithTargets("https://example.com"),
        },
    },
    nucleisdk.ConcurrentScan{
        Label: "dns-takeover",
        Options: []nucleisdk.Option{
            nucleisdk.WithProtocolTypes("dns"),
            nucleisdk.WithTags("dns", "takeover"),
            nucleisdk.WithTargets("example.com"),
        },
    },
    nucleisdk.ConcurrentScan{
        Label: "ssl-checks",
        Options: []nucleisdk.Option{
            nucleisdk.WithProtocolTypes("ssl"),
            nucleisdk.WithTargets("example.com:443"),
        },
    },
)
if err != nil {
    log.Fatal(err)
}

for lr := range results {
    fmt.Printf("[%s] [%s] %s - %s\n", lr.Label, lr.Severity, lr.TemplateID, lr.Host)
}
```

**Types:**

```go
type ConcurrentScan struct {
    Label   string
    Options []Option
}

type LabeledResult struct {
    Label string
    *ScanResult
}
```

### Runtime Engine — Custom Templates per Scan

Set up the engine with only runtime config (no templates). Each scan provides its own templates and targets — ideal for dynamic workflows where templates are fetched at runtime.

```go
// Engine with only runtime config — no templates loaded at Setup
engine, _ := nucleisdk.NewScanEngine(
    nucleisdk.WithRateLimit(100),
    nucleisdk.WithTimeout(10),
    nucleisdk.WithNoInteractsh(),
    nucleisdk.WithSilent(),
)
engine.Setup()
defer engine.Close()

ctx := context.Background()

// Scan 1: raw YAML bytes (template from API, database, etc.)
templateYAML, _ := os.ReadFile("/path/to/CVE-2024-1234.yaml")
results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
    Targets: []string{"https://target.example.com"},
    TemplateBytes: []nucleisdk.TemplateBytesEntry{
        nucleisdk.TemplateBytes("CVE-2024-1234", templateYAML),
    },
})
for r := range results {
    fmt.Printf("[%s] %s - %s\n", r.Severity, r.TemplateID, r.MatchedURL)
}

// Scan 2: specific template files
results, _ = engine.Scan(ctx, &nucleisdk.ScanOptions{
    Targets:       []string{"https://another-target.com"},
    TemplateFiles: []string{"/path/to/sqli.yaml", "/path/to/xss.yaml"},
})
for r := range results {
    fmt.Printf("[%s] %s - %s\n", r.Severity, r.TemplateID, r.MatchedURL)
}

// Scan 3: template directory
results, _ = engine.Scan(ctx, &nucleisdk.ScanOptions{
    Targets:      []string{"https://wordpress.example.com"},
    TemplateDirs: []string{"/path/to/nuclei-templates/technologies/wordpress/"},
})
for r := range results {
    fmt.Printf("[%s] %s - %s\n", r.Severity, r.TemplateID, r.MatchedURL)
}
```

### ScanPool — Continuous Dynamic Scanning

`ScanPool` provides a worker pool for workflows where scan jobs arrive over time — from APIs, message queues, webhooks, or vulnerability feeds.

```go
engine, _ := nucleisdk.NewScanEngine(
    nucleisdk.WithRateLimit(100),
    nucleisdk.WithSilent(),
)
engine.Setup()
defer engine.Close()

ctx := context.Background()
pool := engine.NewScanPool(ctx, 10) // 10 concurrent workers

// Consume results in background
go func() {
    for r := range pool.Results() {
        fmt.Printf("[%s] [%s] %s - %s\n", r.Label, r.Severity, r.TemplateID, r.Host)
    }
}()

// Submit jobs dynamically
pool.Submit("scan-1", &nucleisdk.ScanOptions{
    Targets: []string{"https://target1.com"},
    Tags:    []string{"cve"},
})
pool.Submit("scan-2", &nucleisdk.ScanOptions{
    Targets: []string{"https://target2.com"},
    TemplateBytes: []nucleisdk.TemplateBytesEntry{
        nucleisdk.TemplateBytes("custom-check", yamlBytes),
    },
})

// Close pool and wait for all jobs to complete
pool.Close()

// Check stats
stats := pool.Stats()
fmt.Printf("submitted=%d completed=%d failed=%d\n",
    stats.Submitted, stats.Completed, stats.Failed)
```

**ScanPool API:**

| Method | Description |
|--------|-------------|
| `Submit(label string, opts *ScanOptions) error` | Queue a labeled scan job |
| `Results() <-chan *LabeledResult` | Channel streaming all results from all jobs |
| `Close()` | Signal no more jobs, wait for completion |
| `Stats() PoolStats` | Get pool statistics |

**PoolStats:**

```go
type PoolStats struct {
    Submitted int64
    Completed int64
    Failed    int64
    Pending   int64
}
```

### Advanced: NucleiOptions()

After `Setup()`, access the full nuclei `types.Options` struct for advanced customization beyond what the SDK's `With*` functions expose:

```go
engine, _ := nucleisdk.NewScanEngine(nucleisdk.WithRateLimit(100))
engine.Setup()

// Full access to every nuclei internal option
opts := engine.NucleiOptions()
opts.FollowRedirects = true
opts.MaxHostError = 5
opts.StopAtFirstMatch = true
opts.CustomHeaders = []string{"X-Custom: value"}
opts.ResponseReadSize = 1048576

// All subsequent scans use these options
results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
    Targets: []string{"https://example.com"},
    Tags:    []string{"cve"},
})
```

> `NucleiOptions()` returns a pointer to the live options struct. Changes take effect immediately for all subsequent scans.

### GetLoadedTemplates()

Inspect templates loaded at Setup time:

```go
engine.Setup()

templates := engine.GetLoadedTemplates()
fmt.Printf("Loaded %d templates\n", len(templates))

for _, t := range templates {
    fmt.Printf("  %s [%s] tags=%v\n", t.ID, t.Info.SeverityHolder.Severity, t.Info.Tags.ToSlice())
}
```

### ScanEngine API

| Method | Description |
|--------|-------------|
| `NewScanEngine(opts ...Option) (*ScanEngine, error)` | Create engine with configuration |
| `Setup() error` | One-time heavy initialization |
| `Scan(ctx, *ScanOptions) (<-chan *ScanResult, error)` | Execute lightweight scan |
| `ScanWithCallback(ctx, *ScanOptions, func(*ScanResult)) error` | Scan with callback |
| `RunParallel(ctx, ...ConcurrentScan) (<-chan *LabeledResult, error)` | Run multiple labeled scans concurrently |
| `NewScanPool(ctx, workers int) *ScanPool` | Create worker pool |
| `NucleiOptions() *types.Options` | Get underlying nuclei options (after Setup) |
| `GetLoadedTemplates() []*templates.Template` | Get all loaded templates |
| `Close() error` | Release all resources |

---

## Template Loading and Filtering

### How It Works

Templates are loaded **once** at `Setup()` time (heavy: disk I/O, YAML parsing, compilation) and stored in memory. Per-scan `Tags`, `Severities`, `ProtocolTypes`, etc. only **filter** from this pre-loaded set — no new loading happens.

```
Setup()  -->  Load & compile all templates  -->  se.allTemplates (in-memory)
                                                        |
Scan(tags=["http"])   -->  filter from allTemplates  -->  [http templates]
Scan(tags=["dns"])    -->  filter from allTemplates  -->  [dns templates]
Scan(tags=["ssl"])    -->  filter from allTemplates  -->  [ssl templates]
```

The filtering is done by the SDK using nuclei's `TagFilter` — the nuclei core engine receives a pre-filtered template list.

### Single Scan — Tags at Setup

When you know exactly what templates you need, setting tags at Setup is efficient:

```go
engine, _ := nucleisdk.NewScanEngine(
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
    nucleisdk.WithTags("cve", "exposure"),
    nucleisdk.WithSeverityFilter("high", "critical"),
)
engine.Setup() // Only loads CVE/exposure templates with high/critical severity
defer engine.Close()

results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
    Targets: []string{"https://example.com"},
})
```

### Concurrent Scans — No Tags at Setup

When running multiple scans with different tags (pool, parallel), load all templates at Setup:

```go
engine, _ := nucleisdk.NewScanEngine(
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
    // No WithTags() — loads ALL templates
)
engine.Setup()
defer engine.Close()

pool := engine.NewScanPool(ctx, 10)

// All of these work because ALL templates were loaded
pool.Submit("http", &nucleisdk.ScanOptions{
    Targets: []string{"https://example.com"},
    Tags:    []string{"http", "cve"},
})
pool.Submit("dns", &nucleisdk.ScanOptions{
    Targets: []string{"example.com"},
    Tags:    []string{"dns", "takeover"},
})
pool.Submit("ssl", &nucleisdk.ScanOptions{
    Targets: []string{"example.com:443"},
    Tags:    []string{"ssl"},
})
```

> If you set `WithTags("http")` at Setup, per-scan `Tags: ["dns"]` returns **zero results** because DNS templates were never loaded.

### Direct Templates — Always Work

`TemplateFiles`, `TemplateDirs`, and `TemplateBytes` bypass the global store entirely. They load fresh per-scan, so they always work regardless of Setup configuration:

```go
pool.Submit("custom", &nucleisdk.ScanOptions{
    Targets:       []string{"https://target.com"},
    TemplateFiles: []string{"/path/to/custom.yaml"},
})
pool.Submit("raw", &nucleisdk.ScanOptions{
    Targets: []string{"https://target.com"},
    TemplateBytes: []nucleisdk.TemplateBytesEntry{
        nucleisdk.TemplateBytes("my-check", yamlBytes),
    },
})
```

### Quick Reference

| Setup Config | Per-Scan Filter | Result |
|---|---|---|
| No tags (all templates) | `Tags: ["dns"]` | DNS templates found |
| No tags (all templates) | `Tags: ["http", "ssl"]` | HTTP + SSL found |
| `WithTags("http")` | `Tags: ["http"]` | HTTP templates found |
| `WithTags("http")` | `Tags: ["dns"]` | **Zero results** |
| Any config | `TemplateFiles: [...]` | Always works (direct mode) |
| Any config | `TemplateBytes: [...]` | Always works (direct mode) |

---

## Preset Scanners

Pre-configured scanners with sensible defaults for common security testing scenarios. Each preset wraps `ScanEngine` with domain-specific template tags, concurrency settings, and timeouts.

### API Security Scanner

REST, GraphQL, OpenAPI/Swagger security testing.

```go
scanner, _ := nucleisdk.NewAPISecurityScanner(
    nucleisdk.WithOpenAPISpec("/path/to/openapi.yaml"),
    nucleisdk.WithAuth(nucleisdk.BearerToken("token", "api.example.com")),
    nucleisdk.WithRateLimit(30),
)
defer scanner.Close()

results, _ := scanner.Run(context.Background())
for r := range results {
    fmt.Printf("[%s] %s - %s\n", r.Severity, r.TemplateID, r.MatchedURL)
}
```

**Default Configuration:**
- Protocol: `http`
- Tags: `api, swagger, openapi, graphql, rest, jwt, auth-bypass, exposure, misconfig, token, cors, ssrf, idor, bola, injection, sqli, xss, rce`
- Threads: 25 | Host concurrency: 10 | Rate limit: 50/s
- Timeout: 15s | Retries: 1 | Matcher status: enabled

### WordPress Scanner

WordPress-specific vulnerability and misconfiguration testing.

```go
scanner, _ := nucleisdk.NewWordPressScanner(
    nucleisdk.WithTargets("https://wordpress.example.com"),
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
)
defer scanner.Close()

results, _ := scanner.Run(context.Background())
for r := range results {
    fmt.Printf("[%s] %s\n", r.Severity, r.TemplateID)
}
```

**Default Configuration:**
- Protocol: `http`
- Tags: `wordpress, wp-plugin, wp-theme, wp, woocommerce, xmlrpc, wp-config, wp-cron, wp-admin, wp-login`
- Threads: 25 | Host concurrency: 5 | Rate limit: 30/s
- Timeout: 10s | Retries: 2

### Web Scanner

General web application security testing.

```go
scanner, _ := nucleisdk.NewWebScanner(
    nucleisdk.WithTargets("https://example.com"),
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
)
defer scanner.Close()

results, _ := scanner.Run(context.Background())
```

**Default Configuration:**
- Protocol: `http`
- Exclude tags: `dos, fuzz`
- Threads: 50 | Host concurrency: 25 | Rate limit: 150/s
- Timeout: 10s | Retries: 1

### Network Scanner

Network and infrastructure security testing (DNS, SSL, TCP).

```go
scanner, _ := nucleisdk.NewNetworkScanner(
    nucleisdk.WithTargets("192.168.1.0/24"),
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
)
defer scanner.Close()

results, _ := scanner.Run(context.Background())
```

**Default Configuration:**
- Protocol: `network, dns, ssl`
- Tags: `network, dns, ssl, tls, cve, default-login, exposure, misconfig`
- Threads: 25 | Host concurrency: 50 | Rate limit: 100/s
- Timeout: 5s | Retries: 2

### Preset API (common to all presets)

| Method | Description |
|--------|-------------|
| `Run(ctx context.Context) (<-chan *ScanResult, error)` | Execute scan, return results channel |
| `RunWithCallback(ctx context.Context, cb func(*ScanResult)) error` | Execute scan with callback |
| `Scanner() *Scanner` | Access the underlying Scanner for advanced use |
| `Close() error` | Release resources |

### SDK Default Values

When options are not explicitly set, these defaults apply:

| Setting | Default |
|---------|---------|
| Timeout | 10s |
| Retries | 1 |
| Threads | 25 |
| Host concurrency | 25 |
| Rate limit | 150/s (per second) |
| Scan strategy | `template-spray` |
| Update check | disabled |

### Scan Strategy Constants

```go
nucleisdk.StrategyTemplateSpray  // "template-spray" — run all templates against each host (default)
nucleisdk.StrategyHostSpray      // "host-spray" — run each template against all hosts before moving to next
```

---

## Configuration Reference

All configuration is done through `With*` option functions passed to `NewScanEngine()`, `NewScanner()`, or any preset constructor.

### Template Options

```go
WithTemplateDir(dir string)                     // Add template directory
WithTemplateDirs(dirs ...string)                // Add multiple template directories
WithTemplateFile(file string)                   // Add single template file
WithTemplateFiles(files ...string)              // Add multiple template files
WithTemplateBytes(name string, data []byte)     // Add raw YAML template
WithTemplateURL(url string)                     // Fetch template from URL
WithTemplateURLs(urls ...string)                // Fetch multiple templates from URLs
WithWorkflows(paths ...string)                  // Add workflow file paths
WithTrustedDomains(domains ...string)           // Trusted domains for remote templates
```

### Template Filter Options

```go
WithTags(tags ...string)                        // Filter by tags (OR logic)
WithExcludeTags(tags ...string)                 // Exclude templates by tags
WithSeverityFilter(severities ...string)        // Filter: "info", "low", "medium", "high", "critical"
WithExcludeSeverities(severities ...string)     // Exclude by severity
WithTemplateIDs(ids ...string)                  // Filter by template IDs
WithExcludeTemplateIDs(ids ...string)           // Exclude by template IDs
WithProtocolTypes(types string)                 // Filter: "http", "dns", "network", "ssl", etc.
WithAuthors(authors ...string)                  // Filter by template author
```

### Target Options

```go
WithTargets(targets ...string)                  // Set target URLs/hosts/IPs
WithTargetFile(path string)                     // Read targets from file
WithTargetReader(reader io.Reader)              // Read targets from reader
WithOpenAPISpec(path string)                    // Use OpenAPI spec for API scanning
WithSwaggerSpec(path string)                    // Use Swagger spec
WithExcludeTargets(hosts ...string)             // Exclude specific hosts from scanning
```

### HTTP Probing Options

```go
WithHTTPProbe()                                 // Enable HTTP probing for non-URL targets (raw hosts/IPs)
WithProbeConcurrency(n int)                     // Concurrent HTTP probes (default 50)
WithScanAllIPs()                                // Scan all DNS-resolved IPs, not just first
WithIPVersion(versions ...string)               // IP versions: "4", "6", or both
```

### Network Options

```go
WithProxy(proxy string)                         // HTTP/SOCKS5 proxy URL
WithProxies(proxies ...string)                  // Multiple proxies (round-robin)
WithProxyInternal(enabled bool)                 // Proxy internal requests too
WithTimeout(seconds int)                        // Request timeout in seconds
WithRetries(count int)                          // Retry count on failure
```

### Concurrency Options

```go
WithThreads(count int)                          // Concurrent templates to execute
WithHostConcurrency(count int)                  // Concurrent hosts per template
WithBulkSize(count int)                         // Alias for WithHostConcurrency
WithRateLimit(maxPerSecond int)                 // Max requests per second
WithRateLimitCustom(count int, d time.Duration) // Custom rate limit window
WithPayloadConcurrency(count int)               // Concurrent payloads per template
```

### Authentication Options

```go
WithAuth(auth AuthConfig)                       // Add authentication config
WithSecretsFile(path string)                    // Nuclei secrets file
WithSecretsFiles(paths ...string)               // Multiple secrets files
```

### Header and Variable Options

```go
WithHeaders(headers ...string)                  // Headers in "Key: Value" format
WithHeader(key, value string)                   // Single header
WithVars(vars ...string)                        // Variables in "key=value" format
WithVar(key, value string)                      // Single variable
```

### Feature Options

```go
WithHeadless(opts *HeadlessConfig)              // Enable headless browser
WithScanStrategy(strategy string)               // "template-spray" or "host-spray"
WithDASTMode()                                  // Enable DAST/fuzzing mode
WithCodeTemplates()                             // Enable code protocol templates
WithMatcherStatus()                             // Report all matcher results
```

**HeadlessConfig:**

```go
type HeadlessConfig struct {
    PageTimeout int      // Page load timeout
    ShowBrowser bool     // Show browser window (debugging)
    UseChrome   bool     // Use Chrome instead of default
    ExtraArgs   []string // Extra browser arguments
}
```

### Verbosity Options

```go
WithVerbose()                                   // Enable verbose output
WithDebug()                                     // Enable debug output
WithSilent()                                    // Suppress all output
WithUpdateCheck()                               // Enable nuclei update checks
```

### Interactsh Options

```go
WithNoInteractsh()                              // Disable OOB testing service
```

### Template Execution Options

```go
WithSelfContainedTemplates()                    // Enable self-contained templates
WithGlobalMatchersTemplates()                   // Enable global matchers
WithDisableTemplateCache()                      // Disable template caching
WithFileTemplates()                             // Enable file protocol templates
WithPassiveMode()                               // Passive HTTP response processing
WithSignedTemplatesOnly()                       // Only run signed templates
```

### Response Options

```go
WithResponseReadSize(size int)                  // Max response read size in bytes
```

### Sandbox Options

```go
WithSandboxOptions(allowLocal, restrictLocal bool) // Configure sandbox
```

### Execution Control Options

```go
WithStopAtFirstMatch()                          // Stop after first match per host
WithDisableMaxHostErr()                         // Disable host error threshold
```

### Advanced Network Options

```go
WithLeaveDefaultPorts()                         // Preserve default ports in URLs
WithNetworkInterface(iface string)              // Set network interface
WithSourceIP(ip string)                         // Set source IP address
WithSystemResolvers()                           // Use system DNS resolvers
WithResolvers(resolvers ...string)              // Custom DNS resolvers
```

### Result Filtering Options

```go
WithResultSeverityFilter(severities ...string)  // Post-scan severity filter on results
```

---

## Authentication

### Basic Auth

```go
nucleisdk.WithAuth(nucleisdk.BasicAuth("admin", "password123", "example.com"))
```

### Bearer Token

```go
nucleisdk.WithAuth(nucleisdk.BearerToken("eyJhbGciOi...", "api.example.com"))
```

### API Key Header

```go
nucleisdk.WithAuth(nucleisdk.APIKeyHeader("X-API-Key", "key123", "api.example.com"))
```

### Custom Headers

```go
nucleisdk.WithAuth(nucleisdk.HeaderAuth(map[string]string{
    "Authorization": "Custom scheme",
    "X-Tenant":      "tenant-123",
}, "example.com"))
```

### Cookie Auth

```go
nucleisdk.WithAuth(nucleisdk.CookieAuth(map[string]string{
    "session_id": "abc123",
    "csrf_token": "xyz789",
}, "example.com"))
```

### Query Parameter Auth

```go
nucleisdk.WithAuth(nucleisdk.QueryAuth(map[string]string{
    "api_key": "key123",
    "token":   "abc",
}, "api.example.com"))
```

### Multiple Auth Configs

```go
engine, _ := nucleisdk.NewScanEngine(
    nucleisdk.WithAuth(nucleisdk.BearerToken("token", "api.example.com")),
    nucleisdk.WithAuth(nucleisdk.BasicAuth("admin", "pass", "admin.example.com")),
    nucleisdk.WithAuth(nucleisdk.CookieAuth(map[string]string{
        "session": "abc",
    }, "app.example.com")),
)
```

### Secrets File

```go
nucleisdk.WithSecretsFile("/path/to/nuclei-secrets.yaml")
```

**AuthConfig struct:**

```go
type AuthConfig struct {
    Type        AuthType              // AuthBasic, AuthBearer, AuthHeader, AuthCookie, AuthQuery
    Domains     []string              // Domains this auth applies to
    Username    string                // For BasicAuth
    Password    string                // For BasicAuth
    Token       string                // For BearerToken
    Headers     map[string]string     // For HeaderAuth
    Cookies     map[string]string     // For CookieAuth
    QueryParams map[string]string     // For QueryAuth
}
```

---

## ScanOptions Reference

Per-scan parameters passed to `ScanEngine.Scan()` and `ScanPool.Submit()`:

```go
type ScanOptions struct {
    // Targets
    Targets    []string              // URLs, domains, IPs to scan
    TargetFile string                // Path to file with targets (one per line)

    // DAST targets with full HTTP request metadata
    RequestResponseTargets []RequestResponseTarget // Preserves method, headers, body for fuzzing

    // Template filtering (filters from global store loaded at Setup)
    Tags          []string           // Filter by tags (OR logic)
    ExcludeTags   []string           // Exclude by tags
    Severities    []string           // Filter by severity
    ProtocolTypes string             // Filter by protocol ("http", "dns", "ssl", etc.)
    TemplateIDs   []string           // Filter by template ID
    ExcludeIDs    []string           // Exclude by template ID
    Authors       []string           // Filter by author

    // Direct template sources (bypass global store, load fresh per-scan)
    TemplateFiles []string           // Template file paths
    TemplateDirs  []string           // Template directory paths
    TemplateBytes []TemplateBytesEntry // Raw YAML templates

    // Result filtering
    ResultSeverityFilter []string    // Post-execution severity filter
}

// RequestResponseTarget provides full HTTP request metadata for DAST fuzzing.
// Without this, nuclei defaults to GET with no body for URL-only targets.
type RequestResponseTarget struct {
    URL     string            // Full URL (e.g., "https://example.com/api/users")
    Method  string            // HTTP method (e.g., "POST", "PUT")
    Headers map[string]string // Request headers
    Body    string            // Request body
}
```

---

## ScanResult Reference

### ScanResult Fields

```go
type ScanResult struct {
    // Identification
    TemplateID   string
    TemplateName string
    TemplatePath string
    Severity     string                // "info", "low", "medium", "high", "critical"
    Type         string                // Protocol type

    // Match details
    Host             string
    MatchedURL       string
    MatcherName      string
    ExtractorName    string
    ExtractedResults []string
    IP               string
    Port             string
    Scheme           string
    URL              string
    Path             string

    // Request/Response
    Request     string
    Response    string
    CURLCommand string

    // Metadata
    Tags        []string
    Authors     []string
    Description string
    Impact      string
    Remediation string
    Reference   []string
    Metadata    map[string]interface{}

    // Classification
    CVEID       []string
    CWEID       []string
    CVSSMetrics string
    CVSSScore   float64
    EPSSScore   float64
    CPE         string

    // Fuzzing
    IsFuzzingResult  bool
    FuzzingMethod    string
    FuzzingParameter string
    FuzzingPosition  string

    // Status
    MatcherStatus bool
    Timestamp     time.Time
    Error         string
}
```

### ScanResult Methods

| Method | Return | Description |
|--------|--------|-------------|
| `JSON()` | `string` | Serialize result as JSON string |
| `JSONBytes()` | `([]byte, error)` | Serialize result as JSON bytes |
| `JSONPretty()` | `string` | Serialize as pretty-printed JSON |
| `RawEvent()` | `*output.ResultEvent` | Get underlying nuclei result event |
| `IsCritical()` | `bool` | True if severity is "critical" |
| `IsHighOrAbove()` | `bool` | True if severity is "high" or "critical" |
| `SeverityLevel()` | `int` | Numeric severity: 0=unknown, 1=info, 2=low, 3=medium, 4=high, 5=critical |

---

## Target Utilities

```go
// Read targets from a file (one per line, skips empty lines and comments)
targets, err := nucleisdk.TargetsFromFile("/path/to/targets.txt")

// Read targets from any io.Reader
targets, err := nucleisdk.TargetsFromReader(reader)

// Expand CIDR notation to individual IPs
targets, err := nucleisdk.TargetsFromCIDR("192.168.1.0/24")

// Expand multiple CIDRs
targets, err := nucleisdk.TargetsFromCIDRs([]string{"10.0.0.0/24", "172.16.0.0/24"})

// Generate IP range (inclusive)
targets, err := nucleisdk.IPRange("10.0.0.1", "10.0.0.254")
```

---

## Template Utilities

```go
// Download template from URL
data, err := nucleisdk.FetchTemplateFromURL(ctx, "https://example.com/template.yaml")

// Validate template YAML — returns template ID if valid
id, err := nucleisdk.ValidateTemplate(data)

// Parse template metadata without full compilation
info, err := nucleisdk.ParseTemplateInfo(data)
fmt.Printf("ID: %s, Severity: %s, Tags: %v\n", info.ID, info.Severity, info.Tags)

// Create template bytes entry for ScanOptions
entry := nucleisdk.TemplateBytes("my-check", yamlBytes)
```

**TemplateInfo:**

```go
type TemplateInfo struct {
    ID          string
    Name        string
    Author      string
    Severity    string
    Tags        []string
    Description string
}
```

---

## Building Custom Workflows

### CI/CD Pipeline Scanner

Fail the pipeline on critical findings:

```go
func scanOnDeploy(deployURL string) error {
    engine, err := nucleisdk.NewScanEngine(
        nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
        nucleisdk.WithRateLimit(100),
        nucleisdk.WithNoInteractsh(),
        nucleisdk.WithSilent(),
    )
    if err != nil {
        return err
    }
    if err := engine.Setup(); err != nil {
        return err
    }
    defer engine.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
    defer cancel()

    results, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
        Targets:    []string{deployURL},
        Tags:       []string{"cve", "exposure", "misconfig"},
        Severities: []string{"critical", "high"},
    })
    if err != nil {
        return err
    }

    var criticals []*nucleisdk.ScanResult
    for r := range results {
        if r.IsCritical() {
            criticals = append(criticals, r)
        }
        log.Printf("[%s] %s - %s\n", r.Severity, r.TemplateID, r.MatchedURL)
    }

    if len(criticals) > 0 {
        return fmt.Errorf("BLOCKING: %d critical vulnerabilities found", len(criticals))
    }
    return nil
}
```

### Continuous Vulnerability Monitoring

Feed targets from an asset inventory, scan continuously:

```go
func monitor(ctx context.Context, assetStream <-chan Asset) {
    engine, _ := nucleisdk.NewScanEngine(
        nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
        nucleisdk.WithRateLimit(50),
        nucleisdk.WithNoInteractsh(),
        nucleisdk.WithSilent(),
    )
    engine.Setup()
    defer engine.Close()

    pool := engine.NewScanPool(ctx, 20)

    // Consume results — send to database, Slack, SIEM
    go func() {
        for r := range pool.Results() {
            saveToDatabase(r)
            if r.IsHighOrAbove() {
                alertSlack(r)
            }
        }
    }()

    // Feed targets from asset stream
    for asset := range assetStream {
        pool.Submit(asset.ID, &nucleisdk.ScanOptions{
            Targets: []string{asset.URL},
            Tags:    []string{"cve", "exposure"},
        })
    }

    pool.Close()
}
```

### Multi-Tenant Security Platform

Different scan profiles per tenant:

```go
func scanTenant(ctx context.Context, engine *nucleisdk.ScanEngine, tenant Tenant) (<-chan *nucleisdk.ScanResult, error) {
    opts := &nucleisdk.ScanOptions{
        Targets: tenant.Assets,
    }

    switch tenant.Plan {
    case "basic":
        opts.Tags = []string{"cve"}
        opts.Severities = []string{"critical", "high"}
    case "pro":
        opts.Tags = []string{"cve", "exposure", "misconfig"}
    case "enterprise":
        // Full scan — no tag filter
    }

    return engine.Scan(ctx, opts)
}
```

### CVE Verification Service

Verify specific CVEs against targets with custom templates:

```go
func verifyCVE(ctx context.Context, engine *nucleisdk.ScanEngine, cveID string, templateYAML []byte, targets []string) ([]nucleisdk.ScanResult, error) {
    results, err := engine.Scan(ctx, &nucleisdk.ScanOptions{
        Targets: targets,
        TemplateBytes: []nucleisdk.TemplateBytesEntry{
            nucleisdk.TemplateBytes(cveID, templateYAML),
        },
    })
    if err != nil {
        return nil, err
    }

    var findings []nucleisdk.ScanResult
    for r := range results {
        findings = append(findings, *r)
    }
    return findings, nil
}
```

### Asset Discovery and Scanning

Discover assets via CIDR expansion, then scan:

```go
func scanNetwork(ctx context.Context, cidr string) {
    targets, err := nucleisdk.TargetsFromCIDR(cidr)
    if err != nil {
        log.Fatal(err)
    }

    engine, _ := nucleisdk.NewScanEngine(
        nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
        nucleisdk.WithRateLimit(50),
        nucleisdk.WithSilent(),
    )
    engine.Setup()
    defer engine.Close()

    // Phase 1: Discovery
    results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
        Targets: targets,
        Tags:    []string{"tech", "detect", "panel"},
    })

    var liveHosts []string
    for r := range results {
        liveHosts = append(liveHosts, r.Host)
    }

    // Phase 2: Deep scan on discovered hosts
    results, _ = engine.Scan(ctx, &nucleisdk.ScanOptions{
        Targets:    liveHosts,
        Tags:       []string{"cve", "exposure", "misconfig"},
        Severities: []string{"high", "critical"},
    })
    for r := range results {
        fmt.Printf("[%s] %s - %s\n", r.Severity, r.TemplateID, r.MatchedURL)
    }
}
```

### Target File — Scanning from a File

Pass a file path instead of a target list. The file should have one target per line (empty lines and `#` comments are skipped):

```go
// One-shot scanner with target file
scanner, _ := nucleisdk.NewScanner(
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
    nucleisdk.WithTargetFile("/path/to/targets.txt"),
    nucleisdk.WithTags("cve"),
)
defer scanner.Close()
results, _ := scanner.Run(context.Background())
for r := range results {
    fmt.Printf("[%s] %s\n", r.Severity, r.TemplateID)
}
```

With `ScanEngine`, pass `TargetFile` in per-scan options:

```go
engine.Setup()
defer engine.Close()

// Single scan from file
results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
    TargetFile: "/path/to/targets.txt",
    Tags:       []string{"cve"},
})
for r := range results {
    fmt.Printf("[%s] %s\n", r.Severity, r.TemplateID)
}

// Pool with file targets
pool := engine.NewScanPool(ctx, 10)
pool.Submit("from-file", &nucleisdk.ScanOptions{
    TargetFile: "/path/to/targets.txt",
    Tags:       []string{"cve"},
})
```

Combine file and inline targets — both are merged:

```go
results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
    Targets:    []string{"https://extra-target.com"},
    TargetFile: "/path/to/targets.txt",
    Tags:       []string{"cve"},
})
```

### HTTP Probing — Scanning Raw Hosts/IPs

When targets are raw IPs or hostnames (without `http://` or `https://`), enable HTTP probing to discover HTTP/HTTPS services:

```go
func scanSubnet(ctx context.Context, cidr string) {
    targets, _ := nucleisdk.TargetsFromCIDR(cidr)

    engine, _ := nucleisdk.NewScanEngine(
        nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
        nucleisdk.WithHTTPProbe(),           // Probe raw IPs for HTTP/HTTPS
        nucleisdk.WithProbeConcurrency(100), // 100 concurrent probes
        nucleisdk.WithScanAllIPs(),          // Scan all resolved IPs
        nucleisdk.WithIPVersion("4", "6"),   // Dual-stack
        nucleisdk.WithRateLimit(50),
        nucleisdk.WithSilent(),
    )
    engine.Setup()
    defer engine.Close()

    results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
        Targets:    targets,
        Tags:       []string{"cve", "exposure"},
        Severities: []string{"high", "critical"},
    })
    for r := range results {
        fmt.Printf("[%s] %s (%s): %s\n", r.Severity, r.Host, r.IP, r.TemplateID)
    }
}
```

Exclude specific hosts:

```go
engine, _ := nucleisdk.NewScanEngine(
    nucleisdk.WithExcludeTargets("internal.example.com", "192.168.1.1"),
    nucleisdk.WithHTTPProbe(),
    nucleisdk.WithRateLimit(100),
)
```

### Webhook-Driven Scanning

Trigger scans from an HTTP webhook:

```go
func webhookHandler(engine *nucleisdk.ScanEngine, pool *nucleisdk.ScanPool) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            ID      string   `json:"id"`
            Targets []string `json:"targets"`
            Tags    []string `json:"tags"`
        }
        json.NewDecoder(r.Body).Decode(&req)

        err := pool.Submit(req.ID, &nucleisdk.ScanOptions{
            Targets: req.Targets,
            Tags:    req.Tags,
        })
        if err != nil {
            http.Error(w, err.Error(), 500)
            return
        }

        w.WriteHeader(http.StatusAccepted)
        json.NewEncoder(w).Encode(map[string]string{"status": "queued", "id": req.ID})
    }
}
```

---

## Error Handling

```go
engine, err := nucleisdk.NewScanEngine(opts...)
if err != nil {
    // Configuration error — invalid options
    log.Fatal(err)
}

if err := engine.Setup(); err != nil {
    // Initialization error — template loading, interactsh, etc.
    log.Fatal(err)
}

results, err := engine.Scan(ctx, scanOpts)
if err != nil {
    // Scan error — no targets, no matching templates, etc.
    log.Fatal(err)
}

for r := range results {
    if r.Error != "" {
        // Per-result error — template execution failed for this target
        log.Printf("Error: %s on %s: %s\n", r.TemplateID, r.Host, r.Error)
        continue
    }
    // Process result
}
```

Common errors:
- `"no targets provided"` — ScanOptions has no targets
- `"no templates match the given filters"` — per-scan tags/filters match nothing in the loaded template set
- `"engine not set up"` — `Scan()` called before `Setup()`

---

## Performance Tips

1. **Use ScanEngine, not Scanner** — Scanner creates/destroys everything per run. ScanEngine shares heavy resources.

2. **Load all templates at Setup for pools** — Don't set `WithTags()` if your pool scans use different tags. Filter per-scan instead.

3. **Use direct templates for dynamic workflows** — `TemplateBytes` and `TemplateFiles` bypass the global store and are perfect for runtime template loading.

4. **Tune concurrency for your target** — Start with `WithThreads(25)`, `WithHostConcurrency(10)`, `WithRateLimit(100)` and adjust based on target capacity.

5. **Disable interactsh if not needed** — `WithNoInteractsh()` eliminates OOB polling overhead. Only needed for blind vulnerability detection.

6. **Use context cancellation** — Pass cancellable contexts to `Scan()` for timeout control and graceful shutdown.

7. **Use ScanPool for dynamic workloads** — Better than manually managing goroutines. Bounded concurrency prevents resource exhaustion.

8. **Use WithSilent()** — Suppresses nuclei's internal output, reducing I/O overhead in production.
