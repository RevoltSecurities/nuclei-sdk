# nuclei-sdk

[![Go Reference](https://pkg.go.dev/badge/github.com/RevoltSecurities/nuclei-sdk.svg)](https://pkg.go.dev/github.com/RevoltSecurities/nuclei-sdk)
[![Release](https://img.shields.io/github/v/release/RevoltSecurities/nuclei-sdk)](https://github.com/RevoltSecurities/nuclei-sdk/releases)
[![PyPI](https://img.shields.io/pypi/v/nuclei-sdk)](https://pypi.org/project/nuclei-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**The missing SDK for Nuclei.** Build production security tools in Go or Python — scanners, platforms, CI gates, monitoring systems — powered by the world's most popular template-based vulnerability scanner.

---

## The Problem

[Nuclei](https://github.com/projectdiscovery/nuclei) has 60,000+ stars and is the industry standard for template-based vulnerability scanning. But integrating it into your own tools has always been painful:

| Pain Point | What Happens |
|---|---|
| **Go-only** | Nuclei's `lib/` API requires Go. Python, TypeScript, Java teams have no clean path |
| **Heavy per-scan overhead** | Each scan re-initializes templates, interactsh, rate limiters, protocol state. Running 100 scans means 100x the startup cost |
| **No concurrent architecture** | No built-in way to run multiple scan types simultaneously with shared resources |
| **No worker pool** | Building continuous scanning (from APIs, queues, feeds) means writing your own concurrency from scratch |
| **No presets** | Every project reinvents "API security scan" or "WordPress scan" configuration from scratch |

## The Solution

**nuclei-sdk** is a multi-language SDK that wraps Nuclei into a clean, embeddable library designed for building production security tools.

### What you get

- **Go SDK** — native library with init-once/scan-many architecture. Heavy resources (templates, interactsh, rate limiter, parser) initialized once; each `Scan()` call creates only a lightweight executor (~5 fields)
- **Python SDK** — fully async (`asyncio`) client. No Go toolchain required — the bridge binary auto-installs from GitHub Releases with SHA256 verification
- **Any language next** — the bridge speaks JSON lines over stdin/stdout (like MCP stdio). TypeScript, Rust, Java, Ruby — if it can spawn a process and parse JSON, it can use Nuclei
- **ScanEngine** — run 1000+ concurrent scans on a single engine. Each scan filters from pre-loaded templates or brings its own
- **ScanPool** — bounded worker pool for continuous scanning from APIs, queues, webhooks, or vulnerability feeds
- **RunParallel** — fire multiple scan types simultaneously (HTTP CVEs + DNS takeover + SSL audit) with labeled results
- **4 preset scanners** — Web, API Security, WordPress, Network — ready to use, fully customizable
- **82 configuration options** — proxy, auth, headers, concurrency, sandboxing, HTTP probing, and everything else Nuclei supports
- **Runtime templates** — pass raw YAML bytes, file paths, URLs, or directories per-scan. No upfront template configuration needed

### Who is this for?

| You are... | You can build... |
|---|---|
| **Security engineer** | Custom scanners for your org's specific stack (WordPress fleet, API gateway, microservices) |
| **Platform developer** | SaaS security products with Nuclei as the scanning engine behind your API |
| **DevSecOps engineer** | CI/CD gates that block deploys on critical findings |
| **Bug bounty hunter** | Automated recon pipelines that scan continuously and alert on new findings |
| **SOC/Blue team** | Continuous vulnerability monitoring fed from your asset inventory |
| **Researcher** | Rapid prototyping of detection logic with runtime template injection |

---

## Architecture

```
                    nuclei-sdk
                        |
          +-------------+-------------+
          |                           |
       Go SDK                   Bridge Binary
    (native library)         (JSON-line protocol)
          |                           |
    import & use              stdin/stdout JSON
    directly in Go                    |
                        +-------------+-------------+
                        |             |             |
                     Python       TypeScript      Any
                      SDK          (soon)       Language
```

**How the bridge works:**

```
Python/Any Client                  nuclei-sdk-bridge (Go)
      |                                    |
      |  {"cmd":"setup","config":{...}}    |
      | ---------------------------------> |  Initialize engine
      |  {"type":"setup_complete"}         |
      | <--------------------------------- |
      |                                    |
      |  {"cmd":"scan","options":{...}}    |
      | ---------------------------------> |  Run scan
      |  {"type":"result","data":{...}}    |
      | <--------------------------------- |  Stream results
      |  {"type":"scan_complete"}          |
      | <--------------------------------- |
```

**Engine resource model:**

```
Global Resources (initialized once in Setup):
  Template Store, Parser, Catalog, Output Writer,
  Interactsh Client, Rate Limiter, Browser, Host Error Cache

Per-Scan Resources (created per Scan call, very lightweight):
  core.Engine (~5 fields), ExecutorOptions copy,
  SimpleInputProvider, Filtered template list
```

This is what makes nuclei-sdk fast — you pay the initialization cost once, then run thousands of lightweight scans against it.

---

## Installation

### Go

```bash
go get github.com/RevoltSecurities/nuclei-sdk
```

### Python

```bash
pip install nuclei-sdk
```

The Go bridge binary is **auto-installed** from [GitHub Releases](https://github.com/RevoltSecurities/nuclei-sdk/releases) on first use. Supports Linux, macOS, and Windows on amd64/arm64. No Go toolchain required.

---

## Quick Start

### Go — Simple Scan

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

    results, _ := scanner.Run(context.Background())
    for result := range results {
        fmt.Printf("[%s] %s - %s\n", result.Severity, result.TemplateID, result.MatchedURL)
    }
}
```

### Python — Simple Scan

```python
import asyncio
from nucleisdk import ScanEngine

async def main():
    async with ScanEngine(
        template_dirs=["/path/to/nuclei-templates"],
        rate_limit=100,
        no_interactsh=True,
    ) as engine:
        async for r in engine.scan(
            targets=["https://example.com"],
            tags=["cve", "exposure"],
            severities=["high", "critical"],
        ):
            print(f"[{r.severity}] {r.template_id} - {r.matched_url}")

asyncio.run(main())
```

---

## Real-World Use Cases

### 1. CI/CD Pipeline Gate

Block deploys when critical vulnerabilities are found:

**Go:**
```go
engine.Setup()
results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
    Targets:    []string{deployURL},
    Severities: []string{"critical", "high"},
})
for r := range results {
    if r.IsCritical() {
        log.Fatalf("BLOCKED: %s on %s", r.TemplateID, r.MatchedURL)
    }
}
fmt.Println("No critical findings — deploy approved")
```

**Python:**
```python
async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
    findings = await engine.scan_collect(
        targets=[deploy_url], severities=["critical", "high"]
    )
    if any(r.is_critical() for r in findings):
        sys.exit("BLOCKED: Critical vulnerability found")
    print("Deploy approved")
```

### 2. Continuous Vulnerability Monitoring

Feed targets from your asset inventory and scan continuously:

**Go:**
```go
pool := engine.NewScanPool(ctx, 20)

go func() {
    for r := range pool.Results() {
        saveToDatabase(r)
        if r.IsHighOrAbove() {
            sendSlackAlert(r)
        }
    }
}()

// Feed from asset inventory, CMDB, or discovery tool
for asset := range assetInventoryStream {
    pool.Submit(asset.ID, &nucleisdk.ScanOptions{
        Targets: []string{asset.URL},
        Tags:    []string{"cve", "exposure"},
    })
}
pool.Close()
```

**Python:**
```python
async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
    pool = await engine.scan_pool(workers=20, on_result=save_to_database)

    async for asset in asset_inventory_stream():
        await pool.submit(asset["id"], targets=[asset["url"]], tags=["cve"])

    await pool.close()
    print(f"Scanned {pool.stats.completed} assets")
```

### 3. Multi-Protocol Parallel Scanning

Run HTTP, DNS, and SSL scans simultaneously with labeled results:

**Go:**
```go
results, _ := engine.RunParallel(ctx,
    nucleisdk.ConcurrentScan{
        Label:   "http-cves",
        Options: []nucleisdk.Option{
            nucleisdk.WithProtocolTypes("http"),
            nucleisdk.WithTags("cve", "exposure"),
            nucleisdk.WithSeverityFilter("high", "critical"),
            nucleisdk.WithTargets("https://example.com"),
        },
    },
    nucleisdk.ConcurrentScan{
        Label:   "dns-takeover",
        Options: []nucleisdk.Option{
            nucleisdk.WithProtocolTypes("dns"),
            nucleisdk.WithTags("dns", "takeover"),
            nucleisdk.WithTargets("example.com"),
        },
    },
    nucleisdk.ConcurrentScan{
        Label:   "ssl-audit",
        Options: []nucleisdk.Option{
            nucleisdk.WithProtocolTypes("ssl"),
            nucleisdk.WithTargets("example.com:443"),
        },
    },
)

for lr := range results {
    fmt.Printf("[%s] [%s] %s - %s\n", lr.Label, lr.Severity, lr.TemplateID, lr.Host)
}
```

**Python:**
```python
async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
    async for lr in engine.run_parallel(
        {"label": "http-cves", "targets": ["https://example.com"], "tags": ["cve"]},
        {"label": "dns-takeover", "targets": ["example.com"], "tags": ["dns", "takeover"]},
        {"label": "ssl-audit", "targets": ["example.com:443"], "protocol_types": "ssl"},
    ):
        print(f"[{lr.label}] [{lr.result.severity}] {lr.result.template_id}")
```

### 4. Runtime Template Injection

Set up the engine once with no templates, then pass templates dynamically per-scan. Perfect for platforms where templates come from a database, API, or user upload:

**Go:**
```go
// Engine with NO templates — a "blank runner"
engine, _ := nucleisdk.NewScanEngine(
    nucleisdk.WithRateLimit(100),
    nucleisdk.WithSilent(),
)
engine.Setup()
defer engine.Close()

// Each scan brings its own template
templateYAML, _ := os.ReadFile("/path/to/CVE-2024-1234.yaml")
results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
    Targets: []string{"https://target.com"},
    TemplateBytes: []nucleisdk.TemplateBytesEntry{
        nucleisdk.TemplateBytes("CVE-2024-1234", templateYAML),
    },
})
```

**Python:**
```python
async with ScanEngine(rate_limit=100) as engine:
    template_yaml = Path("CVE-2024-1234.yaml").read_bytes()
    async for r in engine.scan(
        targets=["https://target.com"],
        template_bytes=[TemplateBytesEntry("CVE-2024-1234", template_yaml)],
    ):
        print(f"[{r.severity}] {r.template_id}")
```

### 5. WordPress Fleet Scanner

Scan all your WordPress sites with optimized presets:

**Go:**
```go
scanner, _ := nucleisdk.NewWordPressScanner(
    nucleisdk.WithTargets(wpSites...),
    nucleisdk.WithTemplateDir("/path/to/nuclei-templates"),
)
defer scanner.Close()

results, _ := scanner.Run(ctx)
for r := range results {
    fmt.Printf("[%s] %s — %s\n", r.Severity, r.TemplateID, r.Host)
}
```

**Python:**
```python
from nucleisdk import ScanEngine, wordpress_scanner

async with ScanEngine(**wordpress_scanner().__dict__) as engine:
    async for r in engine.scan(targets=wp_sites):
        print(f"[{r.severity}] {r.template_id} — {r.host}")
```

### 6. API Security Assessment

Scan APIs with OpenAPI specs and authenticated requests:

**Go:**
```go
scanner, _ := nucleisdk.NewAPISecurityScanner(
    nucleisdk.WithOpenAPISpec("/path/to/openapi.yaml"),
    nucleisdk.WithAuth(nucleisdk.BearerToken("eyJ...", "api.example.com")),
    nucleisdk.WithRateLimit(30),
)
```

**Python:**
```python
from nucleisdk import ScanEngine, api_security_scanner, bearer_token

async with ScanEngine(
    **api_security_scanner().__dict__,
    auth=[bearer_token("eyJ...", "api.example.com")],
    openapi_spec="/path/to/openapi.yaml",
) as engine:
    async for r in engine.scan(targets=["https://api.example.com"]):
        print(f"[{r.severity}] {r.template_id}")
```

---

## Preset Scanners

Pre-configured scanning profiles — use as-is or override any option:

| Preset | Protocol | Tags | Defaults |
|---|---|---|---|
| `WebScanner` / `web_scanner()` | HTTP | all (excludes: dos, fuzz) | 50 threads, 150 req/s |
| `APISecurityScanner` / `api_security_scanner()` | HTTP | api, graphql, swagger, rest | 25 threads, 50 req/s |
| `WordPressScanner` / `wordpress_scanner()` | HTTP | wordpress, wp-plugin, wp-theme | 25 threads, 30 req/s |
| `NetworkScanner` / `network_scanner()` | network, dns, ssl | network, dns, ssl, tls | 25 threads, 100 req/s |

---

## Template Loading — How It Works

Understanding this is key to using ScanEngine effectively:

```
Setup()  →  Load & compile all templates  →  engine.allTemplates (in-memory)
                                                     |
Scan(tags=["http"])   →  filter from allTemplates  →  [http templates only]
Scan(tags=["dns"])    →  filter from allTemplates  →  [dns templates only]
Scan(tags=["ssl"])    →  filter from allTemplates  →  [ssl templates only]
```

**Rule of thumb:**
- **Single scan** — set tags at Setup for efficiency (loads only what you need)
- **Multiple scans with different tags** — don't set tags at Setup, filter per-scan instead
- **Runtime templates** (`TemplateBytes`, `TemplateFiles`, `TemplateDirs`) — bypass the global store entirely, always work regardless of Setup config

| Setup Config | Per-Scan Filter | Result |
|---|---|---|
| No tags (all templates) | `Tags: ["dns"]` | DNS templates found |
| `WithTags("http")` | `Tags: ["http"]` | HTTP templates found |
| `WithTags("http")` | `Tags: ["dns"]` | **Zero results** — DNS never loaded |
| Any config | `TemplateFiles: [...]` | Always works (direct mode) |
| Any config | `TemplateBytes: [...]` | Always works (direct mode) |

---

## Authentication

6 auth methods, usable in both Go and Python:

**Go:**
```go
nucleisdk.WithAuth(nucleisdk.BasicAuth("user", "pass", "example.com"))
nucleisdk.WithAuth(nucleisdk.BearerToken("eyJ...", "api.example.com"))
nucleisdk.WithAuth(nucleisdk.APIKeyHeader("X-API-Key", "key123", "api.example.com"))
nucleisdk.WithAuth(nucleisdk.HeaderAuth(map[string]string{"Auth": "custom"}, "example.com"))
nucleisdk.WithAuth(nucleisdk.CookieAuth(map[string]string{"session": "abc"}, "example.com"))
nucleisdk.WithAuth(nucleisdk.QueryAuth(map[string]string{"token": "xyz"}, "example.com"))
```

**Python:**
```python
from nucleisdk import basic_auth, bearer_token, api_key_header, header_auth, cookie_auth, query_auth

ScanEngine(auth=[
    bearer_token("eyJ...", "api.example.com"),
    basic_auth("user", "pass", "internal.example.com"),
])
```

---

## Target Utilities

Load targets from files, CIDRs, or IP ranges:

**Go:**
```go
targets, _ := nucleisdk.TargetsFromFile("/path/to/targets.txt")
targets, _ = nucleisdk.TargetsFromCIDR("192.168.1.0/24")
targets, _ = nucleisdk.IPRange("10.0.0.1", "10.0.0.254")
```

**Python:**
```python
from nucleisdk import targets_from_file, targets_from_cidr, ip_range

targets = targets_from_file("/path/to/targets.txt")
targets = targets_from_cidr("192.168.1.0/24")     # 254 IPs
targets = ip_range("10.0.0.1", "10.0.0.254")
```

Or pass a file path directly to any scan:
```python
async for r in engine.scan(target_file="/path/to/targets.txt", tags=["cve"]):
    ...
```

---

## Configuration Reference

82 configuration options organized by category. Full reference in [Go SDK docs](docs/GOLANG-SDK.md) and [Python SDK docs](docs/PYTHON-SDK.md).

**Highlights:**

```go
// Concurrency
nucleisdk.WithThreads(50)            // concurrent templates
nucleisdk.WithHostConcurrency(25)    // concurrent hosts per template
nucleisdk.WithRateLimit(100)         // max requests/second
nucleisdk.WithPayloadConcurrency(10) // concurrent payloads per request

// Network
nucleisdk.WithProxy("http://127.0.0.1:8080")
nucleisdk.WithNetworkInterface("eth0")
nucleisdk.WithSourceIP("10.0.0.5")
nucleisdk.WithResolvers("8.8.8.8", "1.1.1.1")

// Headers & Variables
nucleisdk.WithHeader("User-Agent", "CustomScanner/1.0")
nucleisdk.WithVar("api_key", "test-key")

// HTTP Probing (scan raw hosts/IPs)
nucleisdk.WithHTTPProbe()
nucleisdk.WithProbeConcurrency(50)
nucleisdk.WithScanAllIPs()

// Sandbox
nucleisdk.WithSandboxOptions(allowLocalFile, restrictNetwork)

// Features
nucleisdk.WithDASTMode()
nucleisdk.WithHeadless(nil)
nucleisdk.WithCodeTemplates()
```

---

## Extend to Any Language

The bridge binary speaks a simple JSON-line protocol over stdin/stdout. Building a client in your language takes ~200 lines:

```
$ echo '{"cmd":"version","id":"1"}' | nuclei-sdk-bridge
{"id":"1","type":"version","data":{"version":"1.0.0",...}}
```

**Commands:** `version`, `setup`, `scan`, `pool_create`, `pool_submit`, `pool_stats`, `pool_close`, `close`

See [Bridge Protocol Reference](docs/GOLANG-SDK.md#bridge-protocol) for the full spec. The Python SDK implementation ([python/nucleisdk/_bridge.py](python/nucleisdk/_bridge.py)) is a working reference client.

---

## Examples

| Example | Description |
|---------|-------------|
| [basic](examples/basic/) | Simple one-shot scan with Scanner |
| [reusable_engine](examples/reusable_engine/) | Sequential scans with shared ScanEngine |
| [concurrent](examples/concurrent/) | Parallel multi-protocol scans with RunParallel |
| [targeted_scan](examples/targeted_scan/) | Per-scan templates (bytes, files, dirs) |
| [scan_pool](examples/scan_pool/) | Worker pool for continuous dynamic scanning |
| [api_security](examples/api_security/) | API security scanning with OpenAPI spec |
| [wordpress](examples/wordpress/) | WordPress-specific vulnerability scanning |
| [raw_template](examples/raw_template/) | Scanning with raw YAML template bytes |
| [custom_config](examples/custom_config/) | Advanced configuration options |

Python examples in [python/examples/](python/examples/).

---

## Full Documentation

| | |
|---|---|
| **Go SDK** | [docs/GOLANG-SDK.md](docs/GOLANG-SDK.md) — complete API reference, all 82 config options, all scan modes |
| **Python SDK** | [docs/PYTHON-SDK.md](docs/PYTHON-SDK.md) — async API, presets, auth, targets, templates, pool, parallel |

---

## Release & Versioning

| Component | Version | Install |
|-----------|---------|---------|
| Go SDK | `v1.0.0` | `go get github.com/RevoltSecurities/nuclei-sdk` |
| Python SDK | `1.0.0` | `pip install nuclei-sdk` |
| Bridge Binary | `1.0.0` | Auto-installed by Python SDK |

### Compatibility & Auto-Install

- The Python SDK auto-downloads the bridge binary on first use with SHA256 checksum verification.
- The SDK enforces a minimum bridge version and will auto-update if the local bridge is incompatible.
- You can pin or override the bridge binary path if you need a custom build or air-gapped deployment.
- Python template parsing utilities (`validate_template`, `parse_template_info`) require PyYAML.  
  Install with `pip install nuclei-sdk[templates]` or `pip install pyyaml`.

### Release Workflow

```bash
# Go binary release (goreleaser → GitHub Releases)
git tag v1.0.0 && git push origin v1.0.0

# Python package release (→ PyPI)
git tag py-v1.0.0 && git push origin py-v1.0.0
```

The Python SDK auto-downloads the bridge binary on first use with SHA256 checksum verification. If versions are incompatible, it auto-updates.

---

## Credits

Made with :heart: by [RevoltSecurities](https://github.com/RevoltSecurities)

**Thanks**

Special thanks to the ProjectDiscovery team for their open-source contributions. This project extends Nuclei for broader integration across the open-source community and aims to help scale vulnerability scanning in production environments.
