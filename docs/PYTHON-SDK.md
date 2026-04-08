# Python SDK Documentation

Comprehensive documentation for the nuclei-sdk Python client — build async security scanners, automated workflows, and vulnerability management platforms in Python.

**Developed by [RevoltSecurities](https://github.com/RevoltSecurities)**

---

## Table of Contents

- [Installation](#installation)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [ScanEngine](#scanengine)
  - [Constructor](#constructor)
  - [Async Context Manager](#async-context-manager)
  - [Manual Setup and Close](#manual-setup-and-close)
  - [Single Scan](#single-scan)
  - [Collect All Results](#collect-all-results)
  - [Multiple Scans on One Engine](#multiple-scans-on-one-engine)
  - [Runtime Engine — Custom Templates per Scan](#runtime-engine--custom-templates-per-scan)
- [run_parallel() — Concurrent Labeled Scans](#run_parallel--concurrent-labeled-scans)
- [ScanPool — Continuous Dynamic Scanning](#scanpool--continuous-dynamic-scanning)
  - [Iterator Mode](#iterator-mode)
  - [Callback Mode](#callback-mode)
  - [Pool Stats](#pool-stats)
  - [Runtime Engine with Pool](#runtime-engine-with-pool)
- [Preset Scanners](#preset-scanners)
  - [web_scanner()](#web_scanner)
  - [api_security_scanner()](#api_security_scanner)
  - [wordpress_scanner()](#wordpress_scanner)
  - [network_scanner()](#network_scanner)
- [Authentication Helpers](#authentication-helpers)
  - [basic_auth()](#basic_auth)
  - [bearer_token()](#bearer_token)
  - [header_auth()](#header_auth)
  - [cookie_auth()](#cookie_auth)
  - [query_auth()](#query_auth)
  - [api_key_header()](#api_key_header)
- [Target Utilities](#target-utilities)
  - [targets_from_file()](#targets_from_file)
  - [targets_from_cidr()](#targets_from_cidr)
  - [targets_from_cidrs()](#targets_from_cidrs)
  - [ip_range()](#ip_range)
- [Template Utilities](#template-utilities)
  - [TemplateInfo](#templateinfo)
  - [fetch_template_from_url()](#fetch_template_from_url)
  - [validate_template()](#validate_template)
  - [parse_template_info()](#parse_template_info)
- [Template Loading and Filtering](#template-loading-and-filtering)
  - [How It Works](#how-it-works)
  - [Single Scan — Tags at Setup](#single-scan--tags-at-setup)
  - [Concurrent Scans — No Tags at Setup](#concurrent-scans--no-tags-at-setup)
  - [Direct Templates — Always Work](#direct-templates--always-work)
- [Models Reference](#models-reference)
  - [ScanResult](#scanresult)
  - [LabeledResult](#labeledresult)
  - [PoolStats](#poolstats)
  - [TemplateBytesEntry](#templatebytesentry)
  - [EngineConfig](#engineconfig)
  - [ScanOptions](#scanoptions)
- [Auto-Installer and Version Management](#auto-installer-and-version-management)
  - [How Auto-Install Works](#how-auto-install-works)
  - [install_bridge()](#install_bridge)
  - [ensure_bridge()](#ensure_bridge)
  - [get_bridge_version()](#get_bridge_version)
  - [check_version_compatible()](#check_version_compatible)
  - [Version Constants](#version-constants)
  - [Force Update](#force-update)
  - [Custom Repository (Forks)](#custom-repository-forks)
  - [Explicit Binary Path](#explicit-binary-path)
  - [SSRF Protection](#ssrf-protection)
- [Exception Handling](#exception-handling)
  - [Exception Hierarchy](#exception-hierarchy)
  - [Handling Each Exception](#handling-each-exception)
  - [Version Mismatch Recovery](#version-mismatch-recovery)
- [Bridge Protocol](#bridge-protocol)
  - [How It Works](#how-the-bridge-works)
  - [BridgeProcess Internals](#bridgeprocess-internals)
- [Different Types of Scans](#different-types-of-scans)
  - [HTTP CVE Scanning](#http-cve-scanning)
  - [DNS Scanning](#dns-scanning)
  - [SSL/TLS Scanning](#ssltls-scanning)
  - [Network Scanning](#network-scanning)
  - [Technology Detection](#technology-detection)
  - [Misconfiguration Scanning](#misconfiguration-scanning)
  - [WordPress Scanning](#wordpress-scanning)
  - [API Security Scanning](#api-security-scanning)
  - [Multi-Protocol Scanning](#multi-protocol-scanning)
  - [Target File — Scanning from a File](#target-file--scanning-from-a-file)
  - [HTTP Probing — Scanning Raw Hosts/IPs](#http-probing--scanning-raw-hostsips)
  - [Custom Template Scanning](#custom-template-scanning)
  - [Severity-Based Scanning](#severity-based-scanning)
- [Building Custom Workflows](#building-custom-workflows)
  - [CI/CD Pipeline Scanner](#cicd-pipeline-scanner)
  - [Continuous Vulnerability Monitoring](#continuous-vulnerability-monitoring)
  - [Security Dashboard Backend](#security-dashboard-backend)
  - [Webhook-Driven Scanning](#webhook-driven-scanning)
  - [CVE Verification Service](#cve-verification-service)
  - [Multi-Tenant Scanner](#multi-tenant-scanner)
  - [Scheduled Scanning](#scheduled-scanning)
  - [Scan Results to Database](#scan-results-to-database)
  - [Slack/Discord Alert Integration](#slackdiscord-alert-integration)
- [Configuration Reference](#configuration-reference)
  - [Engine Configuration Parameters](#engine-configuration-parameters)
  - [Per-Scan Parameters](#per-scan-parameters)
  - [Authentication](#authentication)
- [Performance Tips](#performance-tips)
- [API Reference Summary](#api-reference-summary)

---

## Installation

```bash
pip install nuclei-sdk
```

For template validation/parsing utilities (PyYAML):

```bash
pip install nuclei-sdk[templates]
```

**Requirements:**
- Python 3.9+
- No Go toolchain required — the Go bridge binary is auto-installed from GitHub Releases on first use

**Supported Platforms:**
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64, arm64)

---

## Architecture

The Python SDK communicates with a Go bridge binary (`nuclei-sdk-bridge`) via JSON lines over stdin/stdout:

```
Python (async/await)              Go (nuclei-sdk-bridge)
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

- **Auto-installed**: The bridge binary downloads from GitHub Releases on first use with SHA256 checksum verification
- **Version-checked**: Python SDK validates bridge version compatibility before use
- **Lightweight**: Each Python coroutine uses ~1KB (vs ~8MB per thread)

---

## Quick Start

```python
import asyncio
from nucleisdk import ScanEngine

async def main():
    async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
        async for result in engine.scan(
            targets=["https://example.com"],
            tags=["cve", "exposure"],
            severities=["high", "critical"],
        ):
            print(f"[{result.severity}] {result.template_id} - {result.matched_url}")

asyncio.run(main())
```

---

## ScanEngine

The primary API for the Python SDK. Manages the bridge process lifecycle and provides async scanning methods.

### Constructor

```python
ScanEngine(binary_path=None, **config)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `binary_path` | `str \| None` | `None` | Explicit path to bridge binary. If None, auto-discovers or auto-installs |
| `rate_limit` | `int` | `0` | Max requests per second |
| `timeout` | `int` | `0` | Request timeout in seconds |
| `threads` | `int` | `0` | Concurrent templates to execute |
| `host_concurrency` | `int` | `0` | Concurrent hosts per template |
| `retries` | `int` | `0` | Retry count on failure |
| `no_interactsh` | `bool` | `False` | Disable OOB testing service |
| `verbose` | `bool` | `False` | Enable verbose output |
| `debug` | `bool` | `False` | Enable debug mode |
| `silent` | `bool` | `False` | Suppress output |
| `headless` | `bool` | `False` | Enable headless browser |
| `dast_mode` | `bool` | `False` | Enable DAST/fuzzing mode |
| `proxy` | `list[str]` | `[]` | Proxy URLs |
| `template_dirs` | `list[str]` | `[]` | Template directories to load at setup |
| `template_files` | `list[str]` | `[]` | Template files to load at setup |
| `workflows` | `list[str]` | `[]` | Workflow files |
| `tags` | `list[str]` | `[]` | Tag filter for setup-time loading |
| `exclude_tags` | `list[str]` | `[]` | Exclude tags at setup |
| `severities` | `list[str]` | `[]` | Severity filter at setup |
| `exclude_severities` | `list[str]` | `[]` | Exclude severities at setup |
| `protocol_types` | `str` | `""` | Protocol filter at setup |
| `template_ids` | `list[str]` | `[]` | Template ID filter at setup |
| `exclude_ids` | `list[str]` | `[]` | Exclude template IDs at setup |
| `authors` | `list[str]` | `[]` | Author filter at setup |
| `auth` | `list[dict]` | `[]` | Authentication configurations |

> **Note:** `ScanEngine()` accepts all `EngineConfig` fields as kwargs. See [Configuration Reference](#engine-configuration-parameters) for the full list of 50+ parameters including custom headers, sandbox options, network settings, and more.

### Async Context Manager

The recommended way to use `ScanEngine` — automatically calls `setup()` and `close()`:

```python
async with ScanEngine(rate_limit=100) as engine:
    # engine.setup() already called
    async for r in engine.scan(targets=["https://example.com"]):
        print(r.template_id)
# engine.close() called automatically, even on exceptions
```

### Manual Setup and Close

For more control over the lifecycle:

```python
engine = ScanEngine(rate_limit=100, no_interactsh=True)

# Explicit setup — starts bridge process, initializes engine
await engine.setup()

# Use engine...
async for r in engine.scan(targets=["https://example.com"]):
    print(r.template_id)

# Explicit close — stops bridge process
await engine.close()
```

### Single Scan

```python
async with ScanEngine(
    template_dirs=["/path/to/nuclei-templates"],
    rate_limit=100,
    no_interactsh=True,
    silent=True,
) as engine:
    async for result in engine.scan(
        targets=["https://example.com"],
        tags=["cve", "exposure"],
        severities=["high", "critical"],
        protocol_types="http",
    ):
        print(f"[{result.severity}] {result.template_id}")
        print(f"  URL: {result.matched_url}")
        print(f"  Description: {result.description}")
```

**scan() Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `targets` | `list[str] \| None` | `None` | URLs, domains, IPs to scan |
| `target_file` | `str` | `""` | Path to file with targets |
| `tags` | `list[str] \| None` | `None` | Filter templates by tags |
| `exclude_tags` | `list[str] \| None` | `None` | Exclude by tags |
| `severities` | `list[str] \| None` | `None` | Filter by severity |
| `protocol_types` | `str` | `""` | Filter by protocol |
| `template_ids` | `list[str] \| None` | `None` | Specific template IDs |
| `exclude_ids` | `list[str] \| None` | `None` | Exclude template IDs |
| `authors` | `list[str] \| None` | `None` | Filter by author |
| `template_files` | `list[str] \| None` | `None` | Direct template file paths |
| `template_dirs` | `list[str] \| None` | `None` | Direct template directories |
| `template_bytes` | `list[TemplateBytesEntry] \| None` | `None` | Raw YAML templates |
| `result_severity_filter` | `list[str] \| None` | `None` | Only return results matching these severities |
| `request_response_targets` | `list[TargetRequest] \| None` | `None` | Full HTTP request targets for DAST fuzzing (preserves method, headers, body) |

**Returns:** `AsyncIterator[ScanResult]`

### Collect All Results

```python
results = await engine.scan_collect(
    targets=["https://example.com"],
    tags=["cve"],
)
print(f"Found {len(results)} vulnerabilities")
for r in results:
    print(f"  [{r.severity}] {r.template_id}")
```

### Multiple Scans on One Engine

```python
async with ScanEngine(
    template_dirs=["/path/to/nuclei-templates"],
    rate_limit=100,
) as engine:
    # Scan 1: HTTP CVEs
    async for r in engine.scan(
        targets=["https://example.com"],
        tags=["cve"],
        protocol_types="http",
    ):
        print(f"[HTTP] {r.template_id}")

    # Scan 2: DNS checks (same engine, different filters)
    async for r in engine.scan(
        targets=["example.com"],
        tags=["dns", "takeover"],
    ):
        print(f"[DNS] {r.template_id}")

    # Scan 3: SSL checks
    async for r in engine.scan(
        targets=["example.com:443"],
        tags=["ssl"],
    ):
        print(f"[SSL] {r.template_id}")
```

### Runtime Engine — Custom Templates per Scan

Set up the engine with only runtime config. Each scan provides its own templates:

```python
async with ScanEngine(rate_limit=100, no_interactsh=True, silent=True) as engine:
    # Scan with raw YAML bytes
    template_yaml = open("/path/to/CVE-2024-1234.yaml", "rb").read()
    async for r in engine.scan(
        targets=["https://target.example.com"],
        template_bytes=[TemplateBytesEntry(name="CVE-2024-1234", data=template_yaml)],
    ):
        print(f"[{r.severity}] {r.template_id}")

    # Scan with template files
    async for r in engine.scan(
        targets=["https://another-target.com"],
        template_files=["/path/to/sqli.yaml", "/path/to/xss.yaml"],
    ):
        print(f"[{r.severity}] {r.template_id}")

    # Scan with template directory
    async for r in engine.scan(
        targets=["https://wordpress.example.com"],
        template_dirs=["/path/to/nuclei-templates/technologies/wordpress/"],
    ):
        print(f"[{r.severity}] {r.template_id}")
```

### ScanEngine API Summary

| Method | Description |
|--------|-------------|
| `__init__(binary_path=None, **config)` | Create engine with configuration |
| `async setup()` | Start bridge, initialize engine |
| `async scan(**kwargs)` | Execute scan, yield results |
| `async scan_collect(**kwargs)` | Execute scan, return list of results |
| `async run_parallel(*scans)` | Run concurrent labeled scans, yield LabeledResult |
| `async scan_pool(workers, on_result)` | Create worker pool |
| `async close()` | Shut down engine and bridge |
| `async __aenter__()` | Context manager enter (calls setup) |
| `async __aexit__()` | Context manager exit (calls close) |

---

## run_parallel() — Concurrent Labeled Scans

Run multiple scans concurrently on one engine and yield labeled results as they arrive:

```python
from nucleisdk import ScanEngine

async with ScanEngine(
    template_dirs=["/path/to/nuclei-templates"],
    rate_limit=150,
) as engine:
    async for lr in engine.run_parallel(
        {"label": "cves", "targets": ["https://example.com"], "tags": ["cve"]},
        {"label": "misconfig", "targets": ["https://example.com"], "tags": ["misconfig"]},
        {"label": "exposure", "targets": ["https://example.com"], "tags": ["exposure"]},
    ):
        print(f"[{lr.label}] [{lr.result.severity}] {lr.result.template_id}")
```

Each dict must have a `label` key. All other keys are standard `scan()` parameters (`targets`, `tags`, `severities`, `template_files`, `template_bytes`, etc.).

Scans run as concurrent asyncio tasks — results stream as they come from any scan. Ideal for scanning one target with multiple scan profiles simultaneously.

```python
# Parallel scan with different template sets
async for lr in engine.run_parallel(
    {
        "label": "wordpress",
        "targets": ["https://wp.example.com"],
        "tags": ["wordpress", "wp-plugin"],
    },
    {
        "label": "custom-cves",
        "targets": ["https://wp.example.com"],
        "template_files": ["/path/to/custom-cve.yaml"],
    },
):
    if lr.result.is_high_or_above():
        await send_alert(lr.label, lr.result)
```

---

## ScanPool — Continuous Dynamic Scanning

`ScanPool` provides a worker pool for workflows where scan jobs arrive dynamically — from APIs, queues, webhooks, or feeds.

### Iterator Mode

Manually iterate over results:

```python
async with ScanEngine(
    template_dirs=["/path/to/nuclei-templates"],
    rate_limit=100,
) as engine:
    pool = await engine.scan_pool(workers=10)

    # Submit jobs
    await pool.submit("http-scan", targets=["https://example.com"], tags=["http", "cve"])
    await pool.submit("dns-scan", targets=["example.com"], tags=["dns"])
    await pool.submit("ssl-scan", targets=["example.com:443"], tags=["ssl"])

    # Consume results
    async for lr in pool.results():
        print(f"[{lr.label}] [{lr.result.severity}] {lr.result.template_id}")

    await pool.close()
```

### Callback Mode

Results dispatched to a callback automatically — no manual iteration:

```python
async def handle_result(lr):
    print(f"[{lr.label}] [{lr.result.severity}] {lr.result.template_id}")
    if lr.result.is_high_or_above():
        await send_alert(lr)

async with ScanEngine(rate_limit=100) as engine:
    pool = await engine.scan_pool(workers=10, on_result=handle_result)

    # Submit jobs — results go to handle_result automatically
    await pool.submit("scan-1", targets=["https://example.com"], tags=["cve"])
    await pool.submit("scan-2", targets=["https://target2.com"], tags=["cve"])

    await pool.close()
```

The `on_result` callback can be sync or async:

```python
# Sync callback
def handle_sync(lr):
    print(f"[{lr.label}] {lr.result.template_id}")

# Async callback
async def handle_async(lr):
    await save_to_db(lr)

pool = await engine.scan_pool(workers=10, on_result=handle_async)
```

### Pool Stats

```python
pool = await engine.scan_pool(workers=10)

await pool.submit("scan-1", targets=["https://example.com"], tags=["cve"])
await pool.submit("scan-2", targets=["https://target2.com"], tags=["cve"])

# Check stats while running or after close
stats = await pool.stats()
print(f"Submitted: {stats.submitted}")
print(f"Completed: {stats.completed}")
print(f"Failed: {stats.failed}")
print(f"Pending: {stats.pending}")

await pool.close()
```

### Runtime Engine with Pool

Each pool job provides its own templates — engine has no templates at setup:

```python
async with ScanEngine(rate_limit=100, silent=True) as engine:
    pool = await engine.scan_pool(workers=10)

    # Each job brings its own template
    for job in incoming_jobs:
        template_yaml = fetch_template(job.cve_id)
        await pool.submit(
            job.cve_id,
            targets=[job.target],
            template_bytes=[TemplateBytesEntry(name=job.cve_id, data=template_yaml)],
        )

    await pool.close()
    stats = await pool.stats()
    print(f"Verified {stats.completed} CVEs, {stats.failed} failed")
```

### ScanPool API

| Method | Description |
|--------|-------------|
| `async submit(label, **scan_params)` | Queue a labeled scan job |
| `async results(timeout=600)` | Async iterate over results |
| `async stats()` | Get pool statistics |
| `async close()` | Close pool, wait for completion |

**submit() Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `label` | `str` | Job identifier (e.g., CVE ID, scan name) |
| `targets` | `list[str] \| None` | URLs, domains, IPs |
| `target_file` | `str` | Path to targets file |
| `tags` | `list[str] \| None` | Filter by tags |
| `exclude_tags` | `list[str] \| None` | Exclude by tags |
| `severities` | `list[str] \| None` | Filter by severity |
| `protocol_types` | `str` | Filter by protocol |
| `template_ids` | `list[str] \| None` | Specific template IDs |
| `exclude_ids` | `list[str] \| None` | Exclude template IDs |
| `authors` | `list[str] \| None` | Filter by author |
| `template_files` | `list[str] \| None` | Direct template files |
| `template_dirs` | `list[str] \| None` | Direct template directories |
| `template_bytes` | `list[TemplateBytesEntry] \| None` | Raw YAML templates |
| `result_severity_filter` | `list[str] \| None` | Only return results matching these severities |
| `request_response_targets` | `list[TargetRequest] \| None` | Full HTTP request targets for DAST fuzzing |

---

## Preset Scanners

Pre-configured `EngineConfig` factories for common scanning profiles. Each accepts `**overrides` to customize any field.

```python
from nucleisdk import ScanEngine, web_scanner

# Use a preset as engine config
async with ScanEngine(**web_scanner().__dict__) as engine:
    async for r in engine.scan(targets=["https://example.com"]):
        print(f"[{r.severity}] {r.template_id}")

# Override specific settings
async with ScanEngine(**web_scanner(rate_limit=200, timeout=15).__dict__) as engine:
    ...
```

### web_scanner()

General-purpose HTTP vulnerability scanner.

```python
web_scanner(**overrides) -> EngineConfig
```

**Defaults:** protocol_types=`"http"`, exclude_tags=`["dos", "fuzz"]`, threads=50, host_concurrency=25, rate_limit=150, timeout=10, retries=1

### api_security_scanner()

API-focused security scanner.

```python
api_security_scanner(**overrides) -> EngineConfig
```

**Defaults:** protocol_types=`"http"`, tags=`["api", "swagger", "openapi", "graphql", "rest", "jwt", "auth-bypass", "exposure", "misconfig", "token", "cors", "ssrf", "idor", "bola", "injection", "sqli", "xss", "rce"]`, threads=25, host_concurrency=10, rate_limit=50, timeout=15, retries=1, matcher_status=True

### wordpress_scanner()

WordPress-specific vulnerability scanner.

```python
wordpress_scanner(**overrides) -> EngineConfig
```

**Defaults:** protocol_types=`"http"`, tags=`["wordpress", "wp-plugin", "wp-theme", "wp", "woocommerce", "xmlrpc", "wp-config", "wp-cron", "wp-admin", "wp-login"]`, threads=25, host_concurrency=5, rate_limit=30, timeout=10, retries=2

### network_scanner()

Network protocol scanner for DNS, SSL/TLS, and TCP services.

```python
network_scanner(**overrides) -> EngineConfig
```

**Defaults:** protocol_types=`"network,dns,ssl"`, tags=`["network", "dns", "ssl", "tls", "cve", "default-login", "exposure", "misconfig"]`, threads=25, host_concurrency=50, rate_limit=100, timeout=5, retries=2

---

## Authentication Helpers

Helper functions that return bridge-compatible auth dicts. Pass them to `ScanEngine(auth=[...])`.

```python
from nucleisdk import ScanEngine, bearer_token, basic_auth

engine = ScanEngine(
    auth=[
        bearer_token("eyJhbGciOi...", "api.example.com"),
        basic_auth("admin", "password", "admin.example.com"),
    ],
    rate_limit=100,
)
```

### basic_auth()

```python
basic_auth(username: str, password: str, *domains: str) -> dict
# Returns: {"type": "basic", "username": "...", "password": "...", "domains": [...]}
```

### bearer_token()

```python
bearer_token(token: str, *domains: str) -> dict
# Returns: {"type": "bearer", "token": "...", "domains": [...]}
```

### header_auth()

```python
header_auth(headers: dict[str, str], *domains: str) -> dict
# Returns: {"type": "header", "headers": {...}, "domains": [...]}
```

### cookie_auth()

```python
cookie_auth(cookies: dict[str, str], *domains: str) -> dict
# Returns: {"type": "cookie", "cookies": {...}, "domains": [...]}
```

### query_auth()

```python
query_auth(params: dict[str, str], *domains: str) -> dict
# Returns: {"type": "query", "query_params": {...}, "domains": [...]}
```

### api_key_header()

Convenience wrapper around `header_auth()` for single API key headers:

```python
api_key_header(header_name: str, api_key: str, *domains: str) -> dict
# Returns: {"type": "header", "headers": {"X-API-Key": "..."}, "domains": [...]}

# Example
engine = ScanEngine(auth=[api_key_header("X-API-Key", "key123", "api.example.com")])
```

---

## Target Utilities

Pure Python target expansion utilities. No bridge dependency.

```python
from nucleisdk import targets_from_file, targets_from_cidr, ip_range
```

### targets_from_file()

Read targets from a file, one per line. Skips empty lines and `#` comments.

```python
targets = targets_from_file("/path/to/targets.txt")
# ["https://example.com", "https://target2.com", ...]
```

### targets_from_cidr()

Expand a CIDR to individual IPs. Excludes network/broadcast for networks > /31.

```python
targets = targets_from_cidr("192.168.1.0/24")
# ["192.168.1.1", "192.168.1.2", ..., "192.168.1.254"]  (254 hosts)
```

### targets_from_cidrs()

Expand multiple CIDRs:

```python
targets = targets_from_cidrs(["10.0.0.0/30", "10.0.1.0/30"])
# ["10.0.0.1", "10.0.0.2", "10.0.1.1", "10.0.1.2"]
```

### ip_range()

Generate IPs in a range (inclusive):

```python
targets = ip_range("192.168.1.1", "192.168.1.10")
# ["192.168.1.1", "192.168.1.2", ..., "192.168.1.10"]
```

---

## Template Utilities

Template validation and parsing utilities. PyYAML is required for `validate_template()` and `parse_template_info()` — install with `pip install pyyaml`.

```python
from nucleisdk import TemplateInfo, fetch_template_from_url, validate_template, parse_template_info
```

### TemplateInfo

Dataclass with parsed template metadata:

```python
@dataclass
class TemplateInfo:
    id: str = ""
    name: str = ""
    author: str = ""
    severity: str = ""
    tags: list[str] = field(default_factory=list)
    description: str = ""
```

### fetch_template_from_url()

Download a template from a URL (stdlib urllib, no extra deps):

```python
fetch_template_from_url(url: str, timeout: int = 30) -> bytes
```

```python
yaml_bytes = fetch_template_from_url("https://raw.githubusercontent.com/.../template.yaml")

# With custom timeout
yaml_bytes = fetch_template_from_url("https://example.com/template.yaml", timeout=10)
```

### validate_template()

Validate a template YAML and return its ID. Raises `ValueError` if invalid:

```python
template_id = validate_template(yaml_bytes)
# Returns: "CVE-2024-1234" (template ID string)
# Raises: ValueError if missing id, info, or info.name
```

### parse_template_info()

Parse template metadata without full compilation:

```python
info = parse_template_info(yaml_bytes)
print(info.id)        # "CVE-2024-1234"
print(info.name)      # "Example Vulnerability"
print(info.severity)  # "critical"
print(info.tags)      # ["cve", "rce"]
print(info.author)    # "researcher"
```

---

## Template Loading and Filtering

### How It Works

Templates are loaded **once** at `setup()` time (heavy: bridge starts Go binary, parses YAML, compiles templates) and stored in the Go process memory. Per-scan `tags`, `severities`, `protocol_types`, etc. only **filter** from this pre-loaded set.

```
setup() --> Load & compile all templates --> allTemplates (Go memory)
                                                    |
scan(tags=["http"])  --> filter from allTemplates --> [http templates]
scan(tags=["dns"])   --> filter from allTemplates --> [dns templates]
scan(tags=["ssl"])   --> filter from allTemplates --> [ssl templates]
```

### Single Scan — Tags at Setup

When you know what templates you need upfront:

```python
async with ScanEngine(
    template_dirs=["/path/to/nuclei-templates"],
    tags=["cve", "exposure"],            # Only load CVE/exposure templates
    severities=["high", "critical"],     # Only high/critical
) as engine:
    async for r in engine.scan(targets=["https://example.com"]):
        print(r.template_id)
```

### Concurrent Scans — No Tags at Setup

For pools or multiple scans with different tags, **don't set tags at setup**:

```python
async with ScanEngine(
    template_dirs=["/path/to/nuclei-templates"],
    # No tags — loads ALL templates
    rate_limit=100,
) as engine:
    pool = await engine.scan_pool(workers=10)

    # All work because ALL templates were loaded
    await pool.submit("http", targets=["https://example.com"], tags=["http", "cve"])
    await pool.submit("dns", targets=["example.com"], tags=["dns", "takeover"])
    await pool.submit("ssl", targets=["example.com:443"], tags=["ssl"])

    async for lr in pool.results():
        print(f"[{lr.label}] {lr.result.template_id}")

    await pool.close()
```

> If you set `tags=["http"]` at setup, per-scan `tags=["dns"]` returns **zero results** because DNS templates were never loaded.

### Direct Templates — Always Work

`template_files`, `template_dirs`, and `template_bytes` bypass the global store. They always work regardless of setup configuration:

```python
# These work even if engine was set up with tags=["http"]
await pool.submit("custom", targets=["https://target.com"],
    template_files=["/path/to/custom.yaml"])

await pool.submit("raw", targets=["https://target.com"],
    template_bytes=[TemplateBytesEntry(name="check", data=yaml_bytes)])
```

### Quick Reference

| Setup Config | Per-Scan Filter | Result |
|---|---|---|
| No tags (all loaded) | `tags=["dns"]` | DNS templates found |
| No tags (all loaded) | `tags=["http", "ssl"]` | HTTP + SSL found |
| `tags=["http"]` | `tags=["http"]` | HTTP templates found |
| `tags=["http"]` | `tags=["dns"]` | **Zero results** |
| Any config | `template_files=[...]` | Always works |
| Any config | `template_bytes=[...]` | Always works |

---

## Models Reference

### ScanResult

A single scan finding. Created from bridge JSON responses.

```python
@dataclass
class ScanResult:
    # Identification
    template_id: str = ""
    template_name: str = ""
    template_path: str = ""
    severity: str = ""           # "info", "low", "medium", "high", "critical"
    type: str = ""               # Protocol type

    # Match details
    host: str = ""
    matched_url: str = ""
    matcher_name: str = ""
    extractor_name: str = ""
    extracted_results: list[str] = field(default_factory=list)
    ip: str = ""
    port: str = ""
    scheme: str = ""
    url: str = ""
    path: str = ""

    # Request/Response
    request: str = ""
    response: str = ""
    curl_command: str = ""

    # Metadata
    tags: list[str] = field(default_factory=list)
    authors: list[str] = field(default_factory=list)
    description: str = ""
    impact: str = ""
    remediation: str = ""
    reference: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    # Classification
    cve_id: list[str] = field(default_factory=list)
    cwe_id: list[str] = field(default_factory=list)
    cvss_metrics: str = ""
    cvss_score: float = 0.0
    epss_score: float = 0.0
    cpe: str = ""

    # Fuzzing
    is_fuzzing_result: bool = False
    fuzzing_method: str = ""
    fuzzing_parameter: str = ""
    fuzzing_position: str = ""

    # Status
    matcher_status: bool = False
    timestamp: str = ""
    error: str = ""
```

**Methods:**

| Method | Return | Description |
|--------|--------|-------------|
| `from_dict(data)` | `ScanResult` | Class method — create from dict |
| `is_critical()` | `bool` | True if severity is "critical" |
| `is_high_or_above()` | `bool` | True if severity is "high" or "critical" |
| `severity_level()` | `int` | 0=unknown, 1=info, 2=low, 3=medium, 4=high, 5=critical |

### LabeledResult

A scan result tagged with a job label (from ScanPool):

```python
@dataclass
class LabeledResult:
    label: str                   # Job label from pool.submit()
    result: ScanResult           # The scan result
```

**Methods:**

| Method | Return | Description |
|--------|--------|-------------|
| `from_dict(label, data)` | `LabeledResult` | Class method — create from label + dict |

### PoolStats

Scan pool statistics:

```python
@dataclass
class PoolStats:
    submitted: int = 0
    completed: int = 0
    failed: int = 0
    pending: int = 0
```

### TemplateBytesEntry

A named raw YAML template:

```python
@dataclass
class TemplateBytesEntry:
    name: str                    # Template name/identifier
    data: bytes                  # Raw YAML template content
```

**Methods:**

| Method | Return | Description |
|--------|--------|-------------|
| `to_dict()` | `dict` | Convert to dict with base64-encoded data |

**Usage:**

```python
from nucleisdk import TemplateBytesEntry

yaml_content = b"""
id: custom-check
info:
  name: Custom Check
  severity: high
  author: myteam
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
"""

entry = TemplateBytesEntry(name="custom-check", data=yaml_content)
```

### EngineConfig

Configuration model for the scan engine. Populated from `ScanEngine(**config)` kwargs. Common fields shown below — see [Configuration Reference](#engine-configuration-parameters) for all 50+ parameters.

```python
@dataclass
class EngineConfig:
    # Template loading
    template_dirs: list[str] = field(default_factory=list)
    template_files: list[str] = field(default_factory=list)
    workflows: list[str] = field(default_factory=list)
    template_bytes: list[TemplateBytesEntry] = field(default_factory=list)
    template_urls: list[str] = field(default_factory=list)
    # Filtering
    tags: list[str] = field(default_factory=list)
    exclude_tags: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    exclude_severities: list[str] = field(default_factory=list)
    protocol_types: str = ""
    template_ids: list[str] = field(default_factory=list)
    exclude_ids: list[str] = field(default_factory=list)
    authors: list[str] = field(default_factory=list)
    # Network & concurrency
    timeout: int = 0
    retries: int = 0
    proxy: list[str] = field(default_factory=list)
    threads: int = 0
    host_concurrency: int = 0
    rate_limit: int = 0
    rate_limit_duration: str = ""
    payload_concurrency: int = 0
    # Features
    headless: bool = False
    dast_mode: bool = False
    no_interactsh: bool = False
    scan_strategy: str = ""
    stop_at_first_match: bool = False
    # Output
    verbose: bool = False
    debug: bool = False
    silent: bool = False
    # Auth & headers
    auth: list[dict] = field(default_factory=list)
    secrets_files: list[str] = field(default_factory=list)
    custom_headers: list[str] = field(default_factory=list)
    custom_vars: list[str] = field(default_factory=list)
    # ... plus 20+ more fields (sandbox, network, template modes, etc.)
```

### ScanOptions

Per-scan options (used internally by engine/pool):

```python
@dataclass
class ScanOptions:
    targets: list[str] = field(default_factory=list)
    target_file: str = ""
    tags: list[str] = field(default_factory=list)
    exclude_tags: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    protocol_types: str = ""
    template_ids: list[str] = field(default_factory=list)
    exclude_ids: list[str] = field(default_factory=list)
    authors: list[str] = field(default_factory=list)
    template_files: list[str] = field(default_factory=list)
    template_dirs: list[str] = field(default_factory=list)
    template_bytes: list[TemplateBytesEntry] = field(default_factory=list)
    result_severity_filter: list[str] = field(default_factory=list)
    request_response_targets: list[TargetRequest] = field(default_factory=list)
```

### TargetRequest

Full HTTP request metadata for DAST fuzzing targets. Without this, nuclei defaults to GET with no body for URL-only targets.

```python
@dataclass
class TargetRequest:
    url: str                          # Full URL
    method: str = "GET"               # HTTP method (POST, PUT, PATCH, etc.)
    headers: dict[str, str] = field(default_factory=dict)  # Request headers
    body: str = ""                    # Request body
```

**Usage:**
```python
from nucleisdk import TargetRequest

target = TargetRequest(
    url="https://api.example.com/api/users",
    method="POST",
    headers={"Content-Type": "application/json"},
    body='{"name":"test"}',
)

async for r in engine.scan(
    request_response_targets=[target],
    template_bytes=entries,
):
    print(r)
```

---

## Auto-Installer and Version Management

The Python SDK automatically downloads and manages the Go bridge binary.

### How Auto-Install Works

On first use (when `ScanEngine` starts), the SDK:
1. Looks for `nuclei-sdk-bridge` in standard locations (`~/.local/bin/`, PATH)
2. If found, checks version compatibility via `--version` flag
3. If not found or incompatible, downloads from GitHub Releases
4. Verifies SHA256 checksum
5. Installs to `~/.local/bin/nuclei-sdk-bridge`

### install_bridge()

Explicitly download and install the bridge binary:

```python
from nucleisdk import install_bridge

# Basic install
path = install_bridge()
print(f"Installed to: {path}")

# Custom install directory
path = install_bridge(install_dir="/opt/tools/")

# Silent install (no progress messages)
path = install_bridge(quiet=True)

# Force download latest (even if compatible version exists)
path = install_bridge(update=True)
```

**Signature:**

```python
def install_bridge(
    install_dir: str | None = None,    # Custom install dir (default: ~/.local/bin/)
    quiet: bool = False,                # Suppress progress messages
    repo: str = "RevoltSecurities/nuclei-sdk",  # GitHub repo
    update: bool = False,               # Force download latest
) -> str                                # Returns path to installed binary
```

### ensure_bridge()

Find, validate, or auto-install the bridge binary. This is what `ScanEngine` calls internally:

```python
from nucleisdk import ensure_bridge

# Auto-discover or install
path = ensure_bridge()

# Explicit path (still checks version)
path = ensure_bridge(binary_path="/usr/local/bin/nuclei-sdk-bridge")

# Disable auto-install — raise error if not found
path = ensure_bridge(auto_install=False)

# Force update
path = ensure_bridge(update=True)
```

**Signature:**

```python
def ensure_bridge(
    binary_path: str | None = None,    # Explicit binary path
    quiet: bool = False,                # Suppress messages
    auto_install: bool = True,          # Auto-download if missing
    update: bool = False,               # Force download latest
    repo: str = "RevoltSecurities/nuclei-sdk",  # GitHub repo
) -> str                                # Returns path to working binary
```

### get_bridge_version()

Query the version of an installed bridge binary:

```python
from nucleisdk import get_bridge_version

version = get_bridge_version("/path/to/nuclei-sdk-bridge")
print(version)  # "1.0.0" or None if binary doesn't support --version
```

**Signature:**

```python
def get_bridge_version(binary_path: str) -> str | None
```

### check_version_compatible()

Check if a bridge version is compatible with this SDK:

```python
from nucleisdk import check_version_compatible, MIN_BRIDGE_VERSION

print(check_version_compatible("1.0.0"))  # True
print(check_version_compatible("0.0.1"))  # False (below MIN_BRIDGE_VERSION)
print(check_version_compatible("dev"))    # True (development builds always pass)
print(check_version_compatible(None))     # False
```

**Signature:**

```python
def check_version_compatible(version: str) -> bool
```

### Version Constants

```python
from nucleisdk import MIN_BRIDGE_VERSION, MAX_BRIDGE_VERSION

print(MIN_BRIDGE_VERSION)  # "1.0.0"
print(MAX_BRIDGE_VERSION)  # None (no upper bound)
```

### Force Update

```python
from nucleisdk import install_bridge, ensure_bridge

# Force install latest, bypassing version check
install_bridge(update=True)

# Or via ensure_bridge
ensure_bridge(update=True)
```

### Custom Repository (Forks)

```python
from nucleisdk import install_bridge

# Install from a fork
path = install_bridge(repo="myorg/nuclei-sdk-fork")
```

### Explicit Binary Path

Skip auto-discovery and use a specific binary:

```python
engine = ScanEngine(binary_path="/opt/tools/nuclei-sdk-bridge", rate_limit=100)
```

### SSRF Protection

The installer only downloads from GitHub (`github.com` and `objects.githubusercontent.com`). Repository names are validated to contain only alphanumeric characters, hyphens, underscores, and dots. This prevents SSRF attacks through crafted repository names.

---

## Exception Handling

### Exception Hierarchy

```
BridgeError                         # Base — bridge process errors
└── InstallError                    # Base — installation failures
    ├── UnsupportedPlatformError    # OS/arch not supported
    ├── DownloadError               # Network/GitHub failure
    ├── ChecksumError               # SHA256 mismatch (corrupted download)
    ├── InstallPermissionError      # Cannot write to install directory
    └── VersionMismatchError        # Bridge version incompatible with SDK
```

### Handling Each Exception

```python
from nucleisdk import (
    ScanEngine,
    BridgeError,
    InstallError,
    UnsupportedPlatformError,
    DownloadError,
    ChecksumError,
    InstallPermissionError,
    VersionMismatchError,
)

try:
    async with ScanEngine() as engine:
        async for r in engine.scan(targets=["https://example.com"]):
            print(r.template_id)

except UnsupportedPlatformError:
    print("This OS/architecture doesn't have pre-built binaries")
    print("Build from source: go build ./cmd/nuclei-sdk-bridge/")

except DownloadError as e:
    print(f"Failed to download bridge binary: {e}")
    print("Check network connection and GitHub availability")

except ChecksumError:
    print("Downloaded binary failed checksum verification")
    print("Retry the download or install manually")

except InstallPermissionError:
    print("Cannot write to ~/.local/bin/")
    print("Run with appropriate permissions or specify custom install_dir")

except VersionMismatchError as e:
    print(f"Bridge version incompatible: {e}")
    print("Run: nucleisdk.install_bridge(update=True)")

except InstallError as e:
    print(f"Installation failed: {e}")

except BridgeError as e:
    print(f"Bridge process error: {e}")
```

### Version Mismatch Recovery

```python
from nucleisdk import ScanEngine, VersionMismatchError, install_bridge

try:
    async with ScanEngine() as engine:
        async for r in engine.scan(targets=["https://example.com"]):
            print(r.template_id)
except VersionMismatchError:
    # Auto-recover by updating
    install_bridge(update=True)
    # Retry with updated binary
    async with ScanEngine() as engine:
        async for r in engine.scan(targets=["https://example.com"]):
            print(r.template_id)
```

---

## Bridge Protocol

### How the Bridge Works

The Python SDK spawns the `nuclei-sdk-bridge` Go binary as a subprocess and communicates via JSON lines over stdin/stdout:

1. **Python sends** JSON commands (one per line) to the bridge's stdin
2. **Bridge processes** commands using the Go nuclei-sdk
3. **Bridge sends** JSON responses (one per line) to stdout
4. **Python reads** responses and routes them to the appropriate handler

Commands: `setup`, `scan`, `pool_submit`, `pool_close`, `close`, `version`

### BridgeProcess Internals

The `BridgeProcess` class (internal) manages the subprocess:

- **start()** — spawns subprocess with stdin/stdout/stderr pipes, starts background reader
- **stop()** — cancels reader, closes stdin, waits for process (10s timeout), kills if needed
- **send_command(cmd)** — writes JSON line to stdin
- **wait_response(req_id)** — waits for single response with matching ID
- **iter_responses(req_id)** — async iterator for streaming responses (scan results)
- **set_pool_listener(callback)** — registers callback for pool result routing

The background reader task (`_read_loop`) continuously reads JSON lines from stdout and routes them:
- Single-response commands → futures (waiters)
- Streaming responses → async queues (streams)
- Pool results → pool listener callback

---

## Different Types of Scans

### HTTP CVE Scanning

```python
async with ScanEngine(
    template_dirs=["/path/to/nuclei-templates"],
    rate_limit=100,
) as engine:
    async for r in engine.scan(
        targets=["https://example.com"],
        tags=["cve"],
        protocol_types="http",
        severities=["high", "critical"],
    ):
        print(f"[{r.severity}] {r.template_id}: {r.matched_url}")
        if r.cve_id:
            print(f"  CVE: {', '.join(r.cve_id)}")
        if r.cvss_score:
            print(f"  CVSS: {r.cvss_score}")
```

### DNS Scanning

```python
async for r in engine.scan(
    targets=["example.com"],
    tags=["dns", "takeover"],
    protocol_types="dns",
):
    print(f"[DNS] {r.template_id}: {r.host}")
```

### SSL/TLS Scanning

```python
async for r in engine.scan(
    targets=["example.com:443"],
    tags=["ssl", "tls", "certificate"],
    protocol_types="ssl",
):
    print(f"[SSL] {r.template_id}: {r.host}")
```

### Network Scanning

```python
async for r in engine.scan(
    targets=["192.168.1.1"],
    tags=["network", "default-login"],
    protocol_types="network",
):
    print(f"[Network] {r.template_id}: {r.host}:{r.port}")
```

### Technology Detection

```python
async for r in engine.scan(
    targets=["https://example.com"],
    tags=["tech", "detect"],
):
    print(f"Detected: {r.template_name} on {r.host}")
    if r.extracted_results:
        print(f"  Version: {r.extracted_results}")
```

### Misconfiguration Scanning

```python
async for r in engine.scan(
    targets=["https://example.com"],
    tags=["misconfig", "exposure"],
):
    print(f"[Misconfig] {r.template_id}: {r.matched_url}")
    print(f"  Remediation: {r.remediation}")
```

### WordPress Scanning

```python
async for r in engine.scan(
    targets=["https://wordpress.example.com"],
    tags=["wordpress", "wp-plugin", "wp-theme"],
    protocol_types="http",
):
    print(f"[WordPress] {r.template_id}: {r.matched_url}")
```

### API Security Scanning

```python
async for r in engine.scan(
    targets=["https://api.example.com"],
    tags=["api", "swagger", "jwt", "idor", "bola"],
    protocol_types="http",
):
    print(f"[API] {r.template_id}: {r.matched_url}")
```

### Multi-Protocol Scanning

```python
# Load all templates at setup (no tags) for multi-protocol flexibility
async with ScanEngine(
    template_dirs=["/path/to/nuclei-templates"],
) as engine:
    # HTTP + DNS + SSL in one scan (no protocol filter)
    async for r in engine.scan(
        targets=["https://example.com", "example.com", "example.com:443"],
        tags=["cve", "exposure", "takeover"],
    ):
        print(f"[{r.type}] {r.template_id}: {r.host}")
```

### Custom Template Scanning

```python
custom_template = b"""
id: custom-admin-panel
info:
  name: Admin Panel Detection
  severity: info
  author: myteam
  tags: custom,detect

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/wp-admin"
      - "{{BaseURL}}/administrator"
    matchers:
      - type: status
        status:
          - 200
          - 302
"""

async for r in engine.scan(
    targets=["https://example.com"],
    template_bytes=[TemplateBytesEntry(name="admin-detect", data=custom_template)],
):
    print(f"Admin panel found: {r.matched_url}")
```

### Severity-Based Scanning

```python
# Only critical findings
async for r in engine.scan(
    targets=["https://example.com"],
    severities=["critical"],
):
    print(f"CRITICAL: {r.template_id}")

# Exclude informational noise
async for r in engine.scan(
    targets=["https://example.com"],
    exclude_tags=["info"],
    severities=["low", "medium", "high", "critical"],
):
    print(f"[{r.severity}] {r.template_id}")
```

> **`severities` vs `result_severity_filter`:** `severities` filters which *templates* execute (skips info-severity templates entirely). `result_severity_filter` lets all templates execute but only *returns* results matching the specified severities — useful when you want templates to run for side effects but only report high-impact findings:

```python
async for r in engine.scan(
    targets=["https://example.com"],
    result_severity_filter=["high", "critical"],
):
    print(f"[{r.severity}] {r.template_id}")
```

### OpenAPI/Swagger Scanning

Generate targets from an OpenAPI or Swagger specification:

```python
async with ScanEngine(
    openapi_spec="/path/to/openapi.yaml",
    dast_mode=True,
    rate_limit=50,
) as engine:
    async for r in engine.scan(
        targets=["https://api.example.com"],
        tags=["api", "injection", "sqli", "xss"],
    ):
        print(f"[API] {r.template_id}: {r.matched_url}")
```

### Target File — Scanning from a File

Pass a file path instead of a list of URLs. The file should have one target per line (empty lines and `#` comments are skipped):

```python
# targets.txt:
# https://example.com
# https://target2.com
# 192.168.1.1

async with ScanEngine(rate_limit=100) as engine:
    # Single scan from file
    async for r in engine.scan(
        target_file="/path/to/targets.txt",
        tags=["cve"],
    ):
        print(f"[{r.severity}] {r.template_id}")

    # Pool with file targets
    pool = await engine.scan_pool(workers=10)
    await pool.submit("from-file", target_file="/path/to/targets.txt", tags=["cve"])
    async for lr in pool.results():
        print(f"[{lr.label}] {lr.result.template_id}")
    await pool.close()

    # Parallel scans — one from file, one from list
    async for lr in engine.run_parallel(
        {"label": "file-scan", "target_file": "/path/to/targets.txt", "tags": ["cve"]},
        {"label": "list-scan", "targets": ["https://extra.com"], "tags": ["exposure"]},
    ):
        print(f"[{lr.label}] {lr.result.template_id}")
```

You can also combine `targets` and `target_file` — both are merged:

```python
async for r in engine.scan(
    targets=["https://extra-target.com"],
    target_file="/path/to/targets.txt",
    tags=["cve"],
):
    print(r.template_id)
```

### HTTP Probing — Scanning Raw Hosts/IPs

When targets are raw hosts or IPs (without `http://` or `https://`), enable HTTP probing so nuclei discovers HTTP/HTTPS services via httpx:

```python
from nucleisdk import ScanEngine, targets_from_cidr

# Scan a /24 subnet — nuclei probes each IP for HTTP/HTTPS
targets = targets_from_cidr("192.168.1.0/24")

async with ScanEngine(
    template_dirs=["/path/to/nuclei-templates"],
    http_probe=True,
    probe_concurrency=100,
    rate_limit=50,
) as engine:
    async for r in engine.scan(
        targets=targets,
        tags=["cve", "exposure"],
        severities=["high", "critical"],
    ):
        print(f"[{r.severity}] {r.host}: {r.template_id}")
```

Scan all DNS-resolved IPs and dual-stack (IPv4 + IPv6):

```python
async with ScanEngine(
    http_probe=True,
    scan_all_ips=True,
    ip_version=["4", "6"],
    rate_limit=100,
) as engine:
    async for r in engine.scan(
        targets=["example.com"],
        tags=["cve"],
    ):
        print(f"[{r.ip}] {r.template_id}")
```

Exclude specific hosts from a scan:

```python
async with ScanEngine(
    exclude_targets=["internal.example.com", "192.168.1.1"],
    rate_limit=100,
) as engine:
    async for r in engine.scan(
        targets=["192.168.1.0/24"],
        tags=["cve"],
    ):
        print(r.template_id)
```

### Custom Headers and Variables

Add custom headers to all requests or define template variables:

```python
async with ScanEngine(
    custom_headers=["X-Custom-Auth: Bearer token123", "X-Tenant-ID: acme"],
    custom_vars=["base_path=/api/v2", "admin_email=admin@example.com"],
    rate_limit=100,
) as engine:
    async for r in engine.scan(targets=["https://example.com"], tags=["cve"]):
        print(r.template_id)
```

### Scanning with Presets and Target Utilities

Combine preset scanners with target expansion:

```python
from nucleisdk import ScanEngine, web_scanner, targets_from_cidr, bearer_token

targets = targets_from_cidr("10.0.0.0/24")

async with ScanEngine(
    **web_scanner(rate_limit=200).__dict__,
    auth=[bearer_token("eyJhbGciOi...", "10.0.0.0/24")],
) as engine:
    async for r in engine.scan(targets=targets, severities=["high", "critical"]):
        print(f"[{r.severity}] {r.host}: {r.template_id}")
```

---

## Building Custom Workflows

### CI/CD Pipeline Scanner

```python
import asyncio
import sys
from nucleisdk import ScanEngine

async def ci_scan(deploy_url: str) -> int:
    """Scan a deployment URL. Returns 1 if critical findings, 0 otherwise."""
    async with ScanEngine(
        template_dirs=["/path/to/nuclei-templates"],
        rate_limit=100,
        no_interactsh=True,
        silent=True,
    ) as engine:
        criticals = []
        async for r in engine.scan(
            targets=[deploy_url],
            tags=["cve", "exposure", "misconfig"],
            severities=["critical", "high"],
        ):
            print(f"[{r.severity}] {r.template_id} - {r.matched_url}")
            if r.is_critical():
                criticals.append(r)

        if criticals:
            print(f"\nBLOCKING: {len(criticals)} critical vulnerabilities found")
            return 1
        print("\nNo critical vulnerabilities found")
        return 0

if __name__ == "__main__":
    exit_code = asyncio.run(ci_scan(sys.argv[1]))
    sys.exit(exit_code)
```

### Continuous Vulnerability Monitoring

```python
import asyncio
from nucleisdk import ScanEngine, TemplateBytesEntry

async def monitor(asset_queue: asyncio.Queue):
    """Continuously scan assets from a queue."""
    async with ScanEngine(
        template_dirs=["/path/to/nuclei-templates"],
        rate_limit=50,
        no_interactsh=True,
        silent=True,
    ) as engine:
        pool = await engine.scan_pool(workers=20, on_result=handle_finding)

        while True:
            asset = await asset_queue.get()
            if asset is None:
                break
            await pool.submit(
                asset["id"],
                targets=[asset["url"]],
                tags=["cve", "exposure"],
            )

        await pool.close()

async def handle_finding(lr):
    """Process each finding — save to DB, alert if critical."""
    print(f"[{lr.label}] [{lr.result.severity}] {lr.result.template_id}")
    await save_to_database(lr)
    if lr.result.is_high_or_above():
        await send_slack_alert(lr)
```

### Security Dashboard Backend

```python
from fastapi import FastAPI, BackgroundTasks
from nucleisdk import ScanEngine

app = FastAPI()
engine = None

@app.on_event("startup")
async def startup():
    global engine
    engine = ScanEngine(
        template_dirs=["/path/to/nuclei-templates"],
        rate_limit=100,
        no_interactsh=True,
        silent=True,
    )
    await engine.setup()

@app.on_event("shutdown")
async def shutdown():
    await engine.close()

@app.post("/api/scan")
async def trigger_scan(targets: list[str], tags: list[str] = None):
    results = await engine.scan_collect(targets=targets, tags=tags or ["cve"])
    return {
        "total": len(results),
        "critical": sum(1 for r in results if r.is_critical()),
        "high": sum(1 for r in results if r.severity == "high"),
        "findings": [
            {
                "template_id": r.template_id,
                "severity": r.severity,
                "url": r.matched_url,
                "description": r.description,
            }
            for r in results
        ],
    }
```

### Webhook-Driven Scanning

```python
from aiohttp import web
from nucleisdk import ScanEngine

engine = None
pool = None

async def start_engine(app):
    global engine, pool
    engine = ScanEngine(rate_limit=100, silent=True)
    await engine.setup()
    pool = await engine.scan_pool(workers=10, on_result=store_result)

async def stop_engine(app):
    await pool.close()
    await engine.close()

async def webhook_handler(request):
    data = await request.json()
    await pool.submit(
        data["id"],
        targets=data["targets"],
        tags=data.get("tags", ["cve"]),
    )
    return web.json_response({"status": "queued", "id": data["id"]})

async def store_result(lr):
    # Save to database, send notification, etc.
    print(f"[{lr.label}] {lr.result.template_id}")

app = web.Application()
app.on_startup.append(start_engine)
app.on_cleanup.append(stop_engine)
app.router.add_post("/webhook/scan", webhook_handler)
web.run_app(app, port=8080)
```

### CVE Verification Service

```python
from nucleisdk import ScanEngine, TemplateBytesEntry

async def verify_cve(cve_id: str, template_yaml: bytes, targets: list[str]) -> dict:
    """Verify a specific CVE against targets."""
    async with ScanEngine(rate_limit=50, no_interactsh=True, silent=True) as engine:
        results = await engine.scan_collect(
            targets=targets,
            template_bytes=[TemplateBytesEntry(name=cve_id, data=template_yaml)],
        )

        return {
            "cve_id": cve_id,
            "verified": len(results) > 0,
            "affected_hosts": [r.host for r in results],
            "details": [
                {
                    "host": r.host,
                    "url": r.matched_url,
                    "severity": r.severity,
                    "cvss_score": r.cvss_score,
                }
                for r in results
            ],
        }
```

### Multi-Tenant Scanner

```python
from nucleisdk import ScanEngine

SCAN_PROFILES = {
    "basic": {"tags": ["cve"], "severities": ["critical", "high"]},
    "pro": {"tags": ["cve", "exposure", "misconfig"]},
    "enterprise": {},  # Full scan — no filters
}

async def scan_tenant(engine, tenant):
    profile = SCAN_PROFILES.get(tenant["plan"], SCAN_PROFILES["basic"])

    results = await engine.scan_collect(
        targets=tenant["assets"],
        **profile,
    )

    return {
        "tenant": tenant["id"],
        "findings": len(results),
        "critical": sum(1 for r in results if r.is_critical()),
    }
```

### Scheduled Scanning

```python
import asyncio
from nucleisdk import ScanEngine

async def scheduled_scan(targets: list[str], interval_hours: int = 24):
    """Run scans on a schedule."""
    async with ScanEngine(
        template_dirs=["/path/to/nuclei-templates"],
        rate_limit=50,
        no_interactsh=True,
        silent=True,
    ) as engine:
        while True:
            print(f"Starting scheduled scan of {len(targets)} targets...")
            async for r in engine.scan(
                targets=targets,
                tags=["cve", "exposure"],
                severities=["high", "critical"],
            ):
                await alert_new_finding(r)

            print(f"Scan complete. Next scan in {interval_hours} hours.")
            await asyncio.sleep(interval_hours * 3600)
```

### Scan Results to Database

```python
import json
from nucleisdk import ScanEngine

async def scan_to_db(engine, targets, db_connection):
    """Scan targets and store results in a database."""
    async for r in engine.scan(targets=targets, tags=["cve"]):
        await db_connection.execute(
            """
            INSERT INTO scan_results
            (template_id, severity, host, matched_url, description,
             cve_ids, cvss_score, timestamp, raw_json)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)
            """,
            r.template_id,
            r.severity,
            r.host,
            r.matched_url,
            r.description,
            r.cve_id,
            r.cvss_score,
            json.dumps(r.__dict__),
        )
```

### Slack/Discord Alert Integration

```python
import aiohttp
from nucleisdk import ScanEngine

SLACK_WEBHOOK = "https://hooks.slack.com/services/T.../B.../..."

async def alert_slack(result):
    """Send high/critical findings to Slack."""
    if not result.is_high_or_above():
        return

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*[{result.severity.upper()}] {result.template_id}*\n"
                        f"Host: `{result.host}`\n"
                        f"URL: {result.matched_url}\n"
                        f"Description: {result.description}"
                    ),
                },
            }
        ]
    }

    async with aiohttp.ClientSession() as session:
        await session.post(SLACK_WEBHOOK, json=payload)
```

---

## Configuration Reference

### Engine Configuration Parameters

Passed as kwargs to `ScanEngine()`:

**Template Loading:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `template_dirs` | `list[str]` | `[]` | Template directories to load at setup |
| `template_files` | `list[str]` | `[]` | Template files to load at setup |
| `workflows` | `list[str]` | `[]` | Workflow files |
| `template_bytes` | `list[TemplateBytesEntry]` | `[]` | Raw YAML templates (base64-encoded in bridge) |
| `template_urls` | `list[str]` | `[]` | URLs to fetch templates from |
| `trusted_domains` | `list[str]` | `[]` | Trusted domains for template URLs |

**Template Filtering:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tags` | `list[str]` | `[]` | Tag filter for setup-time loading |
| `exclude_tags` | `list[str]` | `[]` | Exclude tags at setup |
| `severities` | `list[str]` | `[]` | Severity filter at setup |
| `exclude_severities` | `list[str]` | `[]` | Exclude severities at setup |
| `protocol_types` | `str` | `""` | Protocol filter at setup |
| `template_ids` | `list[str]` | `[]` | Template ID filter |
| `exclude_ids` | `list[str]` | `[]` | Exclude template IDs |
| `authors` | `list[str]` | `[]` | Author filter |

**Template Execution Modes:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `self_contained_templates` | `bool` | `False` | Enable self-contained template mode |
| `global_matchers_templates` | `bool` | `False` | Enable global matchers across templates |
| `disable_template_cache` | `bool` | `False` | Disable template compilation cache |
| `file_templates` | `bool` | `False` | Enable file protocol templates |
| `passive_mode` | `bool` | `False` | Run in passive analysis mode |
| `signed_templates_only` | `bool` | `False` | Only run signed/verified templates |
| `code_templates` | `bool` | `False` | Enable code protocol templates |

**Network:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | `int` | `0` | Request timeout (seconds) |
| `retries` | `int` | `0` | Retry count |
| `proxy` | `list[str]` | `[]` | Proxy URLs (HTTP/SOCKS5) |
| `proxy_internal` | `bool` | `False` | Proxy internal requests too |
| `leave_default_ports` | `bool` | `False` | Don't strip default ports from URLs |
| `network_interface` | `str` | `""` | Network interface to use |
| `source_ip` | `str` | `""` | Source IP for outgoing requests |
| `system_resolvers` | `bool` | `False` | Use system DNS resolvers |
| `resolvers` | `list[str]` | `[]` | Custom DNS resolvers |
| `disable_max_host_err` | `bool` | `False` | Disable max host error tracking |

**Concurrency:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `threads` | `int` | `0` | Concurrent templates |
| `host_concurrency` | `int` | `0` | Concurrent hosts per template |
| `rate_limit` | `int` | `0` | Max requests per second |
| `rate_limit_duration` | `str` | `""` | Custom rate limit window (e.g., `"1m"`) |
| `payload_concurrency` | `int` | `0` | Concurrent payload combinations |

**Features:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `headless` | `bool` | `False` | Enable headless browser |
| `dast_mode` | `bool` | `False` | Enable DAST/fuzzing |
| `no_interactsh` | `bool` | `False` | Disable OOB testing |
| `scan_strategy` | `str` | `""` | Scan strategy (e.g., `"host-spray"`) |
| `matcher_status` | `bool` | `False` | Display matcher status |
| `update_check` | `bool` | `False` | Check for nuclei updates |
| `stop_at_first_match` | `bool` | `False` | Stop scanning target after first match |

**Output:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `verbose` | `bool` | `False` | Verbose output |
| `debug` | `bool` | `False` | Debug mode |
| `silent` | `bool` | `False` | Suppress output |
| `response_read_size` | `int` | `0` | Max response body size to read (bytes) |

**Authentication:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `auth` | `list[dict]` | `[]` | Authentication configs (use auth helpers) |
| `secrets_files` | `list[str]` | `[]` | Path to secrets/credentials files |

**Headers & Variables:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `custom_headers` | `list[str]` | `[]` | Custom request headers (`"Key: Value"`) |
| `custom_vars` | `list[str]` | `[]` | Custom template variables (`"key=value"`) |

**Sandbox:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sandbox_allow_local_file` | `bool` | `False` | Allow local file access in sandbox |
| `sandbox_restrict_network` | `bool` | `False` | Restrict network access in sandbox |

**Result Filtering:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `result_severity_filter` | `list[str]` | `[]` | Only output results matching these severities |

**Target Options:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `openapi_spec` | `str` | `""` | OpenAPI spec path/URL for target generation |
| `swagger_spec` | `str` | `""` | Swagger spec path/URL for target generation |
| `exclude_targets` | `list[str]` | `[]` | Hosts to exclude from scanning |

**HTTP Probing:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `http_probe` | `bool` | `False` | Enable HTTP probing for non-URL targets (raw hosts/IPs) |
| `probe_concurrency` | `int` | `0` | Concurrent HTTP probes (default 50 in nuclei) |
| `scan_all_ips` | `bool` | `False` | Scan all DNS-resolved IPs, not just the first |
| `ip_version` | `list[str]` | `[]` | IP versions to scan: `["4"]`, `["6"]`, or `["4", "6"]` |

### Per-Scan Parameters

Passed to `engine.scan()` or `pool.submit()`:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `targets` | `list[str]` | `None` | URLs, domains, IPs |
| `target_file` | `str` | `""` | File with targets (one per line) |
| `tags` | `list[str]` | `None` | Filter from loaded templates |
| `exclude_tags` | `list[str]` | `None` | Exclude by tags |
| `severities` | `list[str]` | `None` | Filter by severity |
| `protocol_types` | `str` | `""` | Filter by protocol |
| `template_ids` | `list[str]` | `None` | Specific template IDs |
| `exclude_ids` | `list[str]` | `None` | Exclude template IDs |
| `authors` | `list[str]` | `None` | Filter by author |
| `template_files` | `list[str]` | `None` | Direct template files (bypass global store) |
| `template_dirs` | `list[str]` | `None` | Direct template dirs (bypass global store) |
| `template_bytes` | `list[TemplateBytesEntry]` | `None` | Raw YAML templates (bypass global store) |
| `result_severity_filter` | `list[str]` | `None` | Only return results matching these severities |

### Authentication

Pass auth configs in the engine constructor:

```python
# Basic Auth
engine = ScanEngine(auth=[{
    "type": "basic",
    "domains": ["example.com"],
    "username": "admin",
    "password": "password123",
}])

# Bearer Token
engine = ScanEngine(auth=[{
    "type": "bearer",
    "domains": ["api.example.com"],
    "token": "eyJhbGciOi...",
}])

# Custom Headers
engine = ScanEngine(auth=[{
    "type": "header",
    "domains": ["example.com"],
    "headers": {"X-API-Key": "key123", "X-Tenant": "tenant1"},
}])

# Cookie Auth
engine = ScanEngine(auth=[{
    "type": "cookie",
    "domains": ["example.com"],
    "cookies": {"session_id": "abc123"},
}])

# Multiple auth configs
engine = ScanEngine(auth=[
    {"type": "bearer", "domains": ["api.example.com"], "token": "token1"},
    {"type": "basic", "domains": ["admin.example.com"], "username": "admin", "password": "pass"},
])
```

---

## Performance Tips

1. **Use async context manager** — `async with ScanEngine() as engine:` ensures proper cleanup even on exceptions.

2. **Load all templates for pools** — Don't set `tags` in `ScanEngine()` if your pool jobs use different tags. Filter per-scan instead.

3. **Use direct templates for dynamic workflows** — `template_bytes` and `template_files` bypass the global store. Perfect for runtime templates from APIs/databases.

4. **Tune concurrency** — Start with `rate_limit=100`, `threads=25`, `host_concurrency=10` and adjust for your target.

5. **Disable interactsh if not needed** — `no_interactsh=True` eliminates OOB polling overhead.

6. **Use silent mode in production** — `silent=True` suppresses nuclei's internal output.

7. **Use callback mode for pools** — `on_result=callback` is simpler and avoids the overhead of managing an async iterator.

8. **Reuse the engine** — One `ScanEngine` instance can run thousands of scans. Don't create a new one per scan.

9. **Use scan_collect() for small result sets** — When you need all results as a list, `scan_collect()` is simpler than iterating.

10. **Use host-spray strategy for targeted scans** — `scan_strategy="host-spray"` sends all templates to one host before moving to the next. Default `"template-spray"` runs each template against all hosts first. Host-spray is better when you want complete results per-host quickly.

    ```python
    engine = ScanEngine(scan_strategy="host-spray", rate_limit=100)
    ```

11. **Use stop_at_first_match for quick checks** — `stop_at_first_match=True` stops scanning a target after the first finding. Useful for "is this vulnerable?" checks where you don't need every finding.

    ```python
    engine = ScanEngine(stop_at_first_match=True, rate_limit=100)
    ```

12. **Handle VersionMismatchError** — The SDK auto-downloads compatible binaries, but handle the error for offline environments.

---

## API Reference Summary

### Classes

| Class | Description |
|-------|-------------|
| `ScanEngine` | Main engine — setup once, scan many times |
| `ScanPool` | Worker pool for dynamic job submission |
| `ScanResult` | Single scan finding with 50+ fields |
| `LabeledResult` | Pool result with job label |
| `PoolStats` | Pool statistics (submitted, completed, failed, pending) |
| `TemplateBytesEntry` | Named raw YAML template |
| `EngineConfig` | Engine configuration dataclass |
| `ScanOptions` | Per-scan options dataclass |
| `TemplateInfo` | Parsed template metadata |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `BridgeError` | Base — bridge process errors |
| `InstallError` | Base — installation failures |
| `UnsupportedPlatformError` | OS/arch not supported |
| `DownloadError` | GitHub download failure |
| `ChecksumError` | SHA256 mismatch |
| `InstallPermissionError` | Cannot write binary |
| `VersionMismatchError` | Bridge version incompatible |

### Functions

| Function | Description |
|----------|-------------|
| `install_bridge(...)` | Download and install bridge binary |
| `ensure_bridge(...)` | Find, validate, or auto-install bridge |
| `get_bridge_version(path)` | Get bridge binary version string |
| `check_version_compatible(ver)` | Check version against MIN/MAX |
| **Presets** | |
| `web_scanner(**overrides)` | Pre-configured HTTP vulnerability scanner |
| `api_security_scanner(**overrides)` | API-focused security scanner |
| `wordpress_scanner(**overrides)` | WordPress-specific scanner |
| `network_scanner(**overrides)` | Network/DNS/SSL scanner |
| **Auth Helpers** | |
| `basic_auth(username, password, *domains)` | Basic authentication config |
| `bearer_token(token, *domains)` | Bearer token authentication config |
| `header_auth(headers, *domains)` | Custom header authentication config |
| `cookie_auth(cookies, *domains)` | Cookie-based authentication config |
| `query_auth(params, *domains)` | Query parameter authentication config |
| `api_key_header(header_name, key, *domains)` | API key header config |
| **Target Utilities** | |
| `targets_from_file(path)` | Read targets from file |
| `targets_from_cidr(cidr)` | Expand CIDR to IPs |
| `targets_from_cidrs(cidrs)` | Expand multiple CIDRs to IPs |
| `ip_range(start, end)` | Generate IP range |
| **Template Utilities** | |
| `fetch_template_from_url(url, timeout=30)` | Download template from URL |
| `validate_template(data)` | Validate template YAML |
| `parse_template_info(data)` | Parse template metadata |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MIN_BRIDGE_VERSION` | `"1.0.0"` | Minimum required bridge version |
| `MAX_BRIDGE_VERSION` | `None` | Maximum allowed (None = no limit) |
| `__version__` | `"1.1.0"` | Python SDK version |
