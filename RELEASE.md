# v1.1.0

## DAST Fuzzing: Full HTTP Request Metadata (`RequestResponseTarget`)

When nuclei's fuzzing engine receives a target as a plain URL string, it defaults to `GET` with no body — this means POST/PUT/PATCH endpoints are never tested correctly. `RequestResponseTarget` fixes this by providing the full HTTP method, headers, and body to the fuzzing engine.

### New Types

**Go SDK:**
- `RequestResponseTarget` struct — URL, Method, Headers, Body
- `ScanOptions.RequestResponseTargets` field
- `WithRequestResponseTargets()` option function

**Python SDK:**
- `TargetRequest` dataclass — url, method, headers, body
- `ScanOptions.request_response_targets` field
- `scan(request_response_targets=[...])` parameter on `ScanEngine` and `ScanPool`

**Bridge Protocol:**
- `request_response_targets` field in scan options JSON

### Usage (Go)

```go
results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
    RequestResponseTargets: []nucleisdk.RequestResponseTarget{{
        URL:     "https://api.example.com/api/users",
        Method:  "POST",
        Headers: map[string]string{"Content-Type": "application/json"},
        Body:    `{"name":"test"}`,
    }},
    TemplateBytes: entries,
})
```

### Usage (Python)

```python
from nucleisdk import ScanEngine, TargetRequest

async for r in engine.scan(
    request_response_targets=[
        TargetRequest(
            url="https://api.example.com/api/users",
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"name":"test"}',
        ),
    ],
    template_bytes=entries,
):
    print(f"[{r.severity}] {r.template_id}")
```

### Technical Details

Nuclei's fuzzing engine has two code paths in `request_fuzz.go`:
1. **ReqResp path**: When `MetaInput.ReqResp != nil` — preserves method, headers, body
2. **URL-only path**: When `ReqResp == nil` — hardcodes `GET` with `nil` body

`RequestResponseTarget` ensures the SDK constructs `MetaInput` entries with `ReqResp` populated, triggering path #1.

---

# v1.0.0

The first release of **nuclei-sdk** -- a multi-language SDK for building custom security scanners powered by [Nuclei](https://github.com/projectdiscovery/nuclei).

## Go SDK

```bash
go get github.com/RevoltSecurities/nuclei-sdk
```

- **Scanner** -- simple one-shot scans
- **ScanEngine** -- init-once/scan-many, lightweight per-scan objects for 1000+ concurrent scans
- **RunParallel** -- multiple scan types simultaneously with labeled results
- **ScanPool** -- worker pool for continuous scanning from APIs, queues, or feeds
- **4 presets** -- Web, API Security, WordPress, Network
- **71 config options**, 6 auth helpers, target/template utilities
- **9 examples** covering every scan mode

## Python SDK

```bash
pip install nuclei-sdk
```

- Fully async (`asyncio`), full feature parity with Go SDK
- Bridge binary **auto-installs** from GitHub Releases (no Go toolchain needed)
- ScanPool, `run_parallel()`, 4 presets, 6 auth helpers, target/template utilities
- SHA256 checksum verification, SSRF-safe installer

## Bridge Binary

JSON-line protocol over stdin/stdout -- build Nuclei clients in **any language** (TypeScript, Rust, Java, Ruby). 8 commands: `version`, `setup`, `scan`, `pool_create`, `pool_submit`, `pool_stats`, `pool_close`, `close`.

### Platforms

| OS | Arch | Format |
|---|---|---|
| Linux | amd64, arm64 | tar.gz |
| macOS | amd64, arm64 | tar.gz |
| Windows | amd64, arm64 | zip |

## Links

- [Go SDK Documentation](docs/GOLANG-SDK.md)
- [Python SDK Documentation](docs/PYTHON-SDK.md)
- [Examples](examples/)
