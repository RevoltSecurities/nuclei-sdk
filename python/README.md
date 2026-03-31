# nuclei-sdk (Python)

Async Python client for the [Nuclei](https://github.com/projectdiscovery/nuclei) scanning engine, built by [RevoltSecurities](https://github.com/RevoltSecurities).

Same architecture as the Go SDK: one engine setup, many lightweight concurrent scans. Built on `asyncio` for maximum scalability — coroutines use ~1KB each vs ~8MB per thread.

## Installation

```bash
pip install nuclei-sdk
```

The Go bridge binary (`nuclei-sdk-bridge`) is **auto-installed** from [GitHub Releases](https://github.com/RevoltSecurities/nuclei-sdk/releases) on first use — no Go toolchain required. Supports Linux, macOS, and Windows on amd64/arm64.

## Quick Start

```python
import asyncio
from nucleisdk import ScanEngine

async def main():
    # Binary auto-downloads if not found — zero setup needed
    engine = ScanEngine(rate_limit=100, timeout=10, no_interactsh=True)
    await engine.setup()

    async for result in engine.scan(targets=["https://example.com"], tags=["cve"], severities=["high"]):
        print(f"[{result.severity}] {result.template_id} - {result.matched_url}")

    await engine.close()

asyncio.run(main())
```

## Async Context Manager

```python
async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
    results = [r async for r in engine.scan(targets=["https://example.com"])]
```

## Multiple Scans (Same Engine)

```python
async with ScanEngine(rate_limit=100) as engine:
    # Scan 1 — HTTP CVEs
    async for r in engine.scan(targets=["https://a.com"], tags=["cve"], protocol_types="http"):
        print(r.template_id)

    # Scan 2 — SSL checks (same engine, no re-initialization)
    async for r in engine.scan(targets=["b.com:443"], protocol_types="ssl"):
        print(r.template_id)
```

## ScanPool: Continuous Dynamic Scanning

### Iterator Mode

```python
from nucleisdk import ScanEngine, TemplateBytesEntry

async def main():
    async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
        pool = await engine.scan_pool(workers=5)

        # Submit jobs dynamically
        await pool.submit("CVE-2024-1234",
            targets=["https://target.com"],
            template_bytes=[TemplateBytesEntry("CVE-2024-1234", yaml_bytes)])

        await pool.submit("wordpress",
            targets=["https://wp.example.com"],
            tags=["wordpress"])

        # Consume results
        async for lr in pool.results():
            print(f"[{lr.label}] [{lr.result.severity}] {lr.result.template_id}")

        await pool.close()
        stats = await pool.stats()
        print(f"Submitted: {stats.submitted}, Completed: {stats.completed}")
```

### Callback Mode (No Manual Iteration)

```python
async def handle_result(lr):
    print(f"[{lr.label}] [{lr.result.severity}] {lr.result.template_id}")

async def main():
    async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
        pool = await engine.scan_pool(workers=5, on_result=handle_result)

        await pool.submit("CVE-2024-1234", targets=["https://target.com"], ...)
        await pool.submit("wordpress", targets=["https://wp.example.com"], tags=["wordpress"])

        await pool.close()  # waits for all jobs; callback fires automatically
```

### Concurrent Submit + Consume with asyncio.gather

```python
async def submit_jobs(pool):
    for cve in cve_feed:
        await pool.submit(cve["id"], targets=[cve["target"]], template_bytes=[...])
    await pool.close()

async def consume_results(pool):
    async for lr in pool.results():
        print(f"[{lr.label}] {lr.result.severity}")

async def main():
    async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
        pool = await engine.scan_pool(workers=10)
        await asyncio.gather(submit_jobs(pool), consume_results(pool))
```

## Targeted Scan with Template Bytes

```python
from nucleisdk import ScanEngine, TemplateBytesEntry

yaml_template = b"""
id: custom-check
info:
  name: Custom Check
  severity: high
  author: me
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
"""

async def main():
    async with ScanEngine(no_interactsh=True) as engine:
        async for r in engine.scan(
            targets=["https://example.com"],
            template_bytes=[TemplateBytesEntry("custom-check", yaml_template)]
        ):
            print(f"[{r.severity}] {r.template_id}")
```

## Bridge Binary Installation

The bridge binary is auto-installed on first use. You can also manage it manually:

### Auto-Install (Default)

```python
# Just use ScanEngine — binary is downloaded automatically if not found
async with ScanEngine(rate_limit=100) as engine:
    ...
```

Output on first run:
```
nucleisdk: nuclei-sdk-bridge not found locally, attempting auto-install from GitHub Releases...
nucleisdk: fetching latest release from RevoltSecurities/nuclei-sdk...
nucleisdk: latest release: v0.1.0
nucleisdk: downloading nuclei-sdk-bridge_0.1.0_darwin_arm64.tar.gz...
nucleisdk: checksum verified.
nucleisdk: installed nuclei-sdk-bridge v0.1.0 to /home/user/.local/bin/nuclei-sdk-bridge
```

### Manual Install

```python
from nucleisdk import install_bridge

# Install to default location (~/.local/bin/ on Linux/macOS)
path = install_bridge()
print(f"Installed to: {path}")

# Install to a custom directory
path = install_bridge(install_dir="/opt/nuclei/bin")
```

### Quiet Mode (No Logging)

```python
from nucleisdk import install_bridge

# Suppress all installation progress messages
path = install_bridge(quiet=True)
```

### Custom Repository (Forks)

```python
from nucleisdk import install_bridge

# Install from a fork — only 'owner/repo' format allowed
path = install_bridge(repo="MyOrg/my-nuclei-fork")

# Combined with other options
path = install_bridge(
    repo="MyOrg/my-nuclei-fork",
    install_dir="/opt/nuclei/bin",
    quiet=True,
)
```

Only GitHub URLs are accepted — full URLs, path traversal, and query injection are all rejected with `InstallError` (SSRF protection).

### Use a Specific Binary

```python
# Skip auto-install entirely — use your own binary
engine = ScanEngine(
    binary_path="/opt/homebrew/bin/nuclei-sdk-bridge",
    rate_limit=100,
)
```

### Build From Source (Alternative)

```bash
# Requires Go toolchain
cd /path/to/nuclei-sdk
go build -o bin/nuclei-sdk-bridge ./cmd/nuclei-sdk-bridge/
```

### Error Handling

```python
from nucleisdk import (
    ScanEngine,
    InstallError,
    DownloadError,
    ChecksumError,
    UnsupportedPlatformError,
    InstallPermissionError,
)

try:
    async with ScanEngine() as engine:
        ...
except UnsupportedPlatformError:
    # OS/arch not in pre-built releases (e.g., FreeBSD, 32-bit)
    print("Build from source: go build -o bin/nuclei-sdk-bridge ./cmd/nuclei-sdk-bridge/")
except DownloadError:
    # No internet, GitHub down, rate limited
    print("Check internet connection or use binary_path=")
except ChecksumError:
    # Downloaded file corrupted — retry
    print("Download corrupted, try again")
except InstallPermissionError:
    # Can't write to ~/.local/bin/
    print("Use install_bridge(install_dir='./bin') for a writable path")
except InstallError:
    # Catch-all for any install failure
    print("Installation failed")
```

### Install Locations

| Platform | Default Path |
|----------|-------------|
| Linux | `~/.local/bin/nuclei-sdk-bridge` |
| macOS | `~/.local/bin/nuclei-sdk-bridge` |
| Windows | `%LOCALAPPDATA%\nuclei-sdk\bin\nuclei-sdk-bridge.exe` |

### Exception Hierarchy

```
BridgeError
└── InstallError
    ├── UnsupportedPlatformError
    ├── DownloadError
    ├── ChecksumError
    ├── InstallPermissionError
    └── VersionMismatchError
```

## Version Management

The Python SDK automatically checks bridge binary version compatibility on startup.

### Automatic Version Check

```python
# Version is checked automatically when ScanEngine starts.
# If the installed binary is incompatible, a compatible one is auto-downloaded.
async with ScanEngine(rate_limit=100) as engine:
    ...
```

### Check Version Manually

```python
from nucleisdk import ensure_bridge, get_bridge_version, check_version_compatible, MIN_BRIDGE_VERSION

path = ensure_bridge(quiet=True)
ver = get_bridge_version(path)
print(f"Bridge version: {ver}")
print(f"Compatible: {check_version_compatible(ver)}")
print(f"Min required: {MIN_BRIDGE_VERSION}")
```

### Force Update

```python
from nucleisdk import install_bridge

# Always downloads the latest version, even if current is compatible
path = install_bridge(update=True)
```

### Handle Version Mismatch

```python
from nucleisdk import ensure_bridge, install_bridge, VersionMismatchError

try:
    path = ensure_bridge(auto_install=False)
except VersionMismatchError as e:
    print(f"Incompatible bridge: {e}")
    path = install_bridge(update=True)
```

## API Reference

### ScanEngine

| Method | Description |
|--------|-------------|
| `ScanEngine(**config)` | Create engine with config (rate_limit, timeout, tags, etc.) |
| `await setup()` | One-time heavy initialization |
| `async for r in scan(**opts)` | Lightweight scan, yields `ScanResult` |
| `await scan_collect(**opts)` | Same as scan(), returns `List[ScanResult]` |
| `await scan_pool(workers, on_result=None)` | Create a `ScanPool` |
| `await close()` | Shut down engine |
| `async with ScanEngine() as engine` | Context manager (auto setup/close) |

### ScanPool

| Method | Description |
|--------|-------------|
| `await submit(label, **opts)` | Queue a scan job |
| `async for lr in results()` | Iterate over `LabeledResult` |
| `await stats()` | Get `PoolStats` |
| `await close()` | Wait for jobs and shut down |

### ScanResult

| Field | Type | Description |
|-------|------|-------------|
| `template_id` | str | Template identifier |
| `severity` | str | info, low, medium, high, critical |
| `matched_url` | str | URL that matched |
| `host` | str | Target host |
| `tags` | List[str] | Template tags |
| `cve_id` | List[str] | CVE identifiers |
| `is_critical()` | bool | Severity == critical |
| `is_high_or_above()` | bool | Severity >= high |
| `severity_level()` | int | 0-5 numeric |

### Installer & Version

| Function | Description |
|----------|-------------|
| `install_bridge(install_dir=None, quiet=False, repo=..., update=False)` | Download and install the bridge binary |
| `ensure_bridge(binary_path=None, quiet=False, auto_install=True, update=False, repo=...)` | Find or auto-install a compatible bridge binary |
| `get_bridge_version(binary_path)` | Get version string from a bridge binary |
| `check_version_compatible(version)` | Check if a version meets SDK requirements |

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `install_dir` | str \| None | `None` | Custom install directory (default: `~/.local/bin/`) |
| `quiet` | bool | `False` | Suppress installation progress messages |
| `repo` | str | `"RevoltSecurities/nuclei-sdk"` | GitHub `owner/repo` to fetch from (SSRF-safe) |
| `update` | bool | `False` | Always download latest version |
| `auto_install` | bool | `True` | Auto-download if not found or incompatible |

## License

MIT
