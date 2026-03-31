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
