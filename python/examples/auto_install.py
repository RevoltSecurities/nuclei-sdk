"""Auto-installer and version management examples.

Covers: auto-install, manual install, version checking, force update,
error handling, custom repos, SSRF protection, and explicit binary paths.
"""

import asyncio

from nucleisdk import (
    ScanEngine,
    install_bridge,
    ensure_bridge,
    get_bridge_version,
    check_version_compatible,
    InstallError,
    DownloadError,
    ChecksumError,
    UnsupportedPlatformError,
    InstallPermissionError,
    VersionMismatchError,
    MIN_BRIDGE_VERSION,
    MAX_BRIDGE_VERSION,
)


# ---------------------------------------------------------------------------
# 1. Auto-Install (Zero Setup)
# ---------------------------------------------------------------------------

async def example_auto_install():
    """Default: binary is auto-installed and version-checked if not found.

    On first run the SDK will:
      1. Look for nuclei-sdk-bridge in standard locations and $PATH
      2. If found, run --version and check compatibility
      3. If not found or incompatible, download from GitHub Releases
    """
    async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
        async for r in engine.scan(targets=["https://example.com"], tags=["tech"]):
            print(f"[{r.severity}] {r.template_id}")


# ---------------------------------------------------------------------------
# 2. Manual Install
# ---------------------------------------------------------------------------

async def example_manual_install():
    """Pre-install the binary before creating the engine."""
    # Downloads to ~/.local/bin/ (Linux/macOS) or %LOCALAPPDATA%\nuclei-sdk\bin\ (Windows)
    path = install_bridge()
    print(f"Installed to: {path}")

    async with ScanEngine(binary_path=path) as engine:
        async for r in engine.scan(targets=["https://example.com"], tags=["tech"]):
            print(f"[{r.severity}] {r.template_id}")


async def example_custom_install_dir():
    """Install the binary to a custom directory."""
    path = install_bridge(install_dir="/opt/nuclei/bin")
    print(f"Installed to: {path}")


async def example_quiet_install():
    """Install without any progress messages."""
    path = install_bridge(quiet=True)
    print(f"Installed to: {path}")


# ---------------------------------------------------------------------------
# 3. Version Management
# ---------------------------------------------------------------------------

async def example_check_version():
    """Check the installed bridge binary version and compatibility."""
    # ensure_bridge finds (or installs) the binary and checks its version
    path = ensure_bridge(quiet=True)
    ver = get_bridge_version(path)

    print(f"Bridge path:    {path}")
    print(f"Bridge version: {ver}")
    print(f"Compatible:     {check_version_compatible(ver)}")
    print(f"Min required:   {MIN_BRIDGE_VERSION}")
    print(f"Max allowed:    {MAX_BRIDGE_VERSION or 'no upper bound'}")


async def example_force_update():
    """Force download the latest bridge binary, even if current is compatible."""
    path = install_bridge(update=True)
    ver = get_bridge_version(path)
    print(f"Updated to: {path} (version {ver})")


async def example_ensure_with_update():
    """Use ensure_bridge with update=True to always get the latest."""
    # Skips all local lookups — goes straight to GitHub Releases
    path = ensure_bridge(update=True)
    print(f"Latest bridge: {path}")


# ---------------------------------------------------------------------------
# 4. Error Handling
# ---------------------------------------------------------------------------

async def example_error_handling():
    """Handle all installation and version errors gracefully."""
    try:
        async with ScanEngine(rate_limit=100, no_interactsh=True) as engine:
            async for r in engine.scan(targets=["https://example.com"]):
                print(r.template_id)

    except VersionMismatchError as e:
        # Bridge binary exists but version is incompatible with this SDK
        print(f"Version mismatch: {e}")
        print("Fix: install_bridge(update=True)")

    except UnsupportedPlatformError as e:
        # No pre-built binary for this OS/arch
        print(f"Platform not supported: {e}")
        print("Build from source:")
        print("  go build -o bin/nuclei-sdk-bridge ./cmd/nuclei-sdk-bridge/")

    except DownloadError as e:
        # Network failure, GitHub down, rate limited
        print(f"Download failed: {e}")
        print("Check internet connection or use binary_path=")

    except ChecksumError as e:
        # Downloaded file is corrupted
        print(f"Checksum failed: {e}")
        print("Try again or download manually")

    except InstallPermissionError as e:
        # Can't write to install directory
        print(f"Permission error: {e}")
        print("Fix: install_bridge(install_dir='./bin')")

    except InstallError as e:
        # Catch-all for any other installation failure
        print(f"Installation failed: {e}")


async def example_version_mismatch_recovery():
    """Detect and recover from version mismatches."""
    try:
        # auto_install=False: don't auto-download if version is incompatible
        path = ensure_bridge(auto_install=False)
        print(f"Using compatible bridge: {path}")

    except VersionMismatchError as e:
        print(f"Incompatible bridge: {e}")
        # Recover by forcing an update
        path = install_bridge(update=True)
        ver = get_bridge_version(path)
        print(f"Updated to {ver} at {path}")

    except InstallError as e:
        print(f"Bridge not found: {e}")


# ---------------------------------------------------------------------------
# 5. Custom Repository (Forks)
# ---------------------------------------------------------------------------

async def example_custom_repo():
    """Install from a forked GitHub repository."""
    # Only 'owner/repo' format — full URLs are rejected (SSRF protection)
    path = install_bridge(repo="MyOrg/my-nuclei-fork")
    print(f"Installed from fork: {path}")


async def example_custom_repo_quiet():
    """Install from custom repo without progress messages."""
    path = install_bridge(repo="MyOrg/my-nuclei-fork", quiet=True)
    print(f"Installed: {path}")


# ---------------------------------------------------------------------------
# 6. Explicit Binary Path
# ---------------------------------------------------------------------------

async def example_explicit_binary():
    """Use a specific binary path — skips auto-install, still checks version."""
    async with ScanEngine(
        binary_path="/opt/homebrew/bin/nuclei-sdk-bridge",
        rate_limit=100,
        no_interactsh=True,
    ) as engine:
        async for r in engine.scan(targets=["https://example.com"], tags=["tech"]):
            print(f"[{r.severity}] {r.template_id}")


# ---------------------------------------------------------------------------
# 7. SSRF Protection Demo
# ---------------------------------------------------------------------------

async def example_ssrf_protection():
    """Demonstrate SSRF protection — all of these are rejected."""
    bad_inputs = [
        "https://evil.com/malware",       # full URL — rejected
        "../../../etc/passwd",             # path traversal — rejected
        "owner/repo?url=http://evil.com",  # query injection — rejected
    ]
    for bad in bad_inputs:
        try:
            install_bridge(repo=bad)
        except InstallError as e:
            print(f"Blocked: {bad!r} -> {type(e).__name__}")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    asyncio.run(example_auto_install())
