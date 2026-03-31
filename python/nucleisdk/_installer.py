"""Auto-installer for the nuclei-sdk-bridge Go binary.

Downloads pre-built binaries from GitHub Releases when the bridge
binary is not found locally. Supports Linux, macOS, and Windows
on amd64 and arm64 architectures.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import re

from ._bridge import BridgeError

DEFAULT_REPO = "RevoltSecurities/nuclei-sdk"
GITHUB_API_BASE = "https://api.github.com/repos"
GITHUB_DOWNLOAD_HOST = "github.com"
BINARY_NAME = "nuclei-sdk-bridge"

# Version compatibility — Python SDK declares which bridge versions it supports.
# Updated when the JSON protocol changes in a breaking way.
MIN_BRIDGE_VERSION = "1.0.0"
MAX_BRIDGE_VERSION = None  # None = no upper bound

# Strict pattern: alphanumeric, hyphens, underscores, dots — no slashes, colons, etc.
_REPO_PATTERN = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

OS_MAP = {
    "Linux": "linux",
    "Darwin": "darwin",
    "Windows": "windows",
}

ARCH_MAP = {
    "x86_64": "amd64",
    "AMD64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


# --- Exceptions ---


class InstallError(BridgeError):
    """Base exception for installation failures."""


class UnsupportedPlatformError(InstallError):
    """Raised when the current OS/arch is not supported."""


class DownloadError(InstallError):
    """Raised when downloading from GitHub fails."""


class ChecksumError(InstallError):
    """Raised when SHA256 checksum verification fails."""


class InstallPermissionError(InstallError):
    """Raised when the installer lacks permission to write the binary."""


class VersionMismatchError(InstallError):
    """Raised when the bridge binary version is incompatible with this SDK."""


# --- Version helpers ---


def _parse_version(v: str) -> tuple:
    """Parse a version string like '0.1.0' or 'v0.1.0' to a tuple of ints."""
    v = v.strip().lstrip("v")
    try:
        return tuple(int(x) for x in v.split("."))
    except (ValueError, AttributeError):
        return (0, 0, 0)


def get_bridge_version(binary_path: str) -> Optional[str]:
    """Run the bridge binary with --version and return the version string.

    Returns:
        Version string (e.g. '0.1.0') or None if the binary doesn't
        support --version (old binary without version flag).
    """
    import subprocess
    try:
        result = subprocess.run(
            [binary_path, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


def check_version_compatible(version: str) -> bool:
    """Check if a bridge version is compatible with this Python SDK.

    Args:
        version: Bridge version string (e.g. '0.1.0').

    Returns:
        True if compatible, False otherwise.
        Always returns True for 'dev' builds (local development).
    """
    if not version:
        return False
    if version == "dev":
        return True
    v = _parse_version(version)
    if v <= (0, 0, 0):
        return False
    if v < _parse_version(MIN_BRIDGE_VERSION):
        return False
    if MAX_BRIDGE_VERSION is not None and v > _parse_version(MAX_BRIDGE_VERSION):
        return False
    return True


# --- Validation ---


def _validate_repo(repo: str) -> str:
    """Validate and sanitize a GitHub org/repo string.

    Only allows alphanumeric characters, hyphens, underscores, and dots
    in the format 'owner/repo'. Prevents URL injection and SSRF.

    Raises:
        InstallError: If the repo string is invalid.
    """
    if not _REPO_PATTERN.match(repo):
        raise InstallError(
            f"Invalid repository format: {repo!r}\n"
            "Expected format: 'owner/repo-name' (e.g., 'RevoltSecurities/nuclei-sdk')\n"
            "Only alphanumeric characters, hyphens, underscores, and dots are allowed."
        )
    return repo


def _validate_download_url(url: str) -> str:
    """Ensure a download URL points to GitHub only.

    Prevents SSRF by rejecting any URL not hosted on github.com.

    Raises:
        DownloadError: If the URL is not a GitHub URL.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise DownloadError(f"Refusing non-HTTPS download URL: {url}")
    if parsed.hostname not in ("github.com", "api.github.com", "objects.githubusercontent.com"):
        raise DownloadError(
            f"Refusing download from non-GitHub host: {parsed.hostname}\n"
            "Only github.com URLs are allowed for security."
        )
    return url


# --- Platform detection ---


def _detect_platform() -> tuple[str, str]:
    """Detect OS and architecture, mapped to goreleaser names.

    Returns:
        Tuple of (os_name, arch) e.g. ("darwin", "arm64").

    Raises:
        UnsupportedPlatformError: If OS or arch is not supported.
    """
    os_name = OS_MAP.get(platform.system())
    if os_name is None:
        raise UnsupportedPlatformError(
            f"Unsupported operating system: {platform.system()}. "
            f"Supported: {', '.join(OS_MAP.keys())}"
        )

    arch = ARCH_MAP.get(platform.machine())
    if arch is None:
        raise UnsupportedPlatformError(
            f"Unsupported architecture: {platform.machine()}. "
            f"Supported: {', '.join(ARCH_MAP.keys())}"
        )

    return os_name, arch


def _default_install_dir() -> Path:
    """Return the default install directory for the current platform.

    - Linux/macOS: ~/.local/bin/
    - Windows: %LOCALAPPDATA%/nuclei-sdk/bin/
    """
    if platform.system() == "Windows":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
        return Path(base) / "nuclei-sdk" / "bin"
    return Path.home() / ".local" / "bin"


def _binary_filename() -> str:
    """Return the binary filename for the current platform."""
    if platform.system() == "Windows":
        return f"{BINARY_NAME}.exe"
    return BINARY_NAME


# --- GitHub API ---


def get_latest_release(repo: str = DEFAULT_REPO) -> dict:
    """Fetch the latest release metadata from GitHub.

    Args:
        repo: GitHub repository in 'owner/repo' format.
              Only alphanumeric, hyphens, underscores, and dots allowed.

    Returns:
        Parsed JSON response from GitHub Releases API.

    Raises:
        DownloadError: If the API request fails.
        InstallError: If the repo format is invalid.
    """
    repo = _validate_repo(repo)
    api_url = f"{GITHUB_API_BASE}/{repo}/releases/latest"

    req = Request(api_url, headers={"Accept": "application/vnd.github+json"})
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, OSError) as e:
        raise DownloadError(
            f"Failed to fetch latest release from GitHub: {e}\n"
            f"URL: {api_url}\n"
            "Check your internet connection or install manually:\n"
            f"  go build -o bin/{BINARY_NAME} ./cmd/{BINARY_NAME}/"
        ) from e


def _find_asset(release: dict, os_name: str, arch: str) -> tuple[str, str]:
    """Find the matching asset URL and checksums URL from a release.

    Returns:
        Tuple of (asset_download_url, checksums_download_url).

    Raises:
        UnsupportedPlatformError: If no matching asset is found.
    """
    ext = "zip" if os_name == "windows" else "tar.gz"
    # goreleaser pattern: nuclei-sdk-bridge_{version}_{os}_{arch}.tar.gz
    suffix = f"_{os_name}_{arch}.{ext}"

    asset_url = None
    checksums_url = None

    for asset in release.get("assets", []):
        name = asset.get("name", "")
        url = asset.get("browser_download_url", "")
        if name.endswith(suffix) and name.startswith(BINARY_NAME):
            asset_url = url
        elif name == "checksums.txt":
            checksums_url = url

    if asset_url is None:
        tag = release.get("tag_name", "unknown")
        raise UnsupportedPlatformError(
            f"No pre-built binary found for {os_name}/{arch} in release {tag}.\n"
            f"Expected asset matching: *{suffix}\n"
            f"Available assets: {[a['name'] for a in release.get('assets', [])]}\n"
            "You may need to build from source:\n"
            f"  go build -o bin/{BINARY_NAME} ./cmd/{BINARY_NAME}/"
        )

    # Validate URLs point to GitHub only (SSRF protection)
    _validate_download_url(asset_url)
    if checksums_url:
        _validate_download_url(checksums_url)

    return asset_url, checksums_url


def _download_file(url: str, dest: Path) -> None:
    """Download a file from URL to a local path.

    Raises:
        DownloadError: If the download fails.
    """
    req = Request(url)
    try:
        with urlopen(req, timeout=120) as resp:
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
    except (HTTPError, URLError, OSError) as e:
        raise DownloadError(f"Failed to download {url}: {e}") from e


def _verify_checksum(archive_path: Path, archive_name: str, checksums_path: Path) -> None:
    """Verify SHA256 checksum of the downloaded archive.

    Raises:
        ChecksumError: If the checksum does not match.
    """
    # Parse checksums.txt (goreleaser format: "sha256  filename")
    expected = None
    with open(checksums_path, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2 and parts[1] == archive_name:
                expected = parts[0]
                break

    if expected is None:
        raise ChecksumError(
            f"Checksum for {archive_name} not found in checksums.txt. "
            "The release may be corrupted or incomplete."
        )

    sha256 = hashlib.sha256()
    with open(archive_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)

    actual = sha256.hexdigest()
    if actual != expected:
        raise ChecksumError(
            f"Checksum mismatch for {archive_name}:\n"
            f"  Expected: {expected}\n"
            f"  Got:      {actual}\n"
            "The download may be corrupted. Try again or install manually."
        )


def _extract_binary(archive_path: Path, os_name: str) -> Path:
    """Extract the bridge binary from the downloaded archive.

    Returns:
        Path to the extracted binary in a temp directory.
    """
    binary = _binary_filename()

    if os_name == "windows":
        with zipfile.ZipFile(archive_path) as zf:
            names = zf.namelist()
            match = next((n for n in names if n.endswith(binary)), None)
            if match is None:
                raise InstallError(
                    f"Binary {binary} not found in archive. Contents: {names}"
                )
            extract_dir = archive_path.parent / "extracted"
            zf.extract(match, extract_dir)
            return extract_dir / match
    else:
        with tarfile.open(archive_path, "r:gz") as tf:
            names = tf.getnames()
            match = next((n for n in names if n.endswith(binary)), None)
            if match is None:
                raise InstallError(
                    f"Binary {binary} not found in archive. Contents: {names}"
                )
            tf.extract(match, archive_path.parent / "extracted", filter="data")
            return archive_path.parent / "extracted" / match


# --- Public API ---


def _log(msg: str, quiet: bool = False) -> None:
    """Write a log message to stderr unless quiet mode is enabled."""
    if not quiet:
        sys.stderr.write(msg)


def download_and_install(
    install_dir: Optional[str] = None,
    quiet: bool = False,
    repo: str = DEFAULT_REPO,
) -> str:
    """Download and install the latest nuclei-sdk-bridge binary.

    Args:
        install_dir: Directory to install the binary into.
                     Defaults to ~/.local/bin/ (Linux/macOS) or
                     %LOCALAPPDATA%/nuclei-sdk/bin/ (Windows).
        quiet: If True, suppress all installation progress messages.
        repo: GitHub repository in 'owner/repo' format.
              Only github.com is allowed as download source.

    Returns:
        Absolute path to the installed binary.

    Raises:
        InstallError: If any step of the installation fails.
    """
    repo = _validate_repo(repo)
    os_name, arch = _detect_platform()

    # Resolve install directory
    dest_dir = Path(install_dir) if install_dir else _default_install_dir()

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise InstallPermissionError(
            f"Cannot create install directory {dest_dir}: {e}\n"
            "Try specifying a different directory:\n"
            f'  from nucleisdk import install_bridge\n'
            f'  install_bridge(install_dir="/path/to/writable/dir")'
        ) from e

    dest_binary = dest_dir / _binary_filename()

    # Fetch release info
    _log(f"nucleisdk: fetching latest release from {repo}...\n", quiet)
    release = get_latest_release(repo)
    tag = release.get("tag_name", "unknown")
    _log(f"nucleisdk: latest release: {tag}\n", quiet)

    # Find matching asset
    asset_url, checksums_url = _find_asset(release, os_name, arch)
    asset_name = asset_url.rsplit("/", 1)[-1]

    _log(f"nucleisdk: downloading {asset_name}...\n", quiet)

    with tempfile.TemporaryDirectory(prefix="nucleisdk-") as tmpdir:
        tmp = Path(tmpdir)

        # Download archive
        archive_path = tmp / asset_name
        _download_file(asset_url, archive_path)

        # Verify checksum if available
        if checksums_url:
            checksums_path = tmp / "checksums.txt"
            _download_file(checksums_url, checksums_path)
            _verify_checksum(archive_path, asset_name, checksums_path)
            _log("nucleisdk: checksum verified.\n", quiet)

        # Extract binary
        extracted = _extract_binary(archive_path, os_name)

        # Move to install dir
        try:
            # Use replace for atomic overwrite on same filesystem;
            # fall back to copy for cross-device moves
            try:
                extracted.replace(dest_binary)
            except OSError:
                import shutil
                shutil.copy2(str(extracted), str(dest_binary))
        except OSError as e:
            raise InstallPermissionError(
                f"Cannot install binary to {dest_binary}: {e}\n"
                "Try running with write permissions or specify a different directory."
            ) from e

    # Make executable (Linux/macOS)
    if os_name != "windows":
        try:
            dest_binary.chmod(dest_binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError as e:
            raise InstallPermissionError(
                f"Cannot set executable permission on {dest_binary}: {e}"
            ) from e

    _log(f"nucleisdk: installed {BINARY_NAME} {tag} to {dest_binary}\n", quiet)
    return str(dest_binary)


def ensure_bridge(
    binary_path: Optional[str] = None,
    quiet: bool = False,
    auto_install: bool = True,
    update: bool = False,
    repo: str = DEFAULT_REPO,
) -> str:
    """Find the bridge binary, check version, or auto-install from GitHub.

    This is the main entry point used by BridgeProcess._find_binary().

    Flow:
        1. Find binary (user path → standard locations → PATH → auto-install)
        2. Run ``binary --version`` to get version
        3. Check version compatibility against MIN/MAX_BRIDGE_VERSION
        4. If incompatible or ``update=True`` → download latest
        5. If compatible → return path
        6. If version check fails (old binary) → warn but proceed

    Args:
        binary_path: Explicit path to the binary. If provided and valid,
                     returned immediately (version still checked).
        quiet: If True, suppress installation progress messages.
        auto_install: If True (default), automatically download the binary
                      when not found. If False, raise InstallError instead.
        update: If True, always download the latest binary from GitHub,
                regardless of whether a compatible one is already installed.
        repo: GitHub repository in 'owner/repo' format.
              Only github.com is allowed (SSRF protection).

    Returns:
        Absolute path to a working bridge binary.

    Raises:
        InstallError: If the binary cannot be found or installed.
        VersionMismatchError: If the binary version is incompatible
                              and auto-install/update is disabled.
    """
    import shutil as _shutil

    # Force update — skip finding existing binary, download latest
    if update:
        _log("nucleisdk: update requested, downloading latest bridge...\n", quiet)
        return download_and_install(quiet=quiet, repo=repo)

    found_path: Optional[str] = None

    # 1. User-provided path
    if binary_path:
        p = os.path.abspath(binary_path)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            found_path = p
        else:
            raise InstallError(
                f"Specified binary not found or not executable: {binary_path}"
            )
    else:
        # 2. Check standard locations
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "..", "bin", BINARY_NAME),
            os.path.join(os.path.dirname(__file__), "bin", BINARY_NAME),
            str(_default_install_dir() / _binary_filename()),
        ]

        if platform.system() == "Windows":
            candidates = [c + ".exe" for c in candidates] + candidates

        for path in candidates:
            full = os.path.abspath(path)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                found_path = full
                break

        # 3. Check PATH
        if not found_path:
            found_path = _shutil.which(BINARY_NAME)

    # 4. If no binary found, auto-install or raise
    if not found_path:
        if not auto_install:
            raise InstallError(
                f"{BINARY_NAME} not found. Auto-install is disabled.\n"
                "Install manually:\n"
                f"  go build -o bin/{BINARY_NAME} ./cmd/{BINARY_NAME}/\n"
                "Or enable auto-install:\n"
                f"  from nucleisdk import install_bridge\n"
                f"  install_bridge()"
            )
        _log(
            f"nucleisdk: {BINARY_NAME} not found locally, "
            "attempting auto-install from GitHub Releases...\n",
            quiet,
        )
        return download_and_install(quiet=quiet, repo=repo)

    # 5. Version check on the found binary
    ver = get_bridge_version(found_path)

    if ver is None:
        # Old binary without --version support — warn and proceed
        _log(
            f"nucleisdk: warning: could not determine version of {found_path}, "
            "proceeding without version check\n",
            quiet,
        )
        return found_path

    if check_version_compatible(ver):
        _log(f"nucleisdk: bridge version {ver} is compatible\n", quiet)
        return found_path

    # Version mismatch
    msg = (
        f"Bridge binary version {ver} is incompatible with this SDK.\n"
        f"Required: >= {MIN_BRIDGE_VERSION}"
    )
    if MAX_BRIDGE_VERSION:
        msg += f", <= {MAX_BRIDGE_VERSION}"
    msg += "\n"

    if auto_install:
        _log(f"nucleisdk: {msg}Downloading compatible version...\n", quiet)
        return download_and_install(quiet=quiet, repo=repo)

    raise VersionMismatchError(
        f"{msg}"
        "Update the bridge binary:\n"
        f"  from nucleisdk import install_bridge\n"
        f"  install_bridge(update=True)"
    )


def install_bridge(
    install_dir: Optional[str] = None,
    quiet: bool = False,
    repo: str = DEFAULT_REPO,
    update: bool = False,
) -> str:
    """Install the nuclei-sdk-bridge binary.

    When ``update=False`` (default), equivalent to ``download_and_install()``.
    When ``update=True``, always downloads the latest version regardless of
    what's currently installed.

    Args:
        install_dir: Custom install directory.
        quiet: Suppress progress messages.
        repo: GitHub 'owner/repo' to fetch from.
        update: If True, always download latest (ignore existing binary).

    Returns:
        Absolute path to the installed binary.
    """
    return download_and_install(
        install_dir=install_dir, quiet=quiet, repo=repo,
    )
