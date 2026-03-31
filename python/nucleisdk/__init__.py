"""nuclei-sdk: Async Python client for the Nuclei scanning engine.

Built by RevoltSecurities.
"""

from .engine import ScanEngine
from .models import (
    EngineConfig,
    LabeledResult,
    PoolStats,
    ScanOptions,
    ScanResult,
    TemplateBytesEntry,
)
from .pool import ScanPool
from ._bridge import BridgeError
from ._installer import (
    InstallError,
    UnsupportedPlatformError,
    DownloadError,
    ChecksumError,
    InstallPermissionError,
    VersionMismatchError,
    install_bridge,
    ensure_bridge,
    get_bridge_version,
    check_version_compatible,
    MIN_BRIDGE_VERSION,
    MAX_BRIDGE_VERSION,
)

# Preset scanner factories
from .presets import (
    web_scanner,
    api_security_scanner,
    wordpress_scanner,
    network_scanner,
)

# Authentication helpers
from .auth import (
    basic_auth,
    bearer_token,
    header_auth,
    cookie_auth,
    query_auth,
    api_key_header,
)

# Target utilities
from .targets import (
    targets_from_file,
    targets_from_cidr,
    targets_from_cidrs,
    ip_range,
)

# Template utilities
from .templates import (
    TemplateInfo,
    fetch_template_from_url,
    validate_template,
    parse_template_info,
)

__all__ = [
    # Core
    "ScanEngine",
    "ScanPool",
    "ScanResult",
    "ScanOptions",
    "LabeledResult",
    "PoolStats",
    "TemplateBytesEntry",
    "EngineConfig",
    "BridgeError",
    # Installer
    "InstallError",
    "UnsupportedPlatformError",
    "DownloadError",
    "ChecksumError",
    "InstallPermissionError",
    "VersionMismatchError",
    "install_bridge",
    "ensure_bridge",
    "get_bridge_version",
    "check_version_compatible",
    "MIN_BRIDGE_VERSION",
    "MAX_BRIDGE_VERSION",
    # Presets
    "web_scanner",
    "api_security_scanner",
    "wordpress_scanner",
    "network_scanner",
    # Auth helpers
    "basic_auth",
    "bearer_token",
    "header_auth",
    "cookie_auth",
    "query_auth",
    "api_key_header",
    # Target utilities
    "targets_from_file",
    "targets_from_cidr",
    "targets_from_cidrs",
    "ip_range",
    # Template utilities
    "TemplateInfo",
    "fetch_template_from_url",
    "validate_template",
    "parse_template_info",
]

__version__ = "1.0.0"
