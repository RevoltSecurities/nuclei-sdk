"""Template utility functions for the nuclei-sdk Python client.

YAML parsing functions (validate_template, parse_template_info) require PyYAML.
Install with: pip install nuclei-sdk[templates] or pip install pyyaml
"""

from __future__ import annotations

import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TemplateInfo:
    """Parsed template metadata."""

    id: str = ""
    name: str = ""
    author: str = ""
    severity: str = ""
    tags: List[str] = field(default_factory=list)
    description: str = ""


def fetch_template_from_url(url: str, timeout: int = 30) -> bytes:
    """Download a nuclei template from a URL.

    Args:
        url: URL to fetch the template from.
        timeout: Request timeout in seconds.

    Returns:
        Raw template bytes (YAML content).

    Raises:
        urllib.error.URLError: On network errors.
        ValueError: If URL is empty.
    """
    if not url:
        raise ValueError("URL cannot be empty")
    req = urllib.request.Request(url, headers={"User-Agent": "nuclei-sdk-python/1.0.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _require_yaml():
    """Import and return the yaml module, raising a clear error if missing."""
    try:
        import yaml
        return yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for template validation/parsing. "
            "Install with: pip install pyyaml"
        )


def validate_template(data: bytes) -> str:
    """Validate a nuclei template YAML and return its template ID.

    Args:
        data: Raw YAML template bytes.

    Returns:
        Template ID string.

    Raises:
        ValueError: If the template is invalid or missing required fields.
        ImportError: If PyYAML is not installed.
    """
    yaml = _require_yaml()
    try:
        doc = yaml.safe_load(data)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}") from e

    if not isinstance(doc, dict):
        raise ValueError("Template must be a YAML mapping")

    template_id = doc.get("id")
    if not template_id:
        raise ValueError("Template missing required 'id' field")

    info = doc.get("info")
    if not isinstance(info, dict):
        raise ValueError("Template missing required 'info' section")

    if not info.get("name"):
        raise ValueError("Template missing required 'info.name' field")

    return str(template_id)


def parse_template_info(data: bytes) -> TemplateInfo:
    """Parse template metadata from YAML without full compilation.

    Args:
        data: Raw YAML template bytes.

    Returns:
        TemplateInfo with extracted metadata.

    Raises:
        ValueError: If the template YAML is invalid.
        ImportError: If PyYAML is not installed.
    """
    yaml = _require_yaml()
    try:
        doc = yaml.safe_load(data)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}") from e

    if not isinstance(doc, dict):
        raise ValueError("Template must be a YAML mapping")

    info = doc.get("info", {})
    if not isinstance(info, dict):
        info = {}

    # Handle author as string or list
    author = info.get("author", "")
    if isinstance(author, list):
        author = ", ".join(str(a) for a in author)
    else:
        author = str(author)

    # Handle tags as comma-separated string or list
    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    elif isinstance(tags, list):
        tags = [str(t) for t in tags]
    else:
        tags = []

    severity = info.get("severity", "")
    if isinstance(severity, dict):
        severity = str(severity)

    return TemplateInfo(
        id=str(doc.get("id", "")),
        name=str(info.get("name", "")),
        author=author,
        severity=str(severity),
        tags=tags,
        description=str(info.get("description", "")),
    )
