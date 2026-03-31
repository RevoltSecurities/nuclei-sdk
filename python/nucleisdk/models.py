"""Data models for the nuclei-sdk Python client."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScanResult:
    """A single scan finding."""

    template_id: str = ""
    template_name: str = ""
    template_path: str = ""
    severity: str = ""
    type: str = ""
    host: str = ""
    matched_url: str = ""
    matcher_name: str = ""
    extractor_name: str = ""
    extracted_results: List[str] = field(default_factory=list)
    ip: str = ""
    port: str = ""
    scheme: str = ""
    url: str = ""
    path: str = ""
    request: str = ""
    response: str = ""
    curl_command: str = ""
    tags: List[str] = field(default_factory=list)
    authors: List[str] = field(default_factory=list)
    description: str = ""
    impact: str = ""
    remediation: str = ""
    reference: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    cve_id: List[str] = field(default_factory=list)
    cwe_id: List[str] = field(default_factory=list)
    cvss_metrics: str = ""
    cvss_score: float = 0.0
    epss_score: float = 0.0
    cpe: str = ""
    is_fuzzing_result: bool = False
    fuzzing_method: str = ""
    fuzzing_parameter: str = ""
    fuzzing_position: str = ""
    matcher_status: bool = False
    timestamp: str = ""
    error: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> ScanResult:
        """Create a ScanResult from a JSON-decoded dict."""
        return cls(
            template_id=data.get("template_id", ""),
            template_name=data.get("template_name", ""),
            template_path=data.get("template_path", ""),
            severity=data.get("severity", ""),
            type=data.get("type", ""),
            host=data.get("host", ""),
            matched_url=data.get("matched_url", ""),
            matcher_name=data.get("matcher_name", ""),
            extractor_name=data.get("extractor_name", ""),
            extracted_results=data.get("extracted_results") or [],
            ip=data.get("ip", ""),
            port=data.get("port", ""),
            scheme=data.get("scheme", ""),
            url=data.get("url", ""),
            path=data.get("path", ""),
            request=data.get("request", ""),
            response=data.get("response", ""),
            curl_command=data.get("curl_command", ""),
            tags=data.get("tags") or [],
            authors=data.get("authors") or [],
            description=data.get("description", ""),
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
            reference=data.get("reference") or [],
            metadata=data.get("metadata") or {},
            cve_id=data.get("cve_id") or [],
            cwe_id=data.get("cwe_id") or [],
            cvss_metrics=data.get("cvss_metrics", ""),
            cvss_score=data.get("cvss_score", 0.0),
            epss_score=data.get("epss_score", 0.0),
            cpe=data.get("cpe", ""),
            is_fuzzing_result=data.get("is_fuzzing_result", False),
            fuzzing_method=data.get("fuzzing_method", ""),
            fuzzing_parameter=data.get("fuzzing_parameter", ""),
            fuzzing_position=data.get("fuzzing_position", ""),
            matcher_status=data.get("matcher_status", False),
            timestamp=data.get("timestamp", ""),
            error=data.get("error", ""),
        )

    def is_critical(self) -> bool:
        return self.severity.lower() == "critical"

    def is_high_or_above(self) -> bool:
        return self.severity_level() >= 4

    def severity_level(self) -> int:
        """0=unknown, 1=info, 2=low, 3=medium, 4=high, 5=critical."""
        return {
            "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5
        }.get(self.severity.lower(), 0)


@dataclass
class LabeledResult:
    """A scan result tagged with a job label."""

    label: str
    result: ScanResult

    @classmethod
    def from_dict(cls, label: str, data: dict) -> LabeledResult:
        return cls(label=label, result=ScanResult.from_dict(data))


@dataclass
class PoolStats:
    """Scan pool statistics."""

    submitted: int = 0
    completed: int = 0
    failed: int = 0
    pending: int = 0

    @classmethod
    def from_dict(cls, data: dict) -> PoolStats:
        return cls(
            submitted=data.get("submitted", 0),
            completed=data.get("completed", 0),
            failed=data.get("failed", 0),
            pending=data.get("pending", 0),
        )


@dataclass
class TemplateBytesEntry:
    """A named raw YAML template."""

    name: str
    data: bytes

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "data": base64.b64encode(self.data).decode("ascii"),
        }


@dataclass
class EngineConfig:
    """Configuration for the scan engine."""

    template_dirs: List[str] = field(default_factory=list)
    template_files: List[str] = field(default_factory=list)
    workflows: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    exclude_tags: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    exclude_severities: List[str] = field(default_factory=list)
    protocol_types: str = ""
    template_ids: List[str] = field(default_factory=list)
    exclude_ids: List[str] = field(default_factory=list)
    authors: List[str] = field(default_factory=list)
    timeout: int = 0
    retries: int = 0
    proxy: List[str] = field(default_factory=list)
    threads: int = 0
    host_concurrency: int = 0
    rate_limit: int = 0
    headless: bool = False
    dast_mode: bool = False
    no_interactsh: bool = False
    verbose: bool = False
    debug: bool = False
    silent: bool = False
    auth: List[dict] = field(default_factory=list)
    secrets_files: List[str] = field(default_factory=list)

    # Headers & Variables
    custom_headers: List[str] = field(default_factory=list)
    custom_vars: List[str] = field(default_factory=list)

    # Template loading (additional)
    template_bytes: List[TemplateBytesEntry] = field(default_factory=list)
    template_urls: List[str] = field(default_factory=list)
    trusted_domains: List[str] = field(default_factory=list)

    # Network (additional)
    proxy_internal: bool = False

    # Concurrency (additional)
    rate_limit_duration: str = ""
    payload_concurrency: int = 0

    # Features (additional)
    scan_strategy: str = ""
    code_templates: bool = False
    matcher_status: bool = False
    update_check: bool = False

    # Template execution modes
    self_contained_templates: bool = False
    global_matchers_templates: bool = False
    disable_template_cache: bool = False
    file_templates: bool = False
    passive_mode: bool = False
    signed_templates_only: bool = False

    # Response
    response_read_size: int = 0

    # Sandbox
    sandbox_allow_local_file: bool = False
    sandbox_restrict_network: bool = False

    # Advanced network
    leave_default_ports: bool = False
    network_interface: str = ""
    source_ip: str = ""
    system_resolvers: bool = False
    resolvers: List[str] = field(default_factory=list)
    disable_max_host_err: bool = False

    # Execution control
    stop_at_first_match: bool = False

    # Result filtering
    result_severity_filter: List[str] = field(default_factory=list)

    # Target options
    openapi_spec: str = ""
    swagger_spec: str = ""
    exclude_targets: List[str] = field(default_factory=list)

    # HTTP probing
    http_probe: bool = False
    probe_concurrency: int = 0
    scan_all_ips: bool = False
    ip_version: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {}
        for k, v in self.__dict__.items():
            if isinstance(v, bool):
                if v:
                    d[k] = v
            elif isinstance(v, (int, float)):
                if v != 0:
                    d[k] = v
            elif isinstance(v, str):
                if v:
                    d[k] = v
            elif isinstance(v, list):
                if v:
                    if v and hasattr(v[0], "to_dict"):
                        d[k] = [item.to_dict() for item in v]
                    else:
                        d[k] = v
            elif isinstance(v, dict):
                if v:
                    d[k] = v
            elif v is not None:
                d[k] = v
        return d


@dataclass
class ScanOptions:
    """Per-scan options."""

    targets: List[str] = field(default_factory=list)
    target_file: str = ""
    tags: List[str] = field(default_factory=list)
    exclude_tags: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    protocol_types: str = ""
    template_ids: List[str] = field(default_factory=list)
    exclude_ids: List[str] = field(default_factory=list)
    authors: List[str] = field(default_factory=list)
    template_files: List[str] = field(default_factory=list)
    template_dirs: List[str] = field(default_factory=list)
    template_bytes: List[TemplateBytesEntry] = field(default_factory=list)
    result_severity_filter: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {}
        if self.targets:
            d["targets"] = self.targets
        if self.target_file:
            d["target_file"] = self.target_file
        if self.tags:
            d["tags"] = self.tags
        if self.exclude_tags:
            d["exclude_tags"] = self.exclude_tags
        if self.severities:
            d["severities"] = self.severities
        if self.protocol_types:
            d["protocol_types"] = self.protocol_types
        if self.template_ids:
            d["template_ids"] = self.template_ids
        if self.exclude_ids:
            d["exclude_ids"] = self.exclude_ids
        if self.authors:
            d["authors"] = self.authors
        if self.template_files:
            d["template_files"] = self.template_files
        if self.template_dirs:
            d["template_dirs"] = self.template_dirs
        if self.template_bytes:
            d["template_bytes"] = [tb.to_dict() for tb in self.template_bytes]
        if self.result_severity_filter:
            d["result_severity_filter"] = self.result_severity_filter
        return d
