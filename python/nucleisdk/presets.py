"""Preset scanner configurations matching Go SDK presets."""

from __future__ import annotations

from .models import EngineConfig


def web_scanner(**overrides) -> EngineConfig:
    """General web application security scanner.

    Matches Go SDK's NewWebScanner defaults:
    - Protocol: http
    - Excludes: dos, fuzz
    - Threads: 50, Host concurrency: 25, Rate limit: 150/s
    - Timeout: 10s, Retries: 1
    """
    defaults = dict(
        protocol_types="http",
        exclude_tags=["dos", "fuzz"],
        threads=50,
        host_concurrency=25,
        timeout=10,
        retries=1,
        rate_limit=150,
    )
    defaults.update(overrides)
    return EngineConfig(**defaults)


def api_security_scanner(**overrides) -> EngineConfig:
    """API security scanner for REST, GraphQL, OpenAPI/Swagger.

    Matches Go SDK's NewAPISecurityScanner defaults:
    - Protocol: http
    - Tags: api, swagger, openapi, graphql, rest, jwt, auth-bypass, etc.
    - Threads: 25, Host concurrency: 10, Rate limit: 50/s
    - Timeout: 15s, Retries: 1, Matcher status: enabled
    """
    defaults = dict(
        protocol_types="http",
        tags=[
            "api", "swagger", "openapi", "graphql", "rest", "jwt",
            "auth-bypass", "exposure", "misconfig", "token", "cors",
            "ssrf", "idor", "bola", "injection", "sqli", "xss", "rce",
        ],
        threads=25,
        host_concurrency=10,
        timeout=15,
        retries=1,
        rate_limit=50,
        matcher_status=True,
    )
    defaults.update(overrides)
    return EngineConfig(**defaults)


def wordpress_scanner(**overrides) -> EngineConfig:
    """WordPress-specific vulnerability scanner.

    Matches Go SDK's NewWordPressScanner defaults:
    - Protocol: http
    - Tags: wordpress, wp-plugin, wp-theme, woocommerce, etc.
    - Threads: 25, Host concurrency: 5, Rate limit: 30/s
    - Timeout: 10s, Retries: 2
    """
    defaults = dict(
        protocol_types="http",
        tags=[
            "wordpress", "wp-plugin", "wp-theme", "wp", "woocommerce",
            "xmlrpc", "wp-config", "wp-cron", "wp-admin", "wp-login",
        ],
        threads=25,
        host_concurrency=5,
        timeout=10,
        retries=2,
        rate_limit=30,
    )
    defaults.update(overrides)
    return EngineConfig(**defaults)


def network_scanner(**overrides) -> EngineConfig:
    """Network and infrastructure security scanner.

    Matches Go SDK's NewNetworkScanner defaults:
    - Protocols: network, dns, ssl
    - Tags: network, dns, ssl, tls, cve, default-login, etc.
    - Threads: 25, Host concurrency: 50, Rate limit: 100/s
    - Timeout: 5s, Retries: 2
    """
    defaults = dict(
        protocol_types="network,dns,ssl",
        tags=[
            "network", "dns", "ssl", "tls", "cve",
            "default-login", "exposure", "misconfig",
        ],
        threads=25,
        host_concurrency=50,
        timeout=5,
        retries=2,
        rate_limit=100,
    )
    defaults.update(overrides)
    return EngineConfig(**defaults)
