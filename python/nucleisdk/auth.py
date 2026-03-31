"""Authentication helper functions for the nuclei-sdk bridge protocol."""

from __future__ import annotations

from typing import Dict, Optional, Sequence


def basic_auth(
    username: str,
    password: str,
    *domains: str,
) -> dict:
    """Create a Basic authentication config.

    Args:
        username: Username for authentication.
        password: Password for authentication.
        *domains: Domains this auth applies to.

    Returns:
        Auth config dict compatible with EngineConfig.auth.
    """
    d: dict = {"type": "basic", "username": username, "password": password}
    if domains:
        d["domains"] = list(domains)
    return d


def bearer_token(
    token: str,
    *domains: str,
) -> dict:
    """Create a Bearer token authentication config.

    Args:
        token: Bearer token string.
        *domains: Domains this auth applies to.

    Returns:
        Auth config dict compatible with EngineConfig.auth.
    """
    d: dict = {"type": "bearer", "token": token}
    if domains:
        d["domains"] = list(domains)
    return d


def header_auth(
    headers: Dict[str, str],
    *domains: str,
) -> dict:
    """Create a custom header authentication config.

    Args:
        headers: Dict of header name → value pairs.
        *domains: Domains this auth applies to.

    Returns:
        Auth config dict compatible with EngineConfig.auth.
    """
    d: dict = {"type": "header", "headers": dict(headers)}
    if domains:
        d["domains"] = list(domains)
    return d


def cookie_auth(
    cookies: Dict[str, str],
    *domains: str,
) -> dict:
    """Create a cookie-based authentication config.

    Args:
        cookies: Dict of cookie name → value pairs.
        *domains: Domains this auth applies to.

    Returns:
        Auth config dict compatible with EngineConfig.auth.
    """
    d: dict = {"type": "cookie", "cookies": dict(cookies)}
    if domains:
        d["domains"] = list(domains)
    return d


def query_auth(
    params: Dict[str, str],
    *domains: str,
) -> dict:
    """Create a query parameter authentication config.

    Args:
        params: Dict of query parameter name → value pairs.
        *domains: Domains this auth applies to.

    Returns:
        Auth config dict compatible with EngineConfig.auth.
    """
    d: dict = {"type": "query", "query_params": dict(params)}
    if domains:
        d["domains"] = list(domains)
    return d


def api_key_header(
    header_name: str,
    api_key: str,
    *domains: str,
) -> dict:
    """Create an API key header authentication config.

    Convenience wrapper around header_auth for single API key headers.

    Args:
        header_name: Header name (e.g., "X-API-Key").
        api_key: API key value.
        *domains: Domains this auth applies to.

    Returns:
        Auth config dict compatible with EngineConfig.auth.
    """
    return header_auth({header_name: api_key}, *domains)
