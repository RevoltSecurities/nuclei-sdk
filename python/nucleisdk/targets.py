"""Target utility functions for the nuclei-sdk Python client."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import List


def targets_from_file(path: str) -> List[str]:
    """Read targets from a file, one per line.

    Skips empty lines and lines starting with '#'.

    Args:
        path: Path to the targets file.

    Returns:
        List of target strings.
    """
    targets = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    return targets


def targets_from_cidr(cidr: str) -> List[str]:
    """Expand a CIDR notation to individual IP addresses.

    For networks larger than /31, excludes network and broadcast addresses.

    Args:
        cidr: CIDR notation string (e.g., "192.168.1.0/24").

    Returns:
        List of IP address strings.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if network.prefixlen <= 30:
        return [str(ip) for ip in network.hosts()]
    return [str(ip) for ip in network]


def targets_from_cidrs(cidrs: List[str]) -> List[str]:
    """Expand multiple CIDR notations to individual IP addresses.

    Args:
        cidrs: List of CIDR notation strings.

    Returns:
        List of IP address strings.
    """
    targets = []
    for cidr in cidrs:
        targets.extend(targets_from_cidr(cidr))
    return targets


def ip_range(start_ip: str, end_ip: str) -> List[str]:
    """Generate a list of IP addresses in a range (inclusive).

    Args:
        start_ip: Starting IP address.
        end_ip: Ending IP address.

    Returns:
        List of IP address strings.

    Raises:
        ValueError: If start_ip > end_ip or IPs are different versions.
    """
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    if start.version != end.version:
        raise ValueError(
            f"IP version mismatch: {start_ip} (v{start.version}) vs {end_ip} (v{end.version})"
        )
    if int(start) > int(end):
        raise ValueError(f"start_ip ({start_ip}) is greater than end_ip ({end_ip})")
    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
