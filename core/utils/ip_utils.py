"""
core/utils/ip_utils.py — Shared IP address classification utilities.

Single authoritative source for private/external IP range checks.
Used by: intelligence modules, detection modules.

Private ranges covered (RFC 1918 + loopback):
    10.0.0.0/8
    172.16.0.0/12  (172.16.x.x – 172.31.x.x)
    192.168.0.0/16
    127.0.0.0/8
"""

from __future__ import annotations

_PRIVATE_PREFIXES: tuple[str, ...] = (
    "10.",
    "127.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)


def is_private(ip: str) -> bool:
    """Return True if ip falls within a private/loopback range."""
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def is_external(ip: str) -> bool:
    """Return True if ip is non-empty and not in a private/loopback range."""
    return bool(ip) and not is_private(ip)
