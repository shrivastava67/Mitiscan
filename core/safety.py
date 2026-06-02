"""Pre-flight safety gates — target scoping, RFC-1918 guards, deny list.

Why: a misfired aggressive scan against the wrong host is a career event.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .errors import ScopeError

__all__ = ["normalize_target", "is_in_scope", "DEFAULT_DENY", "ScopeDecision"]


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Networks we refuse to scan unless the caller explicitly waives the guard.
# These are the easy "oh no I scanned my prod" cases.
DEFAULT_DENY: tuple[str, ...] = (
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # reserved
    "::1/128",            # IPv6 loopback
    "fe80::/10",          # IPv6 link-local
    "ff00::/8",           # IPv6 multicast
)


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    canonical: str


def normalize_target(raw: str) -> str:
    """Strip schemes, ports, whitespace. Returns the canonical host/CIDR.

    Raises ScopeError on garbage input.
    """
    if not raw or not raw.strip():
        raise ScopeError("empty target")
    t = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    # Strip path/query (after `/`) unless input is a CIDR.
    if "/" in t and not _is_ip_or_cidr(t):
        t = t.split("/", 1)[0]
    # Strip :port for v4/hostnames (v6 has many colons; leave alone).
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    if not (_DOMAIN_RE.match(t) or _is_ip_or_cidr(t)):
        raise ScopeError(f"target not a valid hostname / IP / CIDR: {raw!r}")
    return t


def _is_ip_or_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False


def is_in_scope(
    target: str,
    allow_private: bool = False,
    deny: tuple[str, ...] = DEFAULT_DENY,
) -> ScopeDecision:
    """Return whether `target` is safe to scan under current policy."""
    canonical = normalize_target(target)
    try:
        net = ipaddress.ip_network(canonical, strict=False)
    except ValueError:
        # Hostname — no network policy to check here.
        return ScopeDecision(True, "hostname accepted", canonical)

    for cidr in deny:
        deny_net = ipaddress.ip_network(cidr)
        if deny_net.version != net.version:
            continue
        if net.subnet_of(deny_net):
            return ScopeDecision(False, f"target in deny range {cidr}", canonical)
    if net.is_private and not allow_private:
        return ScopeDecision(
            False,
            "target is RFC-1918 / private. pass --allow-private to override.",
            canonical,
        )
    return ScopeDecision(True, "in scope", canonical)
