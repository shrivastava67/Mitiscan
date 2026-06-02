"""Target scope — shared state every module reads/writes."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass
class Scope:
    raw_target: str
    domains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    cidrs: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    live_hosts: set[str] = field(default_factory=set)
    http_urls: set[str] = field(default_factory=set)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    tech_stack: dict[str, list[str]] = field(default_factory=dict)
    cnames: dict[str, str] = field(default_factory=dict)
    discovered_params: dict[str, list[str]] = field(default_factory=dict)
    api_schemas: dict[str, str] = field(default_factory=dict)
    is_internal: bool = False
    no_brute: bool = False
    org_name: str | None = None

    def classify(self) -> None:
        """Parse raw_target into domain / IP / CIDR buckets + internal flag."""
        t = self.raw_target.strip()
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses == 1:
                self.ips.add(str(net.network_address))
            else:
                self.cidrs.add(str(net))
            self.is_internal = net.is_private
        except ValueError:
            self.domains.add(t)
            self.org_name = t.split(".")[0]

    def has_http_surface(self) -> bool:
        return bool(self.http_urls)

    def has_open_port(self, port: int) -> bool:
        return any(port in plist for plist in self.open_ports.values())
