"""Naming a server a mitmproxy capture connected to: the name a flow's client gave, or
what the device's own DNS said the IP is (see addon.http_hostname)."""

from __future__ import annotations

import time
from dataclasses import dataclass

from mitmproxy.net.dns import types as dns_types


@dataclass(frozen=True)
class Hostname:
    """The best name a capture holds for a server, and where it came from."""
    name: str
    source: str              # hostname.source: host, authority, sni, dns, ip or connect
    dns_flow: str = ""       # the lookup that named it, when source is "dns"
    candidates: tuple[str, ...] = ()  # the other names that lookup's IP had


class DnsNames:
    """What the device's own DNS answers said each IP is, for naming a connection that
    carries no name of its own (no Host, no SNI). Only A/AAAA answers count, keyed to the
    name the client asked for — not the CNAME target it resolved through."""

    _KEEP = 16  # answers remembered per IP; a CDN address can stand for many names

    def __init__(self) -> None:
        self._by_ip: dict[str, list[tuple[float, str, str]]] = {}

    def learn(self, flow) -> None:
        resp = flow.response
        if not resp or not resp.questions:
            return
        name = resp.questions[0].name.rstrip(".")
        ts = resp.timestamp or time.time()
        for rr in resp.answers:
            if rr.type not in (dns_types.A, dns_types.AAAA):
                continue
            try:
                ip = str(rr.ipv4_address if rr.type == dns_types.A else rr.ipv6_address)
            except ValueError:
                continue
            seen = self._by_ip.setdefault(ip, [])
            seen.append((ts, name, flow.id))
            del seen[:-self._KEEP]

    def lookup(self, ip: str, before: float) -> Hostname | None:
        """The name of the most recent answer for ip given before the connection opened,
        with the other names that IP was given as candidates."""
        answers = [a for a in self._by_ip.get(ip, ()) if not before or a[0] <= before]
        if not answers:
            return None
        _, name, flow_id = max(answers, key=lambda a: a[0])
        others = tuple(sorted({n for _, n, _ in answers} - {name}))
        return Hostname(name, "dns", flow_id, others)
