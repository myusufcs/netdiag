"""Cek port TCP: terbuka/tertutup + waktu connect."""
from __future__ import annotations

from ..model import Result, Verdict
from ..registry import Probe
from ..util import fmt_ms, tcp_connect_ms

DEFAULT_PORTS = [22, 53, 80, 443, 3306, 5432, 6379, 8080]
NAMES = {22: "ssh", 53: "dns", 80: "http", 443: "https", 3306: "mysql",
         5432: "postgres", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
         25: "smtp", 587: "submission", 993: "imaps", 27017: "mongodb",
         9200: "elastic", 11211: "memcached", 2375: "docker-api"}


class PortsProbe(Probe):
    NAME = "ports"
    TITLE = "Port TCP (terbuka/tertutup + waktu connect)"
    DEFAULT = False        # hanya jalan bila diminta eksplisit (--only ports / --ports)

    def run(self, target, ctx):
        host = ctx.get("host") or target
        ports = ctx.get("ports") or DEFAULT_PORTS
        res = Result(self.NAME, self.TITLE)
        terbuka = []
        for port in ports:
            ms = tcp_connect_ms(host, port, timeout=3)
            label = NAMES.get(port, str(port))
            if ms is None:
                res.add(f"{port}/{label}", "tertutup")
            else:
                terbuka.append(port)
                res.add(f"{port}/{label}", f"terbuka ({fmt_ms(ms)})")
        res.add("total port diuji", len(ports))
        res.add("port terbuka", len(terbuka))
        if not terbuka:
            res.verdict = Verdict.WARN
            res.summary = "tidak ada port yang terbuka dari daftar uji"
        else:
            res.summary = f"{len(terbuka)} port terbuka: {', '.join(str(p) for p in terbuka)}"
            remote = [p for p in terbuka if p in (3306, 5432, 6379, 9200, 11211, 2375, 27017)]
            if remote:
                res.verdict = Verdict.WARN
                res.notes.append(
                    f"port basis data/cache terbuka: {', '.join(str(p) for p in remote)} — "
                    "pastikan hanya dari jaringan tepercaya")
        return res
