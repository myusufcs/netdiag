"""Timing HTTP berlapis (DNS → TCP → TLS → TTFB → total) + rantai redirect."""
from __future__ import annotations

import socket
import ssl
import time

from ..model import Result, Verdict
from ..registry import Probe
from ..util import fmt_ms

MAX_REDIRECT = 5


def _request(host: str, port: int, use_tls: bool, path: str, timeout: float = 10.0) -> dict:
    """Kirim satu permintaan dan ukur tiap fase."""
    t_dns0 = time.perf_counter()
    addr = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)[0][4][0]
    dns_ms = (time.perf_counter() - t_dns0) * 1000

    t_tcp0 = time.perf_counter()
    sock = socket.create_connection((addr, port), timeout=timeout)
    tcp_ms = (time.perf_counter() - t_tcp0) * 1000

    tls_ms = 0.0
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except NotImplementedError:
                pass
            t_tls0 = time.perf_counter()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            tls_ms = (time.perf_counter() - t_tls0) * 1000

        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: netdiag/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        t_req0 = time.perf_counter()
        sock.sendall(req.encode())

        first = sock.recv(1)
        ttfb_ms = (time.perf_counter() - t_req0) * 1000
        chunks = [first]
        while True:
            b = sock.recv(65536)
            if not b:
                break
            chunks.append(b)
        total_ms = (time.perf_counter() - t_req0) * 1000
    finally:
        sock.close()

    data = b"".join(chunks)
    head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
    lines = head.splitlines()
    status = 0
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    location = ""
    for ln in lines[1:]:
        if ln.lower().startswith("location:"):
            location = ln.split(":", 1)[1].strip()

    return {"dns_ms": dns_ms, "tcp_ms": tcp_ms, "tls_ms": tls_ms,
            "ttfb_ms": ttfb_ms, "total_ms": total_ms, "status": status,
            "location": location, "bytes": len(data)}


class HttpProbe(Probe):
    NAME = "http"
    TITLE = "Timing HTTP berlapis + rantai redirect"

    def run(self, target, ctx):
        host = ctx.get("host") or target
        path = ctx.get("path", "/")
        port = 443
        use_tls = True
        res = Result(self.NAME, self.TITLE)

        chain = []
        try:
            for _ in range(MAX_REDIRECT + 1):
                info = _request(host, port, use_tls, path)
                chain.append((host, path, info))
                if info["status"] in (301, 302, 303, 307, 308) and info["location"]:
                    loc = info["location"]
                    if loc.startswith("https://"):
                        loc = loc[len("https://"):]
                    elif loc.startswith("http://"):
                        loc = loc[len("http://"):]
                    nxt = loc.split("/", 1)
                    host = nxt[0]
                    path = "/" + nxt[1] if len(nxt) > 1 else "/"
                    continue
                break
        except Exception as exc:                       # noqa: BLE001
            res.verdict = Verdict.SKIP
            res.summary = f"tidak bisa menghubungi {host}:{port} ({type(exc).__name__})"
            res.notes.append(str(exc)[:200])
            return res

        last = chain[-1][2]
        first = chain[0][2]
        res.add("status akhir", last["status"])
        res.add("rantai redirect", f"{len(chain) - 1}")
        res.add("DNS", fmt_ms(first["dns_ms"]))
        res.add("TCP connect", fmt_ms(first["tcp_ms"]))
        res.add("TLS handshake", fmt_ms(first["tls_ms"]))
        res.add("TTFB", fmt_ms(last["ttfb_ms"]))
        res.add("total", fmt_ms(last["total_ms"]))
        res.add("ukuran respons", f"{last['bytes']} byte")
        for i, (h, p, info) in enumerate(chain, 1):
            res.add(f"langkah {i}", f"{info['status']} — https://{h}{p}")

        if last["status"] >= 500:
            res.verdict = Verdict.FAIL
            res.summary = f"server error HTTP {last['status']}"
        elif last["status"] >= 400:
            res.verdict = Verdict.WARN
            res.summary = f"klien error HTTP {last['status']}"
        elif last["ttfb_ms"] > 1000:
            res.verdict = Verdict.WARN
            res.summary = f"TTFB lambat ({last['ttfb_ms']:.0f} ms)"
        else:
            res.summary = f"HTTP {last['status']}, TTFB {last['ttfb_ms']:.0f} ms"
        if len(chain) - 1 >= MAX_REDIRECT:
            res.verdict = Verdict.WARN
            res.notes.append("rantai redirect panjang (≥5) — perpendek untuk hemat RTT")
        return res
