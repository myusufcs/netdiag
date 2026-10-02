"""TLS: handshake, versi, cipher, ALPN, dan masa berlaku sertifikat."""
from __future__ import annotations

import datetime as dt
import socket
import ssl
import time

from ..model import Result, Verdict
from ..registry import Probe


def handshake(host: str, port: int = 443, timeout: float = 8.0,
              alpn: tuple[str, ...] = ("h2", "http/1.1")) -> dict:
    ctx = ssl.create_default_context()
    try:
        ctx.set_alpn_protocols(list(alpn))
    except NotImplementedError:
        pass
    t0 = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            ms = (time.perf_counter() - t0) * 1000
            cert = ss.getpeercert() or {}
            return {
                "ms": ms,
                "version": ss.version(),
                "cipher": (ss.cipher() or [None, None])[0],
                "alpn": ss.selected_alpn_protocol(),
                "cert": cert,
            }


def parse_cert_date(value: str) -> dt.datetime | None:
    """notAfter dari Python berbentuk 'Sep  2 12:00:00 2027 GMT'."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return dt.datetime.strptime(value, fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


class TlsProbe(Probe):
    NAME = "tls"
    TITLE = "TLS handshake & sertifikat"

    def run(self, target, ctx):
        host = ctx.get("host") or target
        port = ctx.get("tls_port", 443)
        res = Result(self.NAME, self.TITLE)
        try:
            info = handshake(host, port)
        except ssl.SSLCertVerificationError as exc:
            res.verdict = Verdict.FAIL
            res.summary = "sertifikat tidak tervalidasi"
            res.notes.append(str(exc)[:220])
            return res
        except Exception as exc:                       # noqa: BLE001
            res.verdict = Verdict.SKIP
            res.summary = f"handshake gagal: {type(exc).__name__}"
            res.notes.append(f"{exc} (port {port}) — kalau memang bukan layanan TLS, lewati probe ini")
            return res

        res.add("versi TLS", info["version"])
        res.add("cipher", info["cipher"])
        res.add("ALPN", info["alpn"] or "—")
        res.add("waktu handshake", f"{info['ms']:.0f} ms")

        cert = info["cert"]
        subject = dict(x[0] for x in cert.get("subject", [])).get("commonName", "?")
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "?")
        res.add("subject", subject)
        res.add("penerbit", issuer)

        exp = parse_cert_date(cert.get("notAfter", ""))
        if exp:
            days = (exp - dt.datetime.now(dt.timezone.utc)).days
            res.add("kedaluwarsa", f"{exp.date()} ({days} hari lagi)")
            if days < 0:
                res.verdict = Verdict.FAIL
                res.summary = f"sertifikat SUDAH kedaluwarsa {abs(days)} hari lalu"
                return res
            if days < 30:
                res.verdict = Verdict.WARN
                res.summary = f"sertifikat kedaluwarsa dalam {days} hari"

        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        if sans:
            res.add("SAN (contoh)", ", ".join(sans[:5]))

        if info["version"] and info["version"] < "TLSv1.2":
            res.verdict = Verdict.WARN
            res.summary = f"protokol lama: {info['version']}"
        elif res.verdict is Verdict.OK:
            res.summary = f"{info['version']}, sertifikat valid"
        if info["ms"] > 1500:
            res.notes.append(f"handshake lambat ({info['ms']:.0f} ms) — cek RTT dan beban server")
        return res
