"""MTU path: cari MTU terbesar yang lolos tanpa fragmentasi (DF)."""
from __future__ import annotations

from ..model import Result, Verdict
from ..registry import Probe
from ..util import run, which

HEADERS = 28          # IPv4 20 + ICMP 8


def mtu_ok(host: str, payload: int, timeout: int = 6) -> bool | None:
    """True bila paket payload byte lolos dengan DF. None bila tidak bisa diuji."""
    if not which("ping"):
        return None
    code, out = run(["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(payload), "-n", host],
                    timeout=timeout)
    low = (out or "").lower()
    if "frag needed" in low or "message too long" in low or "packet too big" in low:
        return False
    if code == 0 and " 1 received" in out:
        return True
    if "100% packet loss" in out:
        return False
    return None


class MtuProbe(Probe):
    NAME = "mtu"
    TITLE = "MTU path (deteksi fragmentasi / black-hole MTU)"

    def run(self, target, ctx):
        host = ctx.get("host") or target
        res = Result(self.NAME, self.TITLE)

        probe = mtu_ok(host, 1472)          # 1472 + 28 = 1500
        if probe is None:
            res.verdict = Verdict.SKIP
            res.summary = "tidak bisa menguji MTU (ping -M do tidak didukung)"
            return res
        if probe:
            res.add("MTU path", 1500)
            res.summary = "MTU 1500 (standar Ethernet) — tidak ada indikasi fragmentasi"
            return res

        # binary search MTU antara 576 dan 1500
        lo, hi, best = 548, 1472, None
        while lo <= hi:
            mid = (lo + hi) // 2
            ok = mtu_ok(host, mid)
            if ok:
                best = mid
                lo = mid + 1
            elif ok is False:
                hi = mid - 1
            else:
                break
        if best is None:
            res.verdict = Verdict.WARN
            res.summary = "tidak ada payload DF yang lolos — jalur men-drop paket besar"
            res.notes.append("Indikasi black-hole MTU: ICMP 'frag needed' kemungkinan diblokir.")
            return res

        mtu = best + HEADERS
        res.add("MTU path", mtu)
        res.verdict = Verdict.WARN
        res.summary = f"MTU path hanya {mtu} byte (bukan 1500)"
        res.notes.append("Umum pada jalur PPPoE/VPN. Bila aplikasi menggantung saat data besar, "
                         "sesuaikan MSS clamping di router atau MTU di klien.")
        return res
