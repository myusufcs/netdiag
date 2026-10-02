"""Reachability ICMP: packet loss + latensi/jitter."""
from __future__ import annotations

import re

from ..model import Result, Verdict
from ..registry import Probe
from ..util import run, which

RE_LOSS = re.compile(r"(\d+(?:\.\d+)?)% packet loss")
RE_RTT = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)")


def parse_ping(text: str) -> dict:
    """Urai keluaran `ping` Linux: loss%, min/avg/max/mdev (ms)."""
    out = {"loss": None, "min": None, "avg": None, "max": None, "mdev": None}
    m = RE_LOSS.search(text or "")
    if m:
        out["loss"] = float(m.group(1))
    m = RE_RTT.search(text or "")
    if m:
        out["min"], out["avg"], out["max"], out["mdev"] = (float(x) for x in m.groups())
    return out


class ReachProbe(Probe):
    NAME = "reach"
    TITLE = "Reachability ICMP (packet loss & latensi)"

    def run(self, target, ctx):
        host = ctx.get("host") or target
        count = ctx.get("count", 5)
        res = Result(self.NAME, self.TITLE)
        if not which("ping"):
            res.verdict = Verdict.SKIP
            res.summary = "ping tidak terpasang"
            return res

        code, out = run(["ping", "-c", str(count), "-W", "2", "-n", host],
                        timeout=count * 3 + 10)
        stats = parse_ping(out)
        if stats["loss"] is None:
            res.verdict = Verdict.SKIP
            res.summary = "tidak bisa membaca statistik ping"
            res.notes.append(out.splitlines()[-1] if out else "")
            return res

        res.add("paket terkirim", count)
        res.add("packet loss", f"{stats['loss']:.0f}%")
        if stats["avg"] is not None:
            res.add("RTT min/avg/max", f"{stats['min']:.1f} / {stats['avg']:.1f} / {stats['max']:.1f} ms")
            res.add("jitter (mdev)", f"{stats['mdev']:.2f} ms")

        if stats["loss"] >= 50:
            res.verdict = Verdict.FAIL
            res.summary = f"loss {stats['loss']:.0f}% — target praktis tidak terjangkau"
        elif stats["loss"] > 0:
            res.verdict = Verdict.WARN
            res.summary = f"loss {stats['loss']:.0f}% — koneksi tidak stabil"
        elif stats["avg"] is not None and stats["avg"] > 150:
            res.verdict = Verdict.WARN
            res.summary = f"latensi tinggi ({stats['avg']:.0f} ms rata-rata)"
        else:
            res.summary = (f"stabil — loss 0%, rata-rata {stats['avg']:.1f} ms"
                           if stats["avg"] is not None else "stabil")
        if stats["mdev"] is not None and stats["mdev"] > 20:
            res.notes.append(f"jitter {stats['mdev']:.1f} ms — bisa mengganggu VoIP/video")
        return res
