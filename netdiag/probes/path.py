"""Path per-hop lewat mtr (ASN + loss + latensi per hop)."""
from __future__ import annotations

import re

from ..model import Result, Verdict
from ..registry import Probe
from ..util import run, which

RE_HOP = re.compile(
    r"^\s*(\d+)\.\s+(AS\S+|AS\?\?\?)\s+(\S+)\s+([\d.]+)%\s+(\d+)\s+"
    r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)")


def parse_mtr(text: str) -> list[dict]:
    """Urai `mtr -r -w -c N -z` menjadi daftar hop."""
    hops = []
    for ln in (text or "").splitlines():
        m = RE_HOP.match(ln)
        if not m:
            continue
        hops.append({
            "hop": int(m.group(1)),
            "asn": m.group(2),
            "host": m.group(3),
            "loss": float(m.group(4)),
            "sent": int(m.group(5)),
            "last": float(m.group(6)),
            "avg": float(m.group(7)),
            "best": float(m.group(8)),
            "worst": float(m.group(9)),
            "stdev": float(m.group(10)),
        })
    return hops


class PathProbe(Probe):
    NAME = "path"
    TITLE = "Jalur per-hop (mtr) — di mana masalahnya"

    def run(self, target, ctx):
        host = ctx.get("host") or target
        res = Result(self.NAME, self.TITLE)
        if not which("mtr"):
            res.verdict = Verdict.SKIP
            res.summary = "mtr tidak terpasang"
            return res

        code, out = run(["mtr", "-r", "-w", "-c", "5", "-z", "-n", host], timeout=60)
        hops = parse_mtr(out)
        if not hops:
            res.verdict = Verdict.SKIP
            res.summary = "tidak bisa membaca laporan mtr"
            return res

        res.add("jumlah hop", len(hops))
        for h in hops:
            res.add(f"hop {h['hop']} {h['host']} ({h['asn']})",
                    f"loss {h['loss']:.0f}% · avg {h['avg']:.1f} ms")

        last = hops[-1]
        mid_lossy = [h for h in hops[:-1] if h["loss"] >= 20]
        if last["loss"] >= 50:
            res.verdict = Verdict.FAIL
            res.summary = f"hop terakhir kehilangan {last['loss']:.0f}% paket"
        elif mid_lossy:
            res.verdict = Verdict.WARN
            h = mid_lossy[0]
            res.summary = (f"loss {h['loss']:.0f}% di hop {h['hop']} ({h['host']}) — "
                           "perhatikan apakah berlanjut ke hop berikutnya")
            res.notes.append("Loss yang muncul lalu hilang di hop berikutnya biasanya "
                             "rate-limit ICMP, bukan gangguan nyata.")
        elif last["avg"] > 150:
            res.verdict = Verdict.WARN
            res.summary = f"latensi hop terakhir tinggi ({last['avg']:.0f} ms)"
        else:
            res.summary = f"{len(hops)} hop, tanpa loss berarti"
        if last["stdev"] > 30:
            res.notes.append(f"jitter hop terakhir {last['stdev']:.0f} ms")
        return res
