"""Resolusi DNS + konsistensi antar resolver."""
from __future__ import annotations

import time

from ..model import Result, Verdict
from ..registry import Probe
from ..util import run, which

RECORDS = ["A", "AAAA", "MX", "NS", "TXT"]


def parse_dig(text: str) -> list[str]:
    """Ambil jawaban dari keluaran `dig +short`."""
    out = []
    for ln in (text or "").splitlines():
        s = ln.strip().strip('"')
        if s and not s.startswith(";"):
            out.append(s)
    return out


class DnsProbe(Probe):
    NAME = "dns"
    TITLE = "Resolusi DNS & konsistensi antar resolver"

    def run(self, target, ctx):
        host = ctx.get("host") or target
        res = Result(self.NAME, self.TITLE)
        if not which("dig"):
            res.verdict = Verdict.SKIP
            res.summary = "dig tidak terpasang"
            return res

        t0 = time.perf_counter()
        records: dict[str, list[str]] = {}
        for rtype in RECORDS:
            code, out = run(["dig", "+time=3", "+tries=1", "+short", host, rtype], timeout=15)
            records[rtype] = parse_dig(out) if code == 0 else []
        elapsed = (time.perf_counter() - t0) * 1000

        for rtype in RECORDS:
            vals = records[rtype]
            res.add(rtype, ", ".join(vals[:4]) if vals else "—")

        a_records = records["A"]
        if not a_records and not records["AAAA"]:
            res.verdict = Verdict.FAIL
            res.summary = "tidak ada jawaban A maupun AAAA — nama tidak ter-resolve"
            res.notes.append("Cek ejaan nama, server DNS yang dipakai, dan apakah domain aktif.")
            return res

        # konsistensi: tanyakan A ke dua resolver publik yang berbeda
        answers = {}
        for resolver in ("1.1.1.1", "8.8.8.8"):
            code, out = run(["dig", f"@{resolver}", "+time=3", "+tries=1", "+short", host, "A"],
                            timeout=15)
            if code == 0:
                answers[resolver] = sorted(parse_dig(out))
        if len(answers) == 2:
            vals = list(answers.values())
            if vals[0] != vals[1]:
                res.verdict = Verdict.WARN
                res.summary = "jawaban berbeda antar resolver (kemungkinan split-horizon / cache basi)"
                res.notes.append(f"1.1.1.1 → {vals[0]}; 8.8.8.8 → {vals[1]}")
            else:
                res.summary = f"{len(a_records)} alamat A, konsisten di dua resolver"
        else:
            res.summary = f"{len(a_records)} alamat A (konsistensi tidak bisa diperiksa)"

        if elapsed > 2000:
            res.verdict = Verdict.WARN if res.verdict is Verdict.OK else res.verdict
            res.notes.append(f"resolusi total lambat: {elapsed:.0f} ms")
        res.add("waktu resolusi (5 tipe)", f"{elapsed:.0f} ms")
        return res
