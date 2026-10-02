"""Penyusun laporan netdiag: teks, Markdown, JSON."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .model import Report, Verdict


def to_text(r: Report) -> str:
    bar = "=" * 72
    L = [bar, f"  DIAGNOSA JARINGAN — {r.target}", bar]
    if r.address:
        L.append(f"alamat   : {r.address}")
    L.append(f"waktu    : {r.started} → {r.finished}")
    L.append(f"kesimpulan: {r.worst.symbol} {r.worst.value}"
             f"   (OK {r.count(Verdict.OK)} · WARN {r.count(Verdict.WARN)}"
             f" · FAIL {r.count(Verdict.FAIL)} · SKIP {r.count(Verdict.SKIP)})")
    L.append("")

    problems = r.problems()
    if problems:
        L.append("PERLU DIPERHATIKAN")
        L.append("-" * 72)
        for res in problems:
            L.append(f"{res.verdict.symbol} [{res.probe}] {res.title}")
            L.append(f"    {res.summary}")
            for n in res.notes:
                L.append(f"    catatan: {n}")
            L.append("")

    L.append("RINCIAN")
    L.append("-" * 72)
    for res in sorted(r.results, key=lambda x: x.probe):
        L.append(f"{res.verdict.symbol} {res.probe:<8} {res.summary}")
        for m in res.metrics:
            L.append(f"      {m.label:<28} {m.value}")
        L.append("")
    if r.errors:
        L.append("ERROR")
        L.append("-" * 72)
        L.extend(f"  {e}" for e in r.errors)
    return "\n".join(L)


def to_markdown(r: Report) -> str:
    L = [f"# Diagnosa Jaringan — `{r.target}`", ""]
    if r.address:
        L.append(f"- **Alamat**: `{r.address}`")
    L.append(f"- **Waktu**: {r.started} → {r.finished}")
    L.append(f"- **Kesimpulan**: **{r.worst.value}**")
    L.append("")
    L.append("| OK | WARN | FAIL | SKIP |")
    L.append("|---|---|---|---|")
    L.append(f"| {r.count(Verdict.OK)} | {r.count(Verdict.WARN)} | "
             f"{r.count(Verdict.FAIL)} | {r.count(Verdict.SKIP)} |")
    L.append("")
    probs = r.problems()
    if probs:
        L.append("## Perlu diperhatikan")
        L.append("")
        L.append("| Verdict | Probe | Ringkasan | Catatan |")
        L.append("|---|---|---|---|")
        for res in probs:
            notes = " ".join(res.notes).replace("|", "\\|")[:200]
            L.append(f"| {res.verdict.value} | `{res.probe}` | {res.summary} | {notes} |")
        L.append("")
    L.append("## Rincian")
    for res in sorted(r.results, key=lambda x: x.probe):
        L.append("")
        L.append(f"### {res.verdict.symbol} {res.probe} — {res.title}")
        L.append("")
        L.append(f"_{res.summary}_")
        L.append("")
        if res.metrics:
            L.append("| Metrik | Nilai |")
            L.append("|---|---|")
            for m in res.metrics:
                L.append(f"| {m.label} | {m.value.replace('|', chr(92) + '|')} |")
        for n in res.notes:
            L.append(f"\n> {n}")
    return "\n".join(L)


def to_json(r: Report) -> str:
    return json.dumps(r.as_dict(), indent=2, ensure_ascii=False)


def write(outdir: Path, r: Report, formats: list[str]) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() or c in ".-" else "-" for c in r.target)
    base = f"netdiag-{safe}-{stamp}"
    written = []
    for fmt, renderer, ext in (("text", to_text, "txt"), ("md", to_markdown, "md"),
                               ("json", to_json, "json")):
        if fmt in formats:
            p = outdir / f"{base}.{ext}"
            p.write_text(renderer(r), encoding="utf-8")
            written.append(p)
    return written
