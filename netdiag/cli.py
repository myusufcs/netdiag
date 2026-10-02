"""CLI netdiag.

    python3 -m netdiag example.com
    python3 -m netdiag 1.1.1.1 --only reach,path
    python3 -m netdiag example.com --ports 22,443,3306
    python3 -m netdiag example.com --out laporan --format md,json
    python3 -m netdiag --list
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from . import __version__, report as report_mod
from .model import Report, Verdict
from .registry import describe, load_all, select
from .util import resolve


def _split(v: str | None) -> list[str] | None:
    return [x.strip() for x in v.split(",") if x.strip()] if v else None


def run_diag(target: str, only=None, skip=None, ports=None, count=5,
             path="/", timeout=30, progress=None) -> Report:
    load_all()
    host = target
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split(":")[0]

    rep = Report(target=target, address=resolve(host) or "",
                 started=dt.datetime.now().isoformat(timespec="seconds"))
    ctx = {"host": host, "ports": ports, "count": count, "path": path,
           "timeout": timeout}

    for cls in select(only, skip):
        try:
            res = cls().run(target, ctx)
        except Exception as exc:                       # noqa: BLE001
            rep.errors.append(f"{cls.NAME}: {type(exc).__name__}: {exc}")
            continue
        rep.results.append(res)
        if progress:
            progress(res)
    rep.finished = dt.datetime.now().isoformat(timespec="seconds")
    return rep


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="netdiag",
        description="Diagnosa konektivitas jaringan sekali jalan (DNS, ICMP, path, MTU, TLS, HTTP, port)")
    ap.add_argument("target", nargs="?", help="host, domain, atau URL")
    ap.add_argument("--only", help="probe tertentu (dipisah koma)")
    ap.add_argument("--skip", help="lewati probe ini")
    ap.add_argument("--ports", help="daftar port TCP yang diuji (mis. 22,80,443)")
    ap.add_argument("--count", type=int, default=5, help="jumlah paket ping (default 5)")
    ap.add_argument("--path", default="/", help="path HTTP (default /)")
    ap.add_argument("--out", help="folder laporan")
    ap.add_argument("--format", help="text,md,json")
    ap.add_argument("--json", action="store_true", help="cetak JSON ke stdout")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--list", action="store_true", help="daftar probe")
    ap.add_argument("--version", action="version", version=f"netdiag {__version__}")
    args = ap.parse_args(argv)

    if args.list:
        load_all()
        print(f"{'PROBE':<9}{'DEFAULT':<9}DESKRIPSI")
        for name, default, title in describe():
            tanda = "ya" if default else "-"
            print(f"{name:<9}{tanda:<9}{title}")
        return 0

    if not args.target:
        print("target wajib (contoh: netdiag example.com)", file=sys.stderr)
        return 2

    ports = [int(p) for p in _split(args.ports)] if args.ports else None

    def progress(res) -> None:
        if not args.quiet:
            print(f"  {res.verdict.symbol} {res.probe:<7} {res.summary}", file=sys.stderr)

    rep = run_diag(args.target, _split(args.only), _split(args.skip), ports,
                   args.count, args.path, progress=progress if not args.json else None)

    if args.json and not args.out:
        print(report_mod.to_json(rep))
    elif not args.out:
        print(report_mod.to_text(rep))

    if args.out:
        formats = _split(args.format) or ["text", "md", "json"]
        for p in report_mod.write(Path(args.out).expanduser(), rep, formats):
            print(f"  -> {p}")

    return 1 if rep.worst is Verdict.FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
