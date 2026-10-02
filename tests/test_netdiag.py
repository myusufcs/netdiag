"""Uji netdiag: parser keluaran tool, verdict, laporan, dan CLI.

Test ini sengaja TIDAK bergantung pada jaringan — parser diuji dengan keluaran
yang direkam, sehingga tetap jalan di CI tanpa koneksi internet.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netdiag import cli, report as report_mod                        # noqa: E402
from netdiag.model import Metric, Report, Result, Verdict            # noqa: E402
from netdiag.probes.dns import parse_dig                             # noqa: E402
from netdiag.probes.path import parse_mtr                            # noqa: E402
from netdiag.probes.reach import parse_ping                          # noqa: E402
from netdiag.probes.tls import parse_cert_date                       # noqa: E402
from netdiag.registry import ALL_PROBES, describe, load_all, select  # noqa: E402

PING_OK = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=4.10 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=4.30 ms

--- 1.1.1.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 3.929/4.227/4.525/0.298 ms
"""

PING_LOSS = """PING host (10.0.0.9) 56(84) bytes of data.

--- host ping statistics ---
10 packets transmitted, 5 received, 50% packet loss, time 9012ms
rtt min/avg/max/mdev = 120.100/220.500/310.900/45.000 ms
"""

MTR_OK = """Start: 2026-10-02T14:04:43+0700
HOST: parkee                          Loss%   Snt   Last   Avg  Best  Wrst StDev
  1. AS???    _gateway                 0.0%     5    9.1   7.1   5.3   9.1   1.9
  2. AS58495  157.15.209.153           0.0%     5    2.9   3.8   2.9   4.5   0.8
  3. AS13335  1.1.1.1                  0.0%     5    4.1   4.2   3.9   4.5   0.2
"""

MTR_LOSSY = """HOST: parkee                          Loss%   Snt   Last   Avg  Best  Wrst StDev
  1. AS???    _gateway                 0.0%     5    9.1   7.1   5.3   9.1   1.9
  2. AS64500  10.10.46.17             40.0%     5   60.0  61.4  55.0  70.0  10.0
  3. AS64500  203.0.113.9             45.0%     5   62.0  63.0  58.0  72.0  11.0
"""


class TestParsers(unittest.TestCase):
    def test_parse_ping_sehat(self):
        s = parse_ping(PING_OK)
        self.assertEqual(s["loss"], 0.0)
        self.assertAlmostEqual(s["avg"], 4.227, places=2)
        self.assertAlmostEqual(s["mdev"], 0.298, places=2)

    def test_parse_ping_loss(self):
        s = parse_ping(PING_LOSS)
        self.assertEqual(s["loss"], 50.0)
        self.assertAlmostEqual(s["avg"], 220.5, places=1)

    def test_parse_ping_tidak_kenal(self):
        s = parse_ping("ping: tidak ada")
        self.assertIsNone(s["loss"])

    def test_parse_dig(self):
        text = "104.20.23.154\n172.66.0.227\n"
        self.assertEqual(parse_dig(text), ["104.20.23.154", "172.66.0.227"])
        self.assertEqual(parse_dig('  "v=spf1 -all"  '), ["v=spf1 -all"])
        self.assertEqual(parse_dig("\n\n"), [])

    def test_parse_mtr(self):
        hops = parse_mtr(MTR_OK)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[2]["host"], "1.1.1.1")
        self.assertEqual(hops[2]["asn"], "AS13335")
        self.assertEqual(hops[2]["loss"], 0.0)

    def test_parse_mtr_lossy(self):
        hops = parse_mtr(MTR_LOSSY)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[1]["loss"], 40.0)

    def test_parse_cert_date(self):
        d = parse_cert_date("Sep  2 12:00:00 2027 GMT")
        self.assertIsNotNone(d)
        self.assertEqual(d.year, 2027)
        self.assertEqual(d.tzinfo, dt.timezone.utc)
        self.assertIsNone(parse_cert_date("bukan tanggal"))


class TestModel(unittest.TestCase):
    def _rep(self) -> Report:
        r = Report(target="contoh", started="a", finished="b")
        r.results = [
            Result("dns", "DNS", Verdict.OK, "bagus", [Metric("A", "1.2.3.4")]),
            Result("reach", "ICMP", Verdict.WARN, "loss kecil"),
            Result("tls", "TLS", Verdict.FAIL, "sertifikat kedaluwarsa"),
            Result("mtu", "MTU", Verdict.SKIP, "tidak bisa diuji"),
        ]
        return r

    def test_worst_dan_problems(self):
        r = self._rep()
        self.assertIs(r.worst, Verdict.FAIL)
        self.assertEqual([x.probe for x in r.problems()], ["tls", "reach"])

    def test_worst_tanpa_fail(self):
        r = self._rep()
        r.results = [x for x in r.results if x.probe != "tls"]
        self.assertIs(r.worst, Verdict.WARN)

    def test_serialisasi(self):
        d = self._rep().as_dict()
        self.assertEqual(d["verdict"], "FAIL")
        self.assertEqual(d["summary"]["OK"], 1)
        json.dumps(d)


class TestRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        load_all()

    def test_probe_terdaftar(self):
        names = [p.NAME for p in ALL_PROBES]
        self.assertEqual(len(names), len(set(names)))
        for wajib in ("dns", "reach", "path", "mtu", "tls", "http", "ports"):
            self.assertIn(wajib, names)

    def test_default_tidak_menyertakan_ports(self):
        self.assertNotIn("ports", [c.NAME for c in select()])
        self.assertIn("ports", [c.NAME for c in select(["ports"])])

    def test_only_dan_skip(self):
        self.assertEqual([c.NAME for c in select(["dns", "reach"])], ["dns", "reach"])
        skip = [c.NAME for c in select(None, ["path", "mtu"])]
        self.assertNotIn("path", skip)
        self.assertIn("dns", skip)

    def test_describe(self):
        rows = describe()
        self.assertTrue(any(n == "ports" and d is False for n, d, _ in rows))


class TestReport(unittest.TestCase):
    def _rep(self) -> Report:
        r = Report(target="contoh.id", address="1.2.3.4", started="a", finished="b")
        r.results = [Result("dns", "DNS", Verdict.WARN, "resolve lambat",
                            [Metric("A", "1.2.3.4")], ["catatan uji"])]
        return r

    def test_text(self):
        t = report_mod.to_text(self._rep())
        self.assertIn("DIAGNOSA JARINGAN", t)
        self.assertIn("resolve lambat", t)
        self.assertIn("catatan uji", t)

    def test_markdown(self):
        md = report_mod.to_markdown(self._rep())
        self.assertIn("| Verdict | Probe |", md)
        self.assertIn("`dns`", md)

    def test_json(self):
        d = json.loads(report_mod.to_json(self._rep()))
        self.assertEqual(d["target"], "contoh.id")
        self.assertEqual(d["results"][0]["metrics"][0]["label"], "A")

    def test_write(self):
        with tempfile.TemporaryDirectory() as td:
            files = report_mod.write(Path(td), self._rep(), ["text", "md", "json"])
            self.assertEqual(len(files), 3)
            for f in files:
                self.assertTrue(f.stat().st_size > 0)


class TestCli(unittest.TestCase):
    def test_list(self):
        self.assertEqual(cli.main(["--list"]), 0)

    def test_tanpa_target(self):
        self.assertEqual(cli.main([]), 2)

    def test_host_tidak_valid_tidak_melempar(self):
        """Tidak boleh crash: harus melaporkan SKIP/FAIL dengan rapi."""
        with tempfile.TemporaryDirectory() as td:
            code = cli.main(["tidak-ada-host.invalid", "--only", "dns",
                             "--out", td, "--format", "json"])
            self.assertIn(code, (0, 1))
            data = json.loads(next(Path(td).glob("netdiag-*.json")).read_text())
            self.assertEqual(data["errors"], [], data["errors"])
            self.assertTrue(data["results"])

    def test_probe_http_ke_host_kosong_skip(self):
        with tempfile.TemporaryDirectory() as td:
            cli.main(["127.0.0.1", "--only", "http", "--out", td, "--format", "json"])
            data = json.loads(next(Path(td).glob("netdiag-*.json")).read_text())
            self.assertIn(data["results"][0]["verdict"], ("SKIP", "FAIL", "WARN"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
