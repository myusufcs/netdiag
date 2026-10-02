# netdiag

**Diagnosa konektivitas jaringan sekali jalan** — DNS, ICMP, jalur per-hop, MTU path,
TLS, timing HTTP berlapis, dan cek port. Satu perintah, satu laporan.

Dipakai saat pertanyaan harganya: *"kenapa lambat?"*, *"kenapa putus?"*, *"di mana masalahnya?"*

[![CI](https://github.com/myusufcs/netdiag/actions/workflows/ci.yml/badge.svg)](https://github.com/myusufcs/netdiag/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Zero deps](https://img.shields.io/badge/dependencies-none-success)
![License](https://img.shields.io/badge/license-MIT-green)
![Probes](https://img.shields.io/badge/probes-7-informational)

---

## Kenapa ini ada

Nge-debug jaringan biasanya berarti buka 5 terminal: `dig`, `ping`, `mtr`, `openssl s_client`,
`curl -w`, lalu `nc` satu per satu. Hasilnya tersebar dan gampang lupa mana yang sudah dicek.
`netdiag` menjalankan semuanya, mengurutkan temuan berdasarkan masalah, dan menyimpulkan
**di lapisan mana** gangguan terjadi.

## Keluaran contoh

```
$ python3 -m netdiag example.com
  ✅ dns     2 alamat A, konsisten di dua resolver
  ✅ http    HTTP 200, TTFB 77 ms
  ✅ reach   stabil — loss 0%, rata-rata 17.2 ms
  ✅ tls     TLSv1.3, sertifikat valid

========================================================================
  DIAGNOSA JARINGAN — example.com
========================================================================
kesimpulan: ✅ OK   (OK 4 · WARN 0 · FAIL 0 · SKIP 0)

RINCIAN
------------------------------------------------------------------------
✅ http     HTTP 200, TTFB 77 ms
      DNS                          2.1 ms
      TCP connect                  22.3 ms
      TLS handshake                25.3 ms
      TTFB                         76.8 ms
      total                        76.9 ms
      rantai redirect              0

✅ reach    stabil — loss 0%, rata-rata 17.2 ms
      RTT min/avg/max              15.4 / 17.2 / 20.2 ms
      jitter (mdev)                1.99 ms

✅ tls      TLSv1.3, sertifikat valid
      versi TLS                    TLSv1.3
      cipher                       TLS_AES_256_GCM_SHA384
      ALPN                         h2
```

Kalau ada masalah, bagian **PERLU DIPERHATIKAN** muncul di atas dengan penyebab + saran:

```
❌ [reach] Reachability ICMP
    loss 50% — target praktis tidak terjangkau
⚠️  [path] Jalur per-hop (mtr)
    loss 40% di hop 2 (10.10.46.17) — perhatikan apakah berlanjut ke hop berikutnya
    catatan: Loss yang muncul lalu hilang di hop berikutnya biasanya rate-limit ICMP,
             bukan gangguan nyata.
⚠️  [mtu] MTU path
    MTU path hanya 1492 byte (bukan 1500)
    catatan: Umum pada jalur PPPoE/VPN. Bila aplikasi menggantung saat data besar,
             sesuaikan MSS clamping di router atau MTU di klien.
```

## Instalasi & pemakaian

Zero dependency. Memakai tool sistem bila tersedia (`ping`, `dig`, `mtr`) — yang tidak ada
otomatis berstatus `SKIP`, bukan error.

```bash
git clone https://github.com/myusufcs/netdiag
cd netdiag

python3 -m netdiag example.com                     # semua probe default
python3 -m netdiag 1.1.1.1 --only reach,path       # pilih probe
python3 -m netdiag example.com --ports 22,443,3306 # plus cek port
python3 -m netdiag example.com --out laporan --format md,json
python3 -m netdiag --list
```

Exit code: `1` bila ada verdict **FAIL** (ramah untuk skrip/monitoring), `0` selain itu.

## Probe (7)

| Probe | Default | Yang diukur |
|---|---|---|
| `dns` | ✔ | A/AAAA/MX/NS/TXT, waktu resolusi, **konsistensi antara dua resolver publik** (deteksi split-horizon/cache basi) |
| `reach` | ✔ | Packet loss, RTT min/avg/max, **jitter (mdev)** via ICMP |
| `path` | ✔ | Jalur per-hop dengan `mtr`: loss & latensi tiap hop, **plus ASN tiap hop** |
| `mtu` | ✔ | **MTU path** lewat binary-search `ping -M do` — mendeteksi black-hole MTU (penyebab klasik "koneksi menggantung") |
| `tls` | ✔ | Handshake, versi, cipher, ALPN, penerbit, **masa berlaku sertifikat** |
| `http` | ✔ | **Waterfall**: DNS → TCP → TLS → TTFB → total, status, rantai redirect |
| `ports` | opt-in | Port TCP terbuka/tertutup + waktu connect, memperingatkan DB/cache yang terekspos |

## Desain

```
netdiag/
  cli.py        # argparse: target, --only/--skip/--ports, format, exit code
  registry.py   # probe auto-register; probe non-default (ports) hanya bila diminta
  model.py      # Verdict (OK/WARN/FAIL/SKIP), Result, Metric, Report
  report.py     # render teks / Markdown / JSON
  util.py       # jalankan perintah, resolusi nama, ukur TCP connect
  probes/       # dns.py · reach.py · path.py · mtu.py · tls.py · http.py · ports.py
```

Dua keputusan yang disengaja:

1. **Parser dipisah dari eksekusi.** Fungsi seperti `parse_ping()`, `parse_mtr()`, `parse_dig()`
   menerima keluaran tool sebagai teks — sehingga bisa diuji tanpa jaringan, dan CI tetap hijau
   di runner tanpa koneksi.
2. **Tidak pernah crash.** Tool apa pun yang tidak ada, host yang tidak resolve, port yang
   ditutup — semuanya jadi `SKIP`/`FAIL` dengan penjelasan. Diagnosa yang error di tengah jalan
   justru menghilangkan gunanya.

## Batasan yang jujur

- **Loss di tengah jalur belum tentu gangguan.** Router sering membatasi ICMP; yang penting
  apakah loss berlanjut ke hop berikutnya. `netdiag` memberi catatan ini, tapi tetap perlu
  dibaca dengan akal.
- MTU path diuji dengan ICMP DF. Kalau ICMP diblokir di jalur, hasilnya `SKIP`.
- `mtr` butuh raw socket. Tanpa kapabilitas itu, probe `path` akan `SKIP` (bukan mengarang).
- Timing HTTP memakai permintaan `GET /` sederhana, bukan pengukuran seperti browser
  (tanpa eksekusi JS, tanpa aset). Untuk pengukuran aset lengkap, pakai Lighthouse/WebPageTest.
- Tidak melakukan pemindaian port masif. `ports` default hanya daftar kecil dan harus diminta
  eksplisit — tool ini untuk diagnosa, bukan pemindaian.
- Hasilnya bergantung pada titik tempat tool dijalankan. Jalankan dari sisi klien **dan**
  server untuk perbandingan yang berguna.

## Uji

```bash
python3 -m unittest discover -s tests -v     # 22 test
```

Semua test **tidak butuh jaringan** — parser diuji dengan keluaran yang direkam, sehingga
CI dan pengembangan offline tetap bisa berjalan.

## Lisensi

MIT — lihat [LICENSE](LICENSE). Copyright (c) 2026 M Yusuf Chairul Saleh.
