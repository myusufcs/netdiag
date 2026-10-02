"""Utilitas: jalankan perintah, ukur waktu, resolusi nama."""
from __future__ import annotations

import shutil
import socket
import subprocess
import time


def which(name: str) -> str | None:
    return shutil.which(name)


def run(args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, "perintah tidak ditemukan"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as exc:                      # noqa: BLE001
        return 1, str(exc)


def resolve(host: str, family: int = socket.AF_INET) -> str | None:
    try:
        infos = socket.getaddrinfo(host, None, family)
        return infos[0][4][0] if infos else None
    except Exception:                             # noqa: BLE001
        return None


def tcp_connect_ms(host: str, port: int, timeout: float = 5.0) -> float | None:
    """Waktu TCP handshake dalam milidetik, None bila gagal."""
    t0 = time.perf_counter()
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return (time.perf_counter() - t0) * 1000
    except Exception:                             # noqa: BLE001
        return None
    finally:
        s.close()


def fmt_ms(v: float | None) -> str:
    return "—" if v is None else f"{v:.1f} ms"
