"""Registry probe: auto-register + pemilihan."""
from __future__ import annotations

import importlib
import pkgutil

ALL_PROBES: list[type] = []


class Probe:
    NAME = "?"
    TITLE = ""
    DEFAULT = True          # ikut jalan tanpa --only

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if getattr(cls, "NAME", "?") != "?":
            ALL_PROBES.append(cls)

    def run(self, target: str, ctx: dict):
        raise NotImplementedError


def load_all() -> None:
    import netdiag.probes as pkg
    for info in pkgutil.iter_modules(pkg.__path__):
        if info.name.startswith("_"):
            continue
        importlib.import_module(f"netdiag.probes.{info.name}")


def select(only=None, skip=None) -> list[type]:
    out = []
    for cls in ALL_PROBES:
        if only:
            if cls.NAME not in only:
                continue
        elif not cls.DEFAULT:
            continue
        if skip and cls.NAME in skip:
            continue
        out.append(cls)
    return out


def describe() -> list[tuple[str, bool, str]]:
    return [(c.NAME, c.DEFAULT, c.TITLE) for c in sorted(ALL_PROBES, key=lambda c: c.NAME)]
