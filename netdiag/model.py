"""Model hasil diagnosa."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Verdict(str, Enum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"

    @property
    def symbol(self) -> str:
        return {"OK": "✅", "WARN": "⚠️ ", "FAIL": "❌", "SKIP": "➖"}[self.value]

    @property
    def order(self) -> int:
        return {"FAIL": 0, "WARN": 1, "SKIP": 3, "OK": 2}[self.value]


@dataclass
class Metric:
    """Satu angka hasil pengukuran (mis. 'rata-rata RTT' = 4.2 ms)."""
    label: str
    value: str

    def as_dict(self) -> dict:
        return {"label": self.label, "value": self.value}


@dataclass
class Result:
    probe: str
    title: str
    verdict: Verdict = Verdict.OK
    summary: str = ""
    metrics: list[Metric] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, label: str, value) -> "Result":
        self.metrics.append(Metric(label, str(value)))
        return self

    def as_dict(self) -> dict:
        return {
            "probe": self.probe,
            "title": self.title,
            "verdict": self.verdict.value,
            "summary": self.summary,
            "metrics": [m.as_dict() for m in self.metrics],
            "notes": self.notes,
        }


@dataclass
class Report:
    target: str
    address: str = ""
    started: str = ""
    finished: str = ""
    results: list[Result] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def count(self, v: Verdict) -> int:
        return sum(1 for r in self.results if r.verdict is v)

    @property
    def worst(self) -> Verdict:
        for v in (Verdict.FAIL, Verdict.WARN, Verdict.OK):
            if self.count(v):
                return v
        return Verdict.SKIP

    def problems(self) -> list[Result]:
        return sorted((r for r in self.results if r.verdict in (Verdict.FAIL, Verdict.WARN)),
                      key=lambda r: (r.verdict.order, r.probe))

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "address": self.address,
            "started": self.started,
            "finished": self.finished,
            "verdict": self.worst.value,
            "summary": {v.value: self.count(v) for v in Verdict},
            "results": [r.as_dict() for r in self.results],
            "errors": self.errors,
        }
