from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    state: str
    topic: str
    observed: str
    next_step: str | None = None

@dataclass(frozen=True)
class Report:
    verdict: str
    snapshot: dict[str, object]
    findings: list[Finding]
