"""Structured results.

A test is one request (or a short sequence) with an expected answer. Its verdict:
  PASS            the server answered as the requirement expects
  FAIL            the server answered otherwise
  INCONCLUSIVE    the test could not be judged (its control or setup failed, or the server was unreachable)
  NOT_APPLICABLE  the requirement does not apply to this client in this state
A requirement's verdict is FAIL if any of its tests fails, else INCONCLUSIVE if any is inconclusive, else PASS
(NOT_APPLICABLE only when every test is).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

PASS, FAIL, INCONCLUSIVE, NOT_APPLICABLE = "PASS", "FAIL", "INCONCLUSIVE", "NOT_APPLICABLE"
VERDICTS = (PASS, FAIL, INCONCLUSIVE, NOT_APPLICABLE)


@dataclass
class Outcome:
    status: int | None = None
    error: str | None = None
    code_issued: bool | None = None
    note: str | None = None

    def compact(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class TestResult:
    __test__ = False  # not a pytest test class
    test_id: str
    requirement: str
    client: str
    state: str
    verdict: str
    expected: dict
    actual: dict
    evidence: list[str] = field(default_factory=list)
    note: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        if d["note"] is None:
            del d["note"]
        return d


def rollup(verdicts: list[str]) -> str:
    if not verdicts or all(v == NOT_APPLICABLE for v in verdicts):
        return NOT_APPLICABLE
    if FAIL in verdicts:
        return FAIL
    if INCONCLUSIVE in verdicts:
        return INCONCLUSIVE
    return PASS


class ResultSet:
    def __init__(self, run_id: str, state: str, meta: dict[str, Any]) -> None:
        self.run_id, self.state, self.meta = run_id, state, meta
        self.tests: list[TestResult] = []
        self.notes: list[str] = []

    def add(self, t: TestResult) -> TestResult:
        self.tests.append(t)
        print(f"{self.state} {t.client:7} {t.test_id:28} {t.verdict:14} {json.dumps(t.actual)[:110]}")
        return t

    def requirements(self) -> list[dict]:
        from .requirements import judge  # requirement rules live in requirements.yml
        return judge(self.tests)

    def to_dict(self) -> dict:
        return {"schema": "kclab-results/1", "run_id": self.run_id, "state": self.state, "meta": self.meta,
                "tests": [t.to_dict() for t in self.tests], "requirements": self.requirements(),
                "notes": self.notes}

    def write(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n", encoding="utf-8")
