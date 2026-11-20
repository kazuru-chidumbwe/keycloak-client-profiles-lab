"""The requirements matrix (requirements.yml) and the requirement-level verdicts it defines."""

from __future__ import annotations

from functools import lru_cache

import yaml

from . import config
from .results import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, TestResult, rollup


@lru_cache(maxsize=1)
def load() -> list[dict]:
    with open(config.REQUIREMENTS, encoding="utf-8") as f:
        return yaml.safe_load(f)


def by_test() -> dict[str, dict]:
    """test id -> (requirement entry, test entry)."""
    out = {}
    for req in load():
        for t in req["tests"]:
            out[t["id"]] = {"requirement": req, "test": t}
    return out


def expected(test_id: str) -> dict:
    return dict(by_test()[test_id]["test"]["expect"])


def requirement_of(test_id: str) -> str:
    return by_test()[test_id]["requirement"]["id"]


def judge(tests: list[TestResult]) -> list[dict]:
    """Requirement verdict per (requirement, client)."""
    reqs = {r["id"]: r for r in load()}
    grouped: dict[tuple[str, str], list[TestResult]] = {}
    for t in tests:
        grouped.setdefault((t.requirement, t.client), []).append(t)
    out = []
    for (rid, client), ts in sorted(grouped.items()):
        req = reqs[rid]
        v = {t.test_id: t.verdict for t in ts}
        if req.get("pass_rule") == "any_of":
            controls = [v[t["id"]] for t in req["tests"] if t["kind"] == "control" and t["id"] in v]
            groups = [[v.get(tid, INCONCLUSIVE) for tid in g] for g in req["groups"]]
            if any(c != PASS for c in controls):
                verdict = INCONCLUSIVE if NOT_APPLICABLE not in controls else NOT_APPLICABLE
            elif any(all(x == PASS for x in g) for g in groups):
                verdict = PASS
            elif any(INCONCLUSIVE in g for g in groups):
                verdict = INCONCLUSIVE
            else:
                verdict = FAIL
        else:
            verdict = rollup(list(v.values()))
        out.append({"requirement": rid, "client": client, "level": req["level"], "verdict": verdict})
    return out
