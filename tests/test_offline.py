"""Tests that need no Keycloak: redaction, verdict roll-up, the requirements matrix and the results schema."""

import json

import jsonschema
import pytest

from kclab import config, requirements
from kclab.evidence import redact, redact_url, tag
from kclab.results import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, ResultSet, TestResult, rollup

JWT = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"


def test_redact_secret_fields_and_jwts():
    out = redact({"client_secret": "s3", "code": "abc", "grant_type": "refresh_token",
                  "nested": [{"refresh_token": "r1"}], "body": f"token {JWT} end"})
    assert out["client_secret"] == tag("s3") and out["code"] == tag("abc")
    assert out["grant_type"] == "refresh_token"
    assert out["nested"][0]["refresh_token"] == tag("r1")
    assert JWT not in out["body"] and tag(JWT) in out["body"]


def test_redact_url_keeps_non_secret_parameters():
    u = redact_url("https://client.example/cb?code=abc&state=xyz&iss=https%3A%2F%2Fkc")
    assert "abc" not in u and "state=xyz" in u and "iss=" in u


def test_same_value_same_tag():
    assert tag("one") == tag("one") != tag("two")


@pytest.mark.parametrize("verdicts,want", [
    ([PASS, PASS], PASS), ([PASS, FAIL], FAIL), ([PASS, INCONCLUSIVE], INCONCLUSIVE),
    ([NOT_APPLICABLE, NOT_APPLICABLE], NOT_APPLICABLE), ([], NOT_APPLICABLE), ([FAIL, INCONCLUSIVE], FAIL),
])
def test_rollup(verdicts, want):
    assert rollup(verdicts) == want


def t(test_id, verdict, client="R-pub"):
    return TestResult(test_id=test_id, requirement=requirements.requirement_of(test_id), client=client, state="S1",
                      verdict=verdict, expected=requirements.expected(test_id), actual={}, evidence=[])


def p9(control, rotation, wrong_key, missing):
    return {r["requirement"]: r["verdict"] for r in requirements.judge([
        t("P9.refresh.control", control), t("P9.rotation.old_token_replay", rotation),
        t("P9.dpop.wrong_key", wrong_key), t("P9.dpop.missing_proof", missing)])}["P9"]


def test_p9_binding_alone_passes():
    assert p9(PASS, FAIL, PASS, PASS) == PASS


def test_p9_rotation_alone_passes():
    assert p9(PASS, PASS, FAIL, FAIL) == PASS


def test_p9_neither_fails():
    assert p9(PASS, FAIL, FAIL, PASS) == FAIL


def test_p9_without_control_is_inconclusive():
    assert p9(FAIL, PASS, PASS, PASS) == INCONCLUSIVE


def test_every_test_id_is_unique_and_matches_the_schema_pattern():
    ids = [x["id"] for r in requirements.load() for x in r["tests"]]
    assert len(ids) == len(set(ids))
    pattern = json.loads(config.SCHEMA.read_text())["properties"]["tests"]["items"]["properties"]["test_id"]["pattern"]
    for i in ids:
        jsonschema.validate(i, {"type": "string", "pattern": pattern})


def test_result_set_validates_against_the_schema(tmp_path):
    rs = ResultSet("20261120T120000Z-S1-0123abcd", "S1",
                   {"keycloak_image": "x", "keycloak_version": "26.8.2", "lab_version": "0.9.0",
                    "lab_commit": None, "started_utc": "20261120T120000Z", "redacted": True})
    rs.tests.append(t("P1.password_grant", PASS, "F"))
    rs.write(tmp_path / "results.json")
    jsonschema.validate(json.loads((tmp_path / "results.json").read_text()), json.loads(config.SCHEMA.read_text()))
