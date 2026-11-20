"""The checks P1 to P10. Each check takes a fresh client from the fixtures and records one result per test.

A negative test counts only if a positive control on the same client worked (a working code flow, or the check's own
control test); otherwise it is INCONCLUSIVE, because a refusal from a client that cannot work at all proves nothing.
"""

from __future__ import annotations

import time

from jwcrypto import jwk

from . import config
from . import requirements as reqs
from .evidence import error_of
from .fixtures import Lab
from .oauth import AuthResult, Client, pkce
from .results import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, ResultSet, TestResult


class Checks:
    def __init__(self, lab: Lab, rs: ResultSet) -> None:
        self.lab, self.rs = lab, rs

    # ------------------------------------------------------------ helpers

    def add(self, test_id: str, client: str, verdict: str, actual: dict, evidence: list[str],
            note: str | None = None) -> str:
        self.rs.add(TestResult(test_id=test_id, requirement=reqs.requirement_of(test_id), client=client,
                               state=self.rs.state, verdict=verdict, expected=reqs.expected(test_id),
                               actual={k: v for k, v in actual.items() if v is not None}, evidence=evidence,
                               note=note))
        return verdict

    @staticmethod
    def refused(status: int | None) -> bool:
        return status is not None and status >= 400

    def fresh(self, track: str, check: str, test_ids: list[str]) -> Client | None:
        """A new client for the check; INCONCLUSIVE for all its tests if it cannot be created or cannot be tested."""
        c = self.lab.client(track, check)
        if c is None:
            for t in test_ids:
                self.add(t, track, INCONCLUSIVE, {"note": "client could not be created"}, [])
            return None
        self.rs.notes.append(self.lab.describe(c))
        if c.mtls:
            for t in test_ids:
                self.add(t, track, INCONCLUSIVE, {"note": "tokens bound with mutual TLS; the kit has no client "
                                                          "certificates yet"}, [])
            return None
        return c

    def grant(self, c: Client, label: str) -> tuple[AuthResult, object, list[str]]:
        """A complete code flow with PKCE S256: authorization, then token. Returns (auth, token response, evidence)."""
        v, ch = pkce()
        auth = c.authorize(label, challenge=ch)
        tok, ev = c.code_grant(auth.code, v, label + "-token")
        return auth, tok, auth.evidence + ev

    def baseline(self, c: Client, label: str) -> tuple[bool, list[str]]:
        auth, tok, ev = self.grant(c, label)
        return bool(auth.code) and tok.status_code == 200, ev

    def negative(self, test_id: str, track: str, ok_control: bool, refused: bool, actual: dict, ev: list[str],
                 note: str | None = None) -> str:
        if not ok_control:
            return self.add(test_id, track, INCONCLUSIVE, actual, ev, "positive control on this client failed")
        return self.add(test_id, track, PASS if refused else FAIL, actual, ev, note)

    # ------------------------------------------------------------ checks

    def p1(self, track: str) -> None:
        c = self.fresh(track, "p1", ["P1.password_grant"])
        if not c:
            return
        ok, ev0 = self.baseline(c, f"{track}-P1-control")
        r, ev = c.token({"grant_type": "password", "username": config.USER, "password": config.PASSWORD,
                         "scope": "openid"}, f"{track}-P1-ropc")
        self.negative("P1.password_grant", track, ok, self.refused(r.status_code),
                      {"status": r.status_code, "error": error_of(r)}, ev0 + ev)

    def p2(self, track: str) -> None:
        ids = ["P2.s256.control", "P2.missing_challenge", "P2.plain_method"]
        c = self.fresh(track, "p2", ids)
        if not c:
            return
        auth, tok, ev = self.grant(c, f"{track}-P2-s256")
        ok = bool(auth.code) and tok.status_code == 200
        self.add("P2.s256.control", track, PASS if ok else FAIL,
                 {"code_issued": bool(auth.code), "status": tok.status_code}, ev)
        no = c.authorize(f"{track}-P2-nochallenge", challenge=None)
        self.negative("P2.missing_challenge", track, ok, not no.code,
                      {"code_issued": bool(no.code), "error": no.error}, no.evidence)
        plain = c.authorize(f"{track}-P2-plain", challenge="x" * 50, method="plain")
        self.negative("P2.plain_method", track, ok, not plain.code,
                      {"code_issued": bool(plain.code), "error": plain.error}, plain.evidence)

    def p3(self, track: str) -> None:
        c = self.fresh(track, "p3", ["P3.verifier_without_challenge"])
        if not c:
            return
        ok, ev0 = self.baseline(c, f"{track}-P3-control")
        no = c.authorize(f"{track}-P3-nochallenge", challenge=None)
        if not no.code:
            self.negative("P3.verifier_without_challenge", track, ok, True,
                          {"code_issued": False, "error": no.error}, ev0 + no.evidence,
                          "not reachable: the challenge-less authorization request is already refused")
            return
        r, ev = c.code_grant(no.code, pkce()[0], f"{track}-P3-downgrade")
        self.negative("P3.verifier_without_challenge", track, ok, self.refused(r.status_code),
                      {"status": r.status_code, "error": error_of(r)}, ev0 + no.evidence + ev)

    def p4(self, track: str) -> None:
        ids = ["P4.par.control", "P4.direct_request"]
        c = self.fresh(track, "p4", ids)
        if not c:
            return
        v, ch = pkce()
        par = c.authorize(f"{track}-P4-par", challenge=ch, use_par=True)
        tok, ev = c.code_grant(par.code, v, f"{track}-P4-par-token")
        ok = bool(par.code) and tok.status_code == 200
        self.add("P4.par.control", track, PASS if ok else FAIL,
                 {"code_issued": bool(par.code), "status": tok.status_code}, par.evidence + ev)
        direct = c.authorize(f"{track}-P4-direct", challenge=ch, use_par=False)
        self.negative("P4.direct_request", track, ok, not direct.code,
                      {"code_issued": bool(direct.code), "error": direct.error}, direct.evidence)

    def p5(self, track: str) -> None:
        near = {"P5.extra_path": config.REDIRECT + "/extra", "P5.extra_query": config.REDIRECT + "?x=1",
                "P5.other_port": "https://client.example:8443/cb"}
        c = self.fresh(track, "p5", ["P5.exact.control", *near])
        if not c:
            return
        auth, tok, ev = self.grant(c, f"{track}-P5-exact")
        ok = bool(auth.code) and tok.status_code == 200
        self.add("P5.exact.control", track, PASS if ok else FAIL,
                 {"code_issued": bool(auth.code), "status": tok.status_code}, ev)
        for tid, uri in near.items():
            res = c.authorize(f"{track}-{tid}", challenge=pkce()[1], redirect=uri)
            self.negative(tid, track, ok, not res.code, {"code_issued": bool(res.code), "error": res.error},
                          res.evidence)

    def p6(self, track: str) -> None:
        ids = ["P6.code.control", "P6.code_replay", "P6.tokens_revoked_after_replay"]
        c = self.fresh(track, "p6", ids)
        if not c:
            return
        v, ch = pkce()
        auth = c.authorize(f"{track}-P6", challenge=ch)
        first, ev1 = c.code_grant(auth.code, v, f"{track}-P6-first")
        ok = bool(auth.code) and first.status_code == 200
        self.add("P6.code.control", track, PASS if ok else FAIL, {"status": first.status_code}, auth.evidence + ev1)
        replay, ev2 = c.code_grant(auth.code, v, f"{track}-P6-replay")
        self.negative("P6.code_replay", track, ok, self.refused(replay.status_code),
                      {"status": replay.status_code, "error": error_of(replay)}, ev2)
        rt = first.json().get("refresh_token") if ok else None
        if not rt:
            self.add("P6.tokens_revoked_after_replay", track, NOT_APPLICABLE if ok else INCONCLUSIVE,
                     {"note": "no refresh token from the first exchange"}, ev1)
            return
        rr, ev3 = c.token({"grant_type": "refresh_token", "refresh_token": rt}, f"{track}-P6-after-replay")
        self.negative("P6.tokens_revoked_after_replay", track, ok, self.refused(rr.status_code),
                      {"status": rr.status_code, "error": error_of(rr)}, ev3)

    def p7(self, track: str) -> None:
        c = self.fresh(track, "p7", ["P7.code_after_65s"])
        if not c:
            return
        ok, ev0 = self.baseline(c, f"{track}-P7-control")
        v, ch = pkce()
        auth = c.authorize(f"{track}-P7", challenge=ch)
        time.sleep(config.P7_WAIT)
        r, ev = c.code_grant(auth.code, v, f"{track}-P7-late")
        self.negative("P7.code_after_65s", track, ok and bool(auth.code), self.refused(r.status_code),
                      {"status": r.status_code, "error": error_of(r), "waited_s": config.P7_WAIT},
                      ev0 + auth.evidence + ev)

    def p8(self, track: str) -> None:
        ids = ["P8.aud_issuer_string.control", "P8.aud_issuer_array", "P8.aud_token_endpoint"]
        c = self.fresh(track, "p8", ids)
        if not c:
            return
        if not c.private_key_jwt:
            for t in ids:
                self.add(t, track, NOT_APPLICABLE, {"note": "client does not authenticate with an assertion here"}, [])
            return
        results = {}
        for tid, aud in (("P8.aud_issuer_string.control", c.issuer), ("P8.aud_issuer_array", [c.issuer]),
                         ("P8.aud_token_endpoint", c.token_ep)):
            v, ch = pkce()
            auth = c.authorize(f"{track}-{tid}", challenge=ch)
            r, ev = c.code_grant(auth.code, v, f"{track}-{tid}-token", aud=aud)
            results[tid] = (auth, r, auth.evidence + ev)
        auth, r, ev = results["P8.aud_issuer_string.control"]
        ok = bool(auth.code) and r.status_code == 200
        self.add("P8.aud_issuer_string.control", track, PASS if ok else FAIL, {"status": r.status_code}, ev)
        for tid in ("P8.aud_issuer_array", "P8.aud_token_endpoint"):
            auth, r, ev = results[tid]
            self.negative(tid, track, ok and bool(auth.code), self.refused(r.status_code),
                          {"status": r.status_code, "error": error_of(r)}, ev)

    def p9(self, track: str) -> None:
        ids = ["P9.refresh.control", "P9.rotation.old_token_replay", "P9.dpop.wrong_key", "P9.dpop.missing_proof"]
        c = self.fresh(track, "p9", ids)
        if not c:
            return

        def family(label: str) -> tuple[str | None, list[str]]:
            _auth, tok, ev = self.grant(c, label)
            return (tok.json().get("refresh_token") if tok.status_code == 200 else None), ev

        # family A: the control, one refresh with the client's own key
        rt, ev = family(f"{track}-P9-A")
        r, e = c.token({"grant_type": "refresh_token", "refresh_token": rt or ""}, f"{track}-P9-A-refresh")
        ok = bool(rt) and r.status_code == 200
        self.add("P9.refresh.control", track, PASS if ok else FAIL, {"status": r.status_code}, ev + e)

        # family B: rotation, refresh once, then replay the old token
        rt, ev = family(f"{track}-P9-B")
        r1, e1 = c.token({"grant_type": "refresh_token", "refresh_token": rt or ""}, f"{track}-P9-B-refresh")
        rotated = r1.status_code == 200 and r1.json().get("refresh_token") not in (None, rt)
        r2, e2 = c.token({"grant_type": "refresh_token", "refresh_token": rt or ""}, f"{track}-P9-B-old-replay")
        self.negative("P9.rotation.old_token_replay", track, ok and r1.status_code == 200,
                      rotated and self.refused(r2.status_code),
                      {"new_refresh_token": rotated, "status": r2.status_code, "error": error_of(r2)}, ev + e1 + e2)

        # family C: a DPoP proof from another key
        rt, ev = family(f"{track}-P9-C")
        other = jwk.JWK.generate(kty="EC", crv="P-256")
        r3, e3 = c.token({"grant_type": "refresh_token", "refresh_token": rt or ""}, f"{track}-P9-C-otherkey",
                         dpop=True, key=other)
        self.negative("P9.dpop.wrong_key", track, ok and bool(rt), self.refused(r3.status_code),
                      {"status": r3.status_code, "error": error_of(r3)}, ev + e3)

        # family D: no DPoP proof at all
        rt, ev = family(f"{track}-P9-D")
        r4, e4 = c.token({"grant_type": "refresh_token", "refresh_token": rt or ""}, f"{track}-P9-D-noproof",
                         dpop=False)
        self.negative("P9.dpop.missing_proof", track, ok and bool(rt), self.refused(r4.status_code),
                      {"status": r4.status_code, "error": error_of(r4)}, ev + e4)

    def p10(self, track: str) -> None:
        c = self.fresh(track, "p10", ["P10.iss_in_response"])
        if not c:
            return
        auth = c.authorize(f"{track}-P10", challenge=pkce()[1])
        if not auth.code:
            self.add("P10.iss_in_response", track, INCONCLUSIVE, {"error": auth.error}, auth.evidence,
                     "no authorization response to inspect")
            return
        self.add("P10.iss_in_response", track, PASS if auth.iss == c.issuer else FAIL,
                 {"iss": auth.iss, "issuer": c.issuer}, auth.evidence)


PLAN = {
    "F": ["p10", "p1", "p2", "p3", "p5", "p6", "p4", "p7", "p8"],
    "R-pub": ["p10", "p1", "p2", "p3", "p5", "p6", "p9"],
    "R-conf": ["p10", "p1", "p2", "p3", "p5", "p6"],
}


def run_all(lab: Lab, rs: ResultSet, only: set[str] | None = None) -> None:
    ch = Checks(lab, rs)
    for track, names in PLAN.items():
        for name in names:
            if only and name.upper() not in only:
                continue
            getattr(ch, name)(track)
