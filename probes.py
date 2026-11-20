#!/usr/bin/env python3
"""Ten OAuth 2.1 / FAPI 2.0 checks against a Keycloak realm, in three states (blog OA-01).

Usage: probes.py <state>   (S0 default realm, S1 Keycloak client profiles linked, S2L S1 plus every single setting)

Builds both realms for the state from scratch, then runs P1 to P10. Every HTTP exchange goes to
runs/<stamp>-<state>/http.jsonl; results to results.json; realm exports to realm-<name>.json.
A probe whose baseline fails is INC.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import secrets
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from jwcrypto import jwk, jwt

BASE = Path.home() / "oauthc"
CA = str(BASE / "pki" / "ca.crt")
KC = "https://localhost:8443"
REDIRECT = "https://client.example/cb"
USER, PASSWORD = "alice", "Lab-" + "x" * 12

STATE = sys.argv[1]
RUN = BASE / "runs" / f"{time.strftime('%Y%m%dT%H%M%S')}-{STATE}"
RUN.mkdir(parents=True)
LOG = open(RUN / "http.jsonl", "w", encoding="utf-8")
RESULTS: list[dict] = []
NOTES: list[str] = []


# ---------------------------------------------------------------- HTTP with logging

def http(s: requests.Session, method: str, url: str, tag: str, **kw) -> requests.Response:
    kw.setdefault("verify", CA)
    kw.setdefault("allow_redirects", False)
    r = s.request(method, url, **kw)
    LOG.write(json.dumps({
        "tag": tag, "method": method, "url": url,
        "req_data": kw.get("data"), "req_headers": {k: v for k, v in (kw.get("headers") or {}).items()},
        "status": r.status_code, "location": r.headers.get("Location"),
        "resp_headers": {k: v for k, v in r.headers.items() if k.lower() in ("dpop-nonce", "www-authenticate", "content-type")},
        "body": r.text[:4000],
    }) + "\n")
    LOG.flush()
    return r


# ---------------------------------------------------------------- admin

class Admin:
    def __init__(self) -> None:
        self.s = requests.Session()
        pw = (BASE / "admin-password").read_text().strip()
        r = http(self.s, "POST", f"{KC}/realms/master/protocol/openid-connect/token", "admin-login",
                 data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": pw})
        r.raise_for_status()
        self.s.headers["Authorization"] = "Bearer " + r.json()["access_token"]

    def call(self, method: str, path: str, tag: str, body=None) -> requests.Response:
        return http(self.s, method, f"{KC}/admin/realms{path}", tag, json=body)


def make_rsa_jwks() -> tuple[jwk.JWK, str]:
    key = jwk.JWK.generate(kty="RSA", size=2048, kid=uuid.uuid4().hex, use="sig", alg="PS256")
    return key, json.dumps({"keys": [json.loads(key.export_public())]})


def build_realm(a: Admin, realm: str, policies: list[tuple[str, dict, list[str]]]) -> None:
    a.call("DELETE", f"/{realm}", "realm-delete")
    a.call("POST", "", "realm-create", {"realm": realm, "enabled": True}).raise_for_status()
    a.call("POST", f"/{realm}/users", "user-create", {
        "username": USER, "enabled": True, "email": f"{USER}@example.org", "emailVerified": True,
        "firstName": "Alice", "lastName": "Lab",
        "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
    }).raise_for_status()
    if policies:  # S1: guidance = client policies linking the vendor profiles
        r = a.call("PUT", f"/{realm}/client-policies/policies", "policy-set", {"policies": [
            {"name": name, "enabled": True, "conditions": [cond], "profiles": profs}
            for name, cond, profs in policies]})
        r.raise_for_status()


def create_client(a: Admin, realm: str, client_id: str, public: bool, jwks: str | None) -> dict:
    """Admin-console wizard fields only (S0); in S1 the policy's executors then act on it.
    If the policy refuses the wizard representation, retry with the least change it asks for."""
    rep = {"clientId": client_id, "protocol": "openid-connect", "publicClient": public,
           # Console create-client wizard defaults (js/apps/admin-ui/src/clients/add/NewClientForm.tsx, tag 26.8.2,
           # lines 70-72): standard flow on, direct grants off, implicit off.
           "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
           "redirectUris": [REDIRECT], "webOrigins": []}
    r = a.call("POST", f"/{realm}/clients", "client-create", rep)
    if r.status_code >= 400 and not public and jwks:
        NOTES.append(f"{realm}/{client_id}: wizard representation refused ({r.status_code}: {r.text[:200]}); "
                     "retried with client-jwt and a JWKS")
        rep.update({"clientAuthenticatorType": "client-jwt",
                    "attributes": {"use.jwks.string": "true", "jwks.string": jwks,
                                   "token.endpoint.auth.signing.alg": "PS256"}})
        r = a.call("POST", f"/{realm}/clients", "client-create-retry", rep)
    if r.status_code >= 400:
        NOTES.append(f"{realm}/{client_id}: create failed {r.status_code}: {r.text[:300]}")
        return {}
    cid = r.headers["Location"].rsplit("/", 1)[1]
    full = a.call("GET", f"/{realm}/clients/{cid}", "client-get").json()
    if not public and full.get("clientAuthenticatorType") == "client-secret":
        full["secret"] = a.call("GET", f"/{realm}/clients/{cid}/client-secret", "client-secret").json().get("value")
    return full


# ---------------------------------------------------------------- client side

class Client:
    def __init__(self, realm: str, rep: dict, rsa: jwk.JWK | None, par: bool = False):
        self.realm, self.rep, self.rsa = realm, rep, rsa
        self.id = rep["clientId"]
        self.issuer = f"{KC}/realms/{realm}"
        self.token_ep = f"{self.issuer}/protocol/openid-connect/token"
        self.auth_ep = f"{self.issuer}/protocol/openid-connect/auth"
        self.par_ep = f"{self.issuer}/protocol/openid-connect/ext/par/request"
        self.public = rep.get("publicClient", False)
        self.dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
        attrs = rep.get("attributes", {})
        self.dpop = attrs.get("dpop.bound.access.tokens") == "true"
        self.mtls = attrs.get("tls.client.certificate.bound.access.tokens") == "true"
        self.par_required = par or attrs.get("require.pushed.authorization.requests") == "true"

    # client authentication
    def assertion(self, aud) -> str:
        now = int(time.time())
        t = jwt.JWT(header={"alg": "PS256", "kid": self.rsa.kid, "typ": "JWT"},
                    claims={"iss": self.id, "sub": self.id, "aud": aud, "jti": uuid.uuid4().hex,
                            "iat": now, "exp": now + 60})
        t.make_signed_token(self.rsa)
        return t.serialize()

    def auth_params(self, aud=None) -> dict:
        if self.public:
            return {"client_id": self.id}
        if self.rep.get("clientAuthenticatorType") == "client-jwt":
            return {"client_id": self.id,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": self.assertion(self.issuer if aud is None else aud)}
        return {"client_id": self.id, "client_secret": self.rep.get("secret", "")}

    def dpop_proof(self, method: str, url: str, nonce: str | None = None, key: jwk.JWK | None = None) -> str:
        k = key or self.dpop_key
        claims = {"jti": uuid.uuid4().hex, "htm": method, "htu": url, "iat": int(time.time())}
        if nonce:
            claims["nonce"] = nonce
        t = jwt.JWT(header={"typ": "dpop+jwt", "alg": "ES256", "jwk": json.loads(k.export_public())}, claims=claims)
        t.make_signed_token(k)
        return t.serialize()

    def token(self, s: requests.Session, data: dict, tag: str, dpop: bool | None = None,
              aud=None, key: jwk.JWK | None = None) -> requests.Response:
        use_dpop = self.dpop if dpop is None else dpop
        body = {**data, **self.auth_params(aud)}
        headers = {"DPoP": self.dpop_proof("POST", self.token_ep, key=key)} if use_dpop else {}
        r = http(s, "POST", self.token_ep, tag, data=body, headers=headers)
        if use_dpop and r.status_code == 400 and "use_dpop_nonce" in r.text and r.headers.get("DPoP-Nonce"):
            body = {**data, **self.auth_params(aud)}
            headers = {"DPoP": self.dpop_proof("POST", self.token_ep, r.headers["DPoP-Nonce"], key=key)}
            r = http(s, "POST", self.token_ep, tag + "-nonce", data=body, headers=headers)
        return r


def pkce() -> tuple[str, str]:
    v = secrets.token_urlsafe(48)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def run_authorization(c: Client, tag: str, *, challenge: str | None, method: str = "S256",
                      use_par: bool | None = None, redirect: str = REDIRECT) -> dict:
    """Drive the browser part. Returns {'code','iss','error','stage','status'}."""
    s = requests.Session()
    params = {"response_type": "code", "client_id": c.id, "redirect_uri": redirect, "scope": "openid",
              "state": secrets.token_hex(8), "nonce": secrets.token_hex(8)}
    if challenge:
        params.update({"code_challenge": challenge, "code_challenge_method": method})
    par = c.par_required if use_par is None else use_par
    if par:
        r = http(s, "POST", c.par_ep, tag + "-par", data={**params, **c.auth_params()})
        if r.status_code not in (200, 201):
            return {"error": "par_refused", "stage": "par", "status": r.status_code, "body": r.text[:300]}
        url = c.auth_ep + "?" + urlencode({"client_id": c.id, "request_uri": r.json()["request_uri"]})
    else:
        url = c.auth_ep + "?" + urlencode(params)
    r = http(s, "GET", url, tag + "-auth")
    for _ in range(6):
        if r.status_code in (301, 302, 303, 307):
            loc = r.headers["Location"]
            if loc.startswith(redirect.split("?")[0]):
                q = {k: v[0] for k, v in parse_qs(urlparse(loc).query).items()}
                return {"code": q.get("code"), "iss": q.get("iss"), "error": q.get("error"),
                        "stage": "redirect", "status": r.status_code, "location": loc}
            r = http(s, "GET", urljoin(r.url, loc), tag + "-follow")
            continue
        m = re.search(r'<form[^>]*id="(kc-form-login|kc-oauth-consent|kc-oauth)"[^>]*action="([^"]+)"', r.text) or \
            re.search(r'<form[^>]*action="([^"]+login-actions[^"]+)"', r.text)
        if not m:
            return {"error": "no_form", "stage": "page", "status": r.status_code,
                    "body": re.sub(r"\s+", " ", r.text)[:300]}
        action = urljoin(r.url, html.unescape(m.groups()[-1]))  # consent form posts to a relative URL
        if "kc-form-login" in m.group(0) or "username" in r.text and "password" in r.text:
            r = http(s, "POST", action, tag + "-login", data={"username": USER, "password": PASSWORD, "credentialId": ""})
        else:
            r = http(s, "POST", action, tag + "-consent", data={"accept": "Yes"})
    return {"error": "too_many_steps", "stage": "loop", "status": r.status_code}


def record(pid: str, track: str, outcome: str, evidence: str, baseline_ok: bool = True) -> None:
    if not baseline_ok and outcome in ("PASS", "FAIL"):
        outcome = "INC"
    RESULTS.append({"probe": pid, "track": track, "state": STATE, "outcome": outcome, "evidence": evidence})
    print(f"{STATE} {track} {pid}: {outcome}  {evidence[:150]}")


# ---------------------------------------------------------------- probes

def probes_for(c: Client, track: str) -> None:
    v, ch = pkce()
    base = run_authorization(c, f"{track}-baseline", challenge=ch)
    tok = c.token(requests.Session(), {"grant_type": "authorization_code", "code": base.get("code") or "",
                                       "redirect_uri": REDIRECT, "code_verifier": v}, f"{track}-baseline-token")
    baseline_ok = bool(base.get("code")) and tok.status_code == 200
    NOTES.append(f"{track}/{c.id}: baseline auth={base.get('stage')}/{base.get('error') or 'code'} "
                 f"token={tok.status_code} {tok.text[:160] if tok.status_code != 200 else ''}")
    tokens = tok.json() if tok.status_code == 200 else {}

    # P10 iss in the authorization response
    record("P10", track, "PASS" if base.get("iss") == c.issuer else "FAIL",
           f"iss={base.get('iss')}", baseline_ok)

    # P6 reused code
    if base.get("code"):
        r = c.token(requests.Session(), {"grant_type": "authorization_code", "code": base["code"],
                                         "redirect_uri": REDIRECT, "code_verifier": v}, f"{track}-P6-reuse")
        revoked = "n/a"
        if tokens.get("refresh_token"):
            rr = c.token(requests.Session(), {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
                         f"{track}-P6-after-reuse-refresh")
            revoked = "yes" if rr.status_code >= 400 else "no"
        record("P6", track, "PASS" if r.status_code >= 400 else "FAIL",
               f"reuse -> {r.status_code} {r.text[:100]}; tokens from that code revoked: {revoked}", baseline_ok)
    else:
        record("P6", track, "INC", "no baseline code", False)

    # P1 password grant
    r = c.token(requests.Session(), {"grant_type": "password", "username": USER, "password": PASSWORD,
                                     "scope": "openid"}, f"{track}-P1-ropc")
    record("P1", track, "PASS" if r.status_code >= 400 else "FAIL", f"password grant -> {r.status_code} {r.text[:120]}", baseline_ok)

    # P2 PKCE required (no challenge; plain method)
    no_ch = run_authorization(c, f"{track}-P2-nochallenge", challenge=None)
    plain = run_authorization(c, f"{track}-P2-plain", challenge="x" * 50, method="plain")
    p2 = "PASS" if not no_ch.get("code") and not plain.get("code") else "FAIL"
    record("P2", track, p2, f"no challenge -> {no_ch.get('error') or 'code issued'}; plain -> {plain.get('error') or 'code issued'}", baseline_ok)

    # P3 PKCE downgrade: verifier sent although no challenge was sent
    if no_ch.get("code"):
        r = c.token(requests.Session(), {"grant_type": "authorization_code", "code": no_ch["code"],
                                         "redirect_uri": REDIRECT, "code_verifier": pkce()[0]}, f"{track}-P3-downgrade")
        record("P3", track, "PASS" if r.status_code >= 400 else "FAIL", f"verifier without challenge -> {r.status_code} {r.text[:120]}", baseline_ok)
    else:
        record("P3", track, "PASS", "not reachable: challenge-less authorization request refused", baseline_ok)

    # P5 redirect URI near-misses
    misses = {"path": REDIRECT + "/extra", "query": REDIRECT + "?x=1", "port": "https://client.example:8443/cb"}
    accepted = []
    for name, uri in misses.items():
        res = run_authorization(c, f"{track}-P5-{name}", challenge=ch, redirect=uri)
        if res.get("code"):
            accepted.append(name)
    record("P5", track, "PASS" if not accepted else "FAIL", f"near-misses accepted: {accepted or 'none'}", baseline_ok)

    if track == "F":
        # P4 PAR required: plain front-channel request with PKCE
        res = run_authorization(c, "F-P4-nopar", challenge=ch, use_par=False)
        record("P4", track, "PASS" if not res.get("code") else "FAIL", f"unpushed request -> {res.get('error') or 'code issued'}", baseline_ok)

        # P7 code lifetime: realm setting read back, then a 65 s wait
        v7, ch7 = pkce()
        res = run_authorization(c, "F-P7", challenge=ch7)
        time.sleep(65)
        r = c.token(requests.Session(), {"grant_type": "authorization_code", "code": res.get("code") or "",
                                         "redirect_uri": REDIRECT, "code_verifier": v7}, "F-P7-late")
        record("P7", track, "PASS" if r.status_code >= 400 else "FAIL", f"code used after 65 s -> {r.status_code} {r.text[:100]}",
               baseline_ok and bool(res.get("code")))

        # P8 client assertion audience
        if c.rep.get("clientAuthenticatorType") == "client-jwt":
            bad = {"token-endpoint": c.token_ep, "array": [c.issuer]}
            took = []
            for name, aud in bad.items():
                v8, ch8 = pkce()
                res = run_authorization(c, f"F-P8-{name}", challenge=ch8)
                r = c.token(requests.Session(), {"grant_type": "authorization_code", "code": res.get("code") or "",
                                                 "redirect_uri": REDIRECT, "code_verifier": v8}, f"F-P8-{name}", aud=aud)
                if r.status_code == 200:
                    took.append(name)
            record("P8", track, "PASS" if not took else "FAIL", f"non-issuer aud accepted: {took or 'none'}", baseline_ok)
        else:
            record("P8", track, "N/A", "client does not authenticate with an assertion in this state")

    if track.startswith("R") and c.public:
        # P9 public-client refresh token: rotated with replay rejection, or sender-constrained
        # fresh tokens: the baseline tokens were revoked by the P6 code replay
        v9, ch9 = pkce()
        res9 = run_authorization(c, f"{track}-P9-auth", challenge=ch9)
        t9 = c.token(requests.Session(), {"grant_type": "authorization_code", "code": res9.get("code") or "",
                                          "redirect_uri": REDIRECT, "code_verifier": v9}, f"{track}-P9-token")
        rt = t9.json().get("refresh_token") if t9.status_code == 200 else None
        if not rt:
            record("P9", track, "INC", "no refresh token from baseline", False)
        else:
            r1 = c.token(requests.Session(), {"grant_type": "refresh_token", "refresh_token": rt}, "R-P9-refresh1")
            r2 = c.token(requests.Session(), {"grant_type": "refresh_token", "refresh_token": rt}, "R-P9-replay")
            other = jwk.JWK.generate(kty="EC", crv="P-256")
            r3 = c.token(requests.Session(), {"grant_type": "refresh_token", "refresh_token": rt}, "R-P9-otherkey",
                         dpop=True, key=other)
            r4 = c.token(requests.Session(), {"grant_type": "refresh_token", "refresh_token": rt}, "R-P9-noproof", dpop=False)
            rotated = r1.status_code == 200 and r1.json().get("refresh_token") != rt and r2.status_code >= 400
            bound = r3.status_code >= 400 and r4.status_code >= 400
            record("P9", track, ("PASS" if (rotated or bound) else "FAIL") if r1.status_code == 200 else "INC",
                   f"first refresh {r1.status_code}; replay {r2.status_code}; other DPoP key {r3.status_code}; no proof {r4.status_code}",
                   baseline_ok)


def set_client(a: Admin, realm: str, rep: dict, tag: str, **changes) -> dict:
    attrs = changes.pop("attributes", {})
    rep.update(changes)
    rep.setdefault("attributes", {}).update(attrs)
    a.call("PUT", f"/{realm}/clients/{rep['id']}", tag, rep).raise_for_status()
    full = a.call("GET", f"/{realm}/clients/{rep['id']}", tag + "-get").json()
    if rep.get("secret"):
        full["secret"] = rep["secret"]
    return full


def main() -> None:
    a = Admin()
    rsa, jwks = make_rsa_jwks()
    s1 = STATE in ("S1", "S2L")
    any_client = {"condition": "any-client", "configuration": {}}
    build_realm(a, "trackf", [("fapi2", any_client, ["fapi-2-dpop-security-profile"])] if s1 else [])
    build_realm(a, "trackr", [
        ("oauth21-confidential", {"condition": "client-access-type", "configuration": {"type": ["confidential"]}},
         ["oauth-2-1-for-confidential-client"]),
        ("oauth21-public", {"condition": "client-access-type", "configuration": {"type": ["public"]}},
         ["oauth-2-1-for-public-client"]),
    ] if s1 else [])
    fconf = create_client(a, "trackf", "f-conf", public=False, jwks=jwks)
    rconf = create_client(a, "trackr", "r-conf", public=False, jwks=jwks)
    rpub = create_client(a, "trackr", "r-pub", public=True, jwks=None)
    for realm, rep in (("trackf", fconf), ("trackr", rconf)):
        if rep and rep.get("clientAuthenticatorType") == "client-jwt" and "jwks.string" not in rep.get("attributes", {}):
            NOTES.append(f"{realm}/{rep['clientId']}: profile set client-jwt without a key; registered a JWKS (least change)")
            rep.update(set_client(a, realm, rep, "client-jwks", attributes={
                "use.jwks.string": "true", "jwks.string": jwks, "token.endpoint.auth.signing.alg": "PS256"}))
    if STATE == "S2L":  # one documented setting per check
        NOTES.append("S2L: direct grants off, PKCE S256, issuer in response, PAR required (F), "
                     "code lifespan 60 (both realms), revoke refresh token + max reuse 0 (trackr)")
        for realm in ("trackf", "trackr"):
            rr = a.call("GET", f"/{realm}", "s2l-realm-get").json()
            rr["accessCodeLifespan"] = 60
            if realm == "trackr":
                rr["revokeRefreshToken"], rr["refreshTokenMaxReuse"] = True, 0
            a.call("PUT", f"/{realm}", "s2l-realm-set", rr).raise_for_status()
        common = {"pkce.code.challenge.method": "S256", "exclude.issuer.from.auth.response": "false"}
        if fconf:
            fconf = set_client(a, "trackf", fconf, "s2l-fix", directAccessGrantsEnabled=False,
                               attributes={**common, "require.pushed.authorization.requests": "true"})
        if rconf:
            rconf = set_client(a, "trackr", rconf, "s2l-fix", directAccessGrantsEnabled=False, attributes=dict(common))
        if rpub:
            rpub = set_client(a, "trackr", rpub, "s2l-fix", directAccessGrantsEnabled=False, attributes=dict(common))
    realm_settings = a.call("GET", "/trackf", "realm-get").json()
    NOTES.append(f"trackf accessCodeLifespan={realm_settings.get('accessCodeLifespan')} "
                 f"revokeRefreshToken={realm_settings.get('revokeRefreshToken')}")
    for name, rep in (("f-conf", fconf), ("r-conf", rconf), ("r-pub", rpub)):
        attrs = rep.get("attributes", {}) if rep else {}
        NOTES.append(f"{name}: auth={rep.get('clientAuthenticatorType') if rep else None} "
                     f"directGrants={rep.get('directAccessGrantsEnabled') if rep else None} "
                     f"consent={rep.get('consentRequired') if rep else None} "
                     f"pkce={attrs.get('pkce.code.challenge.method')} dpop={attrs.get('dpop.bound.access.tokens')} "
                     f"mtls={attrs.get('tls.client.certificate.bound.access.tokens')} par={attrs.get('require.pushed.authorization.requests')}")
    if fconf:
        probes_for(Client("trackf", fconf, rsa, par=s1), "F")
    if rpub:
        probes_for(Client("trackr", rpub, None), "R-pub")
    if rconf:
        c = Client("trackr", rconf, rsa)
        if c.mtls:
            NOTES.append("r-conf: holder-of-key (mTLS) bound in this state; not probed (no client-certificate PKI)")
        else:
            probes_for(c, "R-conf")
    for realm in ("trackf", "trackr"):
        exp = a.call("POST", f"/{realm}/partial-export?exportClients=true", "realm-export")
        (RUN / f"realm-{realm}.json").write_text(exp.text, encoding="utf-8")
    (RUN / "results.json").write_text(json.dumps({"state": STATE, "results": RESULTS, "notes": NOTES}, indent=2), encoding="utf-8")
    print("\n".join(NOTES))
    print(f"run dir: {RUN}")


if __name__ == "__main__":
    main()
