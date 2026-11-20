#!/usr/bin/env python3
"""The policy-condition trap on Keycloak 26.8.2 (blog OA-01).

Arm A: one client policy, condition any-client, both OAuth 2.1 profiles linked.
Arm B: two policies, condition client-access-type (confidential -> confidential profile, public -> public profile).
In each arm: create a public client with the console wizard fields, read it back, then send one
authorization request with PKCE S256 and record where Keycloak redirects. Every exchange goes to http.jsonl.
"""
import base64
import hashlib
import json
import secrets
import sys
from urllib.parse import urlencode, urlparse, parse_qs

sys.argv = ["probes.py", "TRAP"]
import probes  # noqa: E402  (creates runs/<stamp>-TRAP and the http log)
from probes import KC, REDIRECT, Admin, build_realm, create_client, http  # noqa: E402
import requests  # noqa: E402

ANY = {"condition": "any-client", "configuration": {}}
CONF = {"condition": "client-access-type", "configuration": {"type": ["confidential"]}}
PUB = {"condition": "client-access-type", "configuration": {"type": ["public"]}}
ARMS = {
    "A-any-client": [("oauth21", ANY, ["oauth-2-1-for-confidential-client", "oauth-2-1-for-public-client"])],
    "B-access-type": [("oauth21-confidential", CONF, ["oauth-2-1-for-confidential-client"]),
                      ("oauth21-public", PUB, ["oauth-2-1-for-public-client"])],
}

out = {}
a = Admin()
for arm, policies in ARMS.items():
    realm = "trap" + arm[0].lower()
    build_realm(a, realm, policies)
    rep = create_client(a, realm, "spa", public=True, jwks=None)
    attrs = rep.get("attributes", {})
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"response_type": "code", "client_id": "spa", "redirect_uri": REDIRECT, "scope": "openid",
         "state": secrets.token_hex(8), "code_challenge": challenge, "code_challenge_method": "S256"}
    r = http(requests.Session(), "GET", f"{KC}/realms/{realm}/protocol/openid-connect/auth?{urlencode(q)}",
             f"{arm}-auth")
    loc = r.headers.get("Location") or ""
    err = parse_qs(urlparse(loc).query) if loc.startswith(REDIRECT) else {}
    out[arm] = {
        "publicClient": rep.get("publicClient"),
        "clientAuthenticatorType": rep.get("clientAuthenticatorType"),
        "tls.client.certificate.bound.access.tokens": attrs.get("tls.client.certificate.bound.access.tokens"),
        "dpop.bound.access.tokens": attrs.get("dpop.bound.access.tokens"),
        "pkce.code.challenge.method": attrs.get("pkce.code.challenge.method"),
        "auth_status": r.status_code,
        "auth_result": ("login page" if r.status_code == 200 else
                        (err.get("error", ["?"])[0] + ": " + err.get("error_description", [""])[0]) if err else loc[:200]),
    }
    print(arm, json.dumps(out[arm]))

(probes.RUN / "trap.json").write_text(json.dumps(out, indent=1))
print("run dir", probes.RUN)
