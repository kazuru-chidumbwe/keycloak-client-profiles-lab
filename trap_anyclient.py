#!/usr/bin/env python3
"""The client-policy condition trap.

Arm A: one client policy, condition any-client, both OAuth 2.1 profiles linked.
Arm B: the per-client-type policy set of policies.json (client-access-type confidential -> confidential profile,
       public -> public profile).
In each arm: create a public client with the console wizard fields, read it back, send one authorization request with
PKCE S256, and record where Keycloak sends it. Expected: arm A breaks the public client, arm B does not.

Usage: trap_anyclient.py [--no-redact] [--keep]
Output: ~/oauthc/runs/<stamp>-TRAP/ with trap.json and http.jsonl. Exit status 3 if Keycloak is unavailable.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from urllib.parse import parse_qs, urlencode, urlparse

import requests

from kclab import config
from kclab.evidence import Recorder
from kclab.fixtures import oauth21_policies
from kclab.oauth import Admin, Unavailable, health, pkce

ARM_A = {"policies": [{"name": "oauth21", "enabled": True,
                       "conditions": [{"condition": "any-client", "configuration": {}}],
                       "profiles": ["oauth-2-1-for-confidential-client", "oauth-2-1-for-public-client"]}]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-redact", action="store_true")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args(argv)
    run_dir = config.RUNS / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-TRAP"
    run_dir.mkdir(parents=True)
    rec = Recorder(run_dir, redact_secrets=not a.no_redact)
    try:
        health(rec)
        admin = Admin(rec)
    except Unavailable as e:
        print(f"Keycloak unavailable: {e}", file=sys.stderr)
        rec.close()
        return 3
    out = {}
    realms = []
    try:
        for arm, policies in (("A-any-client", ARM_A), ("B-access-type", oauth21_policies())):
            realm = "trap" + arm[0].lower()
            realms.append(realm)
            admin.call("DELETE", f"/{realm}", "realm-delete")
            admin.call("POST", "", "realm-create", {"realm": realm, "enabled": True}).raise_for_status()
            admin.call("PUT", f"/{realm}/client-policies/policies", "policy-set", policies).raise_for_status()
            r = admin.call("POST", f"/{realm}/clients", "client-create", {
                "clientId": "spa", "protocol": "openid-connect", "publicClient": True, "standardFlowEnabled": True,
                "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
                "redirectUris": [config.REDIRECT], "webOrigins": []})
            r.raise_for_status()
            rep = admin.call("GET", f"/{realm}/clients/{r.headers['Location'].rsplit('/', 1)[1]}", "client-get").json()
            attrs = rep.get("attributes", {})
            q = {"response_type": "code", "client_id": "spa", "redirect_uri": config.REDIRECT, "scope": "openid",
                 "state": "trap", "code_challenge": pkce()[1], "code_challenge_method": "S256"}
            resp, eid = rec.http(requests.Session(), "GET",
                                 f"{config.KC}/realms/{realm}/protocol/openid-connect/auth?{urlencode(q)}", f"{arm}-auth")
            loc = resp.headers.get("Location") or ""
            err = parse_qs(urlparse(loc).query) if loc.startswith(config.REDIRECT) else {}
            out[arm] = {
                "publicClient": rep.get("publicClient"),
                "clientAuthenticatorType": rep.get("clientAuthenticatorType"),
                "tls.client.certificate.bound.access.tokens": attrs.get("tls.client.certificate.bound.access.tokens"),
                "dpop.bound.access.tokens": attrs.get("dpop.bound.access.tokens"),
                "pkce.code.challenge.method": attrs.get("pkce.code.challenge.method"),
                "auth_status": resp.status_code,
                "auth_result": "login page" if resp.status_code == 200 else
                (err.get("error", ["?"])[0] + ": " + err.get("error_description", [""])[0]) if err else loc[:200],
                "public_client_works": resp.status_code == 200,
                "evidence": [eid],
            }
            print(arm, json.dumps(out[arm]))
    finally:
        if not a.keep:
            for realm in realms:
                admin.call("DELETE", f"/{realm}", "realm-teardown")
        (run_dir / "trap.json").write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
        rec.close()
    print("run folder", run_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
