"""Fixtures: realms for a state, and a fresh client for every check.

Each check gets its own client, so what one check does to a client (a replayed code, a revoked token family) cannot
reach another. Inside a check, every sub-test that spends tokens takes its own grant.

States
  S0   default realm, clients with the console create-client wizard fields
  S1   Keycloak's guidance: client policies that link the built-in profiles (FAPI realm: one policy, any-client,
       fapi-2-dpop-security-profile; OAuth 2.1 realm: the per-client-type policy set of policies.json)
  S2L  S1 plus every single setting the documentation offers for a check
"""

from __future__ import annotations

import json
import uuid

from jwcrypto import jwk

from . import config
from .oauth import Admin, Client

FAPI_REALM, OAUTH_REALM = "trackf", "trackr"
TRACKS = {"F": (FAPI_REALM, False), "R-pub": (OAUTH_REALM, True), "R-conf": (OAUTH_REALM, False)}
FAPI_POLICIES = {"policies": [{"name": "fapi2", "enabled": True,
                               "conditions": [{"condition": "any-client", "configuration": {}}],
                               "profiles": ["fapi-2-dpop-security-profile"]}]}


def oauth21_policies() -> dict:
    with open(config.POLICIES, encoding="utf-8") as f:
        return json.load(f)


class Lab:
    def __init__(self, admin: Admin, state: str, notes: list[str]) -> None:
        self.a, self.state, self.notes = admin, state, notes
        self.guided = state in ("S1", "S2L")
        self.rsa = jwk.JWK.generate(kty="RSA", size=2048, kid=uuid.uuid4().hex, use="sig", alg="PS256")
        self.jwks = json.dumps({"keys": [json.loads(self.rsa.export_public())]})
        self.n = 0

    # ------------------------------------------------------------ realms

    def build(self) -> None:
        for realm, policies in ((FAPI_REALM, FAPI_POLICIES), (OAUTH_REALM, oauth21_policies())):
            self.a.call("DELETE", f"/{realm}", "realm-delete")
            self.a.call("POST", "", "realm-create", {"realm": realm, "enabled": True}).raise_for_status()
            self.a.call("POST", f"/{realm}/users", "user-create", {
                "username": config.USER, "enabled": True, "email": f"{config.USER}@example.org",
                "emailVerified": True, "firstName": "Alice", "lastName": "Lab",
                "credentials": [{"type": "password", "value": config.PASSWORD, "temporary": False}],
            }).raise_for_status()
            if self.guided:
                self.a.call("PUT", f"/{realm}/client-policies/policies", "policy-set", policies).raise_for_status()
            if self.state == "S2L":
                rr = self.a.call("GET", f"/{realm}", "s2l-realm-get").json()
                rr["accessCodeLifespan"] = 60
                if realm == OAUTH_REALM:
                    rr["revokeRefreshToken"], rr["refreshTokenMaxReuse"] = True, 0
                self.a.call("PUT", f"/{realm}", "s2l-realm-set", rr).raise_for_status()
        if self.state == "S2L":
            self.notes.append("S2L realm settings: code lifespan 60 (both realms), revoke refresh token and max "
                              "reuse 0 (trackr)")

    def teardown(self) -> None:
        for realm in (FAPI_REALM, OAUTH_REALM):
            self.a.call("DELETE", f"/{realm}", "realm-teardown")

    def export(self, run_dir) -> None:
        for realm in (FAPI_REALM, OAUTH_REALM):
            r = self.a.call("POST", f"/{realm}/partial-export?exportClients=true", "realm-export")
            (run_dir / f"realm-{realm}.json").write_text(r.text, encoding="utf-8")

    # ------------------------------------------------------------ clients

    def client(self, track: str, check: str) -> Client | None:
        """A new client for one check, created with the console wizard fields; S2L settings applied after."""
        realm, public = TRACKS[track]
        self.n += 1
        client_id = f"{track.lower()}-{check.lower()}-{self.n:03d}"
        rep = {"clientId": client_id, "protocol": "openid-connect", "publicClient": public,
               # console create-client wizard (js/apps/admin-ui/src/clients/add/NewClientForm.tsx, 26.8.2, l. 70-72)
               "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
               "redirectUris": [config.REDIRECT], "webOrigins": []}
        r = self.a.call("POST", f"/{realm}/clients", "client-create", rep)
        if r.status_code >= 400 and not public:
            self.notes.append(f"{client_id}: wizard representation refused ({r.status_code}); retried with "
                              "client-jwt and a JWKS")
            rep.update({"clientAuthenticatorType": "client-jwt", "attributes": self._jwks_attrs()})
            r = self.a.call("POST", f"/{realm}/clients", "client-create-retry", rep)
        if r.status_code >= 400:
            self.notes.append(f"{client_id}: create failed {r.status_code}: {r.text[:200]}")
            return None
        cid = r.headers["Location"].rsplit("/", 1)[1]
        full = self._get(realm, cid)
        if full.get("clientAuthenticatorType") == "client-jwt" and "jwks.string" not in full.get("attributes", {}):
            # the FAPI profile switches the client to private_key_jwt without a key: register one (least change)
            full = self._set(realm, full, "client-jwks", attributes=self._jwks_attrs())
        if self.state == "S2L":
            attrs = {"pkce.code.challenge.method": "S256", "exclude.issuer.from.auth.response": "false"}
            if track == "F":
                attrs["require.pushed.authorization.requests"] = "true"
            full = self._set(realm, full, "s2l-fix", directAccessGrantsEnabled=False, attributes=attrs)
        if not public and full.get("clientAuthenticatorType") == "client-secret":
            full["secret"] = self.a.call("GET", f"/{realm}/clients/{cid}/client-secret", "client-secret").json().get("value")
        return Client(self.a.rec, realm, full, self.rsa, par=self.guided and track == "F")

    def _jwks_attrs(self) -> dict:
        return {"use.jwks.string": "true", "jwks.string": self.jwks, "token.endpoint.auth.signing.alg": "PS256"}

    def _get(self, realm: str, cid: str) -> dict:
        return self.a.call("GET", f"/{realm}/clients/{cid}", "client-get").json()

    def _set(self, realm: str, rep: dict, label: str, **changes) -> dict:
        attrs = changes.pop("attributes", {})
        rep.update(changes)
        rep.setdefault("attributes", {}).update(attrs)
        self.a.call("PUT", f"/{realm}/clients/{rep['id']}", label, rep).raise_for_status()
        return self._get(realm, rep["id"])

    def describe(self, c: Client) -> str:
        a = c.rep.get("attributes", {})
        return (f"{c.id}: auth={c.rep.get('clientAuthenticatorType')} directGrants={c.rep.get('directAccessGrantsEnabled')} "
                f"pkce={a.get('pkce.code.challenge.method')} dpop={a.get('dpop.bound.access.tokens')} "
                f"mtls={a.get('tls.client.certificate.bound.access.tokens')} "
                f"par={a.get('require.pushed.authorization.requests')}")
