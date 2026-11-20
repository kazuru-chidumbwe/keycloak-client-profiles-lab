"""Admin API, the client side of OAuth, and the browser part of the authorization flow."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from jwcrypto import jwk, jwt

from . import config
from .evidence import Recorder


class Unavailable(RuntimeError):
    """Keycloak could not be reached or the admin login failed: no test result can be trusted."""


def admin_credentials() -> tuple[str, str]:
    if config.ADMIN_FILE.exists():
        c = json.loads(config.ADMIN_FILE.read_text())
        return c["username"], c["password"]
    legacy = config.BASE / "admin-password"  # kits set up before the hardened setup script
    if legacy.exists():
        return "admin", legacy.read_text().strip()
    raise Unavailable(f"no admin credentials in {config.ADMIN_FILE}; run setup-keycloak.sh first")


def health(rec: Recorder) -> None:
    try:
        r, _ = rec.http(requests.Session(), "GET", f"{config.KC}/realms/master/.well-known/openid-configuration",
                        "health")
    except requests.RequestException as e:
        raise Unavailable(f"Keycloak at {config.KC} unreachable: {e}") from e
    if r.status_code != 200:
        raise Unavailable(f"Keycloak at {config.KC} answered {r.status_code} to the discovery request")


class Admin:
    """Admin API session. The master realm's admin-cli tokens live 60 seconds by default, shorter than a run, so a
    401 triggers one fresh login and one retry."""

    def __init__(self, rec: Recorder) -> None:
        self.rec = rec
        self.s = requests.Session()
        self.user, self.pw = admin_credentials()
        self.login()

    def login(self) -> None:
        self.s.headers.pop("Authorization", None)
        r, _ = self.rec.http(self.s, "POST", f"{config.KC}/realms/master/protocol/openid-connect/token", "admin-login",
                             data={"grant_type": "password", "client_id": "admin-cli", "username": self.user,
                                   "password": self.pw})
        if r.status_code != 200:
            raise Unavailable(f"admin login failed: {r.status_code}")
        self.s.headers["Authorization"] = "Bearer " + r.json()["access_token"]

    def call(self, method: str, path: str, label: str, body=None) -> requests.Response:
        r, _ = self.rec.http(self.s, method, f"{config.KC}/admin/realms{path}", label, json=body)
        if r.status_code == 401:
            self.login()
            r, _ = self.rec.http(self.s, method, f"{config.KC}/admin/realms{path}", label + "-retry", json=body)
        return r

    def server_version(self) -> str | None:
        r, _ = self.rec.http(self.s, "GET", f"{config.KC}/admin/serverinfo", "serverinfo")
        try:
            return r.json()["systemInfo"]["version"]
        except (ValueError, KeyError, TypeError):
            return None


def pkce() -> tuple[str, str]:
    v = secrets.token_urlsafe(48)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


@dataclass
class AuthResult:
    code: str | None = None
    iss: str | None = None
    error: str | None = None
    stage: str = ""
    status: int | None = None
    evidence: list[str] = field(default_factory=list)


class Client:
    """One registered client, seen from the client's side."""

    def __init__(self, rec: Recorder, realm: str, rep: dict, rsa: jwk.JWK | None, par: bool = False):
        self.rec, self.realm, self.rep, self.rsa = rec, realm, rep, rsa
        self.id = rep["clientId"]
        self.issuer = f"{config.KC}/realms/{realm}"
        oidc = f"{self.issuer}/protocol/openid-connect"
        self.token_ep, self.auth_ep, self.par_ep = f"{oidc}/token", f"{oidc}/auth", f"{oidc}/ext/par/request"
        self.public = rep.get("publicClient", False)
        self.dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
        attrs = rep.get("attributes", {})
        self.dpop = attrs.get("dpop.bound.access.tokens") == "true"
        self.mtls = attrs.get("tls.client.certificate.bound.access.tokens") == "true"
        self.par_required = par or attrs.get("require.pushed.authorization.requests") == "true"
        self.private_key_jwt = rep.get("clientAuthenticatorType") == "client-jwt"

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
        if self.private_key_jwt:
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

    def token(self, data: dict, label: str, dpop: bool | None = None, aud=None,
              key: jwk.JWK | None = None) -> tuple[requests.Response, list[str]]:
        """Token request with this client's authentication; follows one DPoP nonce challenge."""
        s = requests.Session()
        use_dpop = self.dpop if dpop is None else dpop
        headers = {"DPoP": self.dpop_proof("POST", self.token_ep, key=key)} if use_dpop else {}
        r, e1 = self.rec.http(s, "POST", self.token_ep, label, data={**data, **self.auth_params(aud)}, headers=headers)
        ev = [e1]
        if use_dpop and r.status_code == 400 and "use_dpop_nonce" in r.text and r.headers.get("DPoP-Nonce"):
            headers = {"DPoP": self.dpop_proof("POST", self.token_ep, r.headers["DPoP-Nonce"], key=key)}
            r, e2 = self.rec.http(s, "POST", self.token_ep, label + "-nonce",
                                  data={**data, **self.auth_params(aud)}, headers=headers)
            ev.append(e2)
        return r, ev

    def code_grant(self, code: str | None, verifier: str, label: str, **kw) -> tuple[requests.Response, list[str]]:
        return self.token({"grant_type": "authorization_code", "code": code or "", "redirect_uri": config.REDIRECT,
                           "code_verifier": verifier}, label, **kw)

    def authorize(self, label: str, *, challenge: str | None, method: str = "S256", use_par: bool | None = None,
                  redirect: str = config.REDIRECT) -> AuthResult:
        """Drive the browser part: authorization request, login, consent, until the redirect back."""
        s = requests.Session()
        ev: list[str] = []
        params = {"response_type": "code", "client_id": self.id, "redirect_uri": redirect, "scope": "openid",
                  "state": secrets.token_hex(8), "nonce": secrets.token_hex(8)}
        if challenge:
            params.update({"code_challenge": challenge, "code_challenge_method": method})
        if self.par_required if use_par is None else use_par:
            r, e = self.rec.http(s, "POST", self.par_ep, label + "-par", data={**params, **self.auth_params()})
            ev.append(e)
            if r.status_code not in (200, 201):
                return AuthResult(error="par_refused", stage="par", status=r.status_code, evidence=ev)
            url = self.auth_ep + "?" + urlencode({"client_id": self.id, "request_uri": r.json()["request_uri"]})
        else:
            url = self.auth_ep + "?" + urlencode(params)
        r, e = self.rec.http(s, "GET", url, label + "-auth")
        ev.append(e)
        for _ in range(6):
            if r.status_code in (301, 302, 303, 307):
                loc = r.headers["Location"]
                if loc.startswith(redirect.split("?")[0]):
                    q = {k: v[0] for k, v in parse_qs(urlparse(loc).query).items()}
                    return AuthResult(code=q.get("code"), iss=q.get("iss"), error=q.get("error"), stage="redirect",
                                      status=r.status_code, evidence=ev)
                r, e = self.rec.http(s, "GET", urljoin(r.url, loc), label + "-follow")
                ev.append(e)
                continue
            m = re.search(r'<form[^>]*id="(kc-form-login|kc-oauth-consent|kc-oauth)"[^>]*action="([^"]+)"', r.text) \
                or re.search(r'<form[^>]*action="([^"]+login-actions[^"]+)"', r.text)
            if not m:
                return AuthResult(error="no_form", stage="page", status=r.status_code, evidence=ev)
            action = urljoin(r.url, html.unescape(m.groups()[-1]))
            if "kc-form-login" in m.group(0) or ("username" in r.text and "password" in r.text):
                r, e = self.rec.http(s, "POST", action, label + "-login",
                                     data={"username": config.USER, "password": config.PASSWORD, "credentialId": ""})
            else:
                r, e = self.rec.http(s, "POST", action, label + "-consent", data={"accept": "Yes"})
            ev.append(e)
        return AuthResult(error="too_many_steps", stage="loop", status=r.status_code, evidence=ev)
