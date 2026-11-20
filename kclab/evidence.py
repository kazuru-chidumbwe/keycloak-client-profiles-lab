"""HTTP with an evidence trail.

Every exchange gets an id (http-0001, http-0002, ...) and one line in http.jsonl. Secrets are redacted by default:
a redacted value is replaced by "<redacted:XXXXXXXX>", the first 8 hex digits of its SHA-256, so the same token can
still be followed across exchanges without the log holding a working credential. Pass redact=False to keep values.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from . import config

SECRET_FIELDS = {
    "password", "client_secret", "client_assertion", "code", "code_verifier", "refresh_token", "access_token",
    "id_token", "request_uri", "value", "secret", "credentials",
}
SECRET_HEADERS = {"authorization", "dpop", "cookie", "set-cookie"}
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def tag(value: Any) -> str:
    return "<redacted:" + hashlib.sha256(str(value).encode()).hexdigest()[:8] + ">"


def redact(obj: Any) -> Any:
    """Redact secret fields in dicts and lists, JWTs anywhere in strings, and secret query parameters in URLs."""
    if isinstance(obj, dict):
        return {k: (tag(v) if str(k).lower() in SECRET_FIELDS and v not in (None, "") else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        if obj.startswith(("http://", "https://")) and "?" in obj:
            obj = redact_url(obj)
        return _JWT.sub(lambda m: tag(m.group(0)), obj)
    return obj


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    q = [(k, tag(v) if k.lower() in SECRET_FIELDS else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _body(r: requests.Response) -> Any:
    try:
        return r.json()
    except ValueError:
        return r.text[:4000]


class Recorder:
    def __init__(self, run_dir: Path, redact_secrets: bool = True) -> None:
        self.dir = run_dir
        self.redact = redact_secrets
        self.n = 0
        self.log = open(run_dir / "http.jsonl", "w", encoding="utf-8", newline="\n")  # noqa: SIM115 (closed in close())

    def close(self) -> None:
        self.log.close()

    def http(self, s: requests.Session, method: str, url: str, label: str, **kw) -> tuple[requests.Response, str]:
        """One HTTP exchange. Returns the response and its evidence id."""
        kw.setdefault("verify", config.CA)
        kw.setdefault("allow_redirects", False)
        kw.setdefault("timeout", config.TIMEOUT)
        r = s.request(method, url, **kw)
        self.n += 1
        eid = f"http-{self.n:04d}"
        rec = {
            "id": eid, "label": label, "method": method, "url": url,
            "request": {"data": kw.get("data"), "json": kw.get("json"),
                        "headers": dict(kw.get("headers") or {})},
            "status": r.status_code,
            "location": r.headers.get("Location"),
            "response_headers": {k: v for k, v in r.headers.items()
                                 if k.lower() in ("dpop-nonce", "www-authenticate", "content-type")},
            "body": _body(r),
        }
        if self.redact:
            rec["request"]["headers"] = {k: (tag(v) if k.lower() in SECRET_HEADERS else v)
                                         for k, v in rec["request"]["headers"].items()}
            rec = redact(rec)
        self.log.write(json.dumps(rec, sort_keys=True) + "\n")
        self.log.flush()
        return r, eid


def error_of(r: requests.Response) -> str | None:
    """The OAuth error code of a response, if it has one."""
    try:
        e = r.json().get("error")
        return str(e) if e else None
    except (ValueError, AttributeError):
        return None
