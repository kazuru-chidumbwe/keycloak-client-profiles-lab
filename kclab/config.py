"""Paths and settings. Every value can be overridden through the environment."""

from __future__ import annotations

import os
from pathlib import Path

BASE = Path(os.environ.get("KCLAB_HOME", Path.home() / "oauthc"))
PKI = BASE / "pki"
CA = str(PKI / "ca.crt")
RUNS = BASE / "runs"
ADMIN_FILE = BASE / "admin-credentials"

KC = os.environ.get("KCLAB_URL", "https://localhost:8443")
REDIRECT = "https://client.example/cb"
USER = "alice"
PASSWORD = "Lab-" + "x" * 12

# (connect, read) in seconds for every HTTP request the lab makes
TIMEOUT = (float(os.environ.get("KCLAB_CONNECT_TIMEOUT", "5")), float(os.environ.get("KCLAB_READ_TIMEOUT", "30")))

# Seconds P7 waits before using a code; FAPI 2.0 allows at most 60 s of code lifetime.
P7_WAIT = int(os.environ.get("KCLAB_P7_WAIT", "65"))

REPO = Path(__file__).resolve().parent.parent
POLICIES = REPO / "policies.json"
REQUIREMENTS = REPO / "requirements.yml"
SCHEMA = REPO / "results.schema.json"
