#!/usr/bin/env python3
"""Ten OAuth 2.1 and FAPI 2.0 checks against Keycloak, in one of three realm states.

Usage: probes.py S0|S1|S2L [--only P2,P9] [--no-redact] [--keep]

  S0   default realm; S1 Keycloak's guidance (built-in client profiles linked); S2L S1 plus every single setting
  --only       run only these checks
  --no-redact  keep codes, tokens and passwords in http.jsonl (they work only against your throwaway container)
  --keep       leave the realms in place after the run (they are exported to the run folder either way)

Output: ~/oauthc/runs/<run id>/ with results.json (schema results.schema.json), http.jsonl, realm exports.
Exit status: 0 run complete, 2 usage, 3 Keycloak unavailable (no result written as a test failure).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time

from kclab import __version__, config
from kclab.checks import run_all
from kclab.evidence import Recorder
from kclab.fixtures import Lab
from kclab.oauth import Admin, Unavailable, health
from kclab.results import ResultSet


def lab_commit() -> str | None:
    try:
        return subprocess.run(["git", "-C", str(config.REPO), "rev-parse", "--short", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("state", choices=["S0", "S1", "S2L"])
    ap.add_argument("--only", default="", help="comma-separated checks, e.g. P2,P9")
    ap.add_argument("--no-redact", action="store_true")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args(argv)

    image_file = config.BASE / "image-digest.txt"
    image = image_file.read_text().strip().removeprefix("image ") if image_file.exists() else "unknown"
    commit = lab_commit()
    started = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_id = f"{started}-{a.state}-" + hashlib.sha256(f"{a.state}|{image}|{__version__}|{commit}".encode()).hexdigest()[:8]
    run_dir = config.RUNS / run_id
    run_dir.mkdir(parents=True)
    rec = Recorder(run_dir, redact_secrets=not a.no_redact)
    meta = {"keycloak_image": image, "keycloak_version": None, "lab_version": __version__, "lab_commit": commit,
            "started_utc": started, "redacted": not a.no_redact}
    rs = ResultSet(run_id, a.state, meta)
    try:
        health(rec)
        admin = Admin(rec)
    except Unavailable as e:
        print(f"Keycloak unavailable: {e}", file=sys.stderr)
        rec.close()
        return 3
    meta["keycloak_version"] = admin.server_version()
    lab = Lab(admin, a.state, rs.notes)
    try:
        lab.build()
        run_all(lab, rs, {x.strip().upper() for x in a.only.split(",") if x.strip()} or None)
        lab.export(run_dir)
    finally:
        if not a.keep:
            lab.teardown()
        rs.write(run_dir / "results.json")
        rec.close()
    try:
        import jsonschema
        jsonschema.validate(json.loads((run_dir / "results.json").read_text()),
                            json.loads(config.SCHEMA.read_text()))
        print("results.json valid against results.schema.json")
    except ImportError:
        print("jsonschema not installed; results.json not validated")
    print("\nrequirement verdicts:")
    for r in rs.requirements():
        print(f"  {r['client']:7} {r['requirement']:4} {r['level']:6} {r['verdict']}")
    print(f"run folder: {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
