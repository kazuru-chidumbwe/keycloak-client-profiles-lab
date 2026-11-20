# Changelog

## 1.0.0 (20 November 2026)

The lab kit of the first post, rebuilt so that every verdict is reproducible and traceable.

- Every check runs on its own client, and every test that spends tokens on its own grant. The public refresh-token
  check (P9) now uses four separate token families, so a replay in one test cannot decide the next.
- Positive controls: a negative test counts only if a valid request on the same client succeeded first.
- Four verdicts (PASS, FAIL, INCONCLUSIVE, NOT_APPLICABLE), rolled up per requirement. P9 passes on binding or on
  rotation, as RFC 9700 section 2.2.2 allows.
- `requirements.yml`: every requirement with its source section, level and tests. New requirement P6r (SHOULD): tokens
  issued from a code are revoked when the code is used again.
- `results.json` with evidence ids into `http.jsonl`, validated against `results.schema.json`. Codes, tokens,
  assertions and passwords are redacted by default (`--no-redact` keeps them).
- Hardened setup: the lab CA key stays on the host, the server key goes into the container through a volume with mode
  600, every capability is dropped, no-new-privileges is set, the bootstrap admin is replaced and deleted, and no secret
  is passed as a command-line argument.
- One command (`run.sh`, `run.ps1` through WSL), a probe container (`Dockerfile.probes`), a Makefile and offline tests.
- Keycloak being unreachable ends a run with exit status 3 instead of producing failed tests.

## 0.1.0 (19 November 2026)

The kit as first tested: Keycloak 26.8.2, ten checks in three realm states, and the client-policy condition trap.
