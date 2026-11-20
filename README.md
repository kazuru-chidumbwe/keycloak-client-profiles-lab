# keycloak-client-profiles-lab

OAuth 2.1 and FAPI 2.0 checks against Keycloak's client profiles, with an evidence trail for every verdict.

Lab kit for the post **"Keycloak's client profiles close the default gaps, if you pick the right policy condition"**.

It starts a throwaway Keycloak 26.8.2 on `127.0.0.1`, builds two realms, and runs ten checks taken from RFC 9700,
the OAuth 2.1 draft and the FAPI 2.0 Security Profile in three states: the console defaults, Keycloak's own guidance
(the built-in client profiles linked through client policies), and every single setting the documentation offers. A
second script reproduces the policy-condition trap that breaks public clients.

Everything runs locally against containers you start yourself. No external service is contacted.

## What it reproduces

Requirement verdicts on Keycloak 26.8.2. `F` is the FAPI realm's confidential client, `R-pub` and `R-conf` the public
and the confidential client of the OAuth 2.1 realm. Every cell rests on the tests and evidence ids in `results.json`.

| # | Requirement | Level | Default realm | Keycloak guidance | Every setting |
|---|---|---|---|---|---|
| P1 | Password grant refused | MUST | pass | pass | pass |
| P2 | PKCE with S256 required | MUST | **fail** (all clients) | pass | pass |
| P3 | PKCE downgrade refused | MUST | pass | pass | pass |
| P4 | Pushed authorization request required (FAPI) | MUST | **fail** | pass | pass |
| P5 | Exact redirect URI match | MUST | pass | pass | pass |
| P6 | Authorization code used once | MUST | pass | pass | pass |
| P6r | Tokens from a replayed code revoked | SHOULD | pass | pass | pass |
| P7 | Code lifetime 60 seconds or less (FAPI) | MUST | pass | pass | pass |
| P8 | Client assertion `aud` is the issuer, as a string (FAPI) | MUST | not applicable | **fail** | **fail** |
| P9 | Public client refresh token sender-constrained or rotated | MUST | **fail** | pass (bound) | pass (bound and rotated) |
| P10 | `iss` in the authorization response | MUST | pass | pass | pass |

With Keycloak's guidance and every setting, `R-conf` is INCONCLUSIVE: the OAuth 2.1 confidential profile binds its
tokens with mutual TLS, and the kit has no client certificates yet. In the default realm `F` authenticates with a
client secret, so P8 does not apply.

P8 fails because Keycloak also accepts a JSON array that holds only the issuer. Keycloak treats this as intended
behaviour ([keycloak/keycloak#54743](https://github.com/keycloak/keycloak/issues/54743), closed as not planned).

The trap is one client policy with the condition `any-client` and both OAuth 2.1 profiles linked. It turns a new
public client into a `client-jwt` client with mTLS-bound tokens, and that client's first authorization request fails
with `invalid client access type: public`. One policy per client type, as in `policies.json`, avoids it.

Last full run: 20 Nov 2026, Keycloak 26.8.2 (image digest in `setup-keycloak.sh`), Ubuntu 24.04, Docker 29.1.

## How a verdict is reached

- **`requirements.yml`** lists every requirement with its source, level (MUST or SHOULD), the clients it applies to,
  and its tests. Test names, expected outcomes and the table above come from it.
- **Every check gets its own client**, and every test that spends tokens gets its own grant, so what one test does to
  a client (a replayed code, a revoked token family) cannot reach another.
- **Positive controls first.** A check's negative tests count only if a working request on the same client succeeded,
  because a refusal from a client that cannot work at all proves nothing.
- **Four verdicts:** PASS, FAIL, INCONCLUSIVE (the control failed or the client could not be tested) and
  NOT_APPLICABLE. Requirement verdicts roll up from the tests; P9 passes on rotation or on binding, as RFC 9700 allows.
- **Evidence ids.** Every HTTP exchange is written to `http.jsonl` with an id (`http-0042`), and every result lists the
  ids it rests on. Codes, tokens, assertions and passwords are redacted by default and replaced by the first 8 hex
  digits of their SHA-256, so a value can still be followed across exchanges.

## Requirements

- Linux with Docker, `openssl`, `curl` and `python3` (the probes themselves run in a container; tested on
  Ubuntu 24.04 and Debian 13). On Windows, WSL 2 with Docker Desktop.
- A free TCP port 8443 on `127.0.0.1`
- About 10 minutes for all three states, because P7 waits 65 seconds on purpose to let a code expire

## Quick start

```bash
./run.sh                 # Keycloak, then S0, S1, S2L and the trap
./run.sh S1              # one state only
```

or step by step:

```bash
bash setup-keycloak.sh                                   # Keycloak on https://localhost:8443, lab CA in ~/oauthc/pki
docker build -f Dockerfile.probes -t kclab-probes .
docker run --rm --network host -v ~/oauthc:/data -e KCLAB_HOME=/data kclab-probes probes.py S0
docker run --rm --network host -v ~/oauthc:/data -e KCLAB_HOME=/data kclab-probes probes.py S1
docker run --rm --network host -v ~/oauthc:/data -e KCLAB_HOME=/data kclab-probes probes.py S2L
docker run --rm --network host -v ~/oauthc:/data -e KCLAB_HOME=/data kclab-probes trap_anyclient.py
```

With Python 3.12 or newer on the host, `make venv` then `make run-default`, `make run-guidance`, `make run-all`,
`make trap` and `make test` do the same without the probe container.

Options: `probes.py S1 --only P2,P9` runs some checks; `--no-redact` keeps codes and tokens in the log (they work only
against your throwaway container); `--keep` leaves the realms in place (they are exported to the run folder either
way). Exit status 3 means Keycloak could not be reached, which is never reported as a test failure.

## Output

```
~/oauthc/runs/<run id>/
  results.json        every test and requirement verdict (schema: results.schema.json)
  http.jsonl          every HTTP exchange, with its evidence id
  realm-trackf.json   the realm exports the run used
  realm-trackr.json
```

`trap_anyclient.py` writes `trap.json` with the client settings and the authorization result for each policy set.

## Files

| File | What it does |
|---|---|
| `setup-keycloak.sh` | Lab CA and server certificate, then Keycloak 26.8.2 in production mode, pinned by image digest |
| `probes.py` | One state (`S0`, `S1` or `S2L`): builds both realms, runs P1 to P10, writes results and evidence |
| `trap_anyclient.py` | The two policy sets on fresh realms, and what each does to a new public client |
| `requirements.yml` | The requirements matrix |
| `results.schema.json` | JSON schema of `results.json` |
| `policies.json` | The client policy set that works in a realm with both confidential and public clients |
| `kclab/` | Evidence recorder, fixtures, the checks, verdict rules |
| `tests/` | Tests that need no Keycloak (redaction, verdict rules, schema) |

## Testing another Keycloak version

```bash
make clean
KC_IMAGE=quay.io/keycloak/keycloak:<version> ./run.sh
```

The setup script warns when `KC_IMAGE` overrides the pinned digest. We would like to hear about any version where a
row differs; please open an issue with the `results.json` of the run.

## Safety

- Use a lab instance only. The scripts delete and recreate the realms `trackf`, `trackr`, `trapa` and `trapb`.
- Keycloak listens on `127.0.0.1` only, with every container capability dropped and no-new-privileges.
- The lab CA private key never leaves `~/oauthc/pki`; only the server certificate and key go into the container, through
  a Docker volume. Do not add the lab CA to a system trust store.
- Keycloak's image takes its bootstrap admin only from an environment variable, which `docker inspect` shows. The setup
  script therefore creates a lab admin whose password is kept only in `~/oauthc/admin-credentials` (mode 600) and
  deletes the bootstrap account. Secrets are passed through files and standard input, not command-line arguments.
- The container does not run with a read-only root file system, because `start` rebuilds the server at first boot.

## Clean up

```bash
make clean          # removes the container and the certificate volume
rm -rf ~/oauthc     # runs, lab CA and credentials
```

## What the kit does not cover yet

The OAuth 2.1 confidential profile binds tokens with mutual TLS, and the kit has no client-certificate PKI yet, so that
client is checked in the default state only and the mTLS variants of the FAPI profile are not tested. The kit is not
the OpenID conformance suite, which Keycloak runs itself for its certification.

## License

MIT, see `LICENSE`.
