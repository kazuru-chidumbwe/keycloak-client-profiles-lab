# Keycloak client profiles: OAuth 2.1 and FAPI 2.0 checks

Lab kit for the post **"Keycloak's client profiles close the default gaps, if you pick the right policy condition"**.

It starts a throwaway Keycloak 26.8.2 on `localhost`, builds two realms, and runs ten checks taken from RFC 9700,
the OAuth 2.1 draft and the FAPI 2.0 Security Profile against them in three states. These are the console defaults,
Keycloak's own guidance (the built-in client profiles linked through client policies), and every single setting the
documentation offers. A second script reproduces the policy-condition trap that breaks public clients.

Everything runs locally against a container you start yourself. No external service is contacted.

## What it reproduces

| # | Check | Default realm | Keycloak guidance | Every setting |
|---|---|---|---|---|
| P1 | Password grant refused | pass | pass | pass |
| P2 | PKCE with S256 required | **fail** | pass | pass |
| P3 | PKCE downgrade refused | pass | pass | pass |
| P4 | Pushed authorization request required (FAPI) | **fail** | pass | pass |
| P5 | Exact redirect URI match | pass | pass | pass |
| P6 | Code reuse refused, its tokens revoked | pass | pass | pass |
| P7 | Code lifetime 60 seconds or less (FAPI) | pass | pass | pass |
| P8 | Client assertion `aud` is the issuer, as a string (FAPI) | not used | **fail** | **fail** |
| P9 | Public client refresh token bound or rotated | **fail** | pass | pass |
| P10 | `iss` in the authorization response | pass | pass | pass |

P8 fails because Keycloak also accepts a JSON array that holds only the issuer. Keycloak treats this as intended
behaviour ([keycloak/keycloak#54743](https://github.com/keycloak/keycloak/issues/54743), closed as not planned).

The trap is one client policy with the condition `any-client` and both OAuth 2.1 profiles linked. It turns a new
public client into a `client-jwt` client with mTLS-bound tokens, and that client's first authorization request fails
with `invalid client access type: public`. One policy per client type, as in `policies.json`, avoids it.

We last ran the kit from a clean home directory on 19 Nov 2026 (Keycloak 26.8.2, Debian 13, Python 3.13,
Docker 26.1), and every row above came out as shown.

## Requirements

- Linux with Docker, `openssl` and `curl` (tested on Debian 13)
- Python 3.12 or newer
- A free TCP port 8443 on `127.0.0.1`
- About 5 minutes in total, because P7 waits 65 seconds on purpose to let a code expire

## Quick start

```bash
mkdir -p ~/oauthc && cp *.py *.sh ~/oauthc/ && cd ~/oauthc
python3 -m venv venv && ./venv/bin/pip install requests jwcrypto

bash setup-keycloak.sh                 # Keycloak on https://localhost:8443 with a throwaway lab CA in ~/oauthc/pki
./venv/bin/python probes.py S0         # default realm
./venv/bin/python probes.py S1         # Keycloak's guidance: built-in client profiles linked
./venv/bin/python probes.py S2L        # S1 plus every single setting the documentation offers
./venv/bin/python trap_anyclient.py    # any-client condition against client-access-type
```

## Expected output

Each probe prints one line per check and client, with the evidence behind the verdict. A few lines from our run:

```
S0 F P2: FAIL  no challenge -> code issued; plain -> code issued
S0 F P4: FAIL  unpushed request -> code issued
S0 R-pub P9: FAIL  first refresh 200; replay 200; other DPoP key 200; no proof 200
S1 R-pub P9: PASS  first refresh 200; replay 200; other DPoP key 400; no proof 400
S1 F P8: FAIL  non-issuer aud accepted: ['array']
```

`F` is the FAPI realm `trackf` with one confidential client. `R-pub` and `R-conf` are the public and the
confidential client of the OAuth 2.1 realm `trackr`. The confidential `trackr` client is checked in the default state
only, because its profile needs mutual TLS and the kit has no client certificates.

Each run also writes a folder you can inspect afterwards:

```
~/oauthc/runs/<time>-<state>/
  results.json        one record per check and client: probe, track, outcome, evidence
  http.jsonl          every HTTP exchange the probes made, request and response
  realm-trackf.json   the realm exports the run used
  realm-trackr.json
```

`trap_anyclient.py` writes `trap.json` with the client settings and the authorization result for each policy set,
next to its own `http.jsonl`.

## Files

| File | What it does |
|---|---|
| `setup-keycloak.sh` | Creates a lab CA and a `localhost` certificate, then starts Keycloak 26.8.2 in production mode, pinned by image digest |
| `probes.py` | Rebuilds the realms for one state (`S0`, `S1` or `S2L`), runs P1 to P10 and logs every exchange |
| `trap_anyclient.py` | Builds the two policy sets on fresh realms and records what each does to a new public client |
| `policies.json` | The client policy set that works in a realm with both confidential and public clients |

## Testing another Keycloak version

```bash
docker rm -f oauthc-kc
KC_IMAGE=quay.io/keycloak/keycloak:<version> bash setup-keycloak.sh
```

Then run the probes again. We would like to hear about any version where a row differs.

## Safety

- Use a lab instance only. The scripts delete and recreate the realms `trackf`, `trackr`, `trapa` and `trapb`.
- Keycloak listens on `127.0.0.1` only. The admin password is generated at setup and kept in
  `~/oauthc/admin-password` with mode 600.
- The CA in `~/oauthc/pki` exists only for this lab and is valid for one year. Do not add it to a system trust store.
- `http.jsonl` holds the codes and tokens of the run. They work only against your throwaway container, but treat the
  folder as you would any credentials.

## Clean up

```bash
docker rm -f oauthc-kc
rm -rf ~/oauthc
```

## Troubleshooting

- **`keycloak did not come up`**: the setup script prints the last 40 lines of the container log, which name the cause,
  for example port 8443 already in use.
- **`container oauthc-kc already exists; leaving it`**: an earlier container is still there. Remove it with
  `docker rm -f oauthc-kc` and run setup again.
- **Certificate errors on Python 3.13**: the setup script adds the key usage and key identifier extensions that the
  stricter X.509 checks of Python 3.13 require. If you created the CA with an older copy of the script, delete
  `~/oauthc/pki` and run setup again.

## What the kit does not cover

The OAuth 2.1 confidential profile binds tokens with mutual TLS, and the kit has no client-certificate PKI. The mTLS
variants of the FAPI profile are therefore not tested either. The kit is not the OpenID conformance suite, which
Keycloak runs itself for its certification.

## License

MIT, see `LICENSE`.
