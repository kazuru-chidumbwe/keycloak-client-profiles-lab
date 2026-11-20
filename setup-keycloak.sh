#!/usr/bin/env bash
# Keycloak in production mode (start) with HTTPS from a throwaway lab CA, on 127.0.0.1:8443 only.
# Own directory (~/oauthc, or $KCLAB_HOME), container, volume and port; touches nothing else on the host.
#
# Hardening:
#  - The lab CA private key never leaves the host directory. Only the server certificate and key are copied into a
#    Docker volume, where the key is mode 600 and owned by Keycloak's user.
#  - The container runs with every capability dropped and no-new-privileges.
#  - Keycloak's bootstrap admin is passed as an environment variable (the only way the image accepts it), so
#    `docker inspect` shows it. The script therefore creates a lab admin with a second random password, kept only in
#    ~/oauthc/admin-credentials (mode 600), and deletes the bootstrap account: the visible password opens nothing.
#  - The container cannot run with a read-only root file system: `start` rebuilds Keycloak's server at first boot
#    and writes into /opt/keycloak. This is stated rather than worked around.
set -euo pipefail

BASE="${KCLAB_HOME:-$HOME/oauthc}"
PINNED="quay.io/keycloak/keycloak@sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b"  # 26.8.2
IMAGE="${KC_IMAGE:-$PINNED}"
NAME="kclab-kc"
VOLUME="kclab-tls"
PORT=8443

if [ "$IMAGE" != "$PINNED" ]; then
  echo "WARNING: KC_IMAGE=$IMAGE overrides the pinned Keycloak 26.8.2 digest; results may differ from the post." >&2
fi

umask 077
mkdir -p "$BASE/pki/server" "$BASE/runs"
cd "$BASE/pki"

if [ ! -f ca.crt ]; then
  # Strict X.509 (Python 3.13+) needs keyUsage on the CA and key identifiers on both certificates.
  openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=kclab lab CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey rsa:3072 -nodes -subj "/CN=localhost" -keyout server/kc.key -out server/kc.csr 2>/dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > server/kc.ext
  openssl x509 -req -in server/kc.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
    -extfile server/kc.ext -out server/kc.crt 2>/dev/null
  chmod 600 ca.key server/kc.key
  chmod 644 ca.crt server/kc.crt
fi

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  echo "container $NAME already exists; leaving it (remove it with: docker rm -f $NAME)"; exit 0
fi

docker pull -q "$IMAGE" >/dev/null
DIGEST=$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE")
echo "image $DIGEST" | tee "$BASE/image-digest.txt"

# server certificate and key only, into a volume Keycloak's user (uid 1000) can read
docker volume create "$VOLUME" >/dev/null
docker run --rm --user 0 --entrypoint bash -v "$VOLUME:/tls" -v "$BASE/pki/server:/src:ro" "$DIGEST" -c \
  'cp /src/kc.crt /src/kc.key /tls/ && chown 1000:0 /tls/kc.crt /tls/kc.key && chmod 600 /tls/kc.key && chmod 644 /tls/kc.crt'

BOOT_PW=$(openssl rand -hex 16)
# secrets go through files and stdin, never through command arguments (visible to other users in ps)
ENVF=$(mktemp); HDR=$(mktemp); trap 'rm -f "$ENVF" "$HDR"' EXIT
printf 'KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap-admin\nKC_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$BOOT_PW" > "$ENVF"
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" \
  -v "$VOLUME:/tls:ro" --cap-drop ALL --security-opt no-new-privileges --env-file "$ENVF" \
  "$DIGEST" start \
  --https-certificate-file=/tls/kc.crt --https-certificate-key-file=/tls/kc.key \
  --hostname="https://localhost:$PORT" >/dev/null

KC="https://localhost:$PORT"
CURL=(curl -sf --cacert "$BASE/pki/ca.crt" --connect-timeout 5 --max-time 30)
up=0
for i in $(seq 1 60); do
  if "${CURL[@]}" "$KC/realms/master/.well-known/openid-configuration" >/dev/null; then up=1; echo "keycloak up after ${i}x5s"; break; fi
  sleep 5
done
[ $up = 1 ] || { echo "keycloak did not come up"; docker logs --tail 40 "$NAME"; exit 1; }

# replace the bootstrap admin with a lab admin whose password is kept only in a mode-600 file
tok(){ printf 'grant_type=password&client_id=admin-cli&username=%s&password=%s' "$1" "$2" \
       | "${CURL[@]}" --data-binary @- "$KC/realms/master/protocol/openid-connect/token" \
       | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'; }
hdr(){ printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$1" > "$HDR"; }   # token via a file
LAB_PW=$(openssl rand -hex 24)
hdr "$(tok bootstrap-admin "$BOOT_PW")"
A=(-H @"$HDR")
printf '{"username":"lab-admin","enabled":true,"credentials":[{"type":"password","value":"%s","temporary":false}]}' "$LAB_PW" \
  | "${CURL[@]}" "${A[@]}" -X POST --data-binary @- "$KC/admin/realms/master/users"
uid(){ "${CURL[@]}" "${A[@]}" "$KC/admin/realms/master/users?username=$1&exact=true" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])'; }
LAB_ID=$(uid lab-admin)
ROLE=$("${CURL[@]}" "${A[@]}" "$KC/admin/realms/master/roles/admin")
"${CURL[@]}" "${A[@]}" -X POST "$KC/admin/realms/master/users/$LAB_ID/role-mappings/realm" -d "[$ROLE]"
printf '{"username": "lab-admin", "password": "%s"}\n' "$LAB_PW" > "$BASE/admin-credentials"
chmod 600 "$BASE/admin-credentials"
hdr "$(tok lab-admin "$LAB_PW")"   # proves the lab admin works before the bootstrap account goes
"${CURL[@]}" "${A[@]}" -X DELETE "$KC/admin/realms/master/users/$(uid bootstrap-admin)"
echo "lab admin ready (credentials in $BASE/admin-credentials); bootstrap admin deleted"
