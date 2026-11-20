#!/usr/bin/env bash
# Keycloak 26.8.2 in production mode (start), HTTPS with a throwaway lab CA, on localhost:8443.
# Own directory, container and port; touches nothing else on the host.
set -euo pipefail

BASE="$HOME/oauthc"
IMAGE="${KC_IMAGE:-quay.io/keycloak/keycloak@sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b}"  # 26.8.2
NAME="oauthc-kc"
PORT=8443

mkdir -p "$BASE/pki" "$BASE/runs"
cd "$BASE/pki"

if [ ! -f ca.crt ]; then
  # Strict X.509 (Python 3.13+) needs keyUsage on the CA and key identifiers on both certificates.
  openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=oauthc lab CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -keyout ca.key -out ca.crt
  openssl req -newkey rsa:3072 -nodes -subj "/CN=localhost" -keyout kc.key -out kc.csr
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > kc.ext
  openssl x509 -req -in kc.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
    -extfile kc.ext -out kc.crt
  chmod 644 kc.key kc.crt ca.crt
fi

docker pull "$IMAGE" >/dev/null
DIGEST=$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE")
echo "image $DIGEST" | tee "$BASE/image-digest.txt"

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  echo "container $NAME already exists; leaving it" ; exit 0
fi

ADMIN_PW=$(openssl rand -hex 16)
echo "$ADMIN_PW" > "$BASE/admin-password"; chmod 600 "$BASE/admin-password"

docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" \
  -v "$BASE/pki:/pki:ro" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PW" \
  "$DIGEST" start \
  --https-certificate-file=/pki/kc.crt --https-certificate-key-file=/pki/kc.key \
  --hostname="https://localhost:$PORT" >/dev/null

for i in $(seq 1 60); do
  if curl -sf --cacert "$BASE/pki/ca.crt" "https://localhost:$PORT/realms/master/.well-known/openid-configuration" >/dev/null; then
    echo "keycloak up after ${i}x5s"; exit 0
  fi
  sleep 5
done
echo "keycloak did not come up"; docker logs --tail 40 "$NAME"; exit 1
