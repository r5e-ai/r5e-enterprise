#!/usr/bin/env bash
# gen-broker-key.sh — generate an ES256 (P-256) keypair for the Standalone
# Identity Broker's JWT signer. F002 T012.
#
# Writes:
#   ./secrets/broker-signing-key.pem       (PKCS#8 PEM private key, 0600)
#   ./secrets/broker-signing-key.pub.pem    (SubjectPublicKeyInfo PEM public key, 0644)
#
# docker-compose.yaml mounts the private key read-only at /secrets/ inside the
# broker container. The public key is used by the JWKS-publication endpoint.

set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
  echo "gen-broker-key.sh: openssl is required but not found in PATH" >&2
  exit 1
fi

SECRETS_DIR="./secrets"
PRIV="${SECRETS_DIR}/broker-signing-key.pem"
PUB="${SECRETS_DIR}/broker-signing-key.pub.pem"

mkdir -p "${SECRETS_DIR}"

if [ -e "${PRIV}" ] || [ -e "${PUB}" ]; then
  echo "gen-broker-key.sh: refusing to overwrite existing key material at ${PRIV} / ${PUB}" >&2
  echo "                    delete them explicitly first if you want to rotate" >&2
  exit 2
fi

# Generate the private key (P-256 / prime256v1) directly in PKCS#8 PEM.
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out "${PRIV}"

# Derive the public key.
openssl pkey -in "${PRIV}" -pubout -out "${PUB}"

chmod 600 "${PRIV}"
chmod 644 "${PUB}"

echo "wrote ${PRIV} (0600)"
echo "wrote ${PUB} (0644)"
