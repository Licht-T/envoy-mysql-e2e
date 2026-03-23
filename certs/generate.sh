#!/usr/bin/env bash
# Generate a self-signed CA and server certificate for Envoy MySQL SSL termination.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# CA
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca-key.pem -out ca-cert.pem -days 3650 \
  -subj "/CN=Test CA"

# Server key + CSR
openssl req -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server.csr \
  -subj "/CN=localhost"

# Sign server cert with CA
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 3650 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:envoy")

rm -f server.csr ca-cert.srl

echo "Certificates generated in $DIR"
