#!/bin/sh
# Generates a throwaway CA, a server cert for the web, mail and dns services, and a client cert for mTLS.
set -eu

dir="${1:-/certs}"

if [ -f "${dir}/server.crt" ]; then
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj "/CN=blackbox-local-ca" \
  -keyout "${dir}/ca.key" -out "${dir}/ca.crt"

openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=web" \
  -keyout "${dir}/server.key" -out "${dir}/server.csr"

printf 'subjectAltName=DNS:web,DNS:mail,DNS:dns\n' > "${dir}/san.ext"
openssl x509 -req -days 30 -in "${dir}/server.csr" \
  -CA "${dir}/ca.crt" -CAkey "${dir}/ca.key" -CAcreateserial \
  -extfile "${dir}/san.ext" -out "${dir}/server.crt"

openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=blackbox" \
  -keyout "${dir}/client.key" -out "${dir}/client.csr"

printf 'extendedKeyUsage=clientAuth\n' > "${dir}/client.ext"
openssl x509 -req -days 30 -in "${dir}/client.csr" \
  -CA "${dir}/ca.crt" -CAkey "${dir}/ca.key" -CAcreateserial \
  -extfile "${dir}/client.ext" -out "${dir}/client.crt"

# CoreDNS runs as nonroot and must read the server key.
chmod 644 "${dir}"/*.key
