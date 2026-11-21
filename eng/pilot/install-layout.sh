#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 ]] || exit 1
base=/srv/fleetory
[[ "$(realpath "$base")" == /srv/fleetory ]] || exit 1
[[ -f "$base/compose.yaml" ]] || exit 1
if find "$base/secrets" -type l -print -quit | grep -q .; then
  printf '%s\n' 'Runtime secret paths must not be links.' >&2
  exit 1
fi
chmod 0750 "$base"
chown root:root "$base"
chmod 0700 "$base/secrets"
chown root:root "$base/secrets"
for entry in postgres:999:999 postgres-init:999:999 keycloak:1000:0 openbao:100:1000 immudb:3322:3322 audit-gateway:101:101 server:1654:1654 signer:1654:1654; do
  IFS=: read -r role uid gid <<<"$entry"
  dir="$base/secrets/$role"
  [[ -d "$dir" ]] || exit 1
  chown -R "$uid:$gid" "$dir"
  find "$dir" -type d -exec chmod 0700 {} +
  find "$dir" -type f -exec chmod 0400 {} +
done
for entry in postgres:999:999 openbao:100:1000 immudb:3322:3322; do
  IFS=: read -r role uid gid <<<"$entry"
  install -m 0700 -o "$uid" -g "$gid" -d "$base/data/$role"
done
find "$base/config" -type d -exec chmod 0755 {} +
find "$base/config" -type f -exec chmod 0644 {} +
find "$base/infra" "$base/releases" -type d -exec chmod 0755 {} +
find "$base/infra" "$base/releases" -type f -exec chmod 0644 {} +
shopt -s nullglob
signer_entrypoints=("$base"/releases/*/signer/entrypoint.sh)
((${#signer_entrypoints[@]} > 0)) || exit 1
for entrypoint in "${signer_entrypoints[@]}"; do
  [[ -f "$entrypoint" && ! -L "$entrypoint" ]] || exit 1
  resolved_entrypoint="$(realpath -e -- "$entrypoint")"
  [[ "$resolved_entrypoint" =~ ^/srv/fleetory/releases/[^/]+/signer/entrypoint\.sh$ ]] || exit 1
  chmod 0755 -- "$resolved_entrypoint"
done
chmod 0600 "$base/.env"
cd "$base"
docker compose config --quiet
printf '%s\n' 'Runtime ownership/modes and Compose configuration validated.'
