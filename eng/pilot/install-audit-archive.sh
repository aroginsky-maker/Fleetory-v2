#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 && "$#" == 0 ]] || exit 1
base=/srv/fleetory
tool="$base/eng/pilot/audit_archive.py"
trusted_directory_chain() {
  local path="$1"
  while :; do
    [[ -d "$path" && ! -L "$path" ]] || return 1
    [[ "$(stat -c '%u' -- "$path")" == 0 ]] || return 1
    [[ $(( 8#$(stat -c '%a' -- "$path") & 8#022 )) == 0 ]] || return 1
    [[ "$(realpath -e -- "$path")" == "$path" ]] || return 1
    [[ "$path" != / ]] || break
    path="$(dirname -- "$path")"
  done
}
trusted_file() {
  local path="$1"
  trusted_directory_chain "$(dirname -- "$path")"
  [[ -f "$path" && ! -L "$path" ]] || return 1
  [[ "$(stat -c '%u' -- "$path")" == 0 ]] || return 1
  [[ $(( 8#$(stat -c '%a' -- "$path") & 8#022 )) == 0 ]] || return 1
}
for source in "$tool" "$base/infra/pilot/audit-archive.service" "$base/infra/pilot/audit-archive.timer"; do
  trusted_file "$source"
done
trusted_directory_chain /etc/systemd/system
# Complete preflight before running the root helper or changing system units.
for suffix in service timer; do
  source="$base/infra/pilot/audit-archive.$suffix"
  target="/etc/systemd/system/fleetory-audit-archive.$suffix"
  if [[ -e "$target" || -L "$target" ]]; then
    trusted_file "$target"
    cmp -s -- "$source" "$target" || exit 1
  fi
done
python3 "$tool" init >/dev/null
for suffix in service timer; do
  target="/etc/systemd/system/fleetory-audit-archive.$suffix"
  if [[ ! -e "$target" ]]; then
    install -o root -g root -m 0644 -- "$base/infra/pilot/audit-archive.$suffix" "$target"
  fi
done
systemd-analyze verify /etc/systemd/system/fleetory-audit-archive.service /etc/systemd/system/fleetory-audit-archive.timer
systemctl daemon-reload
systemctl enable --now fleetory-audit-archive.timer
systemctl start fleetory-audit-archive.service
python3 "$tool" verify
printf '%s\n' 'Pilot audit archive timer installed; independent WORM custody remains unverified.'
