#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" != 0 ]]; then
  printf '%s\n' 'Run this host bootstrap through sudo.' >&2
  exit 1
fi
source /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 ]]; then
  printf '%s\n' 'This profile requires Ubuntu 24.04 LTS.' >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq -o Dpkg::Options::=--force-confold -y upgrade
apt-get -qq install -y ca-certificates curl ufw jq openssl unattended-upgrades
install -m 0755 -d /etc/apt/keyrings
curl --fail --silent --show-error --location https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
arch="$(dpkg --print-architecture)"
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: $arch
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get -qq update
apt-get -qq install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
ufw allow 22/tcp
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
timedatectl set-timezone UTC
install -m 0750 -d /srv/fleetory /srv/fleetory/config /srv/fleetory/releases /srv/fleetory/evidence
install -m 0700 -d /srv/fleetory/secrets
docker version --format 'Docker server: {{.Server.Version}}'
docker compose version --short
ufw status
if [[ -f /var/run/reboot-required ]]; then
  printf '%s\n' 'A controlled reboot is required before service deployment.'
fi
