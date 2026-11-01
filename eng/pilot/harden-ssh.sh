#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 ]] || exit 1
install -m 0755 -d /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-fleetory.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
EOF
sshd -t
systemctl reload ssh.service
ufw allow 80/tcp
ufw allow 443/tcp
hostnamectl set-hostname fleetory-pilot-01
if grep -q '^127\.0\.1\.1[[:space:]]' /etc/hosts; then
  sed -i 's/^127\.0\.1\.1[[:space:]].*/127.0.1.1 fleetory-pilot-01/' /etc/hosts
else
  printf '\n127.0.1.1 fleetory-pilot-01\n' >> /etc/hosts
fi
printf 'preserve_hostname: true\n' > /etc/cloud/cloud.cfg.d/99-fleetory-hostname.cfg
sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication|maxauthtries) '
ufw status
