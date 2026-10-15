#!/usr/bin/env bash
set -euo pipefail

: "${ADMIN_USER:?}" "${SOURCE_DIR:?}" "${SOURCE_ARCHIVE:?}"
systemctl stop cisco-dc-automation.service nginx.service || true
find /var/lib/cisco-dc-automation /var/lib/cisco-dc-automation-key -mindepth 1 -delete
rm -f /etc/cisco-dc-automation/.configured /etc/cisco-dc-automation/appliance.env
rm -f /etc/pki/nginx/cisco-dc-automation.crt /etc/pki/nginx/private/cisco-dc-automation.key \
    /etc/pki/nginx/.cisco-dc-self-signed
dnf clean all
rm -rf /var/cache/dnf/* /root/.cache "${SOURCE_DIR}" "${SOURCE_ARCHIVE}"
rm -f /etc/NetworkManager/system-connections/*.nmconnection /var/lib/NetworkManager/no-auto-default.state
rm -f /etc/ssh/ssh_host_*
cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
hostnamectl set-hostname localhost.localdomain
journalctl --rotate
journalctl --vacuum-time=1s
find /var/log -type f -exec truncate -s 0 {} +
rm -rf /tmp/* /var/tmp/*
rm -f /root/.bash_history "/home/${ADMIN_USER}/.bash_history"
fstrim -av || true