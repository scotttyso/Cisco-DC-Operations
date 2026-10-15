#!/usr/bin/env bash
set -euo pipefail

: "${ADMIN_USER:?}" "${APPLIANCE_VERSION:?}" "${SOURCE_ARCHIVE:?}" "${SOURCE_DIR:?}"
APP_DIR=/opt/cisco-dc-automation
APP_USER=cisco-dc-automation
STATE_DIR=/etc/cisco-dc-automation

dnf -y update
dnf -y install python3 python3-pip openssh-clients nginx openssl firewalld chrony \
    policycoreutils-python-utils open-vm-tools qemu-guest-agent cloud-init cloud-utils-growpart
install -d -m 0755 "${SOURCE_DIR}"
tar -xzf "${SOURCE_ARCHIVE}" -C "${SOURCE_DIR}"
bash "${SOURCE_DIR}/automation-appliance/install.sh"
install -d -m 0700 "${STATE_DIR}"
printf '%s\n' "APP_DIR=${APP_DIR}" "APP_USER=${APP_USER}" "ADMIN_USER=${ADMIN_USER}" \
    'APP_STATE_DIR=/var/lib/cisco-dc-automation' \
    'APP_KEY_FILE=/var/lib/cisco-dc-automation-key/vault.key' > "${STATE_DIR}/build.env"
chmod 0600 "${STATE_DIR}/build.env"
printf '%s\n' "${APPLIANCE_VERSION}" > "${STATE_DIR}/version"
install -m 0755 "${SOURCE_DIR}/automation-appliance/files/cisco-dc-config.py" /usr/local/sbin/cisco-dc-config
install -m 0644 "${SOURCE_DIR}/automation-appliance/files/cisco-dc-firstboot.service" /etc/systemd/system/
install -m 0644 "${SOURCE_DIR}/automation-appliance/nginx-cisco-dc.conf" /etc/nginx/conf.d/
setsebool -P httpd_can_network_connect 1
restorecon -RF /opt/cisco-dc-automation /etc/nginx /usr/local/sbin/cisco-dc-config
systemctl daemon-reload
systemctl enable cisco-dc-firstboot cisco-dc-automation nginx vmtoolsd qemu-guest-agent
systemctl enable --now firewalld chronyd
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
printf '%s\n' 'Cisco DC Operations Appliance' \
    '  WebUI: https://<appliance-ip>/' '  Configure: sudo cisco-dc-config' > /etc/issue.d/cisco-dc.issue