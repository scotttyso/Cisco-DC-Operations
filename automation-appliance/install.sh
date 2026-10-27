#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf '%s\n' 'Run this installer as root on the target appliance.' >&2
    exit 1
fi

# Code and dependencies must remain readable by the unprivileged service.
umask 022

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPTS_DIR=${PROJECT_DIR}/nxos-scripts
APP_DIR=/opt/cisco-dc-automation
SERVICE_USER=cisco-dc-automation

for script in nd_stage_nexus_updates.py nxos_bootflash_stage.py; do
    if [[ ! -f "${SCRIPTS_DIR}/${script}" ]]; then
        printf 'Missing staging script: %s/%s\n' "${SCRIPTS_DIR}" "${script}" >&2
        exit 1
    fi
done
command -v python3 >/dev/null
command -v ssh >/dev/null

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/cisco-dc-automation --shell /usr/sbin/nologin "${SERVICE_USER}"
fi
install -d -m 0755 "${APP_DIR}" "${APP_DIR}/nxos-scripts"
for module in aci_ifstatus_common aci_leaf_ifstatus_pre aci_leaf_ifstatus_post aci_checks aci_jump secure_profiles oidc_auth release_updates nxos_jobs nd_interfaces nd_telemetry interface_description_table automation_ui; do
    install -m 0644 "${PROJECT_DIR}/${module}.py" "${APP_DIR}/"
done
install -m 0644 "${PROJECT_DIR}/VERSION" "${APP_DIR}/"
install -m 0644 "${PROJECT_DIR}/interface_description_table.js" "${APP_DIR}/"
install -m 0644 "${PROJECT_DIR}/requirements.txt" "${APP_DIR}/"
install -d -m 0755 /usr/local/sbin
install -m 0755 "${PROJECT_DIR}/automation-appliance/update.py" /usr/local/sbin/cisco-dc-update
install -m 0644 "${SCRIPTS_DIR}/nd_stage_nexus_updates.py" "${SCRIPTS_DIR}/nxos_bootflash_stage.py" "${APP_DIR}/nxos-scripts/"
python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/python" -m pip install -r "${APP_DIR}/requirements.txt"
chmod -R a+rX "${APP_DIR}/.venv"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0700 /var/lib/cisco-dc-automation /var/lib/cisco-dc-automation-key
install -m 0644 "${PROJECT_DIR}/automation-appliance/cisco-dc-automation.service" /etc/systemd/system/
systemctl daemon-reload
printf '%s\n' 'Installed. Create a WebUI account and configure HTTPS using automation-appliance/README.md before enabling the service.'