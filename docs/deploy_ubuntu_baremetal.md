# Ubuntu 26 Bare-Metal Deployment

Deploy **Cisco DC Operations** on an **Ubuntu Server 26.04 LTS** physical server.
Use **HTTPS on TCP 443** on a dedicated host. If an existing Nginx service already
uses 443, add the app to that Nginx on **HTTPS TCP 8443** instead. Nginx terminates
TLS and proxies to the application on **127.0.0.1:8088**; that loopback-only HTTP
connection is not a customer endpoint. Session cookies require HTTPS and the UI's
live connection uses secure WebSockets through Nginx.

This procedure also applies to an Ubuntu VM. The repository's Rocky Linux Packer
VM already uses the same HTTPS architecture; see **VM HTTPS** below.

**Validation status:** this procedure has not been executed on Ubuntu 26.04 here.
Development validation uses Rocky Linux and Python 3.12. Validate the customer's
Ubuntu/Python/dependency combination and acceptance checks before production use.

**Never run the Packer guest provisioning, cleanup, or first-boot configuration
scripts on bare metal.** In particular, do not run
`automation-appliance/scripts/provision.sh`, `scripts/cleanup.sh`, or
`files/cisco-dc-config.py`. Image cleanup removes network settings, state, and keys.

## Requirements

- Start with 4 CPU cores, 8 GiB RAM, and 64 GiB free disk; increase storage for
  captures/log retention. These are starting recommendations, not capacity guarantees.
- A management IP, DNS name, working DNS resolution, accurate time, and sudo access.
- A customer-approved TLS certificate/full chain and matching private key.
- Approved Ubuntu/Python package repositories, or a compatible offline wheelhouse.
- Browser access to HTTPS 443 (dedicated host) or 8443 (shared Nginx host) from
  permitted management networks.
- Server-to-APIC/ND HTTPS 443; direct switch SSH 22, or ND rescue-user SSH 22 and
  ND-to-switch SSH 22. APIC/ND API calls remain direct, not tunneled through ND.
- Switch-to-SCP-server connectivity for bootflash staging. This app need not host images.

The application service account receives no sudo privileges. Keep existing Ubuntu
networking, DNS, time services, and security controls; the application installer
does not replace them.

## 1. Transfer Clean Application Source

On the development machine, from this project's root:

```bash
python3 automation-appliance/scripts/package_source.py /tmp/cisco-dc-operations-source.tar.gz
cd /tmp
sha256sum cisco-dc-operations-source.tar.gz > cisco-dc-operations-source.tar.gz.sha256
scp cisco-dc-operations-source.tar.gz cisco-dc-operations-source.tar.gz.sha256 deploy-admin@192.0.2.10:~/
```

Use the project venv's Python if needed. Replace the administrator/address with
the customer's values, or transfer through their approved secure channel.
Confirm the checksum through a trusted channel: a checksum does not authenticate
the sender. This bundle is allowlisted source only; it excludes your developer
venv, passwords, profiles, vault key, browser sessions, and VM images. No published
Git repository or sibling project is needed.

## 2. Install Ubuntu Packages

All remaining commands run **on the Ubuntu server**, in a Bash shell, not inside
a switch CLI. Set the real server values in that shell:

```bash
APP_FQDN=existing-host.customer.example
APP_PORT=8443
SERVER_IP=192.0.2.10
TLS_CERT=/etc/ssl/certs/cisco-dc-automation.crt
TLS_KEY=/etc/ssl/private/cisco-dc-automation.key
cat /etc/os-release
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip openssh-client nginx openssl ca-certificates curl
python3 --version
```

For a shared Semaphore host, set `APP_FQDN` to the hostname already used to reach
that server, `APP_PORT=8443`, and `TLS_CERT`/`TLS_KEY` to the existing Nginx
certificate files if that certificate covers the hostname. This requires no new
DNS name. For a dedicated host, choose its app DNS name and set `APP_PORT=443`.

The app requires Python 3.10+. Ubuntu 26's newer interpreter/dependency combination
still requires validation. Do not replace system Python, install app packages into
system Python, or use `--break-system-packages`. If wheels are unavailable, use an
approved package mirror/build environment or an approved compatible interpreter.
Do not copy a virtual environment from a different host or Python version.

## 3. Install the Application

```bash
cd ~
sha256sum --check cisco-dc-operations-source.tar.gz.sha256
mkdir -p ~/cisco-dc-operations-source
tar -xzf ~/cisco-dc-operations-source.tar.gz -C ~/cisco-dc-operations-source
cd ~/cisco-dc-operations-source
sudo bash automation-appliance/install.sh
cd /opt/cisco-dc-automation
sudo .venv/bin/python -m pip check
sudo .venv/bin/python -c 'import automation_ui, aci_jump, netmiko, nicegui, cryptography, requests, yaml, pexpect; print("Application imports OK")'
```

The installer creates root-owned application code/venv in
`/opt/cisco-dc-automation`, the unprivileged `cisco-dc-automation` account, and the
systemd service. State is `/var/lib/cisco-dc-automation`; its separate vault-key
directory is `/var/lib/cisco-dc-automation-key`. Both directories are private.

The installer does not start the service or configure Ubuntu's Nginx/firewall.
The shared unit's `After=cisco-dc-firstboot.service` is only an ordering hint; the
appliance first-boot service does not need to be installed on Ubuntu.

Stop here if dependencies/imports fail. Resolve package/interpreter compatibility
before enabling customer access; do not bypass dependency constraints silently.

## 4. Create the WebUI Administrator

```bash
sudo -u cisco-dc-automation env \
  DC_AUTOMATION_DATA=/var/lib/cisco-dc-automation \
  DC_AUTOMATION_KEY_FILE=/var/lib/cisco-dc-automation-key/vault.key \
  /opt/cisco-dc-automation/.venv/bin/python \
  /opt/cisco-dc-automation/automation_ui.py --create-user admin
```

Enter/confirm a password of at least 12 characters directly at the prompts. Never
put real passwords in commands, source, or chat. This is a WebUI administrator,
not a new Ubuntu login. Additional WebUI accounts can be created later through
**Account settings / User accounts**. The initial command creates the vault key
if absent; preserve it for recovery.

## 5. Install HTTPS Certificates

Use the customer's trusted certificate process. Replace these source paths with
the full certificate chain and matching private key for `APP_FQDN`:

```bash
sudo install -o root -g root -m 0644 /path/to/fullchain.pem "$TLS_CERT"
sudo install -o root -g root -m 0600 /path/to/private-key.pem "$TLS_KEY"
sudo openssl x509 -in "$TLS_CERT" -noout -subject -issuer -dates
```

Nginx must be able to load the key non-interactively at service start. Protect the
key and arrange certificate renewal/reload with the customer. For an internal CA,
distribute CA trust to administrator browsers through the approved process.
On a shared host, you may point `TLS_CERT` and `TLS_KEY` at the existing Nginx
files if the certificate covers `APP_FQDN`; reuse those paths directly instead of
copying the private key. Never replace Semaphore's certificate or key.

For **temporary testing only**, a self-signed certificate can be generated after
setting the real `APP_FQDN` and `SERVER_IP`:

```bash
sudo openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 30 \
  -keyout "$TLS_KEY" \
  -out "$TLS_CERT" \
  -subj "/CN=${APP_FQDN}" \
  -addext "subjectAltName=DNS:${APP_FQDN},IP:${SERVER_IP}"
sudo chmod 0600 "$TLS_KEY"
```

Verify its fingerprint out of band before trusting it. Replace it with the
customer's trusted certificate before production use; do not disable TLS checks
globally or train users to ignore arbitrary certificate warnings.

## 6. Configure Nginx HTTPS and WebSockets

If this host already serves Semaphore on HTTPS 443, keep its existing Nginx
service and site configuration and add Cisco DC Operations on port 8443. Use the
same hostname as Semaphore in `APP_FQDN`; the URL is
`https://${APP_FQDN}:8443/`. The existing certificate must cover that hostname.
This needs no new DNS name and leaves Semaphore on 443. Nginx serves both ports
from its existing service; do not start another Nginx instance or change the
Semaphore site.

Adapt the supplied proxy config for the selected port, certificate paths, and
hostname:

```bash
: "${APP_FQDN:?Set APP_FQDN to the hostname used in the browser}"
: "${APP_PORT:?Set APP_PORT to 8443 for a shared Nginx host, or 443 for a dedicated host}"
: "${TLS_CERT:?Set TLS_CERT to the certificate/full-chain path}"
: "${TLS_KEY:?Set TLS_KEY to the matching private-key path}"
[[ "$APP_PORT" == 443 || "$APP_PORT" == 8443 ]] || { echo "APP_PORT must be 443 or 8443" >&2; exit 1; }
sudo test -r "$TLS_CERT" && sudo test -r "$TLS_KEY" || { echo "Nginx certificate/key path is unreadable" >&2; exit 1; }
sed \
  -e "s|listen 443 ssl;|listen ${APP_PORT} ssl;|" \
  -e "s|server_name _;|server_name ${APP_FQDN};|" \
  -e "s|/etc/pki/nginx/cisco-dc-automation.crt|${TLS_CERT}|" \
  -e "s|/etc/pki/nginx/private/cisco-dc-automation.key|${TLS_KEY}|" \
  ~/cisco-dc-operations-source/automation-appliance/nginx-cisco-dc.conf \
  | sudo tee /etc/nginx/sites-available/cisco-dc-operations >/dev/null
sudo ln -s /etc/nginx/sites-available/cisco-dc-operations /etc/nginx/sites-enabled/cisco-dc-operations
sudo nginx -t
```

Only on a fresh **dedicated** server, disable Ubuntu's unused default HTTP site
after confirming it hosts nothing the customer needs:

```bash
if [[ -L /etc/nginx/sites-enabled/default ]]; then
  sudo unlink /etc/nginx/sites-enabled/default
fi
sudo nginx -t
```

For a shared Semaphore host, do not unlink the default site or edit/replace the
Semaphore server block. The new listener on 8443 is added alongside the existing
443 configuration; `nginx -t` checks the combined configuration before reload.
The application site serves HTTPS only; this procedure does not open port 80. If
HTTP-to-HTTPS redirection is desired, arrange it separately.

Keep the supplied WebSocket `Upgrade`/`Connection` headers, forwarded scheme,
disabled proxy buffering, and long read timeout. They are required for the live UI.

## 7. Start and Verify

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cisco-dc-automation.service
sudo systemctl enable --now nginx.service
sudo systemctl reload nginx.service
sudo systemctl --no-pager --full status cisco-dc-automation.service nginx.service
sudo ss -ltnp
curl --fail --silent --show-error -o /dev/null -w 'Backend HTTP %{http_code}\n' http://127.0.0.1:8088/login
curl --fail --silent --show-error -o /dev/null -w 'HTTPS %{http_code}\n' "https://${APP_FQDN}:${APP_PORT}/login"
```

Confirm **8088 binds only to 127.0.0.1** and Nginx still listens on both the
existing 443 and selected application port. Test
`https://${APP_FQDN}:${APP_PORT}/` and the existing Semaphore URL after the reload.
Backend HTTP is
only a local health check: the production service enables `--secure-cookies`, so
sign in through the configured HTTPS URL, never through backend HTTP.
For a temporary certificate, use `curl --cacert` with the verified certificate
rather than `-k`. Test that the WebSocket connection remains established.

## 8. Restrict Firewall Access

Use the customer's firewall/change policy. Permit the selected HTTPS `APP_PORT`
from approved administrator networks and retain approved SSH management access.
Do not expose 8088. If UFW is the approved host firewall, example rules are:

```bash
sudo ufw allow from 192.0.2.0/24 to any port 22 proto tcp
sudo ufw allow from 192.0.2.0/24 to any port "$APP_PORT" proto tcp
sudo ufw status verbose
```

Replace the subnet and SSH port with the actual management values. Do not enable
an inactive firewall remotely until SSH rules and console recovery are confirmed.
Do not replace an existing firewall manager or disable AppArmor/security controls
globally to troubleshoot an application issue.

## 9. Customer Acceptance Checks

- Sign in through `https://${APP_FQDN}:${APP_PORT}/` using trusted HTTPS and
  create/review users and administrator roles.
- **APICs:** save Shared APIC Login domain/username/password, the switch DNS Domain,
  and APIC profiles. Use overrides only when a server requires a different account.
- **Nexus Dashboards:** save Shared ND Login domain/API account and the separate
  rescue-user password when jumping is needed; add dashboard profiles.
- Run an ACI PRE capture on one approved switch first. If jumping, select an ND
  node that permits rescue-user SSH and can SSH to switches; an API VIP may not.
- Start ND staging in plan-only and bootflash staging in dry-run. Applying can
  stage images or delete/copy switch files. ACI `show` captures remain read-only.
- Interface-description preview is read-only, but confirmed Apply sends ND PUTs;
  use an approved noncritical port. Device deployment is not automatically verified.
- Verify logs, report permissions/retention, certificate renewal, backup ownership,
  service restart, and an approved reboot test. Do not interrupt active jobs.

## Logs, Backup, and Recovery

```bash
sudo journalctl -u cisco-dc-automation.service -n 100 --no-pager
sudo journalctl -u nginx.service -n 100 --no-pager
sudo tail -n 100 /var/log/nginx/error.log
```

Back up state and key **separately** into encrypted, restricted backup storage.
Stop the application after active work completes so SQLite and reports are
consistent. Example local staging backups:

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
sudo systemctl stop cisco-dc-automation.service
sudo install -d -m 0700 /var/backups/cisco-dc-operations
sudo tar -czf "/var/backups/cisco-dc-operations/state-${STAMP}.tar.gz" -C /var/lib cisco-dc-automation
sudo tar -czf "/var/backups/cisco-dc-operations/key-${STAMP}.tar.gz" -C /var/lib cisco-dc-automation-key
sudo chmod 0600 "/var/backups/cisco-dc-operations/state-${STAMP}.tar.gz" "/var/backups/cisco-dc-operations/key-${STAMP}.tar.gz"
sudo systemctl start cisco-dc-automation.service
```

Move the key backup to a separate protected destination; anyone obtaining both
state and key can decrypt device credentials. Back up TLS material and approved
service overrides separately. Root or a compromised service account can decrypt
saved secrets even without backups.

For recovery, stop the service and restore matching state/key backups under
`/var/lib`, with ownership `cisco-dc-automation:cisco-dc-automation`, private
directories (0700), and key mode 0600. Do not generate a new key over encrypted
state. Reset a lost WebUI password by rerunning step 4 for the existing username.

## Updating and Rolling Back

### Recommended: Administrator Updater

New installations install `automation-appliance/update.py` as
`/usr/local/sbin/cisco-dc-update`. Finish **all active jobs** and run it from an
administrator shell, not from the WebUI:

```bash
# Replace v0.1.2 with an actual published release containing your desired changes.
sudo /usr/local/sbin/cisco-dc-update --version v0.1.2
```

For an offline or locally packaged bundle, transfer the archive and its checksum
through your approved channel, then run:

```bash
sudo /usr/local/sbin/cisco-dc-update \
  --archive /path/to/cisco-dc-operations-source.tar.gz
# By default the checksum is /path/to/cisco-dc-operations-source.tar.gz.sha256.
# Use --checksum /path/to/approved.sha256 to select a different checksum file.
```

Only use trusted source: the updater runs the bundle's installer as root.
SHA-256 detects corruption but does not authenticate a bundle and checksum
obtained from an untrusted source. Releases are fetched over verified HTTPS.

The updater:

1. Prevents concurrent updater runs and checks for the standard installation,
   data/key paths, and backend at `127.0.0.1:8088`. Custom deployments must use
   the manual procedure below.
2. Verifies the checksum, safely unpacks regular source files into a private
   temporary directory, and checks required files and the requested version.
3. Displays installed and target versions, then requires typing `UPDATE`.
   `--yes` skips the prompt and explicitly confirms that jobs are finished
   and the UI outage is approved; it does not skip validation.
4. Stops the service, checks backup space, and creates private archives in a
   new `/var/backups/cisco-dc-automation-update-*` directory: application
   code/venv, state, vault key, and existing Nginx/application/systemd config
   plus the installed updater. State and key are separate files.
5. Runs the bundle's installer, `pip check`, an application import check as the
   unprivileged service account, and
   service startup. It waits up to 60 seconds for an active service and an
   HTTP 200 from the loopback login endpoint.

On failure after stopping the service, it attempts to keep the service stopped,
returns a nonzero exit code, and reports the recovery directory. Backups may be
incomplete if backup creation failed. **It never automatically rolls back a
database or restores the vault key.** Review errors and the service journal
before recovery. Downloads and temporary extraction files are cleaned up;
backups are retained. It does not enforce an upgrade-only version order, so
review the displayed versions before confirming a same-version reinstall or
downgrade.

Move the key backup to separate protected storage. Preserve TLS keys/certificates
separately as well: their configured paths may be outside the configuration
backup. The updater does not change Nginx/TLS configuration or regenerate
accounts/keys. Complete the HTTPS/UI acceptance checks after it succeeds.

**One-time bootstrap for v0.1.1 and earlier:** these releases do not install the
updater. Obtain an approved copy of `automation-appliance/update.py` from the
updated checkout or a checksum-verified newer source bundle. Run it directly:

```bash
sudo python3 /path/to/automation-appliance/update.py \
  --archive /path/to/cisco-dc-operations-source.tar.gz
```

The new bundle's installer installs the `cisco-dc-update` command for subsequent
updates. A new versioned release must be published to ship this script through
GitHub release assets; previously published bundles are unchanged.

### Manual Update and Recovery Reference

You do **not** need to rebuild the server or appliance image. Download an
application source bundle, extract it into a fresh staging directory, and rerun
its installer while the application service is stopped. Do not extract directly
over the installed application or replace its data directories. The WebUI does
not install code or receive sudo rights.

**The bundle must contain the changes you want.** Editing a development checkout
does not update an already-published GitHub release. For a versioned deployment,
publish a new release containing those commits using
[the release procedure](releasing.md). Alternatively, package the current
checkout as described below.

1. Finish active automation jobs and schedule a short UI outage. Record the
   installed version with `cat /opt/cisco-dc-automation/VERSION`. Retain its
   original source bundle and back up the installed `/opt/cisco-dc-automation`
   code/venv for recovery.
2. Obtain the new source archive through either method:

   **Published release:** open **Account settings → Check for software updates**
   as an administrator for the exact release download commands, or run the
   following on the bare-metal server. Replace the example tag with the actual
   published release containing your changes:

   ```bash
   set -euo pipefail
   RELEASE_TAG=v0.1.1  # Example only; this release must exist before downloading.
   ARCHIVE="cisco-dc-operations-${RELEASE_TAG}.tar.gz"
   BASE_URL="https://github.com/scotttyso/Cisco-DC-Operations/releases/download/${RELEASE_TAG}"
   WORK_DIR=$(mktemp -d "$HOME/cisco-dc-update.XXXXXX")
   cd "$WORK_DIR"
   curl --fail --location --output "$ARCHIVE" "$BASE_URL/$ARCHIVE"
   curl --fail --location --output "$ARCHIVE.sha256" "$BASE_URL/$ARCHIVE.sha256"
   sha256sum --check "$ARCHIVE.sha256"
   mkdir source
   tar -xzf "$ARCHIVE" -C source
   ```

   **Unreleased checkout:** on the development machine, from the
   Cisco-DC-Operations repository root, create the allowlisted bundle:

   ```bash
   python3 automation-appliance/scripts/package_source.py /tmp/cisco-dc-operations-source.tar.gz
   cd /tmp
   sha256sum cisco-dc-operations-source.tar.gz > cisco-dc-operations-source.tar.gz.sha256
   ```

   Transfer both files through your approved secure channel. On the bare-metal
   server, verify and extract them into a fresh directory:

   ```bash
   set -euo pipefail
   WORK_DIR=$(mktemp -d "$HOME/cisco-dc-update.XXXXXX")
   cd /path/to/transferred-files
   sha256sum --check cisco-dc-operations-source.tar.gz.sha256
   mkdir "$WORK_DIR/source"
   tar -xzf cisco-dc-operations-source.tar.gz -C "$WORK_DIR/source"
   ```

   Verify the source/checksum provenance through a trusted channel. An
   unreleased bundle includes current checkout edits but retains that checkout's
   `VERSION`; it is not a new published release.

3. In the same server shell, stop the service and create private backups of
   application state and the vault key **separately**:

   ```bash
   sudo systemctl stop cisco-dc-automation.service
   BACKUP_DIR=$(sudo mktemp -d /var/backups/cisco-dc-automation-update.XXXXXX)
   sudo tar -czf "$BACKUP_DIR/state.tar.gz" -C /var/lib cisco-dc-automation
   sudo tar -czf "$BACKUP_DIR/vault-key.tar.gz" -C /var/lib cisco-dc-automation-key
   printf 'Backup directory: %s\n' "$BACKUP_DIR"
   ```

   Securely retain these backups separately under your backup policy. Also
   preserve any custom systemd settings, `/etc/cisco-dc-automation/service.env`,
   Nginx configuration, and TLS certificates/keys. These commands assume the
   standard installation paths; adapt them if your service uses custom paths.
   Losing or regenerating the vault key makes saved credentials unreadable.

4. Install and validate the new application, then start the service:

   ```bash
   sudo bash "$WORK_DIR/source/automation-appliance/install.sh"
   sudo /opt/cisco-dc-automation/.venv/bin/python -m pip check
   (
     cd /opt/cisco-dc-automation
     sudo .venv/bin/python -c 'import automation_ui; print("Application imports OK")'
   )
   sudo systemctl start cisco-dc-automation.service
   sudo systemctl --no-pager --full status cisco-dc-automation.service
   ```

   If installation or validation fails, leave the service stopped and resolve
   the failure before proceeding. Inspect startup errors with
   `sudo journalctl -u cisco-dc-automation.service -n 100 --no-pager`.

The installer replaces application code, bundled NX-OS scripts, dependencies,
and the supplied systemd unit. Use systemd drop-ins for local unit overrides.
It preserves `/var/lib/cisco-dc-automation` and
`/var/lib/cisco-dc-automation-key`; it does not replace Nginx/TLS configuration.
Do not recreate WebUI users or regenerate the vault key during an update.
**Never run Packer provisioning, cleanup, or first-boot scripts as an update.**

Refresh the existing HTTPS URL, sign in again if prompted, and verify inventory,
saved credentials, and the new UI controls. Run a read-only plan before applying
automation.

Requirements use version ranges rather than a full release lock. Archive an
approved source/package set for repeatability. Rollback may require both the
previous code/venv at the same installation path and its matching pre-update
state/key; older code may not support a newer database schema.

## VM HTTPS

The Packer VM already installs Nginx on **443**, binds the app to loopback 8088,
uses HTTPS-only cookies, and opens SSH/HTTPS in firewalld. First boot generates a
unique self-signed certificate, not a shared certificate baked into the template.

For customer production use, install the trusted full chain at
`/etc/pki/nginx/cisco-dc-automation.crt` and its key at
`/etc/pki/nginx/private/cisco-dc-automation.key`, with root ownership, certificate
mode 0644, and key mode 0600. Remove `/etc/pki/nginx/.cisco-dc-self-signed` so the
appliance configurator will preserve the customer-installed certificate. Run
`nginx -t` before reloading Nginx. Access the VM using its certificate's DNS name.
No change to the Packer VM's OS is needed for HTTPS.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| 502 from Nginx | Service journal and listener on 127.0.0.1:8088. |
| Login does not persist | Use HTTPS, not backend HTTP; check forwarded scheme and WebSocket headers. |
| Connection lost after update | Refresh/open a new tab on the real HTTPS hostname; check proxy/firewall logs, not stopped demo ports. |
| No WebUI account configured | Create the user with the same state/key environment paths used by systemd. |
| Cannot decrypt credentials | Restore the matching original key; do not delete state or replace the key. |
| Device TLS errors | Install the approved CA trust; review Python/Requests CA configuration without globally disabling verification. |
| Jump/legacy SSH errors | Confirm rescue-user access, ND-to-switch reachability, domain-qualified login, and per-workflow crypto policy. |
| Package installation fails | Check Ubuntu Python, package mirror, compatible wheels, and dependency bounds before enabling service. |

### Service Import Failures After a v0.1.2 Updater Run

The v0.1.2 updater used a private `077` umask that its installer inherited.
New virtual-environment files could become root-only, allowing the root import
check to pass while the service account failed with errors such as
`ModuleNotFoundError: No module named 'authlib.integrations'`.
The updated installer uses `022` for application code and repairs readability
within the venv; the updater now checks imports as the service account.

For an affected standard installation, repair only the dependency environment,
then verify imports as the service account before starting:

```bash
sudo chmod -R a+rX /opt/cisco-dc-automation/.venv
sudo -u cisco-dc-automation /opt/cisco-dc-automation/.venv/bin/python -c \
  'import os; os.chdir("/opt/cisco-dc-automation"); import automation_ui; print("Service imports OK")'
sudo systemctl start cisco-dc-automation.service
sudo systemctl --no-pager --full status cisco-dc-automation.service
```

Run each command separately and stop if the import check fails; inspect the
service journal rather than repeatedly reinstalling. Do not apply permission
changes to the state/key directories under `/var/lib`; they must stay private.
If permissions were not the cause, retain the full traceback for diagnosis.

This guide does not certify a real Ubuntu install, VM boot, or customer device
workflow. Complete the acceptance checks in the target environment before rollout.