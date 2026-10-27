# Releases and Updates

## Publish a Release

Releases are created from version tags, not from every push to `main`. The
`Publish release` GitHub Actions workflow runs the test suite, creates the
allowlisted application archive, writes its SHA-256 checksum, and publishes
both assets with generated release notes.

Before tagging, merge reviewed changes to `main`, verify the tests, and set
`VERSION` to the exact tag you plan to publish:

```bash
printf '%s\n' v0.1.0 > VERSION
git add VERSION
git commit -m "Prepare v0.1.0 release"
git tag -a v0.1.0 -m "Cisco DC Operations v0.1.0"
git push origin main
git push origin v0.1.0
```

Use semantic versions: patch for fixes, minor for compatible features, and major
for incompatible behavior or state migrations. Use a suffix such as `-rc.1` for
pre-release testing. This first, pre-1.0 baseline is `v0.1.0`. Confirm the
workflow succeeds and the release contains both
`cisco-dc-operations-v0.1.0.tar.gz` and its `.sha256` file before announcing it.

## Install a Release from the WebUI

An administrator can open **Account settings → Check for software updates** to
check the latest public GitHub release and read its release notes. If a newer
version is available, the dialog provides a version-specific
`sudo /usr/local/sbin/cisco-dc-update --version vX.Y.Z` command. The updater
downloads and verifies the archive/checksum, confirms the outage, backs up
code/state/key, installs, and checks service readiness. This is deliberately not an in-app code installer: the
WebUI service has no sudo access and cannot write the root-owned application.

On the server, an administrator should finish active jobs, back up application
state and the vault key separately under their backup policy, then run the
displayed command from a normal administrative shell. The updater creates
additional local recovery archives before running the approved bundle's installer.
Verify status and sign in again as required. The installer replaces application
code/dependencies but leaves `/var/lib/cisco-dc-automation` and the vault key in
place. Never run the image cleanup script during an application update.

For offline bundles, the updater accepts `--archive` and an optional `--checksum`.
See [Updating and Rolling Back](deploy_ubuntu_baremetal.md#updating-and-rolling-back)
for the full workflow, failure handling, and one-time bootstrap on v0.1.1 or older.
Those releases do not contain the updater; obtain it from an approved updated
checkout or newer bundle first.

The update checker reads only public GitHub release metadata; no GitHub token is
stored on the customer server. Published source archives exclude runtime profiles,
credentials, vault keys, sessions, and reports.

## Customer CLI Quick Reference (v0.2.0)

Run these commands from an administrator SSH or console session on a standard
appliance installation, not inside the WebUI.

### Reset a Local WebUI Password

Replace `CUSTOMER_USERNAME` with the exact existing WebUI username:

```bash
sudo -u cisco-dc-automation env \
  DC_AUTOMATION_DATA=/var/lib/cisco-dc-automation \
  DC_AUTOMATION_KEY_FILE=/var/lib/cisco-dc-automation-key/vault.key \
  /opt/cisco-dc-automation/.venv/bin/python \
  /opt/cisco-dc-automation/automation_ui.py --create-user CUSTOMER_USERNAME
```

Enter and confirm the new password at the hidden prompts. For an existing user,
this resets the password, preserves their role, and invalidates their existing
WebUI sessions. No application restart is required. A username that does not
exist creates a new administrator, so check the spelling carefully. This changes
a local WebUI password, not a Linux, device, or corporate OIDC password.

These paths match the standard service configuration. If an administrator has
overridden the data directory or vault-key configuration in
`/etc/cisco-dc-automation/service.env`, use those same settings for the reset;
do not create a replacement vault key.

### Update to v0.2.0

Finish all active jobs and follow the backup prerequisites above, then run:

```bash
sudo /usr/local/sbin/cisco-dc-update --version v0.2.0
```

Type `UPDATE` when prompted. The updater downloads the published source archive
and checksum, verifies the checksum, backs up code/state/key, stops the service,
installs the application, and checks backend readiness. It preserves application
data, the vault key, and Nginx/TLS configuration. Protect the backup location
printed by the updater and store the vault-key backup separately.

Verify the installation:

```bash
cat /opt/cisco-dc-automation/VERSION
sudo systemctl status cisco-dc-automation.service --no-pager
curl --fail --silent --show-error --output /dev/null \
  --write-out 'Backend HTTP %{http_code}\n' http://127.0.0.1:8088/login
```

Expect `v0.2.0`, an active service, and HTTP 200. Refresh the browser. If the update
fails, inspect `sudo journalctl -u cisco-dc-automation.service -n 100 --no-pager`
and follow the recovery instructions linked above; do not delete the vault key
or rerun appliance provisioning. v0.1.1 and older installations need the one-time
updater bootstrap described in the deployment guide.

## Configure Corporate OIDC

An administrator opens **Account settings → Corporate sign-in (OIDC)** and sets
the tenant-specific HTTPS issuer, Entra application/client ID, client secret, and
the exact Entra group object IDs mapped to Administrator and Operator. Register
the callback URL `https://<public-host>:<port>/auth/oidc/callback` in the Entra
application. Use the existing host's certificate name and actual public port
(443 or 8443); do not register the internal HTTP backend.

Ensure Entra is configured to emit the `groups` claim for this application. The
app denies users without a mapped group and denies group-overage tokens that omit
group IDs. Keep a local administrator account for break-glass access. OIDC secrets
are encrypted at rest with the existing vault key. Changing or losing that key
has the same recovery implications as saved device credentials.