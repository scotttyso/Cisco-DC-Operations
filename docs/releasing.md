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
version is available, the dialog provides the exact CLI install commands and
checksum verification. This is deliberately not an in-app code installer: the
WebUI service has no sudo access and cannot write the root-owned application.

On the server, an administrator should finish active jobs, back up application
state and the vault key separately, then run the displayed commands from a
normal administrative shell. The commands verify the release archive checksum,
stop the service, run the existing root-owned installer, and start the service.
Verify status and sign in again as required. The installer replaces application
code/dependencies but leaves `/var/lib/cisco-dc-automation` and the vault key in
place. Never run the image cleanup script during an application update.

The update checker reads only public GitHub release metadata; no GitHub token is
stored on the customer server. Published source archives exclude runtime profiles,
credentials, vault keys, sessions, and reports.

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