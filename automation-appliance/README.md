# Cisco DC Operations Appliance

A standalone Rocky Linux 10.2 appliance for this repository's ACI checks and NX-OS
staging WebUI. The build, source bundle, first-boot setup, certificate paths,
systemd services, and deployment examples are owned here. No sibling repository,
remote application clone, Ansible setup, DHCP server, or iServer is required.

## Artifacts

| Artifact | Target |
| --- | --- |
| `cisco-dc-automation-rocky10` template | vSphere clones |
| `output/<vm-name>-<version>.ova` | VMware OVF deployment with vApp settings |
| `output/<vm-name>-<version>.qcow2` | OpenShift Virtualization |

Defaults are 4 CPUs, 8 GiB RAM, and a 64 GiB disk. Increase storage for long
snapshot/log retention. The application does not mirror upgrade images itself;
SCP sources and ND image repositories remain external.

## Build Prerequisites

- Packer 1.11+ and the vSphere plugin (`packer init .`).
- Python 3.10+ on the build host; `qemu-img` for qcow2 conversion and `xorriso`
  for the kickstart CD.
- vCenter placement permissions, an installation ISO, and SSH access to the build
  VM. The build network needs DHCP unless static build-IP variables are supplied.
- Guest access to Rocky repositories and Python packages. No GitHub token or
  application Git clone is used during provisioning.
- Rocky Linux 10 requires x86-64-v3 CPUs/compatible EVC settings, including AVX2.

## Build

From this repository's root:

```bash
cd automation-appliance
cp appliance.example.pkrvars.hcl appliance.auto.pkrvars.hcl
```

Edit the ignored auto-variable file for your vCenter, datastore, network, ISO,
VM name, and desired image formats. Keep secrets out of that file. Set these
environment variables securely in your own shell or secret-management workflow:

- `PKR_VAR_vsphere_password`: vCenter password.
- `PKR_VAR_build_password`: temporary OS administrator password.
- `PKR_VAR_build_password_hash`: SHA-512 crypt hash of that same build password.

Then run:

```bash
python3 scripts/package_source.py output/application-source.tar.gz
packer init .
packer fmt -check .
packer validate .
packer build .
```

The first packaging step also lets `packer validate` verify its file provisioner
input on a fresh checkout. The build repackages current source before upload.
The archive contains only named application/deployment files: not `.venv`, local
credentials, vault keys, browser sessions, logs, build variables, or VM output.
Private auto-variable files, build cache, and `output/` are Git-ignored.

The build uses the source in this checkout, so commit/push is not required for
local builds. Pin Python dependency versions and OS/package sources to an approved
release set when reproducible production images are required; version ranges and
guest package updates currently allow newer compatible dependencies.

## Image Lifecycle

1. Packer installs Rocky from the ISO and a locally generated OEMDRV kickstart CD.
2. An allowlisted archive of this project is uploaded; no external application
   repository is cloned. Provisioning installs the WebUI, bundled NX-OS scripts,
   Nginx, OpenSSH, guest agents, firewalld, and first-boot service.
3. The service account `cisco-dc-automation` has no sudo rights. Application code
   is root-owned; only the two private runtime-state directories are writable.
4. Cleanup removes any runtime state, keys, certificates, SSH host keys, machine
   identity, cloud-init state, build source, and logs before export. The build-only
   passwordless sudo rule is removed and the temporary OS password expired during
   shutdown. No WebUI accounts or device credentials are baked into the image.
5. The OVF export receives local vApp metadata and a refreshed SHA-256 manifest,
   then is packaged as an OVA. qcow2 conversion is optional; requested conversions
   fail explicitly when `qemu-img` is missing.

## First Boot

The OS administrator defaults to `dcadmin`. A deployment starts with DHCP and
an expired build password unless replaced through first-boot settings. Use the VM
console for the initial OS password change, then run:

```bash
sudo cisco-dc-config
```

The configurator supports hostname/domain, DHCP/static IPv4, DNS/search domains,
NTP/timezone, OS administrator password, and initial WebUI administrator creation.
Changing networking can disconnect SSH; use the console for network changes.

Non-interactive settings are read from these sources, highest priority first:

1. `/etc/cisco-dc-automation/appliance.env`, written by cloud-init or locally.
2. VMware vApp properties delivered by VMware Tools.
3. VMware `guestinfo.<key>` advanced settings on a template clone.

See [files/appliance.env.example](files/appliance.env.example). Environment keys
include `HOSTNAME`, `DOMAIN`, `IP_SOURCE`, `IP_ADDRESS`, `PREFIX`, `GATEWAY`,
`DNS_SERVERS`, `DNS_SEARCH`, `NTP_SERVERS`, `TIMEZONE`, `ADMIN_PASSWORD`,
`UI_ADMIN_USER`, and `UI_ADMIN_PASSWORD`. Guestinfo uses lowercase keys such as
`guestinfo.ip_address`. Passwords are optional; enter them directly in the console
instead when possible. No account is created without a supplied UI password.

When no settings are supplied, first boot creates a unique self-signed certificate
and leaves DHCP enabled. The UI is available at `https://<appliance>/` on **443**,
but requires an administrator created through the console. Backend port 8088 is
bound to loopback and uses HTTPS-only session cookies behind Nginx.

Certificates are `/etc/pki/nginx/cisco-dc-automation.crt` and
`/etc/pki/nginx/private/cisco-dc-automation.key`. Replace with trusted certificates
and remove `/etc/pki/nginx/.cisco-dc-self-signed` to prevent the configurator from
refreshing an operator-installed certificate. SELinux remains enforcing and
the firewall allows SSH/HTTPS only.

## VMware Deployment

Deploy the OVA with **Deploy OVF Template** and fill in networking/time properties.
Alternatively clone the template, set matching `guestinfo.*` values before boot,
or use `sudo cisco-dc-config` through the console.

VM administrators and local users with VMware Tools access may read vApp and
guestinfo values. Do not treat password properties as a secret store; prefer
console entry, or rotate passwords supplied that way after deployment.

## OpenShift Virtualization

The examples use a management-network Linux bridge, `br-dc-management`. Arrange
that bridge/VLAN on eligible workers using your cluster's network policy, then
adjust the NAD, storage class, placement, addresses, and cloud-init secret for
your environment. EFI boot matches the Packer-built disk; Secure Boot is disabled.

```bash
oc new-project cisco-dc-images
virtctl image-upload pvc cisco-dc-automation-rocky10 -n cisco-dc-images \
  --size=64Gi --image-path=output/cisco-dc-automation-rocky10-1.0.0.qcow2 \
  --storage-class=<storage-class>
oc new-project cisco-dc-automation
oc apply -f openshift/network-attachment-definition.yaml
oc apply -f openshift/cloudinit-secret.yaml
oc apply -f openshift/virtualmachine.yaml
virtctl console cisco-dc-automation -n cisco-dc-automation
```

Cross-namespace DataVolume cloning needs appropriate cluster/CDI permissions.
Cloud-init writes the private first-boot settings file; the local first-boot
service then applies it. The example contains no passwords. Complete initial
account/password setup in the VM console. Kubernetes Secrets require cluster
encryption-at-rest/RBAC controls; do not commit filled-in secret manifests.

## Install Without Packer

For a complete Ubuntu 26.04 bare-metal or Ubuntu VM procedure, follow the
[HTTPS deployment guide](../docs/deploy_ubuntu_baremetal.md). Both customer
deployment types use HTTPS on port 443, with the application backend accessible
only on loopback. The Rocky Packer VM already uses this arrangement.

On a dedicated Linux VM with Python 3.10+, OpenSSH clients, and package access,
run from this repository alone:

```bash
sudo bash automation-appliance/install.sh
sudo -u cisco-dc-automation env \
  DC_AUTOMATION_DATA=/var/lib/cisco-dc-automation \
  DC_AUTOMATION_KEY_FILE=/var/lib/cisco-dc-automation-key/vault.key \
  /opt/cisco-dc-automation/.venv/bin/python \
  /opt/cisco-dc-automation/automation_ui.py --create-user admin
```

This application installer does not alter the host network/firewall, install Nginx,
or run the image provisioner/cleanup. Install Nginx and a certificate separately,
use [nginx-cisco-dc.conf](nginx-cisco-dc.conf), verify with `nginx -t`, and enable
`cisco-dc-automation.service`. On SELinux-enforcing hosts allow Nginx proxy access
with `setsebool -P httpd_can_network_connect 1`. Do not run image cleanup on a
configured appliance or general-purpose host.

## Secrets and Recovery

Runtime data lives in `/var/lib/cisco-dc-automation`; the default vault key is
`/var/lib/cisco-dc-automation-key/vault.key` (0600). Back them up separately. A secret
manager can inject a Fernet `DC_AUTOMATION_KEY` through a root-only service env
file. Root or a compromised application account can still decrypt saved secrets.
Do not clone already-configured deployments containing credentials or sessions.
Replacing the key without migrating encrypted credentials makes them unreadable.

## Validation Status

Packer initialization/validation, shell syntax, source packaging, synthetic OVA
creation, OVF manifest hashes, and first-boot input/credential-handoff tests have
been checked locally. No vCenter build, real OVA/qcow2 boot, SELinux/firewall guest
run, or OpenShift deployment has been performed. Those require target-environment
validation before releasing an appliance image.