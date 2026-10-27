#!/usr/bin/python3
"""Update a standard Cisco DC Operations installation from an approved source bundle."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener


SERVICE = "cisco-dc-automation.service"
APP = Path("/opt/cisco-dc-automation")
STATE = Path("/var/lib/cisco-dc-automation")
KEY = Path("/var/lib/cisco-dc-automation-key")
ENV_FILE = Path("/etc/cisco-dc-automation/service.env")
REPOSITORY = "https://github.com/scotttyso/Cisco-DC-Operations"
TAG_PATTERN = re.compile(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")
REQUIRED_FILES = (
    "VERSION", "requirements.txt", "automation_ui.py", "aci_checks.py", "aci_jump.py",
    "aci_ifstatus_common.py", "aci_leaf_ifstatus_pre.py", "aci_leaf_ifstatus_post.py",
    "secure_profiles.py", "oidc_auth.py", "release_updates.py", "nxos_jobs.py",
    "nd_interfaces.py", "nd_telemetry.py", "interface_description_table.py", "interface_description_table.js",
    "nxos-scripts/nd_stage_nexus_updates.py", "nxos-scripts/nxos_bootflash_stage.py",
    "automation-appliance/install.sh", "automation-appliance/cisco-dc-automation.service",
)


def run(*command: str, capture: bool = False) -> str:
    result = subprocess.run(command, check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else ""


def verify_checksum(archive: Path, checksum: Path) -> None:
    if checksum.stat().st_size > 4096:
        raise ValueError("Checksum file is too large")
    match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *]([^\r\n]+)\n?",
                         checksum.read_text(encoding="utf-8"))
    if not match or match[2] != archive.name:
        raise ValueError("Expected one SHA-256 checksum naming the selected archive")
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != match[1].lower():
        raise ValueError("Archive SHA-256 checksum does not match; installation was not attempted")


def extract_source(archive: Path, destination: Path, expected_version: str | None) -> str:
    with tarfile.open(archive, "r:gz") as bundle:
        members = []
        names = set()
        total = 0
        for member in bundle:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or not path.parts or member.name != path.as_posix()
                    or member.name in names or not member.isfile()):
                raise ValueError(f"Unsafe or duplicate archive entry: {member.name!r}")
            names.add(member.name)
            total += member.size
            if len(names) > 1000 or member.size > 32 * 1024 * 1024 or total > 128 * 1024 * 1024:
                raise ValueError("Source archive exceeds permitted size")
            members.append(member)
        missing = set(REQUIRED_FILES) - names
        if missing:
            raise ValueError("Incomplete source archive: " + ", ".join(sorted(missing)))
        destination.mkdir(mode=0o700)
        for member in members:
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError(f"Cannot read archive entry: {member.name}")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o600)
    version = (destination / "VERSION").read_text(encoding="utf-8").strip()
    if not TAG_PATTERN.fullmatch(version):
        raise ValueError("Bundle VERSION must be a vMAJOR.MINOR.PATCH release tag")
    if expected_version and version != expected_version:
        raise ValueError(f"Bundle VERSION {version!r} does not match requested {expected_version}")
    return version


def prepare_source(args: argparse.Namespace, work: Path) -> tuple[Path, str]:
    if args.version:
        archive = work / f"cisco-dc-operations-{args.version}.tar.gz"
        for name in (archive.name, archive.name + ".sha256"):
            run("curl", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
                "--connect-timeout", "15", "--max-time", "300", "--retry", "2",
                "--output", str(work / name),
                f"{REPOSITORY}/releases/download/{args.version}/{name}")
    else:
        original = args.archive.expanduser().resolve(strict=True)
        checksum = (args.checksum or Path(str(original) + ".sha256")).expanduser().resolve(strict=True)
        archive = work / original.name
        shutil.copyfile(original, archive)
        shutil.copyfile(checksum, Path(str(archive) + ".sha256"))
    verify_checksum(archive, Path(str(archive) + ".sha256"))
    source = work / "source"
    version = extract_source(archive, source, args.version)
    return source, version


def preflight() -> None:
    for path in (APP, STATE, KEY):
        if not path.is_dir() or path.is_symlink():
            raise ValueError(f"Expected an existing standard installation directory: {path}")
    if not (KEY / "vault.key").is_file():
        raise ValueError("Existing vault.key is missing; refusing to create a replacement")
    expected = {"DC_AUTOMATION_DATA": str(STATE), "DC_AUTOMATION_KEY_FILE": str(KEY / "vault.key"),
                "DC_NXOS_SCRIPTS_DIR": str(APP / "nxos-scripts")}
    environment = shlex.split(run("systemctl", "show", SERVICE, "--property=Environment", "--value", capture=True))
    files = run("systemctl", "show", SERVICE, "--property=EnvironmentFiles", "--value", capture=True)
    if files and files != f"{ENV_FILE} (ignore_errors=yes)":
        raise ValueError("Custom EnvironmentFiles require the manual upgrade procedure")
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.lstrip().startswith(("#", ";")):
                tokens = shlex.split(line)
                if len(tokens) != 1 or "=" not in tokens[0]:
                    raise ValueError("Complex service.env syntax requires the manual upgrade procedure")
                environment.extend(tokens)
    values = dict(entry.split("=", 1) for entry in environment)
    if any(values.get(name, default) != default for name, default in expected.items()):
        raise ValueError("Custom data/key/script paths require the manual upgrade procedure")
    working = run("systemctl", "show", SERVICE, "--property=WorkingDirectory", "--value", capture=True)
    command = run("systemctl", "show", SERVICE, "--property=ExecStart", "--value", capture=True)
    if working != str(APP) or f"{APP}/automation_ui.py" not in command:
        raise ValueError("Custom application location requires the manual upgrade procedure")
    if not re.search(r"--host\s+127\.0\.0\.1(?:\s|;)", command) or not re.search(
        r"--port\s+8088(?:\s|;)", command
    ):
        raise ValueError("Updater expects the standard backend at 127.0.0.1:8088")


def make_backups(directory: Path) -> None:
    required = sum(int(run("du", "-sb", str(path), capture=True).split()[0])
                   for path in (APP, STATE, KEY))
    if shutil.disk_usage(directory).free < required + 128 * 1024 * 1024:
        raise RuntimeError("Insufficient backup space for code, state, and key plus 128 MiB headroom")
    for filename, path in (("application.tar.gz", APP), ("state.tar.gz", STATE), ("vault-key.tar.gz", KEY)):
        run("tar", "--acls", "--xattrs", "-czf", str(directory / filename),
            "-C", str(path.parent), path.name)
    config = [path for path in (
        Path("/etc/systemd/system") / SERVICE,
        Path("/etc/systemd/system") / (SERVICE + ".d"),
        Path("/etc/cisco-dc-automation"), Path("/etc/nginx"),
        Path("/usr/local/sbin/cisco-dc-update"),
    ) if path.exists()]
    if config:
        run("tar", "--acls", "--xattrs", "-czf", str(directory / "configuration.tar.gz"),
            "-C", "/", *(str(path.relative_to("/")) for path in config))
    for archive in directory.glob("*.tar.gz"):
        archive.chmod(0o600)


def wait_ready(timeout: float = 60) -> None:
    endpoint = "http://127.0.0.1:8088/login"
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + timeout
    last_error = "No response"
    while time.monotonic() < deadline:
        try:
            run("systemctl", "is-active", "--quiet", SERVICE)
            with opener.open(endpoint, timeout=3) as response:
                if response.status == 200 and response.geturl() == endpoint:
                    return
                last_error = f"HTTP {response.status} from {response.geturl()}"
        except (OSError, URLError, subprocess.CalledProcessError) as error:
            last_error = str(error)
        time.sleep(2)
    raise RuntimeError(f"Backend did not become healthy within {timeout} seconds: {last_error}")


def install_update(source: Path, backup: Path) -> None:
    success = False
    try:
        run("systemctl", "stop", SERVICE)
        make_backups(backup)
        print(f"Backups saved: {backup}", flush=True)
        run("bash", str(source / "automation-appliance/install.sh"))
        python = str(APP / ".venv/bin/python")
        run(python, "-m", "pip", "check")
        run("runuser", "-u", "cisco-dc-automation", "--", python, "-c",
            "import os; os.chdir('/opt/cisco-dc-automation'); "
            "import automation_ui; print('Application imports OK')")
        run("systemctl", "start", SERVICE)
        wait_ready()
        success = True
    finally:
        if not success:
            print(f"Update failed. Recovery files (possibly incomplete): {backup}\n"
                  "No automatic rollback was attempted. Restore matching code/state/key backups "
                  "if needed; inspect the service journal before restarting.", file=sys.stderr, flush=True)
            try:
                run("systemctl", "stop", SERVICE)
            except subprocess.CalledProcessError as error:
                raise RuntimeError("Could not stop the service after failure; stop it manually "
                                   "and inspect the journal before recovery") from error


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--version", help="Published release tag, e.g. v0.1.2")
    source.add_argument("--archive", type=Path, help="Approved local .tar.gz source bundle")
    parser.add_argument("--checksum", type=Path, help="Local checksum file (default: ARCHIVE.sha256)")
    parser.add_argument("--yes", action="store_true", help="Confirm outage and that all jobs have finished")
    args = parser.parse_args(argv)
    if args.version and not TAG_PATTERN.fullmatch(args.version):
        parser.error("--version must be a release tag such as v0.1.2")
    if args.checksum and not args.archive:
        parser.error("--checksum requires --archive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if os.geteuid() != 0:
        print("ERROR: Run this updater with sudo from an administrator shell.", file=sys.stderr)
        return 1
    os.umask(0o077)
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    try:
        descriptor = os.open("/run/lock/cisco-dc-update.lock",
                             os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(descriptor, "r+") as lock:
            info = os.fstat(lock.fileno())
            if info.st_uid != 0 or not stat.S_ISREG(info.st_mode):
                raise ValueError("Updater lock must be a root-owned regular file")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another Cisco DC Operations update is running") from None
            preflight()
            with tempfile.TemporaryDirectory(prefix="cisco-dc-update-", dir="/var/tmp") as temporary:
                source, version = prepare_source(args, Path(temporary))
                installed = (APP / "VERSION").read_text(encoding="utf-8").strip()
                print(f"Installed: {installed} | Requested bundle: {version}", flush=True)
                print("This stops the UI and runs the bundle's installer as root. "
                      "Finish ALL active jobs first. Use only trusted bundles.", flush=True)
                if not args.yes and input("Type UPDATE to continue: ").strip() != "UPDATE":
                    print("Cancelled; service was not stopped.")
                    return 0
                backup = Path(tempfile.mkdtemp(prefix="cisco-dc-automation-update-", dir="/var/backups"))
                print(f"Recovery directory: {backup}", flush=True)
                install_update(source, backup)
                print(f"Update complete: {version}. Backend is healthy. Refresh your HTTPS UI.\n"
                      f"Backups retained at {backup}. Move the vault-key backup to separate "
                      "protected storage. Nginx/TLS configuration was not changed.", flush=True)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, tarfile.TarError,
            EOFError, KeyboardInterrupt) as error:
        print(f"ERROR: Update did not complete: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
