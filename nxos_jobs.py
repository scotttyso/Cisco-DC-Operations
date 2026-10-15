"""Isolated adapters for the bundled NX-OS staging scripts."""

from __future__ import annotations

import asyncio
import os
import re
import signal
import sys
from pathlib import Path

import yaml


SCRIPTS_DIR = Path(os.environ.get("DC_NXOS_SCRIPTS_DIR",
                  Path(__file__).resolve().parent / "nxos-scripts"))
SCRIPT_NAMES = {"nd": "nd_stage_nexus_updates.py", "bootflash": "nxos_bootflash_stage.py"}


def nd_switch_selection(mode: str, devices: str = "", groups: list[dict] | None = None) -> dict:
    def hosts(value: str) -> list[str]:
        return list(dict.fromkeys(value.replace(",", " ").split()))

    if mode == "per_switch":
        selected = hosts(devices)
        if not selected:
            raise ValueError("Enter at least one switch")
        return {"switches": {"hosts": selected}}
    if mode != "named":
        raise ValueError("Select named update groups or per-switch groups")
    result = {}
    members = set()
    for group in groups or []:
        name = group.get("name", "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", name):
            raise ValueError("Group names must be 1-48 letters, digits, underscores, or hyphens")
        if name in result:
            raise ValueError(f"Duplicate update group name: {name}")
        selected = hosts(group.get("hosts", ""))
        if not selected:
            raise ValueError(f"Add at least one switch to {name}")
        overlap = members.intersection(host.casefold() for host in selected)
        if overlap:
            raise ValueError("Switch listed in multiple groups: " + ", ".join(sorted(overlap)))
        members.update(host.casefold() for host in selected)
        result[name] = {"hosts": selected}
    if not result:
        raise ValueError("Add at least one named update group")
    return {"update_groups": result}


def reject_plaintext_passwords(value) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if ("password" in str(key).lower() and key != "password_env") or str(key).lower().startswith("vault"):
                raise ValueError("Remove passwords/vault paths from YAML; use the credential fields")
            reject_plaintext_passwords(child)
    elif isinstance(value, list):
        for child in value:
            reject_plaintext_passwords(child)


def validate_bootflash_config(config: dict) -> None:
    reject_plaintext_passwords(config)
    allowed = {"nexus_dashboard", "switches", "scp", "images", "upgrade_paths", "login_timeout"}
    if set(config) - allowed:
        raise ValueError("Unsupported bootflash configuration section")
    for section, keys in (
        ("switches", {"username", "hosts"}), ("nexus_dashboard", {"username", "host"}),
        ("scp", {"server", "username", "file_path", "vrf", "timeout", "copy_options"}),
    ):
        values = config.get(section, {})
        if not isinstance(values, dict) or set(values) - keys:
            raise ValueError(f"Unsupported {section} option (custom SSH options are not accepted by the UI)")
    for section in ("switches", "scp", "images", "upgrade_paths"):
        if not config.get(section):
            raise ValueError(f"Missing bootflash section: {section}")
    hosts = config["switches"].get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("switches.hosts must be a nonempty list")
    for host in [*hosts, config.get("nexus_dashboard", {}).get("host", "")]:
        if host and not re.fullmatch(r"[A-Za-z0-9_.:-]+", str(host)):
            raise ValueError("Invalid switch or Nexus Dashboard host")
    for section in ("switches", "scp", "nexus_dashboard"):
        username = config.get(section, {}).get("username", "")
        if username and not re.fullmatch(r"[A-Za-z0-9_.@-]+", username):
            raise ValueError(f"Invalid {section} username")
    if not config["switches"].get("username") or not config["scp"].get("username") or not config["scp"].get("server"):
        raise ValueError("Switch username, SCP username, and SCP server are required")

    def safe_cli(value):
        if isinstance(value, dict):
            for child in value.values():
                safe_cli(child)
        elif isinstance(value, list):
            for child in value:
                safe_cli(child)
        elif isinstance(value, str) and re.search(r"[\r\n;|&`$<>]", value):
            raise ValueError("Shell/CLI control characters are not permitted in bootflash values")

    safe_cli(config)
    for key, minimum in (("login_timeout", 1),):
        if key in config and (not isinstance(config[key], int) or config[key] < minimum):
            raise ValueError(f"{key} must be a positive integer")


class NXJob:
    def __init__(self, kind: str, directory: Path, config: dict, credentials: dict,
                 apply: bool = False, direct: bool = False, pre_report: bool = False,
                 workers: int = 8):
        self.kind = kind
        self.directory = directory
        self.config = config
        self.credentials = credentials
        self.apply = apply
        self.direct = direct
        self.pre_report = pre_report
        self.workers = max(1, min(16, workers))
        self.process = None
        self.cancelled = False
        self.script = SCRIPTS_DIR / SCRIPT_NAMES[kind]
        if not self.script.is_file():
            raise ValueError(f"Staging script not found: {self.script}. Set DC_NXOS_SCRIPTS_DIR.")
        reject_plaintext_passwords(config)
        if kind == "bootflash":
            validate_bootflash_config(config)
        required = ["password"] + (["scp_password"] if kind == "bootflash" else [])
        if kind == "bootflash" and config.get("nexus_dashboard", {}).get("host") and not direct:
            required.append("nd_password")
        if any(not credentials.get(name) for name in required):
            raise ValueError("Required automation passwords are missing")

    def command(self) -> list[str]:
        arguments = [sys.executable, "-u", str(self.script), "--config", str(self.directory / "input.yaml")]
        if self.kind == "nd":
            arguments += ["--password-env", "DC_ND_PASSWORD"]
            if self.apply:
                arguments += ["--apply"]
            if self.pre_report and self.apply:
                arguments += ["--run-pre-report"]
        else:
            arguments += ["--workers", str(self.workers), "--log-dir", str(self.directory / "sessions")]
            if not self.apply:
                arguments += ["--dry-run"]
            if self.direct:
                arguments += ["--direct"]
        return arguments

    def redact(self, text: str) -> str:
        for name, secret in self.credentials.items():
            if "password" in name and secret:
                text = text.replace(secret, "[REDACTED]")
        return text

    async def run(self, notify) -> int:
        self.directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        config_path = self.directory / "input.yaml"
        config_path.write_text(yaml.safe_dump(self.config, sort_keys=False), encoding="utf-8")
        config_path.chmod(0o600)
        environment = {name: value for name, value in os.environ.items() if name not in {
            "DC_AUTOMATION_KEY", "NEXUS_PASSWORD", "NEXUS_DASHBOARD_PASSWORD", "SCP_SERVER_PASSWORD", "DC_ND_PASSWORD",
        }}
        if self.kind == "nd":
            environment["DC_ND_PASSWORD"] = self.credentials["password"]
        else:
            environment.update(NEXUS_PASSWORD=self.credentials["password"],
                               SCP_SERVER_PASSWORD=self.credentials["scp_password"],
                               NEXUS_DASHBOARD_PASSWORD=self.credentials.get("nd_password", ""))
        if self.cancelled:
            return -15
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.command(), env=environment, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                start_new_session=True, limit=1024 * 1024,
            )
            if self.cancelled:
                self.cancel()
            with (self.directory / "console.log").open("w", encoding="utf-8") as stream:
                while line := await self.process.stdout.readline():
                    text = self.redact(line.decode(errors="replace").rstrip())
                    stream.write(text + "\n")
                    stream.flush()
                    notify(text)
            return await self.process.wait()
        except BaseException:
            self.cancel()
            if self.process:
                await self.process.wait()
            raise
        finally:
            for path in self.directory.rglob("*.log"):
                path.write_text(self.redact(path.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
                path.chmod(0o600)
            self.credentials.clear()

    def cancel(self) -> None:
        self.cancelled = True
        if self.process and self.process.returncode is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass