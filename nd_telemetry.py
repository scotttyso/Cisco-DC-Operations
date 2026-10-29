"""Preview and push ND software telemetry using direct or appliance-hop SSH."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode

import yaml

from aci_jump import NexusDashboardSSH
from nd_interfaces import nd_helpers
from nxos_jobs import reject_plaintext_passwords


TELEMETRY_EXAMPLE = """switches:
  username: netops
  hosts:
    - 192.0.2.101
    - 192.0.2.102
# Optional per-switch inband source-interface overrides (same keys as hosts).
source_interfaces: {}
# source_interfaces:
#   192.0.2.101: Vlan64
"""

CLI_ERROR = re.compile(
    r"(?im)^\s*(?:%.*(?:invalid|error|failed|denied|incomplete|ambiguous|not allowed|not supported)"
    r"|(?:error|syntax error|invalid command|invalid input|permission denied)\b)"
)


def source_interface(value: str) -> str:
    if isinstance(value, str):
        for short, full in (("eth", "Ethernet"), ("lo", "Loopback"), ("po", "port-channel"), ("vl", "Vlan")):
            if re.match(rf"(?i)^{short}\d", value):
                value = full + value[len(short):]
    if not isinstance(value, str) or not re.fullmatch(
        r"(?i)(?:vlan[1-9]\d{0,3}|loopback\d+|ethernet\d+/\d+(?:/\d+)?(?:\.\d+)?|port-channel[1-9]\d*(?:\.\d+)?)", value
    ):
        raise ValueError("Inband source must be a Vlan, Loopback, Ethernet, or port-channel interface")
    if value.lower().startswith("vlan") and int(value[4:]) > 4094:
        raise ValueError("VLAN interface must be between 1 and 4094")
    return value


def telemetry_selection(text: str) -> dict:
    try:
        config = yaml.safe_load(text)
    except yaml.YAMLError:
        raise ValueError("Invalid telemetry YAML") from None
    reject_plaintext_passwords(config)
    if not isinstance(config, dict) or set(config) - {"switches", "source_interfaces"}:
        raise ValueError("Telemetry YAML supports switches and source_interfaces only")
    switches = config.get("switches")
    if not isinstance(switches, dict) or set(switches) != {"username", "hosts"}:
        raise ValueError("switches must contain username and hosts")
    if not isinstance(switches["username"], str) or not re.fullmatch(r"[A-Za-z0-9_.@\\:-]+", switches["username"]):
        raise ValueError("Enter a valid switch SSH username in the YAML")
    hosts = switches["hosts"]
    if not isinstance(hosts, list) or not hosts or any(
        not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", host) for host in hosts
    ):
        raise ValueError("switches.hosts must be a nonempty list of switch names, IPs, or serials")
    if len({host.casefold() for host in hosts}) != len(hosts):
        raise ValueError("Duplicate switch selections are not allowed")
    overrides = config.get("source_interfaces", {})
    if not isinstance(overrides, dict) or any(host not in hosts for host in overrides):
        raise ValueError("source_interfaces keys must match entries in switches.hosts")
    overrides = {host: source_interface(interface) for host, interface in overrides.items()}
    return {"switches": switches, "source_interfaces": overrides}


def selected_switches(inventory: list[dict], hosts: list[str]) -> list[dict]:
    selected = []
    seen = set()
    for host in hosts:
        matches = [switch for switch in inventory if host.casefold() in {
            str(switch[key]).casefold() for key in ("serial", "name", "address")
        }]
        if not matches:
            short = host.casefold().split(".")[0]
            matches = [switch for switch in inventory
                       if "." not in host and str(switch["name"]).casefold().split(".")[0] == short]
        if len(matches) != 1:
            known = ", ".join(f"{switch['name']} ({switch['address'] or 'no IP'}, {switch['serial']})"
                              for switch in inventory[:10])
            raise ValueError(f"{host}: expected exactly one matching ND switch, found {len(matches)}. "
                             f"ND returned {len(inventory)} switches"
                             + (f": {known}" + (" ..." if len(inventory) > 10 else "") if inventory else ""))
        switch = matches[0]
        if switch["serial"] in seen:
            raise ValueError(f"{host}: the same switch was selected more than once")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", switch["address"]):
            raise ValueError(f"{host}: ND did not return a valid switch management IP/hostname")
        seen.add(switch["serial"])
        selected.append({**switch, "selected_as": host})
    return selected


def discover_source(output: str, address: str) -> str:
    try:
        expected = ipaddress.ip_address(address)
    except ValueError:
        raise ValueError("ND management address is not an IP; supply a source_interfaces override") from None
    matches = set()
    interface = None
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        try:
            interface = source_interface(fields[0])
        except ValueError:
            if not line[0].isspace():
                interface = None
        for field in fields:
            try:
                address_value = ipaddress.ip_interface(field).ip
            except ValueError:
                continue
            if address_value == expected and interface:
                matches.add(interface)
    if len(matches) != 1:
        raise ValueError("Cannot uniquely map the ND management IP to an inband interface; "
                         "add a source_interfaces override and preview again")
    return next(iter(matches))


def configuration_lines(template: str) -> list[str]:
    if not isinstance(template, str) or not template.strip():
        raise ValueError("ND returned an empty softwareConfiguration")
    if any(ord(character) < 32 and character not in "\r\n" for character in template):
        raise ValueError("Telemetry template contains unsupported control characters")
    lines = [line.rstrip() for line in template.splitlines() if line.strip() and not line.lstrip().startswith("!")]
    if lines and lines[0].strip() == "configure terminal":
        lines.pop(0)
    if lines and lines[-1].strip() == "end":
        lines.pop()
    if not lines or not any(line == "telemetry" for line in lines):
        raise ValueError("ND softwareConfiguration does not contain a telemetry configuration")
    for line in lines:
        command = line.strip()
        if not line.startswith(" ") and command != "telemetry" and not re.fullmatch(r"feature [a-zA-Z0-9_-]+", command):
            raise ValueError(f"Unsupported top-level telemetry command: {command}")
        if re.match(r"(?i)(?:end|exit|configure|do|run|reload|copy|write|bash|python|guestshell)\b", command):
            raise ValueError(f"Unsupported telemetry command: {command}")
    return lines


def replace_source(template: str, interface: str) -> str:
    source_interface(interface)
    lines = template.splitlines(keepends=True)
    telemetry = False
    destination_indent = None
    replacements = 0
    for index, line in enumerate(lines):
        command = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if command and indent == 0:
            telemetry = command == "telemetry"
            destination_indent = None
        if not telemetry or not command:
            continue
        if destination_indent is not None and indent <= destination_indent:
            destination_indent = None
        if command == "destination-profile":
            destination_indent = indent
        elif destination_indent is not None and command.startswith("source-interface "):
            newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            lines[index] = " " * indent + f"source-interface {interface}" + newline
            replacements += 1
    if replacements != 1:
        raise ValueError("Expected exactly one telemetry destination-profile source-interface in the ND template")
    return "".join(lines)


class TelemetrySSH(NexusDashboardSSH):
    def __init__(self, target: str, username: str, password: str, jump: dict | None):
        super().__init__(target, username, password, jump, 60, switch_label="NX-OS switch")

    def discover(self, address: str) -> str:
        family = "ipv6" if ":" in address else "ip"
        output = self.send_command(f"show {family} interface brief vrf all", read_timeout=90)
        if CLI_ERROR.search(output):
            raise ValueError("Switch rejected interface discovery; add a source_interfaces override")
        return discover_source(output, address)

    def push(self, template: str, notify: Callable[[str], None] | None = None) -> None:
        lines = configuration_lines(template)
        prompt = self.session._capture_prompt(r"[A-Za-z0-9][\w.\-]*# ?$")
        self.session.sw_prompt_re = re.escape(prompt.rstrip("# ")) + r"(?:\([^\r\n)]*\))?#\s*$"

        def execute(command: str, timeout: int = 120) -> str:
            if notify:
                notify(f"> {command}")
            try:
                output = self.session.cmd(command, timeout=timeout)
            except Exception:
                if notify and isinstance(self.session.child.before, str):
                    notify(self.session.child.before)
                raise
            if notify and output:
                notify(output)
            if CLI_ERROR.search(output):
                raise RuntimeError(f"Switch rejected '{command}': {output.strip()[:1200]}")
            return output

        try:
            execute("configure terminal")
            ancestors = []
            previous_indent = None
            for line in lines:
                indent = len(line) - len(line.lstrip(" "))
                if previous_indent is not None and indent > previous_indent:
                    ancestors.append(previous_indent)
                while ancestors and indent <= ancestors[-1]:
                    execute("exit")
                    ancestors.pop()
                execute(line.strip())
                previous_indent = indent
            execute("end")
            try:
                output = execute("copy running-config startup-config", timeout=300)
                if not re.search(r"(?im)\bcopy complete\b|\[OK\]", output):
                    raise RuntimeError("Switch did not confirm that the copy completed")
            except Exception as error:
                raise RuntimeError(f"Telemetry applied to running-config, but startup-config save failed: {error}") from error
        except Exception:
            self.session.child.close(force=True)
            raise


def normalize_vrf(value, fabric: str) -> str:
    # A missing field means management; ND may also abbreviate it as mgmt
    text = str(value or "management").strip().casefold()
    text = {"mgmt": "management"}.get(text, text)
    if text not in {"management", "default", "inband"}:
        raise ValueError(f"{fabric}: unsupported telemetry source VRF {value!r}")
    return text


class TelemetryPush:
    def __init__(self, profile: dict, credentials: dict):
        self.client = nd_helpers()["NexusDashboard"](
            "https://" + profile["address"], credentials["username"], credentials["password"],
            bool(profile["verify_tls"]), 60, credentials["domain"]
        )

    def close(self) -> None:
        self.client.session.close()

    def inventory_vrfs(self, fabric: str) -> dict[str, tuple[str, str]]:
        vrfs = {}
        offset = 0
        while True:
            response = self.client.request("GET", "/manage/inventory/switches?" + urlencode(
                {"max": 100, "offset": offset, "sort": "hostname:asc"}))
            items = response.get("switches") if isinstance(response, dict) else None
            if not isinstance(items, list) or not items:
                break
            for item in items:
                extra = item.get("additionalData") if isinstance(item, dict) else None
                serial = str(item.get("serialNumber") or item.get("switchId") or "")
                if item.get("fabricName") == fabric and serial and isinstance(extra, dict) and extra.get("sourceVrfName") \
                        and str(extra.get("platformType") or "nx-os").casefold() == "nx-os":
                    vrf = normalize_vrf(extra["sourceVrfName"], fabric)
                    try:
                        interface = source_interface(str(extra.get("sourceInterfaceName") or "")) if vrf != "management" else ""
                    except ValueError:
                        interface = ""
                    vrfs[serial] = (vrf, interface)
            offset += len(items)
            counts = (response.get("meta") or {}).get("counts") or {}
            if not counts.get("remaining") or offset >= 10000:
                break
        return vrfs

    def fabric_vrf(self, fabric: str) -> str:
        response = self.client.request("GET", "/manage/fabrics/" + quote(fabric, safe=""))
        if not isinstance(response, dict):
            raise ValueError(f"{fabric}: ND returned an unexpected fabric record")
        return normalize_vrf(response.get("telemetrySourceVrf"), fabric)

    def preview(self, selection: dict, password: str, jump: dict | None) -> list[dict]:
        switches = nd_helpers()["load_switches"](self.client.request("GET", nd_helpers()["SWITCHES"]))
        inventory = [{"serial": switch.serial, "name": switch.name, "address": switch.address,
                      "fabric": switch.fabric} for switch in switches]
        targets = selected_switches(inventory, selection["switches"]["hosts"])
        plans = []
        fabrics = {}
        inventories = {}
        for switch in targets:
            fabric = switch["fabric"]
            if fabric not in inventories:
                inventories[fabric] = self.inventory_vrfs(fabric)
            vrf, inventory_interface = inventories[fabric].get(switch["serial"], (None, ""))
            if vrf is None:
                if fabric not in fabrics:
                    fabrics[fabric] = self.fabric_vrf(fabric)
                vrf = fabrics[fabric]
            payload = self.client.request("GET", "/analyze/telemetry/switchesConfig?" + urlencode(
                {"fabricName": fabric, "switchId": switch["serial"]}))
            if not isinstance(payload, dict) or payload.get("validSoftwareConfiguration") is not True:
                raise ValueError(f"{switch['name']}: ND did not return a valid software telemetry configuration")
            template = payload.get("softwareConfiguration")
            configuration_lines(template)
            interface = ""
            origin = "ND template unchanged"
            if vrf != "management":
                interface = selection["source_interfaces"].get(switch["selected_as"], "")
                origin = "YAML override"
                if not interface and inventory_interface:
                    interface, origin = inventory_interface, "ND inventory sourceInterfaceName"
                if not interface:
                    origin = "Discovered from ND management IP"
                    connection = TelemetrySSH(switch["address"], selection["switches"]["username"], password, jump)
                    try:
                        interface = connection.discover(switch["address"])
                    finally:
                        connection.disconnect()
                template = replace_source(template, interface)
            plans.append({**switch, "vrf": vrf, "source_interface": interface, "source": origin,
                          "template": template, "state": "READY", "detail": ""})
        return plans


def push_plans(plans: list[dict], username: str, password: str, jump: dict | None,
               notify: Callable[[str], None], log_directory: Path | None = None) -> list[dict]:
    results = []
    stopped = False

    def redact(text: str) -> str:
        for secret in (password, jump["password"] if jump is not None else ""):
            if secret:
                text = text.replace(secret, "[REDACTED]")
        return text

    for index, plan in enumerate(plans):
        result = {key: value for key, value in plan.items() if key != "template"}
        path = log_directory / f"switch-{index + 1}.log" if log_directory is not None else None
        if path is not None:
            path.touch(mode=0o600, exist_ok=False)
            result["log_file"] = path.name
        with (path.open("w", encoding="utf-8") if path is not None else nullcontext()) as stream:
            def record(message: str) -> None:
                text = redact(message)
                if stream is not None:
                    stream.write(f"{datetime.now(timezone.utc).isoformat()} {text}\n")
                    stream.flush()
                notify(f"{plan['name']}: {text}")

            record(f"Switch {plan['name']} | {plan['serial']} | {plan['address']} | {plan['fabric']}")
            if stopped:
                result.update(state="NOT_ATTEMPTED", detail="Stopped after a previous switch failed")
            else:
                connection = None
                route = "via Nexus Dashboard rescue-user" if jump is not None else "directly to switch"
                record(f"connecting {route}")
                try:
                    connection = TelemetrySSH(plan["address"], username, password, jump)
                    connection.push(plan["template"], record)
                    result.update(state="PUSHED", detail="CLI accepted configuration and confirmed startup-config save. "
                                  "Telemetry reception on ND has not been verified.")
                except Exception as error:
                    result.update(state="FAILED", detail="Configuration may be partially applied: " + redact(str(error)))
                    stopped = True
                finally:
                    if connection:
                        connection.disconnect()
            record(f"{result['state']} - {result['detail']}")
        results.append(result)
        if result["state"] == "FAILED":
            notify("Stopped after failure; remaining switches were not attempted. Preview again before retrying.")
    return results
