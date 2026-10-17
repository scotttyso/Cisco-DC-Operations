"""Nexus Dashboard interface-description read/modify/write operations."""

from __future__ import annotations

import copy
import re
import runpy
from functools import cache
from urllib.parse import quote

from nxos_jobs import SCRIPTS_DIR


@cache
def nd_helpers() -> dict:
    return runpy.run_path(str(SCRIPTS_DIR / "nd_stage_nexus_updates.py"))


def interface_path(fabric: str, serial: str, interface: str | None = None) -> str:
    if not fabric.strip() or not serial.strip():
        raise ValueError("Fabric and switch serial are required")
    path = f"/manage/fabrics/{quote(fabric, safe='')}/switches/{quote(serial, safe='')}/interfaces"
    if interface is not None:
        if not re.fullmatch(r"Ethernet\d+/\d+(?:/\d+)?", interface):
            raise ValueError("Select a physical Ethernet interface")
        path += "/" + quote(interface, safe="")
    return path


def validate_description(description: str) -> str:
    if not isinstance(description, str) or any(ord(character) < 32 or ord(character) == 127 for character in description):
        raise ValueError("Description must be a single line without control characters")
    return description


def filter_interface_rows(rows: list[dict], pattern: str = "", regex: bool = False,
                          field: str = "all", operator: str | None = None) -> list[dict]:
    operator = operator or ("regex" if regex else "contains")
    if operator not in {"contains", "not_contains", "regex", "not_regex"}:
        raise ValueError("Unsupported interface filter operator")
    if field != "all" and any(field not in row for row in rows):
        raise ValueError("Unsupported interface filter column")
    if not pattern:
        return list(rows)
    if operator in {"regex", "not_regex"}:
        try:
            expression = re.compile(pattern, re.IGNORECASE)
        except re.error as error:
            raise ValueError(f"Invalid interface regex: {error}") from None

        def regex_matches(row: dict) -> bool:
            values = row.values() if field == "all" else (row[field],)
            return any(expression.search(str(value)) for value in values)

        return [row for row in rows if regex_matches(row) == (operator == "regex")]
    query = pattern.strip().casefold()

    def text_matches(row: dict) -> bool:
        values = row.values() if field == "all" else (row[field],)
        return any(query in str(value).casefold() for value in values)

    return [row for row in rows if text_matches(row) == (operator == "contains")]


def interface_records(payload) -> list[dict]:
    records = []
    for record in nd_helpers()["walk_records"](payload):
        name = record.get("interfaceName")
        if isinstance(name, str) and re.fullmatch(r"Ethernet\d+/\d+(?:/\d+)?", name):
            records.append(record)
    return sorted(records, key=lambda record: [int(part) for part in re.findall(r"\d+", record["interfaceName"])])


def interface_edit_block_reason(mode, policy_type) -> str:
    unavailable = {"", "unknown", "none", "null", "n/a", "na", "unassigned"}
    reasons = []
    if not isinstance(policy_type, str) or policy_type.strip().casefold() in unavailable:
        reasons.append("No assigned interface policy")
    if not isinstance(mode, str) or mode.strip().casefold() in unavailable:
        reasons.append("Mode is unknown or empty")
    return "; ".join(reasons)


def writable_interface(payload, serial: str, interface: str) -> dict:
    matches = [record for record in interface_records(payload) if record.get("interfaceName") == interface]
    if len(matches) != 1:
        raise ValueError("GET did not return exactly one matching interface")
    record = matches[0]
    if record.get("switchId") != serial or record.get("interfaceType") != "ethernet":
        raise ValueError("GET returned a different switch or non-Ethernet interface")
    try:
        network = record["configData"]["networkOS"]
        policy = network["policy"]
        if network["networkOSType"] != "nx-os" or not isinstance(policy, dict) or not policy.get("policyType"):
            raise ValueError("Unsupported interface policy")
        blocked = interface_edit_block_reason(record["configData"].get("mode"), policy.get("policyType"))
        if blocked:
            raise ValueError("Description update blocked: " + blocked)
        if policy.get("description") is not None and not isinstance(policy["description"], str):
            raise ValueError("Unsupported description value")
    except (KeyError, TypeError):
        raise ValueError("GET lacks the writable configData.networkOS.policy settings") from None
    return {key: copy.deepcopy(record[key]) for key in ("interfaceName", "interfaceType", "switchId", "configData")}


def description_payload(payload, serial: str, interface: str, description: str) -> dict:
    result = writable_interface(payload, serial, interface)
    result["configData"]["networkOS"]["policy"]["description"] = validate_description(description)
    return result


def current_description(payload: dict) -> str:
    return payload["configData"]["networkOS"]["policy"].get("description") or ""


class InterfaceDescriptions:
    def __init__(self, url: str, username: str, password: str, verify_tls: bool = True,
                 domain: str = "local", timeout: int = 60):
        self.client = nd_helpers()["NexusDashboard"](url, username, password, verify_tls, timeout, domain)

    def close(self) -> None:
        self.client.session.close()

    def switches(self) -> list[dict]:
        switches = nd_helpers()["load_switches"](self.client.request("GET", nd_helpers()["SWITCHES"]))
        return [{"serial": switch.serial, "name": switch.name, "address": switch.address,
                 "fabric": switch.fabric} for switch in switches]

    def update_groups(self) -> tuple[list[dict], list[dict]]:
        helpers = nd_helpers()
        switches = helpers["load_switches"](self.client.request("GET", helpers["SWITCHES"]))
        groups = helpers["load_existing_groups"](self.client, switches)
        inventory = [{"serial": switch.serial, "name": switch.name, "address": switch.address,
                      "fabric": switch.fabric} for switch in switches]
        return groups, inventory

    def interfaces(self, fabric: str, serial: str) -> list[dict]:
        payload = self.client.request("GET", interface_path(fabric, serial))
        grouped = {}
        for record in interface_records(payload):
            if record.get("switchId", serial) != serial or record.get("interfaceType", "ethernet") != "ethernet":
                continue
            values = grouped.setdefault(record["interfaceName"], {"description": set(), "policy": set(), "mode": set()})
            config = record.get("configData")
            config = config if isinstance(config, dict) else {}
            network = config.get("networkOS")
            network = network if isinstance(network, dict) else {}
            policy = network.get("policy")
            policy = policy if isinstance(policy, dict) else {}
            if "description" in policy or "description" in record:
                values["description"].add(str(policy.get("description", record.get("description")) or ""))
            if "policyType" in policy:
                values["policy"].add(str(policy["policyType"] or ""))
            if "mode" in config:
                values["mode"].add(str(config["mode"] or ""))
        rows = []
        for interface, values in grouped.items():
            conflicts = [field for field, candidates in values.items() if len(candidates) > 1]
            row = {"interface": interface, "notice": ""}
            for field, candidates in values.items():
                row[field] = "Multiple values; preview required" if len(candidates) > 1 else next(iter(candidates), "")
            if conflicts:
                row["notice"] = "Collection records disagree on " + ", ".join(conflicts) + "; current settings must be checked at preview"
            blocked = interface_edit_block_reason(row["mode"], row["policy"])
            if any(field in conflicts for field in ("mode", "policy")):
                blocked = "ND records disagree on policy or mode; reload consistent settings before editing"
            row.update(editable=not blocked, blocked_reason=blocked)
            rows.append(row)
        if not rows:
            raise ValueError("ND returned no physical Ethernet interfaces for this switch")
        return rows

    def preview(self, fabric: str, serial: str, changes: dict[str, str]) -> list[dict]:
        plans = []
        for interface, description in changes.items():
            path = interface_path(fabric, serial, interface)
            validate_description(description)
            record = writable_interface(self.client.request("GET", path), serial, interface)
            plans.append({"interface": interface, "old": current_description(record), "new": description,
                          "fabric": fabric, "serial": serial, "original": record,
                          "state": "UNCHANGED" if current_description(record) == description else "READY"})
        if not plans:
            raise ValueError("Select at least one interface")
        return plans

    def apply(self, plans: list[dict]) -> list[dict]:
        results = []
        for plan in plans:
            result = {key: plan[key] for key in ("interface", "fabric", "serial", "old", "new")}
            result.update(state="ERROR", detail="")
            try:
                path = interface_path(plan["fabric"], plan["serial"], plan["interface"])
                latest = writable_interface(self.client.request("GET", path), plan["serial"], plan["interface"])
                if latest != plan["original"]:
                    result.update(state="CONFLICT", detail="Settings changed after preview; reload and preview again")
                elif current_description(latest) == plan["new"]:
                    result.update(state="UNCHANGED", detail="No PUT needed")
                else:
                    updated = description_payload(latest, plan["serial"], plan["interface"], plan["new"])
                    self.client.request("PUT", path, updated)
                    verified = writable_interface(self.client.request("GET", path), plan["serial"], plan["interface"])
                    if verified == updated:
                        result.update(state="UPDATED", detail="ND description and preserved settings verified")
                    else:
                        result.update(state="VERIFY_REQUIRED", detail="PUT returned; subsequent GET differs from requested settings")
            except Exception as error:
                result["detail"] = str(error)
            results.append(result)
        return results