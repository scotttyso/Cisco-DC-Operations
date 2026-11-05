"""Fabric-scoped diagnostic snapshots and pre/post comparison for the WebUI."""

from __future__ import annotations

import difflib
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from netmiko.exceptions import NetmikoAuthenticationException

from aci_ifstatus_common import (
    COMMAND, MAC_QUERY, ISIS_QUERY, LEGACY_MAC_COMMAND, LEGACY_ISIS_COMMAND, ROLE_COMMANDS, ApicClient, CaptureCancelled,
    aci_login_username, capture_leaf_commands, check_capture_cancelled, command_label,
    discover_active_nodes, fqdn, moquery_attributes, parse_interface_brief, validate_role_commands,
    upgraded_role_commands,
    validate_reconnect_limits,
)
from aci_leaf_ifstatus_post import compare


def select_leaves(leaves: list[dict], group: str, node_ids: str = "") -> list[dict]:
    if group == "all":
        selected = leaves
    elif group in ("odd", "even"):
        selected = [leaf for leaf in leaves if int(leaf["node_id"]) % 2 == (group == "odd")]
    elif group == "nodes":
        wanted = set(node_ids.replace(",", " ").split())
        known = {leaf["node_id"] for leaf in leaves}
        if not wanted or wanted - known:
            raise ValueError("Enter node IDs present in the selected fabric/baseline and role")
        selected = [leaf for leaf in leaves if leaf["node_id"] in wanted]
    else:
        raise ValueError("Unknown switch group")
    if not selected:
        raise ValueError("No switches in the selected group and role")
    return selected


def capture_snapshot(apic: dict, username: str, password: str, baseline: dict | None = None,
                     group: str = "all", node_ids: str = "", workers: int = 20,
                     connect_timeout: int = 20, read_timeout: int = 90,
                     dns_domain: str = "", notify=lambda message: None,
                     role: str = "all", role_commands: dict | None = None,
                     jump: dict | None = None, cancel_event: threading.Event | None = None,
                     ssh_diagnostics: bool = False, reconnects_per_command: int = 1,
                     reconnects_per_switch: int = 3) -> dict:
    reconnects_per_command, reconnects_per_switch = validate_reconnect_limits(
        reconnects_per_command, reconnects_per_switch)
    check_capture_cancelled(cancel_event)
    if role not in ("all", "leaf", "spine"):
        raise ValueError("Select all switches, leaf, or spine")
    command_lists = (validate_role_commands(baseline_role_commands(baseline)) if baseline
                     else upgraded_role_commands(role_commands))
    username = aci_login_username(username, apic.get("domain", "local"))
    if baseline:
        if baseline["apic_id"] != apic["id"] or baseline["apic"] != apic["address"]:
            raise ValueError("Baseline belongs to a different APIC profile/address")
        leaves = [entry["leaf"] for entry in baseline["nodes"]]
    else:
        client = ApicClient(apic["address"], verify_tls=bool(apic["verify_tls"]))
        try:
            client.login(username, password)
            check_capture_cancelled(cancel_event)
            leaves = discover_active_nodes(client)
        finally:
            client.logout()
    check_capture_cancelled(cancel_event)
    leaves = select_leaves([node for node in leaves if role == "all" or node.get("role", "leaf") == role], group, node_ids)
    auth_lock = threading.Lock()
    auth_ok = threading.Event()
    auth_bad = threading.Event()
    if not baseline and not jump:
        auth_ok.set()

    def collect(leaf):
        target = leaf.get("inb_ip") or leaf.get("oob_ip") or fqdn(leaf["name"], dns_domain)
        entry = {"leaf": leaf, "target": target, "commands": {}, "error": ""}
        diagnostics = {} if ssh_diagnostics else None

        def capture():
            check_capture_cancelled(cancel_event)
            if not target:
                raise ValueError("Switch has no OOB address or name")
            return capture_leaf_commands(target, username, password, connect_timeout, read_timeout,
                                         commands=command_lists[leaf.get("role", "leaf")],
                                         jump=jump, cancel_event=cancel_event, diagnostics=diagnostics,
                                         reconnects_per_command=reconnects_per_command,
                                         reconnects_per_switch=reconnects_per_switch, notify=notify)

        try:
            with auth_lock:
                check_capture_cancelled(cancel_event)
                if auth_bad.is_set():
                    raise NetmikoAuthenticationException("Skipped: unproven password rejected by another leaf")
                if not auth_ok.is_set():
                    try:
                        entry["commands"] = capture()
                    except NetmikoAuthenticationException:
                        auth_bad.set()
                        raise
                    auth_ok.set()
            if not entry["commands"]:
                entry["commands"] = capture()
            check_capture_cancelled(cancel_event)
        except CaptureCancelled:
            raise
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        if diagnostics is not None:
            entry["ssh_diagnostics"] = diagnostics
        notify(f"{leaf.get('role', 'leaf').upper()} {leaf['node_id']} {leaf['name']}: "
               + ("ERROR" if entry["error"] or any(result["status"] != "OK"
                  for result in entry["commands"].values()) else "captured"))
        return entry

    entries = []
    with ThreadPoolExecutor(max_workers=max(1, min(32, workers))) as executor:
        futures = [executor.submit(collect, leaf) for leaf in leaves]
        try:
            for future in as_completed(futures):
                check_capture_cancelled(cancel_event)
                entries.append(future.result())
        except CaptureCancelled:
            for future in futures:
                future.cancel()
            raise
    check_capture_cancelled(cancel_event)
    entries.sort(key=lambda entry: int(entry["leaf"]["node_id"]))
    return {"version": 2, "id": uuid4().hex, "apic_id": apic["id"], "apic": apic["address"],
            "phase": "post" if baseline else "pre", "baseline_id": baseline["id"] if baseline else None,
            "captured_at": datetime.now(timezone.utc).isoformat(), "group": group, "role": role,
            "role_commands": command_lists, "dns_domain": dns_domain,
            "reconnects_per_command": reconnects_per_command, "reconnects_per_switch": reconnects_per_switch,
            "ssh_connection": "nexus_dashboard" if jump else "direct", "nodes": entries}


def ssh_diagnostic_report(snapshot: dict, baseline: dict | None, node_id: str) -> str:
    sections = []
    for phase, capture in (("PRE", baseline), (snapshot.get("phase", "").upper(), snapshot)):
        if not capture:
            continue
        entry = next((entry for entry in capture.get("nodes", [])
                      if entry["leaf"]["node_id"] == node_id), None)
        if entry and entry.get("ssh_diagnostics", {}).get("session_log"):
            sections.append(f"=== {phase} | Node {node_id} | {entry['leaf']['name']} ===\n"
                            + entry["ssh_diagnostics"]["session_log"])
    return "\n\n".join(sections)


def baseline_role_commands(snapshot: dict) -> dict:
    if "role_commands" in snapshot:
        return snapshot["role_commands"]
    replacements = {MAC_QUERY: LEGACY_MAC_COMMAND, ISIS_QUERY: LEGACY_ISIS_COMMAND}
    commands = {role: [replacements.get(command, command) for command in values]
                for role, values in ROLE_COMMANDS.items()}
    for role in commands:
        recorded = dict.fromkeys(command for entry in snapshot["nodes"]
                                 if entry["leaf"].get("role", "leaf") == role
                                 for command in entry.get("commands", {}))
        if recorded:
            commands[role] = list(recorded)
    return commands


def node_commands(snapshot: dict, entry: dict) -> tuple[str, ...]:
    role = entry["leaf"].get("role", "leaf")
    return tuple(snapshot["role_commands"][role] if "role_commands" in snapshot
                 else entry.get("commands") or ROLE_COMMANDS[role])


def snapshot_results(snapshot: dict, baseline: dict | None = None) -> list[dict]:
    """Map capture output to its actual phase, including previously saved snapshots."""
    if snapshot["phase"] == "post":
        return compare_snapshots(baseline or {"apic_id": snapshot["apic_id"],
                                 "apic": snapshot["apic"], "nodes": []}, snapshot)
    return [{"id": f"{entry['leaf']['node_id']}:{command}",
             "node_id": entry["leaf"]["node_id"], "name": entry["leaf"]["name"],
             "role": entry["leaf"].get("role", "leaf"),
             "command": command, "command_label": command_label(command),
             "state": "CAPTURED" if result.get("status") == "OK" and not entry["error"] else "ERROR",
             "pre": result.get("output", ""), "post": "",
             "detail": entry["error"] or (result.get("error") or result.get("output", "")
                                        if result.get("status") != "OK" else "")}
            for entry in snapshot["nodes"] for command in node_commands(snapshot, entry)
            for result in [entry["commands"].get(command, {})]]


def _environment_signature(output: str) -> dict | None:
    components = {}
    sections = set()
    section = None
    for line in output.splitlines():
        columns = line.split()
        if (len(columns) >= 3 and columns[0].lower() in {"supply", "module"}
                and "model" in {value.lower() for value in columns}
                and "status" in {value.lower() for value in columns}):
            section = columns[0].lower()
            sections.add(section)
            continue
        if section is None:
            continue
        if not line.strip():
            section = None
            continue
        if not line.strip(" -"):
            continue
        if line.lstrip().startswith("(") and "watt" in line.lower():
            continue
        values = line.split()
        if (len(values) >= 3 and
                (values[0].isdigit() or values[0].lower().startswith("fan"))):
            components[f"{section} {values[0]}"] = {
                "model": values[1], "status": values[-1],
            }
        else:
            section = None
    if sections != {"supply", "module"} or not components:
        return None
    return components


def _module_signature(output: str) -> dict | None:
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if line.split() != ["Mod", "Ports", "Module-Type", "Model", "Status"]:
            continue
        modules = {}
        for row in lines[index + 1:]:
            if not row.strip(" -"):
                if modules:
                    break
                continue
            values = row.split()
            if not values or not values[0].isdigit():
                break
            if len(values) < 5 or not values[1].isdigit():
                return None
            module_type = " ".join(values[2:-2])
            status = values[-1]
            if (module_type.lower() in {"supervisor module", "system controller"}
                    and status.lower() in {"active", "standby"}):
                status = "active/standby"
            if values[0] in modules:
                return None
            modules[values[0]] = {
                "ports": values[1], "type": module_type, "model": values[-2], "status": status,
            }
        return modules or None
    return None


def _isis_signature(output: str) -> dict | None:
    lines = output.splitlines()
    adjacencies = {}
    found_header = False
    for index, line in enumerate(lines):
        header = line.lower()
        if not all(field in header for field in ("system id", "snpa", "level", "state", "hold time", "interface")):
            continue
        found_header = True
        parsed_rows = False
        for row in lines[index + 1:]:
            if not row.strip():
                if parsed_rows:
                    break
                continue
            if not row.strip(" -"):
                continue
            values = row.split()
            if (len(values) >= 6 and
                    values[-1].lower().startswith(("ethernet", "eth", "port-channel", "po"))):
                system_id, state = values[0], values[3]
                interface = values[-1].split(".", 1)[0]
                adjacencies.setdefault(f"neighbor {system_id} on {interface}", []).append(state)
                parsed_rows = True
            elif parsed_rows:
                break
    return {key: {"state": ", ".join(sorted(states))} for key, states in adjacencies.items()} if found_header else None


def _mac_table_signature(output: str) -> dict | None:
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if "MAC Address" not in line or "Ports/SWID.SSID.LID" not in line:
            continue
        endpoints = {}
        for row in lines[index + 1:]:
            if not row.strip() or not row.strip(" -+"):
                continue
            if row.strip().endswith(("#", ">")) or row.strip().startswith("Total"):
                break
            values = row.split()
            mac_index = next((offset for offset, value in enumerate(values)
                              if re.fullmatch(r"[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}", value)), None)
            if mac_index is None or len(values[mac_index + 1:]) != 5:
                raise ValueError(f"Cannot parse MAC table row: {row.strip()}")
            mac, port = values[mac_index].lower(), values[-1].lower()
            endpoints[f"MAC {mac} on {port}"] = {"port": port}
        return endpoints
    return None


def _port_channels(output: str) -> dict | None:
    if not re.search(r"Group\s+Port-.*Member Ports", output):
        return None
    channels = {}
    current = None
    for line in output.splitlines():
        match = re.match(r"\s*\d+\s+Po(\d+)\(([^)]+)\)\s+(\S+)\s+(\S+)\s*(.*)", line)
        if match:
            identifier, flags, kind, protocol, members = match.groups()
            if identifier in channels:
                return None
            current = {"flags": flags, "type": kind, "protocol": protocol, "members": {}}
            channels[identifier] = current
        elif current is not None and re.match(r"\s*(?:Eth|Ethernet)\d", line, re.IGNORECASE):
            members = line.strip()
        else:
            if re.match(r"\s*\d+\s+Po", line):
                return None
            current = None
            continue
        parsed = re.findall(r"(?:Eth|Ethernet)(\d+(?:/\d+)+)\(([^)]+)\)", members, re.IGNORECASE)
        if re.sub(r"(?:Eth|Ethernet)\d+(?:/\d+)+\([^)]+\)", "", members, flags=re.IGNORECASE).strip():
            return None
        for port, flag in parsed:
            physical = "Ethernet" + port
            if physical in current["members"]:
                return None
            current["members"][physical] = flag
    return channels


def _port_channel_signature(output: str) -> dict | None:
    channels = _port_channels(output)
    if channels is None:
        return None
    signature = {}
    for channel in channels.values():
        if not channel["members"]:
            return None
        key = "members " + ", ".join(sorted(channel["members"]))
        if key in signature:
            return None
        signature[key] = {field: channel[field] for field in ("flags", "type", "protocol")}
        signature[key].update(channel["members"])
    return signature


def _vpc_signature(output: str, channel_output: dict) -> dict | None:
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "vPC status":
            continue
        header_index = next((offset for offset in range(index + 1, len(lines))
                             if re.match(r"\s*id\s+Port\s+Status\s+Consistency\s+Reason\s+Active vlans",
                                         lines[offset])), None)
        if header_index is None:
            return None
        header = lines[header_index]
        fields = ("Status", "Consistency", "Reason", "Active vlans")
        starts = [header.index(field) for field in fields]
        channels = (_port_channels(channel_output.get("output", ""))
                    if channel_output.get("status") == "OK" else None)
        signature = {"vPC context": {"output": " ".join("\n".join(lines[:index]).split())}}
        current = None
        for row in lines[header_index + 1:]:
            if not row.strip() or not row.strip(" -"):
                continue
            match = re.match(r"\s*\d+\s+Po(\d+)\s+", row)
            if match:
                channel = channels.get(match[1]) if channels is not None else None
                if not channel or not channel["members"]:
                    raise ValueError("Cannot map vPC port-channels to physical members: "
                                     "a usable show port-channel summary is required in both captures")
                key = "members " + ", ".join(sorted(channel["members"]))
                if key in signature:
                    raise ValueError("Multiple vPCs map to the same physical members")
                current = {field: [] for field in fields}
                signature[key] = current
            elif current is None or row[:starts[0]].strip():
                return None
            for field_index, field in enumerate(fields):
                value = row[starts[field_index]:starts[field_index + 1] if field_index + 1 < len(fields) else None].strip()
                if value:
                    current[field].append(value)
        for key, values in signature.items():
            if key != "vPC context":
                signature[key] = {field: ("".join(parts) if field == "Active vlans" else " ".join(parts))
                                  for field, parts in values.items()}
        return signature
    return None


def _mac_query_signature(output: str) -> dict:
    endpoints = {}
    for attributes in moquery_attributes(output, "epmMacEp"):
        if "tunnel" in attributes["ifId"].lower():
            continue
        key = f"MAC {attributes['addr'].lower()} | dn={attributes['dn']}"
        endpoints.setdefault(key, {"count": 0})["count"] += 1
    return endpoints


def _isis_query_signature(output: str) -> dict:
    neighbors = {}
    for attributes in moquery_attributes(output, "isisAdjEp"):
        neighbor = next(attributes[field].strip() for field in ("sysId", "name")
                        if isinstance(attributes.get(field), str) and attributes[field].strip())
        identifier = re.sub(r"[:.]", "", neighbor.lower())
        neighbors.setdefault(f"neighbor {identifier}", []).append(attributes["operSt"].lower())
    return {key: {"operSt": ", ".join(sorted(states))} for key, states in neighbors.items()}


def _output_diff(before: str, after: str) -> str:
    pre_lines = [line.rstrip() for line in before.strip().splitlines()]
    post_lines = [line.rstrip() for line in after.strip().splitlines()]
    return "\n".join(difflib.unified_diff(pre_lines, post_lines, fromfile="pre", tofile="post", lineterm=""))


def _signature_diff(before: dict, after: dict) -> str:
    def lines(signature):
        return [f"{key} | " + " | ".join(f"{field}={value}" for field, value in sorted(values.items()))
                for key, values in sorted(signature.items())]

    return "\n".join(difflib.unified_diff(lines(before), lines(after),
                                           fromfile="pre", tofile="post", lineterm=""))


def compare_snapshots(baseline: dict, current: dict) -> list[dict]:
    if baseline["apic_id"] != current["apic_id"] or baseline["apic"] != current["apic"]:
        raise ValueError("Cannot compare snapshots from different APICs")
    before = {entry["leaf"]["node_id"]: entry for entry in baseline["nodes"]}
    rows = []
    for entry in current["nodes"]:
        node_id = entry["leaf"]["node_id"]
        previous = before.get(node_id, {})
        commands = dict.fromkeys((*node_commands(baseline, previous or entry), *node_commands(current, entry)))
        for command in commands:
            pre = previous.get("commands", {}).get(command, {})
            post = entry["commands"].get(command, {})
            state, detail = "MATCH", ""
            if entry["error"] or post.get("status") != "OK":
                state, detail = "ERROR", entry["error"] or post.get("error") or post.get("output", "No post output")
            elif previous.get("error") or pre.get("status") != "OK":
                state, detail = "NO_BASELINE", previous.get("error") or pre.get("error") or pre.get("output", "No pre output")
            elif command == COMMAND:
                pre_ports = {row["port"]: row for row in parse_interface_brief(pre["output"])}
                post_ports = {row["port"]: row for row in parse_interface_brief(post["output"])}
                if not pre_ports or not post_ports:
                    state, detail = "ERROR", "No physical Ethernet rows parsed"
                else:
                    differences = compare(pre_ports, post_ports)
                    if differences:
                        state = "REVIEW"
                        detail = "\n".join(f"{port}: {old} -> {new} {reason}"
                                           for port, old, new, reason in differences)
            else:
                normalizer = {
                    "show environment": _environment_signature,
                    "show module": _module_signature,
                    "show port-channel summary": _port_channel_signature,
                    "show isis adjacency vrf all": _isis_signature,
                    LEGACY_MAC_COMMAND: _mac_table_signature,
                    MAC_QUERY: _mac_query_signature,
                    ISIS_QUERY: _isis_query_signature,
                }.get(command)
                before_text, after_text = pre["output"], post["output"]
                mapping_error = ""
                before_signature = after_signature = None
                try:
                    before_signature = normalizer(before_text) if normalizer else None
                except ValueError as error:
                    state, mapping_error = "NO_BASELINE", f"Invalid PRE output: {error}"
                if not mapping_error:
                    try:
                        after_signature = normalizer(after_text) if normalizer else None
                    except ValueError as error:
                        state, mapping_error = "ERROR", f"Invalid POST output: {error}"
                if command == "show vpc":
                    try:
                        before_signature = _vpc_signature(
                            before_text, previous.get("commands", {}).get("show port-channel summary", {}))
                        after_signature = _vpc_signature(
                            after_text, entry["commands"].get("show port-channel summary", {}))
                    except ValueError as error:
                        state = "ERROR"
                        mapping_error = str(error)
                if mapping_error:
                    detail = mapping_error
                elif before_signature is not None and after_signature is not None:
                    if before_signature != after_signature:
                        state = "REVIEW"
                        detail = _signature_diff(before_signature, after_signature)
                elif before_text.strip() != after_text.strip():
                    state = "REVIEW"
                    detail = _output_diff(before_text, after_text)
            rows.append({"id": f"{node_id}:{command}", "node_id": node_id,
                         "role": entry["leaf"].get("role", "leaf"),
                         "name": entry["leaf"]["name"], "command": command,
                         "command_label": command_label(command),
                         "state": state, "detail": detail, "pre": pre.get("output", ""),
                         "post": post.get("output", "")})
    return rows


ATTENTION_STATES = ("REVIEW", "ERROR", "NO_BASELINE")


def result_context(row: dict) -> str:
    if row["state"] == "REVIEW":
        if row["command"] == COMMAND:
            changes = row.get("detail", "").splitlines()
            return f"{len(changes)} port change(s): " + "; ".join(changes[:3])[:220]
        return "Output changed from PRE; review expected operational changes"
    if row["state"] in ("ERROR", "NO_BASELINE"):
        detail = (row.get("detail") or "No usable command output").splitlines()[0]
        return detail[:240]
    return "Physical port statuses match PRE" if row["command"] == COMMAND and row["state"] == "MATCH" else {
        "MATCH": "Output matches PRE", "CAPTURED": "PRE output captured; not a post-change verification",
    }.get(row["state"], "")


def summarize_results(rows: list[dict]) -> dict:
    grouped = {}
    for row in rows:
        leaf = grouped.setdefault(row["node_id"], {"node_id": row["node_id"], "name": row["name"],
                                  "role": row.get("role", "leaf"),
                                  "review": 0, "errors": 0, "no_baseline": 0,
                                  "states": set(), "reasons": []})
        leaf["states"].add(row["state"])
        if row["state"] in ATTENTION_STATES:
            key = {"REVIEW": "review", "ERROR": "errors", "NO_BASELINE": "no_baseline"}[row["state"]]
            leaf[key] += 1
            leaf["reasons"].append(f"{row['command']}: {result_context(row)}")
    leaves = []
    for leaf in sorted(grouped.values(), key=lambda item: int(item["node_id"])):
        states = leaf.pop("states")
        leaf["state"] = next((state for state in ("ERROR", "NO_BASELINE", "REVIEW", "MATCH", "CAPTURED")
                              if state in states), "ERROR")
        reasons = leaf.pop("reasons")
        leaf["context"] = " | ".join(reasons[:3])[:500]
        if len(reasons) > 3:
            leaf["context"] += f" | +{len(reasons) - 3} more checks"
        leaves.append(leaf)
    return {"total": len(leaves), "attention": sum(leaf["state"] in ATTENTION_STATES for leaf in leaves),
            "matched": sum(leaf["state"] == "MATCH" for leaf in leaves),
            "captured": sum(leaf["state"] == "CAPTURED" for leaf in leaves), "leaves": leaves,
            "leaf_count": sum(leaf["role"] == "leaf" for leaf in leaves),
            "spine_count": sum(leaf["role"] == "spine" for leaf in leaves)}


def filter_results(rows: list[dict], result: str = "attention", node_id: str | None = None,
                   command: str | None = None, search: str = "", role: str | None = None) -> list[dict]:
    filtered = []
    for row in rows:
        if result == "attention" and row["state"] not in ATTENTION_STATES:
            continue
        if result not in ("all", "attention") and row["state"] != result:
            continue
        if node_id and row["node_id"] != node_id or command and row["command"] != command:
            continue
        if role and row.get("role", "leaf") != role:
            continue
        context = result_context(row)
        if search.strip().casefold() not in " ".join(str(row[key]) for key in ("node_id", "name", "command", "state")).casefold() + " " + context.casefold():
            continue
        filtered.append({key: row[key] for key in ("id", "node_id", "name", "command", "state")}
                | {"context": context, "role": row.get("role", "leaf"),
                   "command_label": command_label(row["command"])})
    return filtered


def save_snapshot(directory: Path, snapshot: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{snapshot['id']}.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(snapshot, stream, indent=2)
    path.chmod(0o600)
    return path


def _snapshot_time(snapshot: dict) -> datetime | None:
    try:
        captured_at = datetime.fromisoformat(snapshot["captured_at"])
    except (KeyError, TypeError, ValueError):
        return None
    return captured_at.replace(tzinfo=timezone.utc) if captured_at.tzinfo is None else captured_at


def _snapshot_directories(data_dir: Path, apic_id: str | None = None) -> list[Path]:
    directories = []
    shared_root = data_dir / "captures" / "aci"
    if shared_root.is_dir():
        directories.extend(path for path in shared_root.iterdir()
                           if path.is_dir() and (apic_id is None or path.name == apic_id))
    runs = data_dir / "runs"
    if runs.is_dir():
        for owner_dir in runs.iterdir():
            aci_dir = owner_dir / "aci"
            if not owner_dir.is_dir() or not aci_dir.is_dir():
                continue
            directories.extend(path for path in aci_dir.iterdir()
                               if path.is_dir() and (apic_id is None or path.name == apic_id))
    return directories


def load_snapshots(data_dir: Path, apic_id: str, apic_address: str) -> list[dict]:
    snapshots = {}
    for directory in _snapshot_directories(data_dir, apic_id):
        for path in directory.glob("*.json"):
            try:
                snapshot = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if (snapshot.get("apic_id") == apic_id and snapshot.get("apic") == apic_address
                    and snapshot.get("id")):
                snapshots.setdefault(snapshot["id"], snapshot)
    return sorted(snapshots.values(),
                  key=lambda snapshot: _snapshot_time(snapshot) or datetime.min.replace(tzinfo=timezone.utc),
                  reverse=True)


def delete_old_snapshots(data_dir: Path, older_than_days: int,
                         now: datetime | None = None) -> int:
    if older_than_days < 1:
        raise ValueError("Retention must be at least one day")
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=older_than_days)
    records = []
    for directory in _snapshot_directories(data_dir):
        for path in directory.glob("*.json"):
            try:
                snapshot = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            captured_at = _snapshot_time(snapshot)
            if captured_at is not None:
                records.append((path, snapshot, captured_at))
    protected_baselines = {
        snapshot.get("baseline_id") for _, snapshot, captured_at in records
        if snapshot.get("phase") == "post" and captured_at >= cutoff
    }
    deleted = 0
    for path, snapshot, captured_at in records:
        if (captured_at < cutoff and
                not (snapshot.get("phase") == "pre" and snapshot.get("id") in protected_baselines)):
            path.unlink()
            deleted += 1
    return deleted