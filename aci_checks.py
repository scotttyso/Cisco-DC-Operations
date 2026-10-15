"""Fabric-scoped diagnostic snapshots and pre/post comparison for the WebUI."""

from __future__ import annotations

import difflib
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from netmiko.exceptions import NetmikoAuthenticationException

from aci_ifstatus_common import (
    COMMAND, ROLE_COMMANDS, ApicClient, aci_login_username, capture_leaf_commands,
    discover_active_nodes, fqdn, parse_interface_brief, validate_role_commands,
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
                     jump: dict | None = None) -> dict:
    if role not in ("all", "leaf", "spine"):
        raise ValueError("Select all switches, leaf, or spine")
    command_lists = validate_role_commands(baseline.get("role_commands") if baseline else role_commands)
    username = aci_login_username(username, apic.get("domain", "local"))
    if baseline:
        if baseline["apic_id"] != apic["id"] or baseline["apic"] != apic["address"]:
            raise ValueError("Baseline belongs to a different APIC profile/address")
        leaves = [entry["leaf"] for entry in baseline["nodes"]]
    else:
        client = ApicClient(apic["address"], verify_tls=bool(apic["verify_tls"]))
        try:
            client.login(username, password)
            leaves = discover_active_nodes(client)
        finally:
            client.logout()
    leaves = select_leaves([node for node in leaves if role == "all" or node.get("role", "leaf") == role], group, node_ids)
    auth_lock = threading.Lock()
    auth_ok = threading.Event()
    auth_bad = threading.Event()
    if not baseline and not jump:
        auth_ok.set()

    def collect(leaf):
        target = leaf["oob_ip"] or fqdn(leaf["name"], dns_domain)
        entry = {"leaf": leaf, "target": target, "commands": {}, "error": ""}

        def capture():
            if not target:
                raise ValueError("Switch has no OOB address or name")
            options = {"commands": command_lists[leaf.get("role", "leaf")]}
            if jump:
                options["jump"] = jump
            return capture_leaf_commands(target, username, password, connect_timeout, read_timeout, **options)

        try:
            with auth_lock:
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
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        notify(f"{leaf.get('role', 'leaf').upper()} {leaf['node_id']} {leaf['name']}: "
               + ("ERROR" if entry["error"] or any(result["status"] != "OK"
                  for result in entry["commands"].values()) else "captured"))
        return entry

    entries = []
    with ThreadPoolExecutor(max_workers=max(1, min(32, workers))) as executor:
        futures = [executor.submit(collect, leaf) for leaf in leaves]
        for future in as_completed(futures):
            entries.append(future.result())
    entries.sort(key=lambda entry: int(entry["leaf"]["node_id"]))
    return {"version": 2, "id": uuid4().hex, "apic_id": apic["id"], "apic": apic["address"],
            "phase": "post" if baseline else "pre", "baseline_id": baseline["id"] if baseline else None,
            "captured_at": datetime.now(timezone.utc).isoformat(), "group": group, "role": role,
            "role_commands": command_lists, "dns_domain": dns_domain,
            "ssh_connection": "nexus_dashboard" if jump else "direct", "nodes": entries}


def node_commands(snapshot: dict, entry: dict) -> tuple[str, ...]:
    role = entry["leaf"].get("role", "leaf")
    return tuple(snapshot.get("role_commands", ROLE_COMMANDS)[role])


def snapshot_results(snapshot: dict, baseline: dict | None = None) -> list[dict]:
    """Map capture output to its actual phase, including previously saved snapshots."""
    if snapshot["phase"] == "post":
        return compare_snapshots(baseline or {"apic_id": snapshot["apic_id"],
                                 "apic": snapshot["apic"], "nodes": []}, snapshot)
    return [{"id": f"{entry['leaf']['node_id']}:{command}",
             "node_id": entry["leaf"]["node_id"], "name": entry["leaf"]["name"],
             "role": entry["leaf"].get("role", "leaf"),
             "command": command, "state": "CAPTURED" if result.get("status") == "OK" and not entry["error"] else "ERROR",
             "pre": result.get("output", ""), "post": "",
             "detail": entry["error"] or (result.get("output", "") if result.get("status") != "OK" else "")}
            for entry in snapshot["nodes"] for command in node_commands(snapshot, entry)
            for result in [entry["commands"].get(command, {})]]


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
                state, detail = "ERROR", entry["error"] or post.get("output", "No post output")
            elif previous.get("error") or pre.get("status") != "OK":
                state, detail = "NO_BASELINE", previous.get("error") or pre.get("output", "No pre output")
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
                pre_lines = [line.rstrip() for line in pre["output"].strip().splitlines()]
                post_lines = [line.rstrip() for line in post["output"].strip().splitlines()]
                if pre_lines != post_lines:
                    state = "REVIEW"
                    detail = "\n".join(difflib.unified_diff(pre_lines, post_lines, fromfile="pre", tofile="post", lineterm=""))
            rows.append({"id": f"{node_id}:{command}", "node_id": node_id,
                         "role": entry["leaf"].get("role", "leaf"),
                         "name": entry["leaf"]["name"], "command": command,
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
                | {"context": context, "role": row.get("role", "leaf")})
    return filtered


def save_snapshot(directory: Path, snapshot: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{snapshot['id']}.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(snapshot, stream, indent=2)
    path.chmod(0o600)
    return path