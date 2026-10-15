#!/usr/bin/env python3
"""
ACI Leaf Interface Status -- POST change (odd or even node IDs)
================================================================
1. Reads ifstatus_pre_manifest.csv written by aci_leaf_ifstatus_pre.py.
2. Asks: run all ODD node IDs, all EVEN node IDs, or specific node ID(s).
3. SSHes to each leaf in that group (OOB IP from the manifest), runs
   `show interface brief`, and compares to <leaf_name>_ifstatus_pre.csv.
4. Prints ONLY exceptions to the terminal (no files written):
     - leaves that are unreachable (still rebooting / offline)
     - ports up -> down   (red)
     - ports down -> up   (yellow)
     - ports missing in pre or post
   Leaves whose ports all match are listed on a single summary line.

READ-ONLY BY DESIGN: leaves receive `show` only. APIC is not contacted.

Example:
    python aci_leaf_ifstatus_post.py
    python aci_leaf_ifstatus_post.py --group odd --username AS_netid
"""

from __future__ import annotations

import argparse
import csv
import getpass
import logging
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime

from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from aci_ifstatus_common import (
    COMMAND, GREEN, MANIFEST_PATH, RED, RESET, YELLOW, assert_read_only,
    capture_leaf_with_retries, fqdn, port_sort_key, pre_csv_path, print_banner, read_port_csv,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compare post-change interface status for odd or even ACI leaves.")
    p.add_argument("--group", choices=("odd", "even"), help="Node ID group to check (prompted if omitted)")
    p.add_argument("--username", default=os.getenv("ACI_USERNAME"),
                   help="Leaf SSH username; defaults to $ACI_USERNAME, else prompts")
    p.add_argument("--workers", type=int, default=20, help="Leaves checked in parallel (default 20)")
    p.add_argument("--retries", type=int, default=2, help="Extra SSH attempts per leaf on failure (default 2)")
    p.add_argument("--retry-delay", type=int, default=15, help="Seconds between attempts (default 15)")
    p.add_argument("--connect-timeout", type=int, default=20)
    p.add_argument("--read-timeout", type=int, default=90)
    return p.parse_args()


def load_manifest() -> list[dict]:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(
            f"{MANIFEST_PATH.name} not found next to this script -- run aci_leaf_ifstatus_pre.py first."
        )
    with MANIFEST_PATH.open(newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if (r.get("node_id") or "").isdigit()]
    if not rows:
        raise ValueError(f"{MANIFEST_PATH.name} has no leaves")
    return rows


def choose_group(preset: str | None) -> str:
    if preset:
        return preset
    while True:
        choice = input("Check which leaves?  1) ODD node IDs   2) EVEN node IDs   "
                       "3) Specific node ID(s)  : ").strip().lower()
        if choice in ("1", "odd", "o"):
            return "odd"
        if choice in ("2", "even", "e"):
            return "even"
        if choice in ("3", "node", "nodes", "n"):
            return "nodes"
        print("  Enter 1, 2 or 3.")


def choose_nodes(manifest: list[dict]) -> list[dict]:
    by_id = {l["node_id"]: l for l in manifest}
    while True:
        raw = input("Node ID(s), comma or space separated (e.g. 101 or 101,103): ")
        ids = [t for t in raw.replace(",", " ").split() if t]
        unknown = [t for t in ids if t not in by_id]
        if ids and not unknown:
            return [by_id[t] for t in dict.fromkeys(ids)]
        if unknown:
            print(f"  Not in manifest: {', '.join(unknown)}")
        else:
            print("  Enter at least one node ID.")


def compare(pre: dict[str, dict], post: dict[str, dict]) -> list[tuple[str, str, str, str]]:
    """Return [(port, pre_status, post_status, post_reason)] for every port that changed."""
    diffs = []
    for port in sorted(set(pre) | set(post), key=port_sort_key):
        a = pre[port]["status"] if port in pre else "(missing)"
        b = post[port]["status"] if port in post else "(missing)"
        if a != b:
            diffs.append((port, a, b, post.get(port, {}).get("reason", "")))
    return diffs


# Lockout guard: set once any leaf accepts the password / once the unproven password is rejected.
_creds_ok = threading.Event()
_creds_bad = threading.Event()
_auth_lock = threading.Lock()


@contextmanager
def _auth_gate():
    """Until a leaf accepts the password, log in one leaf at a time and stop after the first rejection."""
    with _auth_lock:
        if _creds_bad.is_set():
            raise NetmikoAuthenticationException("not attempted: password rejected by another leaf")
        if not _creds_ok.is_set():
            try:
                yield
            except NetmikoAuthenticationException:
                _creds_bad.set()
                raise
            _creds_ok.set()
            return
    yield


def check_leaf(leaf: dict, username: str, password: str, args) -> dict:
    res = {"leaf": leaf, "state": "", "detail": "", "diffs": []}
    pre_path = pre_csv_path(leaf["name"])
    pre_status = leaf.get("capture_status") or "unknown"
    if pre_status != "OK" or not pre_path.exists():
        res.update(state="NO_BASELINE", detail=f"pre capture status: {pre_status}"
                   + ("" if pre_path.exists() else f", {pre_path.name} not found"))
        return res
    target = leaf.get("oob_ip") or fqdn(leaf["name"])
    try:
        rows = capture_leaf_with_retries(
            target, username, password, args.connect_timeout, args.read_timeout,
            args.retries, args.retry_delay, print, retry_auth=_creds_ok.is_set, gate=_auth_gate,
        )
        _creds_ok.set()
    except NetmikoAuthenticationException as exc:
        res.update(state="AUTH_FAIL", detail=str(exc).splitlines()[0])
        return res
    except (NetmikoTimeoutException, OSError) as exc:
        res.update(state="UNREACHABLE", detail=f"{target}: {type(exc).__name__}")
        return res
    except Exception as exc:  # noqa: BLE001 -- one leaf failing must not kill the run
        res.update(state="CAPTURE_FAIL", detail=f"{type(exc).__name__}: {exc}")
        return res
    res["diffs"] = compare(read_port_csv(pre_path), {r["port"]: r for r in rows})
    res["state"] = "CHANGED" if res["diffs"] else "MATCH"
    return res


def print_report(group: str, results: list[dict], elapsed: float) -> None:
    results.sort(key=lambda r: int(r["leaf"]["node_id"]))
    failed = [r for r in results if r["state"] not in ("MATCH", "CHANGED")]
    changed = [r for r in results if r["state"] == "CHANGED"]
    matched = [r for r in results if r["state"] == "MATCH"]

    print()
    print("=" * 78)
    print(f" {group.upper()} leaves: {len(results)} checked in {elapsed:.0f}s   "
          f"{GREEN}{len(matched)} match{RESET}   "
          f"{RED if changed else GREEN}{len(changed)} with port changes{RESET}   "
          f"{RED if failed else GREEN}{len(failed)} not checked{RESET}")
    print("=" * 78)

    if failed:
        print(f"\n{RED}Leaves NOT verified (offline / unreachable / no baseline):{RESET}")
        for r in failed:
            l = r["leaf"]
            print(f"  {RED}node {l['node_id']:<5} {l['name']:<18} {r['state']:<13}{RESET} {r['detail']}")

    for r in changed:
        l = r["leaf"]
        downs = sum(1 for d in r["diffs"] if d[1] == "up")
        print(f"\nnode {l['node_id']}  {l['name']}  -- {len(r['diffs'])} port change(s), {downs} went down")
        print(f"  {'Port':<12}{'Pre':<12}{'Post':<12}Post reason")
        print(f"  {'-' * 10:<12}{'-' * 10:<12}{'-' * 10:<12}{'-' * 20}")
        for port, a, b, reason in r["diffs"]:
            color = RED if a == "up" else YELLOW
            print(f"  {port:<12}{a:<12}{color}{b:<12}{RESET}{reason}")

    if matched:
        names = ", ".join(f"{r['leaf']['node_id']}" for r in matched)
        print(f"\n{GREEN}All ports match pre on node(s): {names}{RESET}")

    print()
    if not failed and not changed:
        print(f"{GREEN}ALL {group.upper()} LEAVES ONLINE AND PORT STATUS MATCHES PRE.{RESET}")
    else:
        print(f"{RED}ACTION REQUIRED: review the leaves/ports listed above.{RESET}")
    print()


def main() -> int:
    args = parse_args()
    print_banner()
    assert_read_only(COMMAND)

    try:
        manifest = load_manifest()
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    first = manifest[0]
    print(f"Baseline: APIC {first.get('apic', '?')}, captured {first.get('captured_at', '?')}, "
          f"{len(manifest)} leaves")
    group = choose_group(args.group)
    if group == "nodes":
        leaves = choose_nodes(manifest)
        group = "node " + ",".join(l["node_id"] for l in leaves)
        print(", ".join(f"{l['node_id']} {l['name']}" for l in leaves))
    else:
        want = 1 if group == "odd" else 0
        leaves = [l for l in manifest if int(l["node_id"]) % 2 == want]
        if not leaves:
            print(f"No {group} node IDs in the manifest.")
            return 0
        print(f"{len(leaves)} {group} leaves: node {leaves[0]['node_id']} .. {leaves[-1]['node_id']}")

    username = args.username or input("Username: ").strip()
    password = getpass.getpass(f"Password for {username}: ")
    if not username or not password:
        print("ERROR: username and password are required", file=sys.stderr)
        return 2

    logging.getLogger("netmiko").setLevel(logging.CRITICAL)
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    start = datetime.now()
    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = [ex.submit(check_leaf, l, username, password, args) for l in leaves]
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            results.append(r)
            print(f"  [{i}/{len(leaves)}] node {r['leaf']['node_id']:<5} {r['leaf']['name']:<18} {r['state']}")

    print_report(group, results, (datetime.now() - start).total_seconds())
    return 0 if all(r["state"] == "MATCH" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
