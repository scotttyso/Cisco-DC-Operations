#!/usr/bin/env python3
"""
ACI Leaf Interface Status -- PRE change (whole fabric)
=======================================================
1. Prompts for the APIC IP and your credentials (used for APIC and leaf SSH).
2. Discovers every ACTIVE leaf on the fabric from APIC (node ID, name, OOB IP).
3. SSHes to each leaf's OOB mgmt IP and runs `show interface brief`.
4. Writes, next to this script:
       <leaf_name>_ifstatus_pre.csv     one per leaf, all physical eth ports
       ifstatus_pre_manifest.csv        leaf list used by the post script

Run once per fabric right before the change. The manifest is overwritten on
each run, so the post script always checks the fabric you captured last.

READ-ONLY BY DESIGN: APIC GET queries only; leaves receive `show` only.

Example:
    python aci_leaf_ifstatus_pre.py
    python aci_leaf_ifstatus_pre.py --apic 10.1.1.1 --username AS_netid
"""

from __future__ import annotations

import argparse
import csv
import getpass
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from aci_ifstatus_common import (
    COMMAND, MANIFEST_FIELDS, MANIFEST_PATH, SCRIPT_DIR, ApicClient,
    assert_read_only, capture_leaf_with_retries, discover_active_leaves, fqdn,
    pre_csv_path, print_banner, write_port_csv,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Capture interface status for all active leaves on an ACI fabric.")
    p.add_argument("--apic", help="APIC IP or hostname (prompted if omitted)")
    p.add_argument("--username", default=os.getenv("ACI_USERNAME"),
                   help="Username for APIC and leaves; defaults to $ACI_USERNAME, else prompts")
    p.add_argument("--verify-tls", action="store_true",
                   help="Verify the APIC TLS certificate (off by default; our APICs use self-signed certs)")
    p.add_argument("--workers", type=int, default=20, help="Leaves captured in parallel (default 20)")
    p.add_argument("--retries", type=int, default=2, help="Extra SSH attempts per leaf on failure (default 2)")
    p.add_argument("--retry-delay", type=int, default=15, help="Seconds between attempts (default 15)")
    p.add_argument("--connect-timeout", type=int, default=20)
    p.add_argument("--read-timeout", type=int, default=90)
    return p.parse_args()


def setup_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(SCRIPT_DIR / "aci_leaf_ifstatus_pre.log", encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
        force=True,
    )
    logging.getLogger("netmiko").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    return logging.getLogger("aci_leaf_ifstatus_pre")


def capture_one(leaf: dict, username: str, password: str, args, log: logging.Logger) -> dict:
    target = leaf["oob_ip"] or fqdn(leaf["name"])
    result = {"capture_status": "OK", "ports": 0, "error": ""}
    try:
        # Password already validated by the APIC login, so auth failures are retried too.
        rows = capture_leaf_with_retries(
            target, username, password, args.connect_timeout, args.read_timeout,
            args.retries, args.retry_delay, log.warning,
        )
    except (NetmikoAuthenticationException, NetmikoTimeoutException, OSError) as exc:
        result.update(capture_status="FAIL_CONNECT", error=f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001 -- one leaf failing must not kill the run
        result.update(capture_status="FAIL_CAPTURE", error=f"{type(exc).__name__}: {exc}")
    else:
        write_port_csv(pre_csv_path(leaf["name"]), leaf["node_id"], leaf["name"], rows)
        up = sum(1 for r in rows if r["status"] == "up")
        result["ports"] = len(rows)
        log.info("  node %-5s %-16s %s -> %d ports (%d up)",
                 leaf["node_id"], leaf["name"], target, len(rows), up)
        return result
    log.error("  node %-5s %-16s %s -> %s %s",
              leaf["node_id"], leaf["name"], target, result["capture_status"], result["error"])
    return result


def main() -> int:
    args = parse_args()
    print_banner()
    assert_read_only(COMMAND)

    apic = args.apic or input("APIC IP or hostname: ").strip()
    if not apic:
        print("ERROR: APIC is required", file=sys.stderr)
        return 2
    username = args.username or input("Username: ").strip()
    password = getpass.getpass(f"Password for {username}: ")
    if not username or not password:
        print("ERROR: username and password are required", file=sys.stderr)
        return 2

    log = setup_logging()
    client = ApicClient(apic, verify_tls=args.verify_tls)
    try:
        client.login(username, password)
        leaves = discover_active_leaves(client)
    except RuntimeError as exc:
        log.error("%s", exc)
        return 1
    finally:
        client.logout()

    if not leaves:
        log.error("APIC %s returned no active leaves.", client.apic)
        return 1
    missing_oob = [l["name"] for l in leaves if not l["oob_ip"]]
    log.info("=" * 70)
    log.info("APIC %s: %d active leaves (node %s .. %s)", client.apic, len(leaves),
             leaves[0]["node_id"], leaves[-1]["node_id"])
    if missing_oob:
        log.warning("No OOB IP in APIC for %s -- will try DNS name instead", ", ".join(missing_oob))
    log.info("Command: %s   Workers: %d   Retries: %d (%ds apart)",
             COMMAND, args.workers, args.retries, args.retry_delay)
    log.info("=" * 70)

    start = datetime.now()
    captured_at = start.strftime("%Y-%m-%d %H:%M:%S")
    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(capture_one, l, username, password, args, log): l for l in leaves}
        for fut in as_completed(futures):
            results[futures[fut]["node_id"]] = fut.result()

    with MANIFEST_PATH.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS)
        w.writeheader()
        for l in leaves:
            w.writerow({**l, **results[l["node_id"]], "apic": client.apic, "captured_at": captured_at})

    failed = [l for l in leaves if results[l["node_id"]]["capture_status"] != "OK"]
    log.info("=" * 70)
    log.info("Done in %.1fs: %d/%d leaves captured. Manifest: %s",
             (datetime.now() - start).total_seconds(), len(leaves) - len(failed), len(leaves),
             MANIFEST_PATH.name)
    for l in failed:
        log.warning("  NO BASELINE: node %s %s (%s)", l["node_id"], l["name"],
                    results[l["node_id"]]["capture_status"])
    log.info("=" * 70)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
