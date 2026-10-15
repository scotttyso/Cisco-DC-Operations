"""
Shared helpers for aci_leaf_ifstatus_pre.py and aci_leaf_ifstatus_post.py.

READ-ONLY BY DESIGN. APIC is only queried with GET class queries (plus the
aaaLogin/aaaLogout session calls). Leaves only receive `show` commands.
"""

from __future__ import annotations

import contextlib
import csv
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Callable

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException

SCRIPT_DIR = Path(__file__).resolve().parent

COMMAND = "show interface brief"
DIAGNOSTIC_COMMANDS = (
    COMMAND,
    "show environment",
    "show vpc",
    "show port-channel summary",
    "show mac address-table dynamic | egrep -v tun",
    "show endpoint summary",
    "show module",
    "show lldp neighbor",
    "show isis adjacency vrf all",
)
SHARED_DIAGNOSTIC_COMMANDS = (
    COMMAND, "show environment", "show module", "show lldp neighbor",
    "show isis adjacency vrf all",
)
LEAF_ONLY_COMMANDS = (
    "show vpc", "show port-channel summary", "show endpoint summary",
    "show mac address-table dynamic | egrep -v tun",
)
ROLE_COMMANDS = {"leaf": DIAGNOSTIC_COMMANDS, "spine": SHARED_DIAGNOSTIC_COMMANDS}

MANIFEST_PATH = SCRIPT_DIR / "ifstatus_pre_manifest.csv"
MANIFEST_FIELDS = [
    "node_id", "name", "oob_ip", "pod", "model", "serial",
    "capture_status", "ports", "error", "apic", "captured_at",
]
PORT_FIELDS = ["node_id", "host", "port", "status", "raw_status", "reason"]

if os.name == "nt":
    os.system("")  # enables ANSI colors in Windows consoles

RED, GREEN, YELLOW, RESET = "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[0m"


# ---------------------------------------------------------------------------
# Read-only guards
# ---------------------------------------------------------------------------
_READ_ONLY_CMD = re.compile(r"^\s*show\s+\S", re.IGNORECASE)
_CMD_CHAINERS = ("\n", "\r", ";", "&&", "||", "|", "`", "$(")


def assert_read_only(command: str) -> None:
    """Raise RuntimeError if `command` is not a pure `show` command."""
    if command == "show mac address-table dynamic | egrep -v tun":
        return
    if not _READ_ONLY_CMD.match(command):
        raise RuntimeError(f"REFUSED: non-read-only command blocked: {command!r}")
    for bad in _CMD_CHAINERS:
        if bad in command:
            raise RuntimeError(f"REFUSED: chaining char {bad!r} in: {command!r}")
    if not re.fullmatch(r"[A-Za-z0-9 _./:,\-\[\]()]+", command):
        raise RuntimeError(f"REFUSED: unsupported characters in show command: {command!r}")


def validate_role_commands(commands: dict | None = None) -> dict[str, tuple[str, ...]]:
    """Validate role lists before opening any device connections."""
    commands = ROLE_COMMANDS if commands is None else commands
    if set(commands) != set(ROLE_COMMANDS):
        raise ValueError("Command lists must contain leaf and spine roles")
    validated = {}
    for role, values in commands.items():
        if not isinstance(values, (list, tuple)) or not values:
            raise ValueError(f"At least one command is required for {role}")
        unique = []
        for command in values:
            if not isinstance(command, str):
                raise ValueError("Commands must be strings")
            assert_read_only(command)
            command = " ".join(command.split())
            leaf_prefixes = [leaf_only.split(" | ")[0] for leaf_only in LEAF_ONLY_COMMANDS]
            if role == "spine" and any(command.lower() == prefix or command.lower().startswith(prefix + " ")
                                       for prefix in leaf_prefixes):
                raise ValueError(f"{command} is leaf-only")
            if command not in unique:
                unique.append(command)
        validated[role] = tuple(unique)
    return validated


# ---------------------------------------------------------------------------
# APIC REST (stdlib only)
# ---------------------------------------------------------------------------
class ApicClient:
    """Minimal read-only APIC REST client."""

    def __init__(self, apic: str, verify_tls: bool = False, timeout: int = 30):
        apic = re.sub(r"^https?://", "", apic.strip()).rstrip("/")
        self.apic = apic
        self.base = f"https://{apic}"
        self.timeout = timeout
        self._username = ""
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(CookieJar()),
        )

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(detail)["imdata"][0]["error"]["attributes"]["text"]
            except (ValueError, KeyError, IndexError, TypeError):
                pass
            raise RuntimeError(f"APIC HTTP {exc.code} on {path.split('?')[0]}: {detail}") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                raise RuntimeError(
                    f"APIC TLS certificate not trusted ({exc.reason.verify_message}). "
                    "Re-run without --verify-tls."
                ) from None
            raise RuntimeError(f"Cannot reach APIC {self.apic}: {exc.reason}") from None

    def login(self, username: str, password: str) -> None:
        self._username = username
        self._request("POST", "/api/aaaLogin.json",
                      {"aaaUser": {"attributes": {"name": username, "pwd": password}}})

    def logout(self) -> None:
        try:
            self._request("POST", "/api/aaaLogout.json",
                          {"aaaUser": {"attributes": {"name": self._username}}})
        except RuntimeError:
            pass

    def get_class(self, cls: str, query_filter: str | None = None) -> list[dict]:
        if not re.fullmatch(r"[A-Za-z]+", cls):
            raise RuntimeError(f"REFUSED: invalid APIC class name {cls!r}")
        path = f"/api/node/class/{cls}.json"
        if query_filter:
            path += "?" + urllib.parse.urlencode({"query-target-filter": query_filter})
        data = self._request("GET", path)
        return [next(iter(obj.values()))["attributes"] for obj in data.get("imdata", [])]


def discover_active_nodes(client: ApicClient, roles: tuple[str, ...] = ("leaf", "spine")) -> list[dict]:
    """Return active fabric switches with role and OOB management address."""
    if not roles or any(role not in ROLE_COMMANDS for role in roles):
        raise ValueError("Supported fabric roles are leaf and spine")
    fabric_roles = ",".join(f'eq(fabricNode.role,"{role}")' for role in roles)
    system_roles = ",".join(f'eq(topSystem.role,"{role}")' for role in roles)
    fabric_filter = f"or({fabric_roles})" if len(roles) > 1 else fabric_roles
    system_filter = f"or({system_roles})" if len(roles) > 1 else system_roles
    nodes = client.get_class(
        "fabricNode", f'and({fabric_filter},eq(fabricNode.fabricSt,"active"))'
    )
    systems = {s.get("id"): s for s in client.get_class("topSystem", system_filter)}
    leaves = []
    for n in nodes:
        role = n.get("role", "leaf" if roles == ("leaf",) else "")
        if role not in roles:
            continue
        oob = (systems.get(n.get("id"), {}).get("oobMgmtAddr") or "").strip()
        pod = re.search(r"/pod-(\d+)/", n.get("dn", ""))
        leaves.append({
            "node_id": n.get("id", ""),
            "name": n.get("name", ""),
            "oob_ip": "" if oob in ("", "0.0.0.0") else oob,
            "pod": pod.group(1) if pod else "",
            "model": n.get("model", ""),
            "serial": n.get("serial", ""),
            "role": role,
        })
    leaves.sort(key=lambda x: int(x["node_id"]) if x["node_id"].isdigit() else 0)
    return leaves


def discover_active_leaves(client: ApicClient) -> list[dict]:
    """Keep the original CLI manifest leaf-only and CSV-compatible."""
    return [{key: value for key, value in node.items() if key != "role"}
            for node in discover_active_nodes(client, roles=("leaf",))]


# ---------------------------------------------------------------------------
# Leaf SSH capture + parse
# ---------------------------------------------------------------------------
_PORT_LINE = re.compile(r"^\s*eth(?:ernet)?(\d+/\d+(?:/\d+)?)\s+(.*)$", re.IGNORECASE)


def parse_interface_brief(text: str) -> list[dict]:
    """
    Parse physical Ethernet rows of `show interface brief`, e.g.:

        eth1/1        0       eth  trunk  up      none                   10G(D) --
        eth1/2        0       eth  trunk  down    sfp-missing            10G(D) --
    """
    rows: list[dict] = []
    seen: set[str] = set()
    for line in text.splitlines():
        m = _PORT_LINE.match(line)
        if not m:
            continue
        port = f"eth{m.group(1)}"
        tokens = m.group(2).split()
        idx = next((i for i, t in enumerate(tokens) if t.lower() in ("up", "down")), None)
        if idx is None:
            if len(tokens) < 4:
                continue
            idx = 3  # VLAN, Type, Mode, Status
        if port in seen:
            continue
        seen.add(port)
        raw = tokens[idx]
        tail = tokens[idx + 1:]
        reason = " ".join(tail[:-2]) if len(tail) > 2 else " ".join(tail)
        rows.append({
            "port": port,
            "status": "up" if raw.lower() == "up" else "down",
            "raw_status": raw,
            "reason": reason,
        })
    return rows


def aci_login_username(username: str, domain: str = "local") -> str:
    if not domain or domain.casefold() == "local" or username.startswith("apic:"):
        return username
    return f"apic:{domain}\\{username}"


def fqdn(host: str, dns_domain: str = "") -> str:
    h = (host or "").strip()
    suffix = dns_domain.strip(". ")
    return h if not h or "." in h or ":" in h or not suffix else h + "." + suffix


def capture_leaf_commands(target: str, username: str, password: str,
                          connect_timeout: int = 20, read_timeout: int = 90,
                          commands: tuple[str, ...] = DIAGNOSTIC_COMMANDS,
                          jump: dict | None = None) -> dict[str, dict]:
    """Capture guarded show commands through one SSH session, retaining failures."""
    for command in commands:
        assert_read_only(command)
    results = {}
    if jump:
        from aci_jump import NexusDashboardSSH
        conn = NexusDashboardSSH(target, username, password, jump, connect_timeout)
    else:
        conn = ConnectHandler(
            device_type="cisco_nxos", host=target, username=username, password=password,
            conn_timeout=connect_timeout, auth_timeout=connect_timeout,
            banner_timeout=connect_timeout, fast_cli=False,
        )
    try:
        for command in commands:
            try:
                output = conn.send_command(command, read_timeout=read_timeout, cmd_verify=False)
                error = bool(re.search(
                    r"(?im)^\s*(?:%.*(?:invalid|error|incomplete|ambiguous)|"
                    r"(?:error:|invalid command|syntax error))", output,
                ))
                if command == COMMAND and not parse_interface_brief(output):
                    error = True
                results[command] = {"status": "ERROR" if error or not output.strip() else "OK",
                                    "output": output}
            except Exception as exc:
                results[command] = {"status": "ERROR", "output": f"{type(exc).__name__}: {exc}"}
    finally:
        with contextlib.suppress(Exception):
            conn.disconnect()
    return results


def capture_leaf(target: str, username: str, password: str,
                 connect_timeout: int, read_timeout: int) -> list[dict]:
    """SSH to a leaf, run COMMAND, return parsed port rows. Raises on failure."""
    assert_read_only(COMMAND)
    device = {
        "device_type": "cisco_nxos",
        "host": target,
        "username": username,
        "password": password,
        "conn_timeout": connect_timeout,
        "auth_timeout": connect_timeout,
        "banner_timeout": connect_timeout,
        "fast_cli": False,
    }
    conn = ConnectHandler(**device)
    try:
        output = conn.send_command(COMMAND, read_timeout=read_timeout, cmd_verify=False)
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001
            pass
    rows = parse_interface_brief(output)
    if not rows:
        raise ValueError(f"no Ethernet ports parsed from `{COMMAND}` output")
    return rows


def capture_leaf_with_retries(
    target: str, username: str, password: str, connect_timeout: int, read_timeout: int,
    retries: int, delay: int, notify: Callable[[str], None],
    retry_auth: Callable[[], bool] = lambda: True,
    gate: Callable[[], contextlib.AbstractContextManager] = contextlib.nullcontext,
) -> list[dict]:
    """capture_leaf() with up to `retries` extra attempts. Re-raises the last error."""
    for attempt in range(retries + 1):
        try:
            with gate():
                return capture_leaf(target, username, password, connect_timeout, read_timeout)
        except Exception as exc:  # noqa: BLE001
            if attempt >= retries:
                raise
            if isinstance(exc, NetmikoAuthenticationException) and not retry_auth():
                raise
            notify(f"  {target}: attempt {attempt + 1} failed ({type(exc).__name__}), "
                   f"retrying in {delay}s")
            time.sleep(delay)
    raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
def pre_csv_path(leaf_name: str) -> Path:
    return SCRIPT_DIR / f"{leaf_name}_ifstatus_pre.csv"


def write_port_csv(path: Path, node_id: str, host: str, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=PORT_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({"node_id": node_id, "host": host, **r})


def read_port_csv(path: Path) -> dict[str, dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return {r["port"]: r for r in csv.DictReader(fh) if r.get("port")}


def port_sort_key(port: str) -> list:
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", port) if x]


def print_banner() -> None:
    print("""********************************************************************
Use of this system is restricted to authorized users. User activity
is monitored and recorded by system personnel. Anyone using this
system expressly consents to such monitoring and recording. BE
ADVISED: if possible criminal activity is detected, system records,
along with certain personal information, may be provided to law
enforcement officials.
********************************************************************""")
    print("\nUse at your own risk!\n")
