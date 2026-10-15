"""Local WebUI accounts, APIC inventory, and encrypted automation credentials."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography.fernet import Fernet


def password_hash(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Use a WebUI password of at least 12 characters")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000)
    return f"{salt}${digest.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    salt, expected = encoded.split("$")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000)
    return hmac.compare_digest(digest.hex(), expected)


def normalize_apic(address: str) -> str:
    address = address.strip()
    parsed = urlsplit(address if "://" in address else "https://" + address)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or any(character.isspace() for character in address)):
        raise ValueError("Enter an APIC hostname or IP, optionally with https:// and a port")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Invalid APIC port") from exc
    return parsed.netloc.lower()


def normalize_dns_domain(value: str) -> str:
    value = value.strip().strip(".").lower()
    if value and (len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                        for label in value.split("."))):
        raise ValueError("DNS Domain must be a domain name, without a URL, port, or spaces")
    return value


def profile_credential_values(existing: dict, username: str, password: str,
                              rescue_password: str = "", target_changed: bool = False,
                              domain: str | None = None) -> dict:
    username = username.strip()
    values = {} if target_changed else existing.copy()
    if password:
        if not username:
            raise ValueError("Username is required with a password")
        values.update(username=username, password=password)
    elif username != existing.get("username", ""):
        if username:
            raise ValueError("Enter a password for the changed username")
        values.pop("username", None)
        values.pop("password", None)
    if rescue_password:
        values["rescue_password"] = rescue_password
    if domain is not None:
        domain = domain.strip() or "local"
        if any(ord(character) < 32 or character in "\\:" for character in domain):
            raise ValueError("A valid Login domain is required")
        values["domain"] = domain
    return values


class ProfileStore:
    def __init__(self, directory: Path, key_file: Path):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        key = os.getenv("DC_AUTOMATION_KEY")
        if not key:
            key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                descriptor = os.open(key_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                if key_file.stat().st_mode & 0o077:
                    raise ValueError("Vault key file must have permissions 0600")
            else:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(Fernet.generate_key())
            key = key_file.read_text(encoding="ascii").strip()
        self.cipher = Fernet(key.encode())
        self.storage_secret = hmac.new(key.encode(), b"nicegui-session", "sha256").hexdigest()
        self.path = directory / "profiles.sqlite3"
        descriptor = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(descriptor)
        self.path.chmod(0o600)
        with self.connection() as database:
            database.executescript("""
                CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS apics (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, address TEXT NOT NULL,
                    verify_tls INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS credentials (
                    owner TEXT NOT NULL, scope TEXT NOT NULL, encrypted BLOB NOT NULL,
                    PRIMARY KEY (owner, scope));
                CREATE TABLE IF NOT EXISTS aci_command_lists (
                    apic_id TEXT PRIMARY KEY, commands TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS nexus_dashboards (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, address TEXT NOT NULL,
                    domain TEXT NOT NULL, verify_tls INTEGER NOT NULL);
            """)
            columns = {row["name"] for row in database.execute("PRAGMA table_info(users)")}
            for name, declaration in (("role", "TEXT NOT NULL DEFAULT 'operator'"),
                                      ("auth_version", "INTEGER NOT NULL DEFAULT 0"),
                                      ("theme", "TEXT NOT NULL DEFAULT 'light'")):
                if name not in columns:
                    database.execute(f"ALTER TABLE users ADD COLUMN {name} {declaration}")
            if "role" not in columns:
                database.execute("UPDATE users SET role = 'admin' WHERE rowid = (SELECT MIN(rowid) FROM users)")
            apic_columns = {row["name"] for row in database.execute("PRAGMA table_info(apics)")}
            if "domain" not in apic_columns:
                database.execute("ALTER TABLE apics ADD COLUMN domain TEXT NOT NULL DEFAULT 'local'")
            if not database.execute("SELECT 1 FROM settings WHERE key = 'dns_domain'").fetchone():
                apic_columns = {row["name"] for row in database.execute("PRAGMA table_info(apics)")}
                domains = sorted({normalize_dns_domain(row["dns_suffix"])
                                  for row in database.execute("SELECT dns_suffix FROM apics WHERE dns_suffix != ''")}) if "dns_suffix" in apic_columns else []
                database.execute("INSERT INTO settings VALUES ('dns_domain', ?)", (domains[0] if len(domains) == 1 else "",))
                if len(domains) > 1:
                    database.execute("INSERT INTO settings VALUES ('dns_domain_conflicts', ?)", (json.dumps(domains),))

    @contextmanager
    def connection(self):
        database = sqlite3.connect(self.path, timeout=10)
        database.row_factory = sqlite3.Row
        try:
            with database:
                yield database
        finally:
            database.close()

    def add_user(self, username: str, password: str) -> None:
        if not username.strip():
            raise ValueError("WebUI username is required")
        encoded = password_hash(password)
        with self.connection() as database:
            database.execute("""INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')
                ON CONFLICT(username) DO UPDATE SET password=excluded.password,
                auth_version=users.auth_version+1""", (username.strip(), encoded))

    def user(self, username: str) -> dict:
        with self.connection() as database:
            row = database.execute("SELECT username, role, auth_version, theme FROM users WHERE username = ?",
                                   (username,)).fetchone()
        return dict(row) if row else {}

    def users(self, actor: str) -> list[dict]:
        with self.connection() as database:
            self.require_admin(database, actor)
            return [dict(row) for row in database.execute("SELECT username, role FROM users ORDER BY username")]

    @staticmethod
    def require_admin(database, actor: str) -> None:
        row = database.execute("SELECT role FROM users WHERE username = ?", (actor,)).fetchone()
        if not row or row["role"] != "admin":
            raise ValueError("Administrator access is required to manage users")

    def create_user(self, actor: str, username: str, password: str, role: str = "operator") -> None:
        with self.connection() as database:
            self.require_admin(database, actor)
            if not username.strip() or role not in ("operator", "admin"):
                raise ValueError("A username and valid account role are required")
            encoded = password_hash(password)
            try:
                database.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                                 (username.strip(), encoded, role))
            except sqlite3.IntegrityError:
                raise ValueError("That username already exists") from None

    def change_password(self, username: str, current: str, new: str, confirmation: str) -> int:
        if new != confirmation:
            raise ValueError("New passwords do not match")
        with self.connection() as database:
            row = database.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
            if not row or not password_matches(current, row["password"]):
                raise ValueError("Current password is incorrect")
            if password_matches(new, row["password"]):
                raise ValueError("Choose a different password")
            encoded = password_hash(new)
            updated = database.execute("""UPDATE users SET password = ?, auth_version = auth_version + 1
                WHERE username = ? AND password = ?""", (encoded, username, row["password"]))
            if not updated.rowcount:
                raise ValueError("Password changed in another session; sign in again")
            return database.execute("SELECT auth_version FROM users WHERE username = ?", (username,)).fetchone()["auth_version"]

    def set_theme(self, username: str, theme: str) -> None:
        if theme not in ("light", "dark"):
            raise ValueError("Unknown theme")
        with self.connection() as database:
            database.execute("UPDATE users SET theme = ? WHERE username = ?", (theme, username))

    def authenticate(self, username: str, password: str) -> bool:
        return bool(self.login_account(username, password))

    def login_account(self, username: str, password: str) -> dict:
        with self.connection() as database:
            row = database.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        fallback = "00" * 16 + "$" + "00" * 32
        matches = password_matches(password, row["password"] if row else fallback)
        return {key: row[key] for key in ("username", "role", "auth_version", "theme")} if row and matches else {}

    def has_users(self) -> bool:
        with self.connection() as database:
            return bool(database.execute("SELECT 1 FROM users LIMIT 1").fetchone())

    def apics(self) -> list[dict]:
        with self.connection() as database:
            return [dict(row) for row in database.execute("SELECT id, name, address, verify_tls, domain FROM apics ORDER BY name")]

    def dns_domain(self) -> str:
        with self.connection() as database:
            return database.execute("SELECT value FROM settings WHERE key = 'dns_domain'").fetchone()["value"]

    def dns_domain_conflicts(self) -> list[str]:
        with self.connection() as database:
            row = database.execute("SELECT value FROM settings WHERE key = 'dns_domain_conflicts'").fetchone()
        return json.loads(row["value"]) if row else []

    def set_dns_domain(self, value: str) -> None:
        domain = normalize_dns_domain(value)
        with self.connection() as database:
            database.execute("INSERT OR REPLACE INTO settings VALUES ('dns_domain', ?)", (domain,))
            database.execute("DELETE FROM settings WHERE key = 'dns_domain_conflicts'")

    def save_apic(self, name: str, address: str, verify_tls: bool = True,
                  profile_id: str | None = None, domain: str | None = None) -> str:
        if not name.strip():
            raise ValueError("APIC display name is required")
        address = normalize_apic(address)
        profile_id = profile_id or uuid4().hex
        with self.connection() as database:
            previous = database.execute("SELECT address, domain, verify_tls FROM apics WHERE id = ?", (profile_id,)).fetchone()
            domain = domain.strip() if domain is not None else previous["domain"] if previous else "local"
            if not domain or any(ord(character) < 32 or character in "\\:" for character in domain):
                raise ValueError("A valid APIC Login domain is required")
            if previous and (previous["address"], previous["domain"], previous["verify_tls"]) != (address, domain, int(verify_tls)):
                database.execute("DELETE FROM credentials WHERE scope = ?", ("aci:" + profile_id,))
            database.execute("""INSERT INTO apics (id, name, address, verify_tls, domain) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,
                address=excluded.address, verify_tls=excluded.verify_tls, domain=excluded.domain""",
                (profile_id, name.strip(), address, int(verify_tls), domain))
        return profile_id

    def delete_apic(self, profile_id: str) -> None:
        with self.connection() as database:
            database.execute("DELETE FROM apics WHERE id = ?", (profile_id,))
            database.execute("DELETE FROM credentials WHERE scope = ?", ("aci:" + profile_id,))
            database.execute("DELETE FROM aci_command_lists WHERE apic_id = ?", (profile_id,))

    def dashboards(self) -> list[dict]:
        with self.connection() as database:
            return [dict(row) for row in database.execute("SELECT * FROM nexus_dashboards ORDER BY name")]

    def save_dashboard(self, name: str, address: str, domain: str = "local", verify_tls: bool = True,
                       profile_id: str | None = None) -> str:
        if not name.strip() or not domain.strip() or any(ord(character) < 32 for character in domain):
            raise ValueError("Dashboard name and authentication domain are required")
        address = normalize_apic(address)
        domain = domain.strip()
        profile_id = profile_id or uuid4().hex
        with self.connection() as database:
            previous = database.execute("SELECT address, domain, verify_tls FROM nexus_dashboards WHERE id = ?",
                                        (profile_id,)).fetchone()
            if previous and (previous["address"], previous["domain"], previous["verify_tls"]) != (address, domain, int(verify_tls)):
                database.execute("DELETE FROM credentials WHERE scope = ?", ("nd-profile:" + profile_id,))
            database.execute("""INSERT INTO nexus_dashboards VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name, address=excluded.address,
                domain=excluded.domain, verify_tls=excluded.verify_tls""",
                (profile_id, name.strip(), address, domain, int(verify_tls)))
        return profile_id

    def delete_dashboard(self, profile_id: str) -> None:
        with self.connection() as database:
            database.execute("DELETE FROM nexus_dashboards WHERE id = ?", (profile_id,))
            database.execute("DELETE FROM credentials WHERE scope = ?", ("nd-profile:" + profile_id,))

    def aci_commands(self, profile_id: str) -> dict[str, tuple[str, ...]]:
        from aci_ifstatus_common import validate_role_commands
        with self.connection() as database:
            row = database.execute("SELECT commands FROM aci_command_lists WHERE apic_id = ?", (profile_id,)).fetchone()
        return validate_role_commands(json.loads(row["commands"]) if row else None)

    def save_aci_commands(self, profile_id: str, commands: dict) -> None:
        from aci_ifstatus_common import validate_role_commands
        validated = validate_role_commands(commands)
        with self.connection() as database:
            if not database.execute("SELECT 1 FROM apics WHERE id = ?", (profile_id,)).fetchone():
                raise ValueError("Select an APIC before saving command lists")
            database.execute("INSERT OR REPLACE INTO aci_command_lists VALUES (?, ?)",
                             (profile_id, json.dumps(validated)))

    @staticmethod
    def credential_scope(kind: str, profile_id: str | None = None) -> str:
        if kind not in ("apic", "dashboard"):
            raise ValueError("Unknown credential group")
        if profile_id is None:
            return "aci-default" if kind == "apic" else "nd-default"
        return ("aci:" if kind == "apic" else "nd-profile:") + profile_id

    def shared_credentials(self, owner: str, kind: str) -> dict:
        return self.credentials(owner, self.credential_scope(kind))

    def effective_credentials(self, owner: str, kind: str, profile_id: str) -> dict:
        shared = self.shared_credentials(owner, kind)
        override = self.credentials(owner, self.credential_scope(kind, profile_id))
        if override.get("username") and override.get("username") != shared.get("username") and not override.get("password"):
            raise ValueError("The server override needs a password for its username")
        resolved = {**shared, **override}
        if resolved and ("domain" not in resolved or override.get("username") and "domain" not in override):
            with self.connection() as database:
                table = "apics" if kind == "apic" else "nexus_dashboards"
                profile = database.execute(f"SELECT domain FROM {table} WHERE id = ?", (profile_id,)).fetchone()
            resolved["domain"] = profile["domain"] if profile else "local"
        return resolved

    def save_credentials(self, owner: str, scope: str, values: dict) -> None:
        encrypted = self.cipher.encrypt(json.dumps(values).encode())
        with self.connection() as database:
            if not database.execute("SELECT 1 FROM users WHERE username = ?", (owner,)).fetchone():
                raise ValueError("Unknown WebUI account")
            database.execute("INSERT OR REPLACE INTO credentials VALUES (?, ?, ?)",
                             (owner, scope, encrypted))

    def credentials(self, owner: str, scope: str) -> dict:
        with self.connection() as database:
            row = database.execute("SELECT encrypted FROM credentials WHERE owner = ? AND scope = ?",
                                   (owner, scope)).fetchone()
        return json.loads(self.cipher.decrypt(row["encrypted"])) if row else {}

    def forget_credentials(self, owner: str, scope: str) -> None:
        with self.connection() as database:
            database.execute("DELETE FROM credentials WHERE owner = ? AND scope = ?", (owner, scope))