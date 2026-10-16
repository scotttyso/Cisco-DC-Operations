#!/usr/bin/env python3
"""Authenticated Cisco DC Operations workspace."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import queue
import requests
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlsplit

DATA_DIR = Path(os.environ.get("DC_AUTOMATION_DATA", Path.home() / ".local/share/cisco-dc-automation"))
KEY_FILE = Path(os.environ.get("DC_AUTOMATION_KEY_FILE", Path.home() / ".config/cisco-dc-automation/vault.key"))
os.environ.setdefault("NICEGUI_STORAGE_PATH", str(DATA_DIR / "sessions"))

import yaml
from cryptography.fernet import InvalidToken
from fastapi import Request
from fastapi.responses import RedirectResponse
from nicegui import app, run, ui

from aci_checks import (ATTENTION_STATES, capture_snapshot, delete_old_snapshots, filter_results, load_snapshots,
                        save_snapshot, snapshot_results, summarize_results)
from aci_ifstatus_common import DIAGNOSTIC_COMMANDS, ROLE_COMMANDS, validate_role_commands
from oidc_auth import OIDCLoginError, create_oidc_client, role_from_claims
from nxos_jobs import NXJob, nd_switch_selection
from nd_interfaces import InterfaceDescriptions, filter_interface_rows, validate_description
from interface_description_table import InterfaceDescriptionTable
from release_updates import installed_version, install_instructions, latest_release
from secure_profiles import ProfileStore, normalize_apic, profile_credential_values


STORE: ProfileStore
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
CSS = """
@import url('https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;500;600;700&display=swap');
:root {--ink:#253139;--muted:#5c6972;--line:#d4dce0;--paper:#fff;--workspace:#f3f5f6;--accent:#007e87;}
.body--dark {--ink:#e5ecec;--muted:#a8b8b9;--line:#465253;--paper:#263032;--workspace:#1b2325;--accent:#65cdd1;}
body {font-family:'Public Sans',sans-serif;letter-spacing:0;color:var(--ink);background:var(--workspace);}
body.body--dark {background:var(--workspace);color:var(--ink);}
.nicegui-content {padding:0;gap:0;}
.topbar {background:#162d35;color:white;min-height:60px;}
.brand {font-size:19px;font-weight:600;line-height:1.2;}
.workspace {width:100%;max-width:1560px;margin:auto;padding:24px 32px;min-width:0;}
.heading {font-size:24px;font-weight:600;margin:0;line-height:1.3;}
.section-title {font-size:17px;font-weight:600;}
.muted {color:var(--muted);font-size:13px;}
.workspace-tabs {width:100%;margin-top:20px;border-bottom:1px solid var(--line);}
.q-tab {text-transform:none;letter-spacing:0;min-height:48px;}
.q-tab-panel {padding:24px 0;}
.q-tab-panels {background:transparent;width:100%;min-width:0;}
.form-grid {display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;width:100%;align-items:start;}
.q-btn {letter-spacing:0;text-transform:none;border-radius:4px;}
.q-field__control {background:var(--paper);}
.q-field--outlined .q-field__control:before {border-color:var(--line);}
.section {width:100%;border-top:1px solid var(--line);padding-top:20px;margin-top:20px;min-width:0;}
.q-table__container {width:100%;border:1px solid var(--line);box-shadow:none;border-radius:4px;background:var(--paper);color:var(--ink);}
.q-table {min-width:660px;}
.q-table th {color:var(--muted);font-weight:600;}
.q-table td {max-width:440px;white-space:normal;overflow-wrap:anywhere;}
.q-table td.interface-unavailable {color:var(--muted);background:var(--workspace);}
.q-toggle__label,.q-checkbox__label {font-size:13px;}
.q-btn-toggle {box-shadow:none;max-width:100%;flex-wrap:wrap;}
.q-btn-toggle .q-btn {min-height:40px;}
.job-log {height:240px;width:100%;border:1px solid var(--line);background:#18272c;color:#d8eae8;border-radius:4px;font-size:12px;}
.code-input textarea {font-family:monospace;font-size:13px;min-height:290px;}
.login-wrap {min-height:80vh;width:100%;display:flex;align-items:center;justify-content:center;padding:24px;}
.login-form {width:380px;max-width:100%;padding:28px;border:1px solid var(--line);border-radius:4px;background:var(--paper);}
.q-card,.q-menu {background:var(--paper);color:var(--ink);}
.metrics {display:flex;flex-wrap:wrap;gap:24px;width:100%;border-bottom:1px solid var(--line);padding-bottom:16px;}
.metric-value {font-size:26px;font-weight:600;line-height:1.3;}
.summary-banner {width:100%;border-left:4px solid var(--accent);padding:10px 14px;background:var(--paper);}
.filter-grid {display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;width:100%;}
.dialog {width:640px;max-width:94vw;border-radius:4px;}
.report-dialog {width:1100px;max-width:96vw;max-height:92vh;}
pre {white-space:pre-wrap;overflow-wrap:anywhere;}
@media(max-width:700px) {.workspace {padding:20px 14px;}.form-grid,.filter-grid {grid-template-columns:1fr;}
 .brand {font-size:16px;}.account {display:none;}.q-tab-panel {padding-top:18px;}.heading {font-size:22px;}
 .topbar {padding:8px 10px;}.topbar>.row {gap:6px;}.topbar .brand {max-width:145px;}
 .topbar .q-btn {padding:6px;min-width:40px;min-height:40px;}}
"""

BOOTFLASH_EXAMPLE = """switches:
  username: netops
  hosts: [192.0.2.101, 192.0.2.102]
scp:
  server: 192.0.2.20
  username: images
  file_path: /images/
  vrf: management
images:
  '9.3(16)': nxos.9.3.16.bin
  '10.3(10)M': nxos64-cs.10.3.10.M.bin
upgrade_paths:
  - model: 'N9K-.*-EX'
    path: ['9.3(16)', '10.3(10)M']
"""


def owner() -> str:
    username = app.storage.user.get("username", "")
    account = STORE.user(username)
    if (not account or time.time() - app.storage.user.get("authenticated_at", 0) > 8 * 3600
            or app.storage.user.get("auth_version", -1) != account["auth_version"]):
        app.storage.user.clear()
        ui.navigate.to("/login")
        raise ValueError("Session expired; sign in again")
    return username


def output_directory() -> Path:
    return DATA_DIR / "runs" / hashlib.sha256(owner().encode()).hexdigest()


def redact(text: str, credentials: dict) -> str:
    for name, value in credentials.items():
        if "password" in name and value:
            text = text.replace(value, "[REDACTED]")
    return text


def notify_error(error, credentials=None):
    message = "Unable to decrypt saved credentials; check the vault key" if isinstance(error, InvalidToken) else str(error)
    ui.notify(redact(message, credentials or {}), type="negative", close_button=True)


def theme_control(username=None):
    preference = STORE.user(username).get("theme", "light") if username else app.storage.user.get("theme", "light")
    dark = ui.dark_mode(preference == "dark")
    ui.colors(primary="#65cdd1" if dark.value else "#007e87")

    def toggle():
        if username:
            STORE.set_theme(owner(), "light" if dark.value else "dark")
        dark.toggle()
        ui.colors(primary="#65cdd1" if dark.value else "#007e87")
        app.storage.user["theme"] = "dark" if dark.value else "light"
        button.props(f"icon={'light_mode' if dark.value else 'dark_mode'}")

    button = ui.button(icon="light_mode" if dark.value else "dark_mode", on_click=toggle).props(
        'flat round color=white aria-label="Switch light or dark theme"')
    button.tooltip("Switch light / dark theme")


def password_dialog():
    username = owner()
    with ui.dialog() as dialog, ui.card().classes("dialog"):
        ui.label("Change password").classes("section-title")
        current = ui.input("Current password", password=True, password_toggle_button=True).props("outlined autocomplete=current-password").classes("w-full")
        new = ui.input("New password", password=True, password_toggle_button=True).props("outlined autocomplete=new-password").classes("w-full")
        confirmation = ui.input("Confirm new password", password=True).props("outlined autocomplete=new-password").classes("w-full")

        async def save():
            try:
                owner()
                values = (current.value or "", new.value or "", confirmation.value or "")
                for field in (current, new, confirmation):
                    field.value = ""
                save_button.disable()
                version = await run.io_bound(STORE.change_password, username, *values)
                app.storage.user["auth_version"] = version
                dialog.close()
                ui.notify("Password changed; other sessions must sign in again", type="positive")
            except ValueError as error:
                notify_error(error)
            finally:
                save_button.enable()

        with ui.row().classes("w-full justify-end"):
            ui.button("Cancel", on_click=dialog.close).props("flat")
            save_button = ui.button("Change password", icon="lock", on_click=save)
    dialog.open()


def users_dialog():
    actor = owner()
    accounts = STORE.users(actor)
    with ui.dialog() as dialog, ui.card().classes("dialog"):
        with ui.row().classes("w-full items-center"):
            ui.label("User accounts").classes("section-title")
            ui.space()
            ui.button(icon="close", on_click=dialog.close).props('flat round aria-label="Close user accounts"').tooltip("Close user accounts")
        table = ui.table(columns=[{"name": name, "label": label, "field": name, "align": "left"}
                                  for name, label in (("username", "Username"), ("role", "Role"))],
                         rows=accounts, row_key="username", pagination=10).classes("w-full")
        ui.label("Create user").classes("section-title mt-4")
        username = ui.input("New username").props("outlined autocomplete=off").classes("w-full")
        role = ui.select({"operator": "Operator", "admin": "Administrator"}, value="operator", label="Role").props("outlined").classes("w-full")
        password = ui.input("Initial password", password=True, password_toggle_button=True).props("outlined autocomplete=new-password").classes("w-full")
        confirmation = ui.input("Confirm initial password", password=True).props("outlined autocomplete=new-password").classes("w-full")

        async def create():
            try:
                current_actor = owner()
                secret = password.value or ""
                matches = secret == (confirmation.value or "")
                password.value = confirmation.value = ""
                if not matches:
                    raise ValueError("Passwords do not match")
                create_button.disable()
                await run.io_bound(STORE.create_user, current_actor, username.value or "", secret, role.value)
                table.rows = STORE.users(owner())
                table.update()
                username.value = ""
                ui.notify("User created", type="positive")
            except ValueError as error:
                notify_error(error)
            finally:
                create_button.enable()

        create_button = ui.button("Create user", icon="person_add", on_click=create)
    dialog.open()


def oidc_settings_dialog():
    actor = owner()
    if STORE.user(actor).get("role") != "admin":
        ui.notify("Administrator access is required to configure corporate sign-in", type="negative")
        return
    config = STORE.oidc_settings()
    with ui.dialog() as dialog, ui.card().classes("dialog"):
        ui.label("Corporate sign-in (OIDC)").classes("section-title")
        ui.label("Configure a tenant-specific Entra v2 issuer and map exact groups claim IDs to application roles.").classes("muted")
        with ui.expansion("Entra application setup help", icon="help_outline").classes("w-full"):
            ui.markdown("""
There is no SAML service-provider metadata file for this OIDC setup. Send the identity team:

- **Application type:** Web / OpenID Connect, single tenant.
- **Redirect URI:** `https://<public-host>[:port]/auth/oidc/callback` (use the exact browser-visible hostname and port; omit `:443` on standard HTTPS).
- **Scopes:** `openid profile email`.
- **ID token claims:** configure Entra to emit assigned **group object IDs** in the `groups` claim. Group-overage responses are denied by this app.

Ask them to return the tenant-specific v2 **issuer URL**, **application/client ID**, and a new **client secret**. Enter the secret only in this form or an approved secrets channel; it is encrypted with the app vault key. The app discovers OIDC endpoints from `<issuer>/.well-known/openid-configuration`.
""").classes("w-full")
        enabled = ui.switch("Enable corporate OIDC sign-in", value=config["enabled"])
        issuer = ui.input("OIDC issuer URL", value=config["issuer"],
                          placeholder="https://login.microsoftonline.com/<tenant-id>/v2.0").props("outlined").classes("w-full")
        client_id = ui.input("Application (client) ID", value=config["client_id"]).props("outlined").classes("w-full")
        client_secret = ui.input("Client secret", password=True, password_toggle_button=True,
                                 placeholder="Leave blank to keep the saved secret").props("outlined").classes("w-full")
        ui.label("Client secret is encrypted with the local vault key. "
                 + ("A secret is saved." if config["client_secret_saved"] else "No secret is saved yet.")).classes("muted")
        admin_groups = ui.textarea("Group IDs mapped to Administrator", value="\n".join(config["admin_groups"]),
                                   placeholder="One Entra group object ID per line").props("outlined autogrow").classes("w-full")
        operator_groups = ui.textarea("Group IDs mapped to Operator", value="\n".join(config["operator_groups"]),
                                      placeholder="One Entra group object ID per line").props("outlined autogrow").classes("w-full")
        ui.label("Register this exact redirect path in Entra: /auth/oidc/callback. "
                 "Local password sign-in remains available for recovery.").classes("muted")

        async def save():
            secret = client_secret.value or ""
            client_secret.value = ""
            save_button.disable()
            try:
                current_actor = owner()
                saved = await run.io_bound(
                    STORE.save_oidc_settings, current_actor, issuer.value or "", client_id.value or "",
                    secret, admin_groups.value or "", operator_groups.value or "", bool(enabled.value))
                ui.notify("Corporate sign-in settings saved" if saved["enabled"]
                          else "Corporate sign-in disabled; local login remains available", type="positive")
                dialog.close()
            except ValueError as error:
                notify_error(error)
            finally:
                save_button.enable()

        with ui.row().classes("w-full justify-end"):
            ui.button("Cancel", on_click=dialog.close).props("flat")
            save_button = ui.button("Save OIDC settings", icon="save", on_click=save)
    dialog.open()


def updates_dialog():
    actor = owner()
    if STORE.user(actor).get("role") != "admin":
        ui.notify("Administrator access is required to check releases", type="negative")
        return
    with ui.dialog() as dialog, ui.card().classes("dialog").style("width: min(900px, 94vw); max-width: 900px"):
        ui.label("Software updates").classes("section-title")
        ui.label(f"Installed release: {installed_version()}").classes("muted")
        status = ui.label("Check GitHub for the latest published release.").classes("muted")
        result = ui.column().classes("w-full gap-3")

        async def check_updates():
            check_button.disable()
            status.text = "Checking GitHub Releases..."
            result.clear()
            try:
                release = await run.io_bound(latest_release)
                owner()
                current = installed_version()
                if current == release["tag"]:
                    status.text = f"{release['tag']} is the latest published release."
                else:
                    status.text = f"Latest release: {release['tag']} (installed: {current})"
                with result:
                    ui.link("View release notes on GitHub", release["url"], new_tab=True)
                    ui.label(release["notes"][:12000]).classes("w-full")
                    if current != release["tag"]:
                        ui.label("After reviewing the release, sign in to the server CLI, "
                                 "finish active jobs, and back up the data and vault key separately before installing.").classes("muted")
                        ui.code(install_instructions(release["tag"]), language="bash").classes("w-full")
            except (ValueError, requests.RequestException) as error:
                status.text = str(error)
            except Exception:
                status.text = "Unable to check GitHub releases; verify server connectivity and try again."
            finally:
                check_button.enable()

        with ui.row().classes("w-full justify-end"):
            ui.button("Close", on_click=dialog.close).props("flat")
            check_button = ui.button("Check for updates", icon="system_update", on_click=check_updates)
    dialog.open()


class InventoryCredentials:
    def __init__(self, kind: str, profile: dict | None = None, on_save=None):
        self.kind = kind
        self.shared = profile is None
        self.on_save = on_save
        self.scope = STORE.credential_scope(kind, None if self.shared else profile.get("id", ""))
        self.existing = STORE.credentials(owner(), self.scope) if self.shared or profile.get("id") else {}
        self.inherited = {} if self.shared else STORE.shared_credentials(owner(), kind)
        self.override = None if self.shared else ui.switch("Override shared credentials", value=bool(self.existing))
        self.rescue = None
        with ui.column().classes("w-full") as fields:
            self.domain = ui.input("Login domain", value=self.existing.get("domain", profile.get("domain", "local") if self.existing and profile
                                   else self.inherited.get("domain", "local"))).props("outlined").classes("w-full")
            self.username = ui.input("Username", value=self.existing.get("username", self.inherited.get("username", ""))).props("outlined autocomplete=off").classes("w-full")
            self.password = ui.input("Password", password=True, password_toggle_button=True).props("outlined autocomplete=new-password").classes("w-full")
            if kind == "dashboard":
                self.rescue = ui.input("Rescue-user password", password=True, password_toggle_button=True).props("outlined autocomplete=new-password").classes("w-full")
        if self.override is not None:
            fields.bind_visibility_from(self.override, "value")
        self.status = ui.label("Encrypted credentials saved for your account" if self.existing else
                               "Uses shared credentials" if not self.shared else "No shared credentials saved for your account").classes("muted")
        if self.shared:
            ui.button("Save shared credentials", icon="save", on_click=self.save_shared)
            ui.button("Forget shared credentials", icon="key_off", on_click=self.forget).props("flat")

    def values(self, target_changed=False):
        if self.override is not None and not self.override.value:
            return None
        values = profile_credential_values(self.existing or self.inherited, self.username.value or "", self.password.value or "",
                                           self.rescue.value or "" if self.rescue else "", target_changed, domain=self.domain.value or "local")
        if not values:
            raise ValueError("Enter credentials, or disable the server override to use shared credentials")
        return values

    def save_shared(self):
        try:
            values = self.values()
            STORE.save_credentials(owner(), self.scope, values)
            self.existing = values
            self.clear()
            self.status.text = "Encrypted shared credentials saved for your account"
            if self.on_save:
                self.on_save()
            ui.notify("Shared credentials saved", type="positive")
        except (ValueError, InvalidToken) as error:
            notify_error(error)

    def clear(self):
        self.password.value = ""
        if self.rescue:
            self.rescue.value = ""

    def forget(self):
        STORE.forget_credentials(owner(), self.scope)
        self.existing.clear()
        self.username.value = ""
        self.domain.value = "local"
        self.clear()
        self.status.text = "No credentials saved for your account"
        if self.on_save:
            self.on_save()


def saved_credentials(kind: str, profile_id: str, tab: str) -> dict:
    values = STORE.effective_credentials(owner(), kind, profile_id)
    if not values.get("username") or not values.get("password"):
        raise ValueError(f"Save your username and password in the {tab} tab first")
    return {key: values[key] for key in ("username", "password", "domain")}


def inventory_rows(kind: str) -> list[dict]:
    account = owner()
    profiles = STORE.apics() if kind == "apic" else STORE.dashboards()
    return [{**profile, "login_domain": STORE.effective_credentials(account, kind, profile["id"]).get("domain", profile["domain"])}
            for profile in profiles]


def dashboard_picker(label: str):
    def options():
        return {profile["id"]: f"{profile['name']} | {profile['address']}" for profile in STORE.dashboards()}

    selector = ui.select(options(), label=label, clearable=True).props("outlined").classes("w-full")

    def refresh():
        owner()
        available = options()
        selector.set_options(available, value=selector.value if selector.value in available else None)

    selector.on("focus", refresh)
    return selector


def ssh_jump(profile_id: str) -> dict:
    profile = next((profile for profile in STORE.dashboards() if profile["id"] == profile_id), None)
    if profile is None:
        raise ValueError("Select a Nexus Dashboard SSH jump appliance")
    values = STORE.effective_credentials(owner(), "dashboard", profile_id)
    if not values.get("rescue_password"):
        raise ValueError("Save your rescue-user password in the Nexus Dashboards tab first")
    return {"host": urlsplit("https://" + profile["address"]).hostname, "password": values["rescue_password"]}


class CredentialFields:
    def __init__(self, scope, extra_passwords=()):
        self.scope = scope
        self.fields = {}
        with ui.element("div").classes("form-grid"):
            self.username = ui.input("Automation username").props("outlined dense autocomplete=off").classes("w-full")
            for name, label in (("password", "Automation password"), *extra_passwords):
                self.fields[name] = ui.input(label, password=True, password_toggle_button=True).props(
                    "outlined dense autocomplete=new-password").classes("w-full")
        with ui.row().classes("w-full items-center gap-4"):
            self.saved = ui.checkbox("Use saved credentials", value=False)
            self.remember = ui.switch("Remember encrypted credentials", value=False)
            ui.button(icon="save", on_click=self.save).props('flat round aria-label="Save encrypted credentials"').tooltip("Save encrypted credentials")
            ui.button(icon="key_off", on_click=self.forget).props('flat round aria-label="Forget saved credentials"').tooltip("Forget saved credentials")
        self.status = ui.label().classes("muted")
        self.refresh()

    def refresh(self):
        try:
            scope = self.scope()
            values = STORE.credentials(owner(), scope) if scope else {}
            self.username.value = values.get("username", "")
            self.saved.value = bool(values)
            self.status.text = "Encrypted credentials available" if values else "No saved credentials"
            self.clear_passwords()
        except (ValueError, InvalidToken) as error:
            notify_error(error)

    def read(self) -> dict:
        scope = self.scope()
        if not scope:
            raise ValueError("Select a target first")
        values = STORE.credentials(owner(), scope) if self.saved.value else {}
        username = (self.username.value or "").strip()
        if values and username != values.get("username") and not self.fields["password"].value:
            raise ValueError("Enter the password for the changed automation username")
        values["username"] = username
        for name, field in self.fields.items():
            values[name] = field.value or values.get(name, "")
        if not values["username"] or not values["password"]:
            raise ValueError("Automation username and password are required")
        return values

    def save(self):
        try:
            STORE.save_credentials(owner(), self.scope(), self.read())
            self.refresh()
            ui.notify("Encrypted credentials saved", type="positive")
        except (ValueError, InvalidToken) as error:
            notify_error(error)

    def forget(self):
        STORE.forget_credentials(owner(), self.scope())
        self.refresh()

    def remember_values(self, values):
        if self.remember.value:
            STORE.save_credentials(owner(), self.scope(), values)
            self.saved.value = True
            self.status.text = "Encrypted credentials available"

    def clear_passwords(self):
        for field in self.fields.values():
            field.value = ""


async def confirm(title: str, action: str) -> bool:
    with ui.dialog() as dialog, ui.card().classes("dialog"):
        ui.label(title).classes("section-title")
        with ui.row().classes("w-full justify-end"):
            ui.button("Cancel", on_click=lambda: dialog.submit(False)).props("flat")
            ui.button(action, icon="warning", on_click=lambda: dialog.submit(True), color="negative")
    return bool(await dialog)


@ui.page("/login")
def login_page(request: Request):
    ui.colors(primary="#007e87", positive="#307c47", negative="#bd3545", warning="#b47c0b")
    with ui.header().classes("topbar"):
        with ui.row().classes("w-full items-center gap-3"):
            ui.icon("hub", size="26px")
            ui.label("Cisco DC Operations").classes("brand")
            ui.space()
            theme_control()
    with ui.element("div").classes("login-wrap"):
        with ui.column().classes("login-form gap-4"):
            ui.label("Sign in").classes("heading")
            oidc_error = request.session.pop("oidc_error", "")
            if oidc_error:
                ui.label(oidc_error).classes("text-negative")
            oidc_config = STORE.oidc_settings()
            if oidc_config["enabled"]:
                ui.link("Sign in with corporate account", "/auth/oidc/login").classes("w-full")
            username = ui.input("WebUI username").props("outlined autocomplete=username").classes("w-full")
            password = ui.input("WebUI password", password=True, password_toggle_button=True).props(
                "outlined autocomplete=current-password").classes("w-full")
            if not STORE.has_users():
                ui.label("No WebUI account configured").classes("text-negative")

            async def login():
                key = request.client.host if request.client else "unknown"
                recent = [stamp for stamp in LOGIN_ATTEMPTS.get(key, []) if time.monotonic() - stamp < 60]
                LOGIN_ATTEMPTS[key] = recent
                if len(recent) >= 5:
                    ui.notify("Too many sign-in attempts; try again in a minute", type="negative")
                    password.value = ""
                    return
                recent.append(time.monotonic())
                name, secret = (username.value or "").strip(), password.value or ""
                password.value = ""
                account = await run.io_bound(STORE.login_account, name, secret)
                if account:
                    app.storage.user.clear()
                    app.storage.user.update(username=name, authenticated_at=time.time(),
                                            auth_version=account["auth_version"], theme=account["theme"],
                                            display_name=name, auth_method="local")
                    LOGIN_ATTEMPTS.pop(key, None)
                    ui.navigate.to("/")
                else:
                    ui.notify("Invalid username or password", type="negative")

            ui.button("Sign in", icon="login", on_click=login).classes("w-full")
            password.on("keydown.enter", login)


@app.get("/auth/oidc/login")
async def oidc_login(request: Request):
    config = STORE.oidc_settings()
    if not config["enabled"]:
        request.session["oidc_error"] = "Corporate sign-in is not enabled."
        return RedirectResponse("/login", status_code=303)
    try:
        client = create_oidc_client(config, STORE.oidc_client_secret())
        redirect_uri = str(request.url_for("oidc_callback"))
        return await client.authorize_redirect(request, redirect_uri)
    except Exception:
        request.session["oidc_error"] = "Unable to start corporate sign-in; verify the OIDC settings."
        return RedirectResponse("/login", status_code=303)


@app.get("/auth/oidc/callback", name="oidc_callback")
async def oidc_callback(request: Request):
    try:
        config = STORE.oidc_settings()
        if not config["enabled"]:
            raise OIDCLoginError("Corporate sign-in is not enabled")
        client = create_oidc_client(config, STORE.oidc_client_secret())
        token = await client.authorize_access_token(request)
        claims = token.get("userinfo")
        if not isinstance(claims, dict):
            raise OIDCLoginError("The identity provider did not return a validated ID token")
        issuer = str(claims.get("iss", "")).rstrip("/")
        if issuer != config["issuer"].rstrip("/"):
            raise OIDCLoginError("The identity provider issuer does not match the configured tenant")
        subject = str(claims.get("sub", ""))
        role = role_from_claims(claims, config)
        preferred_username = str(claims.get("preferred_username") or claims.get("email") or "")
        display_name = str(claims.get("name") or preferred_username)
        account = await run.io_bound(STORE.login_oidc, issuer, subject, preferred_username, display_name, role)
        app.storage.user.clear()
        app.storage.user.update(username=account["username"], authenticated_at=time.time(),
                                auth_version=account["auth_version"], theme=account["theme"],
                                display_name=account["display_name"], auth_method="oidc")
        request.session.pop("oidc_error", None)
        return RedirectResponse("/", status_code=303)
    except OIDCLoginError as error:
        message = str(error)
    except Exception:
        message = "Corporate sign-in failed; verify the tenant configuration and required group claims."
    request.session["oidc_error"] = message
    return RedirectResponse("/login", status_code=303)


def aci_panel(apic_selector):
    current_snapshot = {}
    all_results = []
    snapshots = {}
    baseline_options = {}
    command_fields = {}

    def selected_apic():
        return next((profile for profile in STORE.apics() if profile["id"] == apic_selector.value), None)

    def command_values():
        return validate_role_commands({role: [line.strip() for line in field.value.splitlines() if line.strip()]
                                       for role, field in command_fields.items()})

    def load_commands():
        commands = STORE.aci_commands(apic_selector.value or "")
        for role, field in command_fields.items():
            field.value = "\n".join(commands[role])

    def save_commands():
        try:
            owner()
            STORE.save_aci_commands(apic_selector.value or "", command_values())
            ui.notify("Role commands saved for this APIC", type="positive")
        except (ValueError, RuntimeError) as error:
            notify_error(error)

    with ui.column().classes("w-full gap-4"):
        with ui.row().classes("w-full items-center gap-4"):
            phase = ui.toggle({"pre": "PRE baseline", "post": "POST comparison"}, value="pre")
            capture_role = ui.toggle({"all": "Leaf and spine", "leaf": "Leaf only", "spine": "Spine only"}, value="all")
            group = ui.toggle({"all": "All node IDs", "odd": "Odd", "even": "Even", "nodes": "Node IDs"}, value="all")
            node_ids = ui.input("Node IDs", placeholder="101, 103").props("outlined dense").bind_visibility_from(group, "value", value="nodes")
        ssh_route = ui.toggle({"direct": "Direct SSH", "nd": "SSH via Nexus Dashboard"}, value="direct")
        jump_dashboard = dashboard_picker("SSH jump dashboard").bind_visibility_from(ssh_route, "value", value="nd")
        baseline = ui.select({}, label="PRE baseline", clearable=True).props("outlined dense").classes("w-full").bind_visibility_from(phase, "value", value="post")
        with ui.expansion("Capture settings", icon="tune").classes("w-full"):
            with ui.element("div").classes("form-grid"):
                workers = ui.number("Parallel switches", value=20, min=1, max=32, precision=0).props("outlined dense")
                connect_timeout = ui.number("SSH connection timeout (seconds)", value=20, min=1, precision=0).props("outlined dense")
                read_timeout = ui.number("Per-command timeout (seconds)", value=90, min=1, precision=0).props("outlined dense")
        with ui.expansion("Commands by role", icon="list").classes("w-full"):
            ui.label("POST uses the command lists recorded in its PRE baseline.").classes("muted")
            with ui.column().classes("w-full").bind_visibility_from(phase, "value", value="pre"):
                with ui.element("div").classes("form-grid"):
                    for role, commands in ROLE_COMMANDS.items():
                        command_fields[role] = ui.textarea(f"{role.title()} commands", value="\n".join(commands)).props("outlined autogrow").classes("w-full")
                ui.button("Save role commands", icon="save", on_click=save_commands).props("outline")
        progress = ui.label("Ready").classes("muted")
        messages = queue.SimpleQueue()
        with ui.expansion("Capture log", icon="terminal").classes("w-full"):
            log = ui.log(max_lines=1000).classes("job-log")

        def drain():
            while not messages.empty():
                log.push(messages.get_nowait())

        ui.timer(0.25, drain)

        def refresh_history():
            snapshots.clear()
            baseline_options.clear()
            profile = selected_apic()
            if profile:
                for snapshot in load_snapshots(DATA_DIR, profile["id"], profile["address"]):
                    snapshots[snapshot["id"]] = snapshot
                    if snapshot["phase"] == "pre":
                        baseline_options[snapshot["id"]] = f"{snapshot['captured_at']} | {snapshot['group']} | {len(snapshot['nodes'])} switches"
            baseline.set_options(baseline_options, value=None)
            history.set_options({key: f"{value['phase'].upper()} | {value['captured_at']} | {value['group']}"
                                 for key, value in snapshots.items()}, value=None)

        def show_snapshot(snapshot):
            current_snapshot.clear()
            current_snapshot.update(snapshot)
            rows = snapshot_results(snapshot, snapshots.get(snapshot.get("baseline_id")))
            all_results[:] = rows
            summary = summarize_results(rows)
            total, attention = summary["total"], summary["attention"]
            headline.text = (f"Investigate {attention} of {total} switches" if attention
                             else f"All {total} switches match PRE" if snapshot["phase"] == "post"
                             else f"Baseline captured for {summary['captured']} of {total} switches")
            summary_icon.props(f"name={'warning' if attention else 'fact_check'} color={'warning' if attention else 'positive'}")
            for key, label in metrics.items():
                label.text = str(summary[key])
            affected = [leaf for leaf in summary["leaves"] if leaf["state"] in ATTENTION_STATES]
            leaf_table.rows = affected
            leaf_table.selected = []
            leaf_table.update()
            leaf_section.set_visibility(bool(affected))
            node_filter.set_options({leaf["node_id"]: f"{leaf['node_id']} | {leaf['role']} | {leaf['name']}"
                                     for leaf in summary["leaves"]}, value=None)
            command_filter.set_options(list(dict.fromkeys(row["command"] for row in rows)), value=None)
            role_filter.value = None
            search.value = ""
            result_filter.value = "attention" if snapshot["phase"] == "post" else "all"
            apply_filters()
            counts = {state: sum(row["state"] == state for row in rows) for state in sorted({row["state"] for row in rows})}
            progress.text = " | ".join(f"{count} {state}" for state, count in counts.items())

        def apply_filters():
            owner()
            table.rows = filter_results(all_results, result_filter.value, node_filter.value,
                                        command_filter.value, search.value or "", role=role_filter.value)
            table.selected = []
            table.update()
            visible_count.text = f"{len(table.rows)} of {len(all_results)} command results"
            help_text.text = {
                "attention": "Changed output, failed captures, and missing PRE data require investigation.",
                "REVIEW": "Output differs from PRE. Confirm interface changes; temperatures, counters, and endpoint churn may be expected.",
                "ERROR": "Capture or parsing failed. These switches are not verified; check reachability, authentication, and command support.",
                "NO_BASELINE": "No usable PRE output exists for these checks. A POST capture alone cannot establish a match.",
                "MATCH": "Physical port status or command text matches PRE; this is not a complete device health assessment.",
                "CAPTURED": "PRE output was captured successfully; no post-change comparison has been performed.",
                "all": "All command outcomes, including unchanged checks. REVIEW indicates a difference, not necessarily a fault.",
            }[result_filter.value]

        async def capture():
            values = {}
            jump = None
            try:
                owner()
                profile = selected_apic()
                if not profile:
                    raise ValueError("Select an APIC; add entries on the APICs tab")
                before = snapshots.get(baseline.value) if phase.value == "post" else None
                if phase.value == "post" and not before:
                    raise ValueError("Select a PRE baseline for this APIC")
                values = saved_credentials("apic", profile["id"], "APICs")
                if ssh_route.value == "nd":
                    jump = ssh_jump(jump_dashboard.value)
                    values["rescue_password"] = jump["password"]
                directory = DATA_DIR / "captures" / "aci" / profile["id"]
                settings = dict(group=group.value, node_ids=node_ids.value or "", workers=int(workers.value),
                                connect_timeout=int(connect_timeout.value), read_timeout=int(read_timeout.value),
                                notify=messages.put, role=capture_role.value, dns_domain=STORE.dns_domain(),
                                role_commands=command_values() if before is None else None, jump=jump)
                run_button.disable()
                apic_selector.disable()
                progress.text = "Capturing diagnostic commands..."
                log.clear()

                def work():
                    snapshot = capture_snapshot({**profile, "domain": values["domain"]}, values["username"], values["password"], baseline=before, **settings)
                    snapshot = json.loads(redact(json.dumps(snapshot), values))
                    save_snapshot(directory, snapshot)
                    return snapshot

                snapshot = await run.io_bound(work)
                owner()
                refresh_history()
                history.value = snapshot["id"]
                show_snapshot(snapshot)
            except Exception as error:
                notify_error(error, values)
                progress.text = "Capture did not complete"
            finally:
                values.clear()
                if jump:
                    jump.clear()
                run_button.enable()
                apic_selector.enable()

        with ui.row().classes("w-full items-center"):
            run_button = ui.button("Run ACI checks", icon="play_arrow", on_click=capture)
        with ui.column().classes("section gap-4"):
            with ui.row().classes("w-full items-center"):
                ui.label("Capture history").classes("section-title")
                ui.space()
                ui.button(icon="refresh", on_click=refresh_history).props('flat round aria-label="Refresh capture history"').tooltip("Refresh capture history")
            history = ui.select({}, label="Snapshot").props("outlined dense").classes("w-full")
            history.on_value_change(lambda event: show_snapshot(snapshots[event.value]) if event.value in snapshots else None)
            with ui.row().classes("summary-banner items-start no-wrap"):
                summary_icon = ui.icon("fact_check", size="26px", color="primary")
                headline = ui.label("No snapshot selected").classes("section-title")
            metrics = {}
            with ui.element("div").classes("metrics"):
                for key, label in (("total", "Switches checked"), ("leaf_count", "Leaf"), ("spine_count", "Spine"),
                                   ("attention", "Need investigation"), ("matched", "Match PRE"), ("captured", "Baseline captured")):
                    with ui.column().classes("gap-0"):
                        metrics[key] = ui.label("0").classes("metric-value")
                        ui.label(label).classes("muted")
            with ui.column().classes("w-full gap-3") as leaf_section:
                ui.label("Switches to investigate").classes("section-title")
                leaf_table = ui.table(columns=[
                    {"name": key, "label": label, "field": key, "align": "left", "sortable": True}
                    for key, label in (("node_id", "Node"), ("name", "Switch"), ("role", "Role"), ("state", "Priority"),
                                       ("review", "Changed checks"), ("errors", "Errors"),
                                       ("no_baseline", "No baseline"), ("context", "Investigation context"))
                ], rows=[], row_key="node_id", selection="single", pagination=10).classes("w-full")

                def focus_leaf():
                    if leaf_table.selected:
                        node_filter.value = leaf_table.selected[0]["node_id"]
                        result_filter.value = "attention"
                        apply_filters()

                ui.button("View switch findings", icon="filter_alt", on_click=focus_leaf).props("outline")
            leaf_section.set_visibility(False)
            ui.label("Command findings").classes("section-title")
            with ui.element("div").classes("filter-grid"):
                result_filter = ui.select({"attention": "Needs investigation", "all": "All results",
                                           "REVIEW": "REVIEW - changed output", "ERROR": "ERROR - check failed",
                                           "NO_BASELINE": "NO_BASELINE - missing PRE",
                                           "MATCH": "MATCH - unchanged", "CAPTURED": "CAPTURED - PRE only"},
                                          value="attention", label="Result").props("outlined dense")
                role_filter = ui.select({"leaf": "Leaf", "spine": "Spine"}, label="Role", clearable=True).props("outlined dense")
                node_filter = ui.select({}, label="Switch", clearable=True, with_input=True).props("outlined dense")
                command_filter = ui.select(list(DIAGNOSTIC_COMMANDS), label="Command", clearable=True).props("outlined dense")
            help_text = ui.label("Changed output, failed captures, and missing PRE data require investigation.").classes("muted")
            search = ui.input("Search findings", placeholder="Switch name, node ID, command, or reason").props("outlined dense clearable").classes("w-full")
            visible_count = ui.label("0 command results").classes("muted")
            table = ui.table(columns=[
                {"name": name, "label": label, "field": name, "align": "left", "sortable": True}
                for name, label in (("node_id", "Node"), ("name", "Switch"), ("role", "Role"), ("command", "Command"),
                                    ("state", "Result"), ("context", "Context"))
            ], rows=[], row_key="id", selection="single", pagination=15).classes("w-full")
            for control in (result_filter, role_filter, node_filter, command_filter, search):
                control.on_value_change(apply_filters)

            def inspect():
                owner()
                if not table.selected:
                    ui.notify("Select a result", type="warning")
                    return
                row = next(result for result in all_results if result["id"] == table.selected[0]["id"])
                with ui.dialog() as dialog, ui.card().classes("report-dialog"):
                    with ui.row().classes("w-full items-center"):
                        ui.label(f"Node {row['node_id']} | {row['command']} | {row['state']}").classes("section-title")
                        ui.space()
                        ui.button(icon="close", on_click=dialog.close).props('flat round aria-label="Close report"').tooltip("Close report")
                    with ui.tabs().classes("w-full") as detail_tabs:
                        for label in ("Difference", "Pre", "Post"):
                            ui.tab(label)
                    with ui.tab_panels(detail_tabs, value="Pre" if current_snapshot["phase"] == "pre" else "Difference").classes("w-full"):
                        for label, name in (("Difference", "detail"), ("Pre", "pre"), ("Post", "post")):
                            with ui.tab_panel(label):
                                ui.code((row[name] or "No output")[:60000],
                                        language="diff" if name == "detail" else "text").classes("w-full")
                dialog.open()

            def download():
                owner()
                if current_snapshot:
                    report = {"snapshot": current_snapshot, "results": all_results,
                              "summary": summarize_results(all_results)}
                    ui.download.content(json.dumps(report, indent=2), filename=f"aci-{current_snapshot['id']}.json")

            def delete_old_captures():
                username = owner()
                if STORE.user(username).get("role") != "admin":
                    ui.notify("Administrator access is required to delete shared captures", type="negative")
                    return
                with ui.dialog() as dialog, ui.card().classes("dialog"):
                    ui.label("Delete old shared ACI captures").classes("section-title")
                    retention_days = ui.number("Delete captures older than (days)", value=90, min=1,
                                                precision=0).props("outlined dense")
                    ui.label("Applies across all APICs and legacy per-user captures. PRE baselines used by newer POST captures are kept.").classes("muted")

                    async def remove_old_captures():
                        owner()
                        days = int(retention_days.value or 0)
                        if days < 1:
                            ui.notify("Retention must be at least one day", type="negative")
                            return
                        deleted = await run.io_bound(delete_old_snapshots, DATA_DIR, days)
                        owner()
                        dialog.close()
                        apic_changed()
                        ui.notify(f"Deleted {deleted} old ACI capture(s)", type="positive" if deleted else "info")

                    with ui.row().classes("w-full justify-end"):
                        ui.button("Cancel", on_click=dialog.close).props("flat")
                        ui.button("Delete captures", icon="delete_sweep", color="negative",
                                  on_click=remove_old_captures)
                dialog.open()

            with ui.row():
                ui.button("Inspect result", icon="search", on_click=inspect).props("outline")
                ui.button("Download report", icon="download", on_click=download).props("outline")
            if STORE.user(owner()).get("role") == "admin":
                ui.button("Delete old captures", icon="delete_sweep", on_click=delete_old_captures).props("outline")

    def apic_changed():
        current_snapshot.clear()
        all_results.clear()
        headline.text = "No snapshot selected"
        for label in metrics.values():
            label.text = "0"
        leaf_section.set_visibility(False)
        node_filter.set_options({}, value=None)
        apply_filters()
        load_commands()
        refresh_history()

    apic_selector.on_value_change(apic_changed)
    refresh_history()
    return apic_changed


def nxos_panel(kind: str):
    job = None
    group_fields = []
    with ui.column().classes("w-full gap-4"):
        if kind == "nd":
            nd_profile = dashboard_picker("Nexus Dashboard appliance")
            group_mode = ui.toggle({"named": "Named update groups", "per_switch": "Per-switch groups"}, value="named")
            with ui.column().classes("w-full gap-4").bind_visibility_from(group_mode, "value", value="named"):
                group_container = ui.column().classes("w-full gap-4")

                def add_group():
                    with group_container:
                        with ui.column().classes("w-full gap-2") as container:
                            with ui.row().classes("w-full items-start no-wrap gap-2"):
                                name = ui.input("Update group name").props("outlined dense").classes("flex-1").style("min-width:0")
                                name.tooltip("1-48 letters, digits, underscores, or hyphens")
                                remove = ui.button(icon="delete_outline").props('flat round aria-label="Remove update group"').tooltip("Remove update group")
                            members = ui.textarea("Member switches", placeholder="leaf101, leaf102").props("outlined dense autogrow").classes("w-full")
                            members.tooltip("Comma, space, or newline separated. Group members must share a fabric, target image, and check set.")
                    fields = {"name": name, "hosts": members, "container": container}
                    group_fields.append(fields)

                    def remove_group():
                        group_fields.remove(fields)
                        container.delete()

                    remove.on_click(remove_group)

                add_group()
                ui.button("Add update group", icon="add", on_click=add_group).props("outline")
            devices = ui.textarea("Switch names, addresses, or serials").props("outlined dense").classes("w-full").bind_visibility_from(group_mode, "value", value="per_switch")
            pre_report = ui.checkbox("Request pre-update report before staging", value=False)
        else:
            config_input = ui.textarea("Bootflash YAML configuration", value=BOOTFLASH_EXAMPLE).props("outlined").classes("w-full code-input")
            direct = ui.switch("Connect directly to switches", value=True)
            nd_profile = dashboard_picker("SSH jump dashboard").bind_visibility_from(direct, "value", value=False)
            workers = ui.number("Parallel switches", value=8, min=1, max=16, precision=0).props("outlined dense").classes("w-full").style("max-width:300px")
            credentials = CredentialFields(lambda: "bootflash", extra_passwords=(
                ("scp_password", "SCP server password"),))
        apply = ui.switch("Apply staging changes", value=False)
        status = ui.label("Ready").classes("muted")
        log = ui.log(max_lines=2000).classes("job-log")

        async def start():
            nonlocal job
            values = {}
            jump = None
            bootflash_values = {}
            try:
                owner()
                selection = nd_switch_selection(group_mode.value, devices.value or "",
                                                [{"name": group["name"].value or "", "hosts": group["hosts"].value or ""}
                                                 for group in group_fields]) if kind == "nd" else None
                if apply.value and not await confirm(
                    (f"Create/reuse {len(selection['update_groups'])} named ND update group(s) and stage images?"
                     if "update_groups" in selection else "Create per-switch ND update groups and stage images?") if kind == "nd"
                    else "Delete unneeded bootflash images and copy upgrade images?", "Apply staging",
                ):
                    return
                owner()
                if kind == "nd":
                    profile = next((profile for profile in STORE.dashboards() if profile["id"] == nd_profile.value), None)
                    if profile is None:
                        raise ValueError("Select a Nexus Dashboard appliance")
                    values = saved_credentials("dashboard", profile["id"], "Nexus Dashboards")
                    config = {"nexus_dashboard": {"host": "https://" + profile["address"],
                              "username": values["username"], "domain": values["domain"],
                              "verify_ssl": bool(profile["verify_tls"])}, **selection}
                else:
                    values = credentials.read()
                    values.pop("nd_password", None)
                    bootflash_values = values.copy()
                    try:
                        config = yaml.safe_load(config_input.value)
                    except yaml.YAMLError:
                        raise ValueError("Invalid bootflash YAML") from None
                    if not isinstance(config, dict) or not isinstance(config.get("switches"), dict):
                        raise ValueError("Bootflash configuration requires a switches mapping")
                    config["switches"]["username"] = values["username"]
                    if not direct.value:
                        jump = ssh_jump(nd_profile.value)
                        config["nexus_dashboard"] = {"host": jump["host"], "username": "rescue-user"}
                        values["nd_password"] = jump["password"]
                directory = output_directory() / "nxos" / uuid4().hex
                job = NXJob(kind, directory, config, values.copy(), apply=bool(apply.value),
                            direct=bool(direct.value) if kind == "bootflash" else False,
                            pre_report=bool(pre_report.value) if kind == "nd" else False,
                            workers=int(workers.value) if kind == "bootflash" else 8)
                if kind == "bootflash":
                    credentials.remember_values(bootflash_values)
                    credentials.clear_passwords()
                start_button.disable()
                cancel_button.enable()
                log.clear()
                status.text = "Running staging" if apply.value else "Running plan / dry run"
                code = await job.run(log.push)
                owner()
                status.text = ("Cancelled" if job.cancelled else "Completed" if code == 0 else f"Failed (exit {code})") + f" | Job {directory.name}"
            except Exception as error:
                notify_error(error, values)
                status.text = "Job did not complete"
            finally:
                values.clear()
                bootflash_values.clear()
                if jump:
                    jump.clear()
                if kind == "bootflash":
                    credentials.clear_passwords()
                start_button.enable()
                cancel_button.disable()

        def cancel():
            owner()
            if job:
                job.cancel()

        def download():
            owner()
            if job and (job.directory / "console.log").is_file() and (not job.process or job.process.returncode is not None):
                ui.download.content((job.directory / "console.log").read_bytes(), filename=f"{kind}-{job.directory.name}.log")

        with ui.row():
            start_button = ui.button("Run staging" if kind == "nd" else "Run bootflash job", icon="play_arrow", on_click=start)
            cancel_button = ui.button("Cancel job", icon="stop", on_click=cancel).props("outline")
            cancel_button.disable()
            ui.button("Download log", icon="download", on_click=download).props("outline")


def apic_management(apic_selector, on_change):
    def refresh():
        owner()
        rows = inventory_rows("apic")
        table.rows = rows
        table.selected = []
        table.update()
        options = {row["id"]: f"{row['name']} | {row['address']}" for row in rows}
        selected = apic_selector.value if apic_selector.value in options else None
        apic_selector.set_options(options, value=selected)
        on_change()

    def edit(existing=None):
        owner()
        existing = existing or {}
        with ui.dialog() as dialog, ui.card().classes("dialog"):
            ui.label("Edit APIC" if existing else "Add APIC").classes("section-title")
            name = ui.input("Display name", value=existing.get("name", "")).props("outlined").classes("w-full")
            address = ui.input("APIC hostname or IP", value=existing.get("address", "")).props("outlined").classes("w-full")
            verify = ui.switch("Verify TLS certificate", value=bool(existing.get("verify_tls", True)))
            credentials = InventoryCredentials("apic", existing)

            def save():
                try:
                    owner()
                    changed = bool(existing) and (normalize_apic(address.value or ""), bool(verify.value)) != (
                        existing["address"], bool(existing["verify_tls"]))
                    values = credentials.values(changed)
                    profile_id = STORE.save_apic(name.value or "", address.value or "", bool(verify.value),
                                                existing.get("id"))
                    if values:
                        STORE.save_credentials(owner(), "aci:" + profile_id, values)
                    else:
                        STORE.forget_credentials(owner(), "aci:" + profile_id)
                    credentials.clear()
                    refresh()
                    apic_selector.value = profile_id
                    dialog.close()
                except (ValueError, InvalidToken, sqlite3.IntegrityError) as error:
                    notify_error(error)

            with ui.row().classes("w-full justify-end"):
                ui.button("Cancel", on_click=dialog.close).props("flat")
                ui.button("Save APIC", icon="save", on_click=save)
        dialog.open()

    async def delete():
        owner()
        if table.selected:
            selected = table.selected[0]
            if await confirm(f"Remove {selected['name']} and its saved credentials?", "Remove APIC"):
                owner()
                STORE.delete_apic(selected["id"])
                refresh()

    with ui.column().classes("w-full gap-4"):
        with ui.expansion("Shared APIC credentials", icon="key").classes("w-full"):
            InventoryCredentials("apic", on_save=refresh)
        with ui.row().classes("w-full items-center gap-3"):
            dns_domain = ui.input("DNS Domain", value=STORE.dns_domain()).props("outlined dense").classes("w-full").style("max-width:420px")
            dns_domain.tooltip("Shared by all APICs; used for short switch names without OOB addresses. Blank uses the server's DNS search domains.")

            def save_domain():
                try:
                    owner()
                    STORE.set_dns_domain(dns_domain.value or "")
                    dns_domain.value = STORE.dns_domain()
                    domain_notice.set_visibility(False)
                    ui.notify("DNS Domain saved for all APICs", type="positive")
                except ValueError as error:
                    notify_error(error)

            ui.button("Save DNS Domain", icon="save", on_click=save_domain).props("outline")
        conflicts = STORE.dns_domain_conflicts()
        domain_notice = ui.label("Legacy APIC domains differ: " + ", ".join(conflicts)
                                + ". Confirm the shared DNS Domain before capturing switches.").classes("text-warning")
        domain_notice.set_visibility(bool(conflicts))
        with ui.row().classes("w-full items-center"):
            ui.label("APIC inventory").classes("section-title")
            ui.space()
            ui.button("Add APIC", icon="add", on_click=lambda: edit())
            ui.button(icon="edit", on_click=lambda: edit(table.selected[0]) if table.selected else None).props('flat round aria-label="Edit selected APIC"').tooltip("Edit selected APIC")
            ui.button(icon="delete", on_click=delete).props('flat round color=negative aria-label="Remove selected APIC"').tooltip("Remove selected APIC")
        table = ui.table(columns=[{"name": name, "label": label, "field": name, "align": "left"}
                                 for name, label in (("name", "Fabric / APIC"), ("address", "Address"),
                                                    ("login_domain", "Login domain"), ("verify_tls", "Verify TLS"))],
                         rows=inventory_rows("apic"), row_key="id", selection="single", pagination=15).classes("w-full")


def interface_description_panel():
    state = {"client": None, "profile": None, "switches": [], "rows": [], "drafts": {}, "plans": [], "busy": False, "report": None}

    def clear_preview():
        had_preview = bool(state["plans"])
        state["plans"] = []
        preview_table.rows = []
        preview_table.update()
        apply_button.disable()
        if had_preview:
            status.text = "Preview invalidated; review selected edits and preview again"

    def clear_interfaces():
        state["rows"].clear()
        state["drafts"].clear()
        interfaces.rows = []
        interfaces.selected = []
        interfaces.update()
        update_edit_count()
        visible_count.text = "0 interfaces"
        clear_preview()

    def update_edit_count():
        selected = {row["interface"] for row in interfaces.selected}
        selected_edits = selected.intersection(state["drafts"])
        visible = {row["interface"] for row in interfaces.rows}
        hidden = len(selected_edits - visible)
        queued.text = f"{len(state['drafts'])} edited interfaces | {len(selected_edits)} selected for preview"
        if hidden:
            queued.text += f" | {hidden} hidden by filter"

    def filter_rows(reset_page=False):
        owner()
        try:
            interfaces.rows = filter_interface_rows(state["rows"], search.value or "", regex=filter_mode.value == "regex")
            filter_error.text = ""
        except ValueError as error:
            interfaces.rows = []
            filter_error.text = str(error)
            clear_preview()
        if reset_page:
            interfaces.pagination["page"] = 1
        interfaces.update()
        visible_count.text = f"{len(interfaces.rows)} of {len(state['rows'])} interfaces"
        update_edit_count()

    def selection_changed():
        allowed = {row["interface"] for row in state["rows"] if row.get("editable", False)}
        selected = [row for row in interfaces.selected if row["interface"] in allowed]
        if len(selected) != len(interfaces.selected):
            interfaces.selected = selected
            interfaces.update()
        update_edit_count()
        clear_preview()

    def select_available(clear=False):
        owner()
        if state["busy"]:
            return
        filter_rows()
        if clear:
            interfaces.selected = []
        else:
            selected = {row["interface"]: row for row in interfaces.selected if row.get("editable", False)}
            selected.update({row["interface"]: row for row in interfaces.rows if row.get("editable", False)})
            interfaces.selected = list(selected.values())
        selection_changed()
        interfaces.update()

    def edit_interface(event):
        row = None
        try:
            active_client()
            if state["busy"]:
                return
            name = event.args.get("interface")
            row = next((item for item in state["rows"] if item["interface"] == name), None)
            if row is None:
                raise ValueError("Interface is not in the loaded switch")
            if not row.get("editable", False):
                raise ValueError("Description update blocked: " + row.get("blocked_reason", "No assigned policy or known mode"))
            action = event.args.get("action", "edit")
            value = event.args.get("value", "")
            clear_preview()
            if action == "reset" or action == "edit" and value == "":
                state["drafts"].pop(name, None)
                row.update(proposed="", change="", edit_error="")
            elif action in ("edit", "clear"):
                value = "" if action == "clear" else validate_description(value)
                state["drafts"][name] = value
                row.update(proposed=value, change="CLEAR" if value == "" else "SET", edit_error="")
            else:
                raise ValueError("Unknown interface edit action")
            update_edit_count()
            if action != "edit":
                filter_rows()
        except ValueError as error:
            if row is not None:
                row["edit_error"] = str(error)
                state["drafts"].pop(row["interface"], None)
                update_edit_count()
                filter_rows()
            notify_error(error)

    def dashboard_changed():
        owner()
        if state["busy"]:
            return
        if state["client"]:
            state["client"].close()
        state.update(client=None, profile=None, switches=[])
        fabric.set_options([], value=None)
        switch.set_options({}, value=None)
        clear_interfaces()
        status.text = "Not connected"

    def active_client():
        owner()
        profile = next((profile for profile in STORE.dashboards() if profile["id"] == dashboard.value), None)
        if not state["client"] or profile != state["profile"]:
            raise ValueError("Connect to the selected Nexus Dashboard before continuing")
        return state["client"]

    def begin():
        owner()
        if state["busy"]:
            raise ValueError("Another dashboard operation is running")
        state["busy"] = True
        interfaces.props("editing-busy")
        for row in state["rows"]:
            row["editing_disabled"] = True
        filter_rows()
        for control in controls:
            control.disable()

    def finish():
        state["busy"] = False
        interfaces.props(remove="editing-busy")
        for row in state["rows"]:
            row["editing_disabled"] = not row.get("editable", False)
        filter_rows()
        for control in controls:
            control.enable()
        apply_button.set_enabled(any(plan["state"] == "READY" for plan in state["plans"]))

    async def connect():
        values = {}
        service = None
        started = False
        try:
            begin()
            started = True
            if state["client"]:
                state["client"].close()
            state.update(client=None, profile=None, switches=[])
            fabric.set_options([], value=None)
            switch.set_options({}, value=None)
            clear_interfaces()
            profile = next((profile for profile in STORE.dashboards() if profile["id"] == dashboard.value), None)
            if not profile:
                raise ValueError("Select a dashboard; add it on Nexus Dashboards first")
            values = saved_credentials("dashboard", profile["id"], "Nexus Dashboards")
            status.text = "Connecting and discovering fabrics/switches..."

            def work():
                service = InterfaceDescriptions("https://" + profile["address"], values["username"], values["password"],
                                                bool(profile["verify_tls"]), values["domain"])
                try:
                    return service, service.switches()
                except Exception:
                    service.close()
                    raise

            service, switches = await run.io_bound(work)
            owner()
            if not switches:
                raise ValueError("ND returned no fabric switches")
            state.update(client=service, profile=profile, switches=switches)
            fabric.set_options(sorted({entry["fabric"] for entry in switches}), value=None)
            status.text = f"Connected to {profile['name']} | {len(switches)} switches"
        except Exception as error:
            if service and state["client"] is not service:
                service.close()
            notify_error(error, values)
            status.text = "Connection did not complete"
        finally:
            values.clear()
            if started:
                finish()

    def fabric_changed():
        clear_interfaces()
        switch.set_options({entry["serial"]: f"{entry['name']} | {entry['address']} | {entry['serial']}"
                            for entry in state["switches"] if entry["fabric"] == fabric.value}, value=None)

    async def load_interfaces():
        started = False
        try:
            begin()
            started = True
            service = active_client()
            if not fabric.value or not switch.value:
                raise ValueError("Select a fabric and switch")
            clear_interfaces()
            status.text = "Loading interfaces..."
            rows = await run.io_bound(service.interfaces, fabric.value, switch.value)
            owner()
            state["rows"] = [{**row, "proposed": "", "change": "", "edit_error": "", "editing_disabled": True} for row in rows]
            filter_rows(True)
            status.text = f"{len(rows)} Ethernet interfaces loaded"
            blocked = sum(not row.get("editable", False) for row in rows)
            if blocked:
                status.text += f" | {blocked} unavailable for description updates"
            conflicts = sum(bool(row.get("notice")) for row in rows)
            if conflicts:
                status.text += f" | {conflicts} with differing ND records; preview required"
        except Exception as error:
            notify_error(error)
        finally:
            if started:
                finish()

    async def preview():
        started = False
        try:
            begin()
            started = True
            service = active_client()
            if filter_error.text:
                raise ValueError("Correct the interface filter before previewing")
            selected = {row["interface"] for row in interfaces.selected}
            if any(not row.get("editable", False) for row in state["rows"] if row["interface"] in selected):
                raise ValueError("Selected interfaces without a policy or known mode cannot be updated")
            if any(row["edit_error"] for row in state["rows"] if row["interface"] in selected):
                raise ValueError("Correct invalid descriptions before previewing")
            changes = {name: value for name, value in state["drafts"].items() if name in selected}
            if not changes:
                raise ValueError("Select interfaces with edited descriptions before previewing")
            clear_preview()
            status.text = "Reading current settings for preview..."
            plans = await run.io_bound(service.preview, fabric.value, switch.value, changes)
            owner()
            state["plans"] = plans
            preview_table.rows = [{key: plan[key] for key in ("interface", "old", "new", "state")} for plan in plans]
            preview_table.update()
            status.text = f"Preview ready | {sum(plan['state'] == 'READY' for plan in plans)} changes | no PUT sent"
        except Exception as error:
            notify_error(error)
        finally:
            if started:
                finish()

    async def apply():
        started = False
        try:
            service = active_client()
            plans = list(state["plans"])
            profile = dict(state["profile"])
            changed = sum(plan["state"] == "READY" for plan in plans)
            if not changed or state["busy"]:
                raise ValueError("Preview queued changes before applying")
            if not await confirm(f"Update {changed} interface description(s) on {profile['name']} / {fabric.value} / {switch.value}?", "Apply descriptions"):
                return
            if active_client() is not service or state["plans"] != plans:
                raise ValueError("Selection changed; preview again")
            begin()
            started = True
            report_dir = output_directory() / "operations" / uuid4().hex
            report_dir.mkdir(parents=True, mode=0o700)
            report_path = report_dir / "interface-descriptions.json"
            report = {"dashboard": profile, "state": "IN_PROGRESS", "requested_at": datetime.now(timezone.utc).isoformat(),
                      "results": [{key: plan[key] for key in ("fabric", "serial", "interface", "old", "new", "state")} for plan in plans]}
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            report_path.chmod(0o600)
            state["report"] = report_path
            status.text = "Applying and verifying interface descriptions..."

            def work():
                results = service.apply(plans)
                report.update(results=results, state="COMPLETE", completed_at=datetime.now(timezone.utc).isoformat())
                report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
                return results

            results = await run.io_bound(work)
            owner()
            preview_table.rows = results
            preview_table.update()
            state["plans"] = []
            for result in results:
                state["drafts"].pop(result["interface"], None)
                for row in state["rows"]:
                    if row["interface"] == result["interface"]:
                        row.update(proposed="", change="", edit_error="")
                        if result["state"] == "UPDATED":
                            row["description"] = result["new"]
            filter_rows()
            status.text = " | ".join(f"{sum(result['state'] == value for result in results)} {value}"
                                     for value in sorted({result["state"] for result in results}))
        except Exception as error:
            notify_error(error)
        finally:
            if started:
                finish()

    def download():
        owner()
        if state["report"]:
            ui.download.content(state["report"].read_bytes(), filename="interface-descriptions.json")

    with ui.column().classes("w-full gap-4"):
        ui.label("Interface Descriptions").classes("section-title")
        ui.label("Nexus Dashboard configuration only; switch deployment is not verified.").classes("muted")
        dashboard = dashboard_picker("Nexus Dashboard appliance")
        connect_button = ui.button("Connect dashboard", icon="link", on_click=connect)
        with ui.element("div").classes("form-grid"):
            fabric = ui.select([], label="Fabric", clearable=True).props("outlined dense")
            switch = ui.select({}, label="Switch", clearable=True, with_input=True).props("outlined dense")
        load_button = ui.button("Load interfaces", icon="refresh", on_click=load_interfaces).props("outline")
        status = ui.label("Not connected").classes("muted")
        with ui.row().classes("w-full items-center gap-3"):
            search = ui.input("Filter interfaces").props("outlined dense clearable").classes("flex-1").style("min-width:200px")
            filter_mode = ui.toggle({"text": "Text", "regex": "Regex"}, value="text")
            filter_mode.tooltip("Regex matches interface names; 1/1[4-5]$ matches Ethernet1/14 and Ethernet1/15")
        filter_error = ui.label().classes("text-negative")
        visible_count = ui.label("0 interfaces").classes("muted")
        interfaces = InterfaceDescriptionTable(columns=[{"name": key, "label": label, "field": key, "align": "left", "sortable": True}
                                       for key, label in (("interface", "Interface"), ("proposed", "New description"),
                                                          ("description", "Current description"),
                                                          ("policy", "Policy"), ("mode", "Mode"), ("notice", "ND data note"),
                                                          ("blocked_reason", "Unavailable reason"),
                                                          ("change", "Change"))],
                              rows=[], row_key="interface", selection="multiple", pagination=15,
                              on_select=selection_changed).classes("w-full")
        interfaces.on("select_available", lambda event: select_available(bool(event.args.get("clear"))))
        interfaces.on("description_edit", edit_interface)
        search.on_value_change(lambda: filter_rows(True))
        filter_mode.on_value_change(lambda: filter_rows(True))
        queued = ui.label("0 edited interfaces | 0 selected for preview").classes("muted")
        with ui.row():
            preview_button = ui.button("Preview changes", icon="preview", on_click=preview).props("outline")
            apply_button = ui.button("Apply descriptions", icon="save", color="negative", on_click=apply)
            apply_button.disable()
            ui.button("Download operation report", icon="download", on_click=download).props("outline")
        preview_table = ui.table(columns=[{"name": key, "label": label, "field": key, "align": "left"}
                                         for key, label in (("interface", "Interface"), ("old", "Previous description"),
                                                            ("new", "New description"), ("state", "Result"), ("detail", "Detail"))],
                                rows=[], row_key="interface", pagination=15).classes("w-full")
    controls = (dashboard, fabric, switch, search, filter_mode, connect_button, load_button, preview_button, apply_button)
    dashboard.on_value_change(dashboard_changed)
    fabric.on_value_change(fabric_changed)
    switch.on_value_change(clear_interfaces)
    return dashboard, dashboard_changed


OPERATION_CATALOG = {
    "nd-interface-descriptions": ("Nexus Dashboard - Interface Descriptions", interface_description_panel),
}


def operations_panel():
    operation = ui.select({key: entry[0] for key, entry in OPERATION_CATALOG.items()},
                          value="nd-interface-descriptions", label="Operation").props("outlined").classes("w-full mb-5")
    controls = {}
    for key, (_, builder) in OPERATION_CATALOG.items():
        with ui.column().classes("w-full").bind_visibility_from(operation, "value", value=key):
            controls[key] = builder()
    return controls


def aci_upgrade_panel():
    profiles = STORE.apics()
    selector = ui.select({profile["id"]: f"{profile['name']} | {profile['address']}" for profile in profiles},
                         label="APIC / Fabric", clearable=True).props("outlined").classes("w-full mb-5")
    return selector, aci_panel(selector)


UPGRADE_CATALOG = {
    "aci-checks": ("ACI Checks", aci_upgrade_panel),
    "nxos-bootflash": ("NX-OS / Bootflash", lambda: nxos_panel("bootflash")),
    "nxos-nd-staging": ("NX-OS / ND Staging", lambda: nxos_panel("nd")),
}


def upgrades_panel():
    entries = sorted(UPGRADE_CATALOG.items(), key=lambda entry: entry[1][0].casefold())
    workflow = ui.select({key: entry[0] for key, entry in entries}, value="aci-checks",
                         label="Upgrade workflow").props("outlined").classes("w-full mb-5")
    controls = {}
    for key, (_, builder) in entries:
        with ui.column().classes("w-full").bind_visibility_from(workflow, "value", value=key):
            controls[key] = builder()
    return controls["aci-checks"]


def dashboard_management(dashboard_selector, on_change):
    def refresh():
        owner()
        rows = inventory_rows("dashboard")
        table.rows = rows
        table.selected = []
        table.update()
        options = {row["id"]: f"{row['name']} | {row['address']}" for row in rows}
        selected = dashboard_selector.value if dashboard_selector.value in options else None
        dashboard_selector.set_options(options, value=selected)
        on_change()

    def edit(existing=None):
        owner()
        existing = existing or {}
        with ui.dialog() as dialog, ui.card().classes("dialog"):
            ui.label("Edit Nexus Dashboard" if existing else "Add Nexus Dashboard").classes("section-title")
            name = ui.input("Display name", value=existing.get("name", "")).props("outlined").classes("w-full")
            address = ui.input("Dashboard hostname or IP", value=existing.get("address", "")).props("outlined").classes("w-full")
            verify = ui.switch("Verify TLS certificate", value=bool(existing.get("verify_tls", True)))
            credentials = InventoryCredentials("dashboard", existing)

            def save():
                try:
                    owner()
                    changed = bool(existing) and (normalize_apic(address.value or ""), bool(verify.value)) != (
                        existing["address"], bool(existing["verify_tls"]))
                    values = credentials.values(changed)
                    profile_id = STORE.save_dashboard(name.value or "", address.value or "", existing.get("domain", "local"),
                                                      bool(verify.value), existing.get("id"))
                    if values:
                        STORE.save_credentials(owner(), "nd-profile:" + profile_id, values)
                    else:
                        STORE.forget_credentials(owner(), "nd-profile:" + profile_id)
                    credentials.clear()
                    refresh()
                    dashboard_selector.value = profile_id
                    dialog.close()
                except (ValueError, InvalidToken, sqlite3.IntegrityError) as error:
                    notify_error(error)

            with ui.row().classes("w-full justify-end"):
                ui.button("Cancel", on_click=dialog.close).props("flat")
                ui.button("Save Nexus Dashboard", icon="save", on_click=save)
        dialog.open()

    async def delete():
        owner()
        if table.selected:
            selected = table.selected[0]
            if await confirm(f"Remove {selected['name']} and its saved credentials?", "Remove dashboard"):
                owner()
                STORE.delete_dashboard(selected["id"])
                refresh()

    with ui.column().classes("w-full gap-4"):
        with ui.expansion("Shared Nexus Dashboard credentials", icon="key").classes("w-full"):
            InventoryCredentials("dashboard", on_save=refresh)
        with ui.row().classes("w-full items-center"):
            ui.label("Nexus Dashboard inventory").classes("section-title")
            ui.space()
            ui.button("Add Nexus Dashboard", icon="add", on_click=lambda: edit())
            ui.button(icon="edit", on_click=lambda: edit(table.selected[0]) if table.selected else None).props(
                'flat round aria-label="Edit selected dashboard"').tooltip("Edit selected dashboard")
            ui.button(icon="delete", on_click=delete).props('flat round color=negative aria-label="Remove selected dashboard"').tooltip("Remove selected dashboard")
        table = ui.table(columns=[{"name": key, "label": label, "field": key, "align": "left"}
                                 for key, label in (("name", "Dashboard"), ("address", "Address"),
                                                    ("login_domain", "Login domain"), ("verify_tls", "Verify TLS"))],
                         rows=inventory_rows("dashboard"), row_key="id", selection="single", pagination=15).classes("w-full")


@ui.page("/")
def workspace():
    ui.colors(primary="#007e87", positive="#307c47", negative="#bd3545", warning="#b47c0b")
    try:
        username = owner()
    except ValueError:
        return

    def logout():
        app.storage.user.clear()
        ui.navigate.to("/login")

    with ui.header().classes("topbar"):
        with ui.row().classes("w-full items-center no-wrap gap-3"):
            ui.icon("hub", size="26px")
            ui.label("Cisco DC Operations").classes("brand")
            ui.space()
            ui.label(app.storage.user.get("display_name", username)).classes("account")
            theme_control(username)
            with ui.button(icon="manage_accounts").props('flat round color=white aria-label="Account settings"'):
                ui.tooltip("Account settings")
                with ui.menu():
                    ui.menu_item("Change password", on_click=password_dialog)
                    if STORE.user(username)["role"] == "admin":
                        ui.menu_item("User accounts", on_click=users_dialog)
                        ui.menu_item("Corporate sign-in (OIDC)", on_click=oidc_settings_dialog)
                        ui.menu_item("Check for software updates", on_click=updates_dialog)
            ui.button(icon="logout", on_click=logout).props('flat round color=white aria-label="Sign out"').tooltip("Sign out")
    with ui.column().classes("workspace gap-0"):
        ui.label("Data Center Operations").classes("heading")
        with ui.tabs().classes("workspace-tabs").props("align=left outside-arrows mobile-arrows") as tabs:
            apics = ui.tab("APICs", icon="dns")
            dashboards = ui.tab("Nexus Dashboards", icon="dns")
            operations = ui.tab("Operations", icon="edit_note")
            upgrades = ui.tab("Upgrades", icon="system_update_alt")
        with ui.tab_panels(tabs, value=upgrades).classes("w-full"):
            with ui.tab_panel(upgrades):
                apic_selector, on_apic_change = upgrades_panel()
            with ui.tab_panel(operations):
                operation_controls = operations_panel()
                dashboard_selector, on_dashboard_change = operation_controls["nd-interface-descriptions"]
            with ui.tab_panel(apics):
                apic_management(apic_selector, on_apic_change)
            with ui.tab_panel(dashboards):
                dashboard_management(dashboard_selector, on_dashboard_change)


def main():
    global STORE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create-user", help="Create/update a WebUI account using a prompted password")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--secure-cookies", action="store_true", help="Require HTTPS for session cookies")
    arguments = parser.parse_args()
    os.umask(0o077)
    STORE = ProfileStore(DATA_DIR, KEY_FILE)
    if arguments.create_user:
        password = getpass.getpass("WebUI password: ")
        if password != getpass.getpass("Confirm WebUI password: "):
            parser.error("Passwords do not match")
        try:
            STORE.add_user(arguments.create_user, password)
        except ValueError as error:
            parser.error(str(error))
        print(f"WebUI account saved: {arguments.create_user}")
        return
    ui.add_css(CSS, shared=True)
    ui.run(host=arguments.host, port=arguments.port, title="Cisco DC Operations",
            storage_secret=STORE.storage_secret, show=False, reload=False,
               session_middleware_kwargs={"https_only": arguments.secure_cookies, "max_age": 8 * 3600,
                                          "session_cookie": "cisco_dc_session"})


if __name__ == "__main__":
    main()