import ast
import importlib.util
import inspect
import hashlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import tarfile
import unittest
import yaml
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

from secure_profiles import ProfileStore, normalize_apic, profile_credential_values
import aci_ifstatus_common as common
from oidc_auth import OIDCLoginError, create_oidc_client, role_from_claims, validate_oidc_config
from release_updates import RELEASES_API, install_instructions, latest_release, release_details
from aci_checks import (capture_snapshot, compare_snapshots, delete_old_snapshots, filter_results,
                        load_snapshots, save_snapshot, select_leaves, snapshot_results, summarize_results)
from nxos_jobs import NXJob, nd_switch_selection, reject_plaintext_passwords, validate_bootflash_config
from nd_interfaces import InterfaceDescriptions, description_payload, filter_interface_rows, interface_path


class JumpConnectionTests(unittest.TestCase):
    @patch("aci_jump.jump_helpers")
    def test_jump_uses_rescue_user_and_never_places_passwords_in_commands(self, helpers):
        from unittest.mock import MagicMock
        from aci_jump import NexusDashboardSSH
        session = MagicMock()
        session._capture_prompt.side_effect = ["rescue@nd $", "leaf101#"]
        session.cmd.return_value = "output"
        helpers.return_value = {"SwitchStager": MagicMock(return_value=session), "StageError": RuntimeError,
                                "ND_GENERIC_PROMPT": r"[$#>]", "SWITCH_GENERIC_PROMPT": r"leaf101#",
                                "LEGACY_ERR_RE": common.re.compile("invalid key length"), "LEGACY_SSH_OPTIONS": []}
        connection = NexusDashboardSSH("leaf101.corp.test", "apic:TACACS\\netops", "switch-secret",
                                       {"host": "nd.corp.test", "password": "rescue-secret"}, 20)
        self.assertIn("rescue-user", session._spawn.call_args.args[0])
        command = session.child.sendline.call_args.args[0]
        self.assertIn("leaf101.corp.test", command)
        self.assertNotIn("switch-secret", command)
        self.assertNotIn("rescue-secret", command)
        self.assertEqual(session._authenticate.call_args_list[0].args[0], "rescue-secret")
        self.assertEqual(session._authenticate.call_args_list[1].args[0], "switch-secret")
        self.assertEqual(connection.send_command("show module", read_timeout=90), "output")
        with self.assertRaises(RuntimeError):
            connection.send_command("reload", read_timeout=90)
        connection.disconnect()
        session.disconnect.assert_called_once()

    @patch("aci_checks.capture_leaf_commands")
    @patch("aci_checks.ApicClient")
    def test_jump_applies_only_to_ssh_and_auth_rejection_stops_further_nodes(self, client_type, capture):
        from netmiko.exceptions import NetmikoAuthenticationException
        client_type.return_value.get_class.side_effect = [[
            {"id": str(node), "name": f"leaf{node}", "role": "leaf"} for node in range(101, 105)], []]
        capture.side_effect = NetmikoAuthenticationException("ND rejected SSH credentials")
        profile = {"id": "fabric", "address": "apic.corp.test", "verify_tls": True, "domain": "TACACS"}
        jump = {"host": "nd.corp.test", "password": "rescue-secret"}
        snapshot = capture_snapshot(profile, "netops", "switch-secret", jump=jump)
        client_type.assert_called_once_with("apic.corp.test", verify_tls=True)
        client_type.return_value.login.assert_called_once_with("apic:TACACS\\netops", "switch-secret")
        capture.assert_called_once()
        self.assertEqual(capture.call_args.kwargs["jump"], jump)
        self.assertEqual(snapshot["ssh_connection"], "nexus_dashboard")
        self.assertNotIn("rescue-secret", str(snapshot))

    def test_inventory_credentials_preserve_blanks_but_not_changed_targets(self):
        existing = {"username": "netops", "password": "api-secret", "rescue_password": "rescue-secret"}
        self.assertEqual(profile_credential_values(existing, "netops", ""), existing)
        self.assertEqual(profile_credential_values(existing, "netops", "", target_changed=True), {})
        self.assertEqual(profile_credential_values(existing, "netops", "", "new-rescue")["rescue_password"], "new-rescue")
        with self.assertRaises(ValueError):
            profile_credential_values(existing, "other-user", "")


class NavigationTests(unittest.TestCase):
    def test_alphabetical_tabs_and_grouped_upgrade_workflows(self):
        import automation_ui
        tree = ast.parse(inspect.getsource(automation_ui.workspace))
        labels = [node.args[0].value for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and isinstance(node.func.value, ast.Name) and node.func.value.id == "ui"
                  and node.func.attr == "tab" and node.args]
        self.assertEqual(labels, ["APICs", "Nexus Dashboards", "Operations", "Upgrades"])
        self.assertEqual(labels, sorted(labels, key=str.casefold))
        self.assertEqual({entry[0] for entry in automation_ui.UPGRADE_CATALOG.values()},
                         {"ACI Checks", "NX-OS / ND Staging", "NX-OS / Bootflash"})
        self.assertTrue(all(callable(entry[1]) for entry in automation_ui.UPGRADE_CATALOG.values()))


class InterfaceDescriptionTests(unittest.TestCase):
    def test_description_editor_uses_stable_component_not_dynamic_slots(self):
        import automation_ui
        from nicegui import ui
        from interface_description_table import InterfaceDescriptionTable
        tree = ast.parse(inspect.getsource(automation_ui.interface_description_panel))
        assignment = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "interfaces" for target in node.targets))
        self.assertEqual(assignment.value.func.value.func.id, "InterfaceDescriptionTable")
        with ui.column() as container:
            table = InterfaceDescriptionTable(rows=[], row_key="interface", selection="multiple", pagination=15)
        self.assertEqual(table.selection, "multiple")
        self.assertNotIn("body-cell-proposed", table.slots)
        container.delete()

    def test_unconfigured_ports_remain_visible_but_are_not_editable(self):
        import copy
        records = [self.original]
        for index, mode in enumerate(("unknown", "", "  ", None, " UNKNOWN "), start=20):
            record = copy.deepcopy(self.original)
            record["interfaceName"] = f"Ethernet1/{index}"
            record["configData"]["mode"] = mode
            records.append(record)
        for index, policy in enumerate(("", "unknown", None), start=30):
            record = copy.deepcopy(self.original)
            record["interfaceName"] = f"Ethernet1/{index}"
            record["configData"]["networkOS"]["policy"]["policyType"] = policy
            records.append(record)
        records.append({"interfaceName": "Ethernet1/40", "switchId": "SERIAL1", "interfaceType": "ethernet"})
        service = self.service()
        service.client.request.return_value = {"items": records}
        rows = service.interfaces("Fabric", "SERIAL1")
        self.assertEqual(len(rows), len(records))
        self.assertEqual([row["interface"] for row in rows if row["editable"]], ["Ethernet1/15/1"])
        self.assertTrue(all(row["blocked_reason"] for row in rows if not row["editable"]))

    def test_policy_and_mode_are_rechecked_before_preview_and_put(self):
        import copy
        service = self.service()
        service.client.request.return_value = self.original
        plans = service.preview("Fabric", "SERIAL1", {"Ethernet1/15/1": "New description"})
        for mode, policy in (("unknown", "vpcMember"), ("", "vpcMember"), ("  ", "vpcMember"),
                             (None, "vpcMember"), ("trunk", ""), ("trunk", "unknown"), ("trunk", None)):
            record = copy.deepcopy(self.original)
            record["configData"]["mode"] = mode
            record["configData"]["networkOS"]["policy"]["policyType"] = policy
            service.client.request.reset_mock()
            service.client.request.return_value = record
            with self.subTest(mode=mode, policy=policy), self.assertRaises(ValueError):
                service.preview("Fabric", "SERIAL1", {"Ethernet1/15/1": "New description"})
            self.assertEqual(service.apply(plans)[0]["state"], "ERROR")
            self.assertFalse(any(call.args[0] == "PUT" for call in service.client.request.call_args_list))

    def test_conflicting_policy_or_mode_disables_port_without_hiding_it(self):
        import copy
        other = copy.deepcopy(self.original)
        other["configData"]["mode"] = "unknown"
        service = self.service()
        service.client.request.return_value = [self.original, other]
        rows = service.interfaces("Fabric", "SERIAL1")
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["editable"])
        self.assertIn("disagree", rows[0]["blocked_reason"])

    def test_regex_filter_supports_ranges_anchors_and_invalid_patterns(self):
        rows = [{"interface": name, "description": "GPU uplink"} for name in
                ("Ethernet1/13", "Ethernet1/14", "Ethernet1/15", "Ethernet1/15/1", "Ethernet1/16")]
        self.assertEqual([row["interface"] for row in filter_interface_rows(rows, r"1/1[4-5]", regex=True)],
                         ["Ethernet1/14", "Ethernet1/15", "Ethernet1/15/1"])
        self.assertEqual([row["interface"] for row in filter_interface_rows(rows, r"1/1[4-5]$", regex=True)],
                         ["Ethernet1/14", "Ethernet1/15"])
        self.assertEqual(len(filter_interface_rows(rows, "gpu")), 5)
        self.assertEqual(filter_interface_rows(rows, ""), rows)
        self.assertEqual(filter_interface_rows(rows, "no matches", regex=True), [])
        with self.assertRaises(ValueError):
            filter_interface_rows(rows, "1/[", regex=True)
        self.assertEqual(len(rows), 5)

    def test_column_filter_supports_mode_text_and_regex_matches(self):
        rows = [
            {"interface": "Ethernet1/1", "mode": "trunk"},
            {"interface": "Ethernet1/2", "mode": "unknown"},
            {"interface": "Ethernet1/3", "mode": ""},
            {"interface": "Ethernet1/4", "mode": "Multiple values; preview required"},
        ]
        self.assertEqual([row["interface"] for row in filter_interface_rows(rows, "TRUNK", field="mode")],
                         ["Ethernet1/1"])
        self.assertEqual([row["interface"] for row in filter_interface_rows(rows, "^tr", field="mode", operator="regex")],
                         ["Ethernet1/1"])
        self.assertEqual([row["interface"] for row in filter_interface_rows(rows, "^tr", field="mode", operator="not_regex")],
                         ["Ethernet1/2", "Ethernet1/3", "Ethernet1/4"])
        self.assertEqual([row["interface"] for row in filter_interface_rows(rows, "unknown", field="mode", operator="regex")],
                         ["Ethernet1/2"])
        self.assertEqual([row["interface"] for row in filter_interface_rows(rows, "unknown", field="mode", operator="not_regex")],
                         ["Ethernet1/1", "Ethernet1/3", "Ethernet1/4"])

    def setUp(self):
        self.original = {"interfaceName": "Ethernet1/15/1", "interfaceType": "ethernet", "switchId": "SERIAL1",
                         "configData": {"mode": "trunk", "networkOS": {"networkOSType": "nx-os", "policy": {
                             "policyType": "vpcMember", "primaryInterface": "vPC1151", "portChannelId": "port-channel1151",
                             "portChannelMode": "active", "allowedVlans": "1517-1518", "cdp": True,
                             "lacpPortPriority": 32768, "lacpRate": "normal", "description": "Old description",
                             "debounceTimer": 100, "fec": "auto", "adminState": True}}}}

    def service(self):
        from unittest.mock import MagicMock
        service = InterfaceDescriptions.__new__(InterfaceDescriptions)
        service.client = MagicMock()
        return service

    def test_breakout_url_and_description_only_payload(self):
        import copy
        updated = description_payload(self.original, "SERIAL1", "Ethernet1/15/1", "New description")
        expected = copy.deepcopy(self.original)
        expected["configData"]["networkOS"]["policy"]["description"] = "New description"
        self.assertEqual(updated, expected)
        self.assertEqual(self.original["configData"]["networkOS"]["policy"]["description"], "Old description")
        self.assertEqual(interface_path("Fabric A", "SERIAL1", "Ethernet1/15/1"),
                         "/manage/fabrics/Fabric%20A/switches/SERIAL1/interfaces/Ethernet1%2F15%2F1")

    def test_preview_keeps_distinct_descriptions_for_each_interface(self):
        first = {**self.original, "interfaceName": "Ethernet1/14"}
        second = {**self.original, "interfaceName": "Ethernet1/15"}
        service = self.service()
        service.client.request.side_effect = [first, second]
        plans = service.preview("Fabric", "SERIAL1", {"Ethernet1/14": "Server A", "Ethernet1/15": "Server B"})
        self.assertEqual([(plan["interface"], plan["new"]) for plan in plans],
                         [("Ethernet1/14", "Server A"), ("Ethernet1/15", "Server B")])
        self.assertEqual([call.args[0] for call in service.client.request.call_args_list], ["GET", "GET"])

    def test_schema_and_description_fail_closed(self):
        for value in ("bad\nvalue", "bad\rvalue", "bad\x00value"):
            with self.assertRaises(ValueError):
                description_payload(self.original, "SERIAL1", "Ethernet1/15/1", value)
        with self.assertRaises(ValueError):
            description_payload(self.original, "OTHER", "Ethernet1/15/1", "New")
        with self.assertRaises(ValueError):
            description_payload({**self.original, "configData": {}}, "SERIAL1", "Ethernet1/15/1", "New")
        with self.assertRaises(ValueError):
            description_payload([self.original, self.original], "SERIAL1", "Ethernet1/15/1", "New")

    def test_apply_refetches_preserves_settings_and_verifies(self):
        service = self.service()
        service.client.request.return_value = self.original
        plans = service.preview("Fabric", "SERIAL1", {"Ethernet1/15/1": "New description"})
        updated = description_payload(self.original, "SERIAL1", "Ethernet1/15/1", "New description")
        service.client.request.reset_mock()
        service.client.request.side_effect = [self.original, None, updated]
        results = service.apply(plans)
        self.assertEqual(results[0]["state"], "UPDATED")
        self.assertEqual([call.args[0] for call in service.client.request.call_args_list], ["GET", "PUT", "GET"])
        self.assertEqual(service.client.request.call_args_list[1].args[2], updated)

    def test_concurrent_change_is_not_overwritten(self):
        service = self.service()
        service.client.request.return_value = self.original
        plans = service.preview("Fabric", "SERIAL1", {"Ethernet1/15/1": "New description"})
        changed = description_payload(self.original, "SERIAL1", "Ethernet1/15/1", "Changed elsewhere")
        service.client.request.reset_mock()
        service.client.request.return_value = changed
        self.assertEqual(service.apply(plans)[0]["state"], "CONFLICT")
        self.assertEqual([call.args[0] for call in service.client.request.call_args_list], ["GET"])

    def test_unchanged_description_does_not_put(self):
        service = self.service()
        service.client.request.return_value = self.original
        plans = service.preview("Fabric", "SERIAL1", {"Ethernet1/15/1": "Old description"})
        service.client.request.reset_mock()
        self.assertEqual(service.apply(plans)[0]["state"], "UNCHANGED")
        self.assertEqual([call.args[0] for call in service.client.request.call_args_list], ["GET"])

    def test_verification_mismatch_and_per_port_failure_are_reported(self):
        service = self.service()
        service.client.request.return_value = self.original
        plans = service.preview("Fabric", "SERIAL1", {"Ethernet1/15/1": "New description"})
        service.client.request.side_effect = [self.original, None, self.original]
        self.assertEqual(service.apply(plans)[0]["state"], "VERIFY_REQUIRED")
        service.client.request.side_effect = [RuntimeError("ND denied access"), self.original, None,
                                               description_payload(self.original, "SERIAL1", "Ethernet1/15/1", "New description")]
        results = service.apply(plans + plans)
        self.assertEqual([row["state"] for row in results], ["ERROR", "UPDATED"])

    def test_interface_collection_is_filtered_and_sorted(self):
        service = self.service()
        service.client.request.return_value = {"items": [self.original,
            {**self.original, "interfaceName": "Ethernet1/2"},
            {**self.original, "interfaceName": "port-channel1151", "interfaceType": "portChannel"},
            {**self.original, "interfaceName": "Ethernet1/1", "switchId": "OTHER"}]}
        rows = service.interfaces("Fabric", "SERIAL1")
        self.assertEqual([row["interface"] for row in rows], ["Ethernet1/2", "Ethernet1/15/1"])

    def test_collection_duplicates_and_nested_summaries_list_each_port_once(self):
        service = self.service()
        service.client.request.return_value = {"items": [self.original, self.original,
            {"interfaceName": "Ethernet1/15/1"},
            {**self.original, "interfaceName": "Ethernet1/2"}]}
        rows = service.interfaces("Fabric", "SERIAL1")
        self.assertEqual([row["interface"] for row in rows], ["Ethernet1/2", "Ethernet1/15/1"])
        self.assertEqual(rows[1]["description"], "Old description")
        self.assertEqual(rows[1]["policy"], "vpcMember")
        self.assertEqual(rows[1]["notice"], "")
        self.assertEqual([call.args[0] for call in service.client.request.call_args_list], ["GET"])

    def test_conflicting_collection_values_require_preview_but_do_not_hide_ports(self):
        service = self.service()
        other = description_payload(self.original, "SERIAL1", "Ethernet1/15/1", "Different description")
        service.client.request.return_value = {"items": [self.original, other]}
        rows = service.interfaces("Fabric", "SERIAL1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["description"], "Multiple values; preview required")
        self.assertIn("description", rows[0]["notice"])
        self.assertEqual(rows[0]["mode"], "trunk")
        with self.assertRaises(ValueError):
            service.preview("Fabric", "SERIAL1", {"Ethernet1/15/1": "New description"})
        self.assertFalse(any(call.args[0] == "PUT" for call in service.client.request.call_args_list))


def appliance_module(name, relative_path):
    path = Path(__file__).resolve().parent / "automation-appliance" / relative_path
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class ApplianceTests(unittest.TestCase):
    def test_unpacked_application_runs_without_any_sibling_checkout(self):
        packaging = appliance_module("dc_package_isolated", "scripts/package_source.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "application"
            archive_path = root / "application.tar.gz"
            packaging.package_source(archive_path)
            with tarfile.open(archive_path) as archive:
                for member in archive.getmembers():
                    destination = source / member.name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.extractfile(member).read())
            code = """import runpy, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from nxos_jobs import NXJob
from interface_description_table import InterfaceDescriptionTable
root = Path(sys.argv[1])
job = NXJob('nd', root / 'job', {}, {'password': 'synthetic'})
assert job.script.parent == root / 'nxos-scripts'
settings = runpy.run_path(str(job.script))
assert settings['CUSTOM_CHECK_PREFIX'] == 'nxos_'
arguments = settings['parse_args'](['--nd-url', 'https://nd.example.com'])
assert arguments.nd_url == 'https://nd.example.com'
"""
            environment = os.environ.copy()
            environment.pop("DC_NXOS_SCRIPTS_DIR", None)
            subprocess.run([sys.executable, "-c", code, str(source)], cwd=root,
                           env=environment, capture_output=True, text=True, check=True)

    def test_openshift_examples_match_efi_appliance_and_have_no_embedded_passwords(self):
        directory = Path(__file__).resolve().parent / "automation-appliance" / "openshift"
        documents = {path.name: yaml.safe_load(path.read_text()) for path in directory.glob("*.yaml")}
        vm = documents["virtualmachine.yaml"]
        self.assertFalse(vm["spec"]["template"]["spec"]["domain"]["firmware"]["bootloader"]["efi"]["secureBoot"])
        user_data = documents["cloudinit-secret.yaml"]["stringData"]["userdata"]
        self.assertNotIn("PASSWORD", user_data)
        self.assertIn("/etc/cisco-dc-automation/appliance.env", user_data)

    def test_source_archive_contains_only_independent_deployable_files(self):
        packaging = appliance_module("dc_package_source", "scripts/package_source.py")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "source.tar.gz"
            packaging.package_source(destination)
            with tarfile.open(destination) as archive:
                names = archive.getnames()
                self.assertEqual(set(names), set(packaging.SOURCE_FILES))
                self.assertIn("nxos-scripts/nd_stage_nexus_updates.py", names)
                self.assertIn("automation-appliance/update.py", names)
                self.assertTrue({"oidc_auth.py", "release_updates.py", "VERSION"}.issubset(names))
                self.assertFalse(any(".venv" in name or "vault.key" in name or ".pkrvars" in name for name in names))

    def test_ova_has_local_identity_valid_hashes_and_ordered_members(self):
        artifacts = appliance_module("dc_build_artifacts", "scripts/build_artifacts.py")
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "dc-appliance"
            export.mkdir()
            disk = export / "disk.vmdk"
            disk.write_bytes(b"synthetic-disk")
            ovf = export / "dc-appliance.ovf"
            ovf.write_text(f'<ovf:Envelope xmlns:ovf="{artifacts.OVF}"><ovf:References>'
                           '<ovf:File ovf:id="disk" ovf:href="disk.vmdk"/></ovf:References>'
                           '<ovf:VirtualSystem ovf:id="dc"><ovf:VirtualHardwareSection/>'
                           '</ovf:VirtualSystem></ovf:Envelope>')
            archive_path = artifacts.build_artifacts(export, "1.0.0", skip_qcow2=True)
            with tarfile.open(archive_path) as archive:
                self.assertEqual(archive.getnames(), ["dc-appliance.ovf", "dc-appliance.mf", "disk.vmdk"])
            text = ovf.read_text()
            self.assertIn("Cisco DC Operations Appliance", text)
            self.assertIn("com.vmware.guestInfo", text)
            self.assertIn(artifacts.sha256(disk), ovf.with_suffix(".mf").read_text())

    def test_firstboot_validation_and_secret_handoff_are_local(self):
        configuration = appliance_module("dc_firstboot", "files/cisco-dc-config.py")
        config = configuration.validate({"HOSTNAME": "upgrade.example.com", "IP_SOURCE": "STATIC",
                                         "IP_ADDRESS": "192.0.2.10", "PREFIX": "24", "GATEWAY": "192.0.2.1"})
        self.assertEqual(str(config["interface"]), "192.0.2.10/24")
        with self.assertRaises(ValueError):
            configuration.validate({"IP_SOURCE": "STATIC", "IP_ADDRESS": "192.0.2.10", "GATEWAY": "198.51.100.1"})
        build = {"APP_DIR": "/opt/cisco-dc-automation", "APP_USER": "cisco-dc-automation",
                 "APP_STATE_DIR": "/var/lib/cisco-dc-automation", "APP_KEY_FILE": "/var/lib/cisco-dc-automation-key/vault.key"}
        with patch.object(configuration, "run") as run:
            configuration.set_ui_admin(build, "operator", "synthetic-password")
        self.assertNotIn("synthetic-password", " ".join(run.call_args.args))
        self.assertEqual(run.call_args.kwargs["input"], "operator\nsynthetic-password")


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.updater = appliance_module("dc_updater", "update.py")

    def test_installer_keeps_dependencies_readable_under_private_updater_umask(self):
        script = (Path(__file__).parent / "automation-appliance/install.sh").read_text()
        mask = next(line for line in script.splitlines() if line.startswith("umask "))
        repair = next(line for line in script.splitlines() if line.startswith("chmod -R "))
        self.assertLess(script.index(mask), script.index('python3 -m venv'))
        self.assertGreater(script.index(repair), script.index('-m pip install'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "app"
            venv = app / ".venv"
            subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)],
                           check=True, umask=0o077)
            packages = next((venv / "lib").glob("python*/site-packages"))
            self.assertEqual(packages.stat().st_mode & 0o777, 0o700)
            private_package = packages / "authlib/integrations"
            private_package.mkdir(parents=True, mode=0o700)
            module = private_package / "__init__.py"
            module.write_text("")
            module.chmod(0o600)
            state = app / "state"
            state.mkdir(mode=0o700)
            key = state / "vault.key"
            key.write_text("synthetic")
            key.chmod(0o600)
            environment = {**os.environ, "APP_DIR": str(app)}
            subprocess.run(["bash", "-eu", "-c", mask + "\n" + repair],
                           env=environment, check=True, umask=0o077)
            self.assertEqual(packages.stat().st_mode & 0o777, 0o755)
            self.assertEqual(private_package.stat().st_mode & 0o777, 0o755)
            self.assertEqual(module.stat().st_mode & 0o777, 0o644)
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            fresh = app / "fresh"
            subprocess.run(["bash", "-eu", "-c",
                            mask + '\n"$PYTHON" -m venv --without-pip "$FRESH"'],
                           env={**environment, "PYTHON": sys.executable, "FRESH": str(fresh)},
                           check=True, umask=0o077)
            self.assertEqual(next((fresh / "lib").glob("python*/site-packages")).stat().st_mode & 0o777,
                             0o755)

    def test_bundled_source_extracts_and_checksums_are_verified(self):
        packaging = appliance_module("dc_package_update", "scripts/package_source.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.tar.gz"
            packaging.package_source(archive)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            checksum = root / "source.tar.gz.sha256"
            checksum.write_text(f"{digest}  {archive.name}\n")
            self.updater.verify_checksum(archive, checksum)
            version = (Path(__file__).parent / "VERSION").read_text().strip()
            self.assertEqual(self.updater.extract_source(archive, root / "source", version), version)
            self.assertEqual((root / "source/automation-appliance/install.sh").stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, "does not match"):
                self.updater.extract_source(archive, root / "wrong-version", "v999.0.0")
            for text in (f"{'0' * 64}  {archive.name}\n", f"{digest}  ../other.tar.gz\n",
                         f"{digest}  {archive.name}\n{digest}  {archive.name}\n", "bad\n"):
                checksum.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    self.updater.verify_checksum(archive, checksum)

    def test_unsafe_archives_are_rejected_before_extraction(self):
        members = []
        for name in ("../escape", "/tmp/escape", "folder/../../escape", "folder\\escape"):
            members.append(tarfile.TarInfo(name))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            member = tarfile.TarInfo("unsafe")
            member.type = kind
            member.linkname = "/etc/passwd"
            members.append(member)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, member in enumerate(members):
                archive = root / f"unsafe-{index}.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    bundle.addfile(member)
                target = root / f"source-{index}"
                with self.subTest(name=member.name, kind=member.type), self.assertRaises(ValueError):
                    self.updater.extract_source(archive, target, None)
                self.assertFalse(target.exists())
            for entries in (["duplicate", "duplicate"], ["VERSION"]):
                archive = root / "incomplete.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    for name in entries:
                        bundle.addfile(tarfile.TarInfo(name))
                with self.assertRaises(ValueError):
                    self.updater.extract_source(archive, root / "invalid", None)

    def test_local_bundle_is_copied_and_verified_without_network(self):
        packaging = appliance_module("dc_package_local_update", "scripts/package_source.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.tar.gz"
            packaging.package_source(archive)
            checksum = root / "approved.sha256"
            checksum.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
            work = root / "work"
            work.mkdir()
            args = self.updater.parse_args(["--archive", str(archive), "--checksum", str(checksum)])
            with patch.object(self.updater, "run") as run:
                source, version = self.updater.prepare_source(args, work)
            run.assert_not_called()
            self.assertEqual(source, work / "source")
            self.assertEqual(version, (Path(__file__).parent / "VERSION").read_text().strip())

    def test_downloads_are_versioned_https_and_verified_before_extraction(self):
        args = self.updater.parse_args(["--version", "v1.2.3"])
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(self.updater, "run") as run, \
                patch.object(self.updater, "verify_checksum") as verify, \
                patch.object(self.updater, "extract_source", return_value="v1.2.3") as extract:
            self.updater.prepare_source(args, Path(directory))
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                self.assertIn("--fail", call.args)
                self.assertIn("--proto-redir", call.args)
                self.assertIn("=https", call.args)
                self.assertTrue(call.args[-1].startswith(
                    "https://github.com/scotttyso/Cisco-DC-Operations/releases/download/v1.2.3/"))
            verify.assert_called_once()
            extract.assert_called_once()
        with patch.object(self.updater, "run"), \
                patch.object(self.updater, "verify_checksum", side_effect=ValueError("bad checksum")), \
                patch.object(self.updater, "extract_source") as extract:
            with self.assertRaisesRegex(ValueError, "bad checksum"):
                self.updater.prepare_source(args, Path("/unused"))
            extract.assert_not_called()

    def test_success_orders_stop_backups_install_validation_and_start(self):
        events = []
        with patch.object(self.updater, "run", side_effect=lambda *args, **kwargs: events.append(args)), \
                patch.object(self.updater, "make_backups", side_effect=lambda path: events.append(("backup",))), \
                patch.object(self.updater, "wait_ready", side_effect=lambda: events.append(("health",))):
            self.updater.install_update(Path("/source"), Path("/backups"))
        self.assertEqual(events[0], ("systemctl", "stop", self.updater.SERVICE))
        self.assertEqual(events[1], ("backup",))
        self.assertEqual(events[2], ("bash", "/source/automation-appliance/install.sh"))
        self.assertIn("-m", events[3])
        self.assertIn("check", events[3])
        self.assertEqual(events[4][:4], ("runuser", "-u", "cisco-dc-automation", "--"))
        self.assertEqual(events[-2], ("systemctl", "start", self.updater.SERVICE))
        self.assertEqual(events[-1], ("health",))

    def test_failures_leave_service_stopped_without_automatic_rollback(self):
        for stage in ("backup", "install", "import", "health"):
            with self.subTest(stage=stage):
                events = []

                def run(*args, **kwargs):
                    events.append(args)
                    if ((stage == "install" and args[0] == "bash")
                            or (stage == "import" and "-c" in args)):
                        raise subprocess.CalledProcessError(1, args)

                with patch.object(self.updater, "run", side_effect=run), \
                        patch.object(self.updater, "make_backups",
                                     side_effect=RuntimeError("backup failed") if stage == "backup" else None), \
                        patch.object(self.updater, "wait_ready",
                                     side_effect=RuntimeError("health failed") if stage == "health" else None):
                    with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                        self.updater.install_update(Path("/source"), Path("/backups"))
                self.assertEqual(events[-1], ("systemctl", "stop", self.updater.SERVICE))
                if stage == "backup":
                    self.assertFalse(any(args[0] == "bash" for args in events))
                self.assertFalse(any("restore" in " ".join(args) for args in events))

    def test_health_requires_active_service_and_http_200(self):
        response = MagicMock(status=200)
        response.geturl.return_value = "http://127.0.0.1:8088/login"
        with patch.object(self.updater, "run") as run, \
                patch.object(self.updater, "build_opener") as build:
            request = build.return_value.open
            request.return_value.__enter__.return_value = response
            self.updater.wait_ready()
            run.assert_called_once_with("systemctl", "is-active", "--quiet", self.updater.SERVICE)
            request.assert_called_once_with("http://127.0.0.1:8088/login", timeout=3)
            self.assertEqual(build.call_args.args[0].proxies, {})
        with patch.object(self.updater, "run"), \
                patch.object(self.updater, "build_opener") as build, \
                patch.object(self.updater.time, "sleep"), \
                patch.object(self.updater.time, "monotonic", side_effect=[0, 0, 61]):
            build.return_value.open.side_effect = OSError("connection refused")
            with self.assertRaisesRegex(RuntimeError, "connection refused"):
                self.updater.wait_ready()

    def test_requires_explicit_source_and_root(self):
        for args in ([], ["--version", "main"], ["--version", "v1.2.3", "--archive", "a"],
                     ["--version", "v1.2.3", "--checksum", "a"]):
            with self.subTest(args=args), patch("sys.stderr"), self.assertRaises(SystemExit):
                self.updater.parse_args(args)
        with patch.object(self.updater.os, "geteuid", return_value=1000), \
                patch.object(self.updater, "preflight") as preflight:
            self.assertEqual(self.updater.main(["--version", "v1.2.3"]), 1)
            preflight.assert_not_called()

    def test_preflight_rejects_custom_state_key_and_backend_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("app", "state", "key"):
                (root / name).mkdir()
            (root / "key/vault.key").write_text("synthetic")
            env = root / "service.env"
            environment = {}

            def show(*args, **kwargs):
                if "--property=Environment" in args:
                    return environment.get("environment", "")
                if "--property=EnvironmentFiles" in args:
                    return environment.get("files", "")
                if "--property=WorkingDirectory" in args:
                    return str(root / "app")
                if "--property=ExecStart" in args:
                    return environment.get("command",
                        f"{{ argv[]={root}/app/.venv/bin/python {root}/app/automation_ui.py "
                        "--host 127.0.0.1 --port 8088 ; }")
                self.fail(f"Unexpected command: {args}")

            with patch.object(self.updater, "APP", root / "app"), \
                    patch.object(self.updater, "STATE", root / "state"), \
                    patch.object(self.updater, "KEY", root / "key"), \
                    patch.object(self.updater, "ENV_FILE", env), \
                    patch.object(self.updater, "run", side_effect=show):
                self.updater.preflight()
                for name in ("DC_AUTOMATION_DATA", "DC_AUTOMATION_KEY_FILE", "DC_NXOS_SCRIPTS_DIR"):
                    environment["environment"] = f"{name}=/custom"
                    with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Custom"):
                        self.updater.preflight()
                environment.clear()
                env.write_text("DC_AUTOMATION_DATA=/custom\n")
                with self.assertRaisesRegex(ValueError, "Custom"):
                    self.updater.preflight()
                env.unlink()
                environment["files"] = "/custom.env (ignore_errors=no)"
                with self.assertRaisesRegex(ValueError, "EnvironmentFiles"):
                    self.updater.preflight()
                environment.clear()
                environment["command"] = f"{root}/app/automation_ui.py --host 0.0.0.0 --port 9999"
                with self.assertRaisesRegex(ValueError, "standard backend"):
                    self.updater.preflight()

    def test_backup_failure_for_insufficient_space_precedes_any_archive_write(self):
        with patch.object(self.updater, "run", return_value="1000 /path") as run, \
                patch.object(self.updater.shutil, "disk_usage",
                             return_value=SimpleNamespace(free=1000)):
            with self.assertRaisesRegex(RuntimeError, "Insufficient"):
                self.updater.make_backups(Path("/backups"))
            self.assertTrue(all(call.args[0] == "du" for call in run.call_args_list))

    def test_backups_preserve_code_state_and_key_in_separate_private_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("app", "state", "key", "backups"):
                (root / name).mkdir()
            for name in ("app", "state", "key"):
                (root / name / "fixture").write_text(f"synthetic-{name}")
            (root / "app/python-link").symlink_to("/usr/bin/python3")
            with patch.object(self.updater, "APP", root / "app"), \
                    patch.object(self.updater, "STATE", root / "state"), \
                    patch.object(self.updater, "KEY", root / "key"), \
                    patch.object(Path, "exists", return_value=False):
                self.updater.make_backups(root / "backups")
            for filename, folder in (("application", "app"), ("state", "state"), ("vault-key", "key")):
                path = root / f"backups/{filename}.tar.gz"
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                with tarfile.open(path) as archive:
                    self.assertEqual(archive.extractfile(f"{folder}/fixture").read(),
                                     f"synthetic-{folder}".encode())
                    if folder == "app":
                        self.assertTrue(archive.getmember("app/python-link").issym())

    def test_main_requires_confirmation_and_preserves_recovery_directory(self):
        real_open = os.open
        real_stat = os.fstat
        real_mkdtemp = tempfile.mkdtemp
        for answer in ("cancel", "UPDATE"):
            with self.subTest(answer=answer), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "VERSION").write_text("v0.1.0")
                lock_fd = None

                def open_file(path, *args, **kwargs):
                    nonlocal lock_fd
                    if path == "/run/lock/cisco-dc-update.lock":
                        lock_fd = real_open(root / "lock", *args, **kwargs)
                        return lock_fd
                    return real_open(path, *args, **kwargs)

                def file_stat(fd):
                    if fd == lock_fd:
                        return SimpleNamespace(st_uid=0, st_mode=0o100600)
                    return real_stat(fd)

                def temporary_directory(suffix=None, prefix=None, dir=None):
                    return real_mkdtemp(suffix=suffix, prefix=prefix, dir=root)

                with patch.object(self.updater, "APP", root), \
                        patch.object(self.updater.os, "geteuid", return_value=0), \
                        patch.object(self.updater.os, "umask"), \
                        patch.object(self.updater.os, "open", side_effect=open_file), \
                        patch.object(self.updater.os, "fstat", side_effect=file_stat), \
                        patch.object(self.updater.tempfile, "mkdtemp", side_effect=temporary_directory), \
                        patch.dict(os.environ), \
                        patch.object(self.updater, "preflight") as preflight, \
                        patch.object(self.updater, "prepare_source", return_value=(root / "source", "v0.1.1")), \
                        patch.object(self.updater, "install_update") as install, \
                        patch("builtins.input", return_value=answer):
                    self.assertEqual(self.updater.main(["--version", "v0.1.1"]), 0)
                    preflight.assert_called_once()
                    if answer == "UPDATE":
                        install.assert_called_once()
                        self.assertTrue(install.call_args.args[1].is_dir())
                        self.assertEqual(install.call_args.args[1].stat().st_mode & 0o777, 0o700)
                    else:
                        install.assert_not_called()


class NXJobTests(unittest.TestCase):
    def test_parallel_submission_reaches_ten_with_isolated_sessions_and_reports_partial_failure(self):
        import threading
        import requests
        helpers, checks, images, switch = self.split_fixture()
        client = object.__new__(helpers["NexusDashboard"])
        client.url = "https://nd.example.test"
        client.request_timeout = 60
        client.session = requests.Session()
        client.session.verify = False
        client.session.cookies.set("AuthCookie", "synthetic")
        barrier = threading.Barrier(10, timeout=5)
        lock = threading.Lock()
        sessions, calls = [], []
        active = peak = 0

        def apply(worker, plan, selected_checks, additions, pre_report):
            nonlocal active, peak
            with lock:
                sessions.append(worker.session)
                calls.append(plan.group_name)
                active += 1
                peak = max(peak, active)
            self.assertIsNot(worker.session, client.session)
            self.assertEqual(worker.session.cookies.get("AuthCookie"), "synthetic")
            self.assertFalse(worker.session.verify)
            worker.session.cookies.set("worker", plan.group_name)
            worker.session.close = MagicMock()
            try:
                barrier.wait()
                if plan.group_name == "g0":
                    raise RuntimeError("synthetic failure")
            finally:
                with lock:
                    active -= 1

        plans = [helpers["make_plan"](f"g{i}", [switch(str(i))], checks, images) for i in range(20)]
        additions = {(plan.fabric, plan.group_name): plan.serials for plan in plans}
        with patch.dict(helpers["submit_plans"].__globals__, {"apply_plan": apply}), \
                self.assertRaisesRegex(RuntimeError, "other groups may have been staged.*g0"):
            helpers["submit_plans"](client, plans, checks, additions, False, 10, {})
        self.assertEqual(peak, 10)
        self.assertEqual(len(calls), 20)
        self.assertEqual(len({id(session) for session in sessions}), 20)
        self.assertNotIn("worker", client.session.cookies)
        for session in sessions:
            session.close.assert_called_once()
        barrier = threading.Barrier(1, timeout=5)
        sessions, calls = [], []
        active = peak = 0
        with patch.dict(helpers["submit_plans"].__globals__, {"apply_plan": apply}), \
                self.assertRaisesRegex(RuntimeError, "other groups may have been staged.*g0"):
            helpers["submit_plans"](client, plans, checks, additions, False, 1, {})
        self.assertEqual(peak, 1)
        self.assertEqual(len(calls), 20)
        for session in sessions:
            session.close.assert_called_once()
        client.session.close()

    def test_parallel_setting_validation_and_existing_selection_schema(self):
        from nxos_jobs import nd_switch_selection
        helpers, _, _, _ = self.split_fixture()
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "input.yaml"
            for value in (0, 11, True, 1.5, "10"):
                config.write_text(yaml.safe_dump({"nexus_dashboard": {"host": "nd.example.test"},
                                                 "parallel_groups": value}))
                with self.subTest(value=value), self.assertRaises(SystemExit):
                    helpers["parse_args"](["--config", str(config)])
            config.write_text(yaml.safe_dump({"nexus_dashboard": {"host": "nd.example.test"},
                                             "parallel_groups": 1}))
            self.assertEqual(helpers["parse_args"](["--config", str(config)]).parallel_groups, 1)
            self.assertEqual(helpers["parse_args"](["--config", str(config), "--parallel-groups", "10"]).parallel_groups, 10)
            groups = [{"fabric": fabric, "name": "same", "members": [fabric + "-s"], "hosts": "new, new"}
                      for fabric in ("F1", "F2")]
            selection = nd_switch_selection("existing", groups=groups)
            self.assertEqual(selection["existing_groups"][0]["add_hosts"], ["new"])
            config.write_text(yaml.safe_dump({"nexus_dashboard": {"host": "nd.example.test"}, **selection}))
            self.assertEqual(len(helpers["parse_args"](["--config", str(config)]).existing_groups), 2)
            with self.assertRaisesRegex(ValueError, "at least one existing"):
                nd_switch_selection("existing")

    def test_existing_group_membership_is_preserved_and_revalidated(self):
        helpers, checks, images, switch = self.split_fixture()
        switches = [switch("s"), switch("new"), switch("other", fabric="F2")]
        record = {"updateGroupName": "leaf", "updateGroupSwitches": ["s"]}
        entry = {"fabric": "F1", "name": "leaf", "members": ["s"], "add_hosts": ["new", "s"]}
        client = MagicMock()
        client.request.return_value = record
        inventory_groups = helpers["load_existing_groups"](client, switches)
        self.assertEqual(inventory_groups, [
            {"fabric": fabric, "name": "leaf", "members": ["s"]} for fabric in ("F1", "F2")])
        self.assertEqual([call.args[1] for call in client.request.call_args_list],
                         [helpers["fabric_path"](fabric, "updateGroups") for fabric in ("F1", "F2")])
        groups, snapshots = helpers["resolve_existing_groups"](client, switches, [entry])
        self.assertEqual([item.serial for item in groups[0][1]], ["s", "new"])
        self.assertEqual(snapshots, {("F1", "leaf"): ["s"]})
        with self.assertRaisesRegex(ValueError, "Membership changed"):
            helpers["resolve_existing_groups"](client, switches, [{**entry, "members": []}])
        with self.assertRaisesRegex(ValueError, "must belong to F1"):
            helpers["resolve_existing_groups"](client, switches, [{**entry, "add_hosts": ["other"]}])
        with self.assertRaisesRegex(ValueError, "invalid switch membership"):
            helpers["group_member_ids"]({"updateGroupSwitches": [{"serial": "s"}]})
        plan = helpers["make_plan"](*groups[0], checks, images)
        client.fork.return_value.request.return_value = {**record, "updateGroupSwitches": ["s", "late"]}
        apply = MagicMock()
        with patch.dict(helpers["submit_plans"].__globals__, {"apply_plan": apply}), \
                self.assertRaisesRegex(RuntimeError, "submissions failed"):
            helpers["submit_plans"](client, [plan], checks, {("F1", "leaf"): ["new"]}, False, 1, snapshots)
        apply.assert_not_called()
        client.fork.return_value.session.close.assert_called_once()

    def test_existing_groups_cli_preserves_members_and_refuses_moves_or_splitting(self):
        helpers, checks, images, switch = self.split_fixture()
        for apply, conflict, mixed, stale in ((False, False, False, False), (True, False, False, False),
                                             (True, True, False, False), (True, False, True, False),
                                             (True, False, False, True)):
            with self.subTest(apply=apply, conflict=conflict, mixed=mixed, stale=stale), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "input.yaml"
                selection = {"fabric": "F1", "name": "leaf", "members": ["s"], "add_hosts": ["new"]}
                config.write_text(yaml.safe_dump({"nexus_dashboard": {"host": "nd.example.test"},
                                                 "existing_groups": [selection]}))
                record = {"updateGroupName": "leaf", "updateGroupSwitches": ["s"]}
                reads = 0

                def request(method, path, payload=None):
                    nonlocal reads
                    self.assertEqual(method, "GET")
                    if path == helpers["SWITCHES"]:
                        return []
                    if path == helpers["IMAGES"]:
                        return images
                    if path == helpers["group_path"]("F1", "leaf"):
                        reads += 1
                        return {**record, "updateGroupSwitches": ["s", "late"]} if stale and reads > 1 else record
                    return [record] + ([{"updateGroupName": "other", "updateGroupSwitches": ["new"]}] if conflict else [])

                client = MagicMock()
                client.request.side_effect = request
                client.fork.return_value = client
                apply_plan = MagicMock()
                ensure = MagicMock(return_value=checks)
                argv = ["script", "--config", str(config)] + (["--apply"] if apply else [])
                with patch.object(sys, "argv", argv), patch.dict(os.environ, {"NEXUS_PASSWORD": "synthetic"}), \
                        patch.dict(helpers["main"].__globals__, {
                            "NexusDashboard": MagicMock(return_value=client),
                            "load_switches": MagicMock(return_value=[switch("s"), switch("new", vpc=mixed)]),
                            "load_check_catalog": MagicMock(return_value=({}, checks)),
                            "ensure_check_catalog": ensure, "apply_plan": apply_plan,
                        }):
                    self.assertEqual(helpers["main"](), 1 if conflict or mixed or stale else 0)
                if apply and not (conflict or mixed or stale):
                    self.assertEqual(apply_plan.call_args.args[1].serials, ["s", "new"])
                    self.assertEqual(apply_plan.call_args.args[3], ["new"])
                else:
                    apply_plan.assert_not_called()
                if not apply or conflict or mixed:
                    ensure.assert_not_called()

    def split_fixture(self):
        from nd_interfaces import nd_helpers
        helpers = nd_helpers()
        checks = [{"reportCheckName": "nxos_Interface_status", "cliCommand": "show interface"},
                  {"reportCheckName": "nxos_vPC_state", "cliCommand": "show vpc"},
                  {"reportCheckName": "nxos_Dual_supervisor_redundancy", "cliCommand": "show module"}]
        images = [{"imageName": "nxos64-cs.10.6.4.M.bin", "releaseVersion": "10.6.4",
                   "platform": "n9k", "imagePresent": "Verified", "imageSubType": "nx-os"}]

        def switch(serial, vpc=False, chassis=False, fabric="F1", version="10.3(8)"):
            return helpers["Switch"](serial, serial, "", "N9K-C9508" if chassis else "N9K-C93240YC-FX2",
                                     version, "n9k", "peer" if vpc else "", "primary" if vpc else "", fabric)
        return helpers, checks, images, switch

    def test_mixed_groups_split_with_correct_names_and_checks(self):
        helpers, checks, images, switch = self.split_fixture()
        name = "DCM-Access-OOB-Grp1-Odd"
        members = [switch("s"), switch("v", True), switch("s9508", False, True), switch("v9508", True, True)]
        result = helpers["split_update_groups"]([(name, members)], checks, images)
        self.assertEqual({group: [s.serial for s in hosts] for group, hosts in result}, {
            name: ["s"], name + "-vpc": ["v"], name + "-9508": ["s9508"],
            name + "-vpc-9508": ["v9508"],
        })
        for group, hosts in result:
            plan = helpers["make_plan"](group, hosts, checks, images)
            self.assertEqual("nxos_vPC_state" in plan.check_names, hosts[0].is_vpc)
            self.assertEqual("nxos_Dual_supervisor_redundancy" in plan.check_names,
                             "9508" in hosts[0].model)
        homogeneous = [("same", [switch("v1", True), switch("v2", True)])]
        self.assertEqual(helpers["split_update_groups"](homogeneous, checks, images), homogeneous)
        # vPC/standalone does not require splitting when the selected checks are identical.
        original = [(name, members)]
        self.assertEqual(helpers["split_update_groups"](original, checks[:1], images), original)

    def test_split_names_stay_short_unique_and_deterministic(self):
        helpers, checks, images, switch = self.split_fixture()
        groups = [
            ("x" * 47 + "a", [switch("s1"), switch("v1", True)]),
            ("x" * 47 + "b", [switch("s2"), switch("v2", True)]),
            ("group", [switch("s3"), switch("v3", True)]),
            ("group-vpc", [switch("s4")]),
        ]
        first = helpers["split_update_groups"](groups, checks, images)
        self.assertEqual(first, helpers["split_update_groups"](groups, checks, images))
        names = [name for name, _ in first]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(helpers["GROUP_NAME_RE"].fullmatch(name) for name in names))
        self.assertTrue(all(name.endswith("-vpc") for name, members in first if members[0].is_vpc))
        self.assertEqual(sorted(s.serial for _, members in first for s in members),
                         sorted(s.serial for _, members in groups for s in members))

    def test_split_preserves_fabric_image_and_upgrade_rule_rejections(self):
        helpers, checks, images, switch = self.split_fixture()
        for other, expected in (
            (switch("v", True, fabric="F2"), "spans fabrics"),
            (switch("v", True, version="10.6(3)"), "outside"),
            (switch("v", True, version="9.3(8)"), "different images"),
        ):
            catalog = images + [{"imageName": "nxos.9.3.16.bin", "releaseVersion": "9.3.16",
                                 "platform": "n9k", "imagePresent": "Present", "imageSubType": "nx-os"}]
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, expected):
                helpers["split_update_groups"]([("mixed", [switch("s"), other])], checks, catalog)

    def test_split_groups_reach_plan_apply_and_existing_membership_guards(self):
        helpers, checks, images, switch = self.split_fixture()
        globals_ = helpers["main"].__globals__
        members = [switch("s"), switch("v", True)]
        for apply, conflict in ((False, False), (True, False), (True, True)):
            with self.subTest(apply=apply, conflict=conflict), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "input.yaml"
                config.write_text(yaml.safe_dump({"nexus_dashboard": {"host": "nd.example.test"},
                                                 "update_groups": {"mixed": {"hosts": ["s", "v"]}}}))

                def request(method, path, payload=None):
                    self.assertEqual(method, "GET")
                    if path == helpers["SWITCHES"]:
                        return []
                    if path == helpers["IMAGES"]:
                        return images
                    if conflict:
                        return [{"updateGroupName": "mixed-vpc", "updateGroupSwitches": ["stranger"]}]
                    return [{"updateGroupName": "mixed-vpc", "updateGroupSwitches": ["v"]}]

                client = MagicMock()
                client.request.side_effect = request
                apply_plan = MagicMock()
                argv = ["script", "--config", str(config)] + (["--apply"] if apply else [])
                with patch.object(sys, "argv", argv), \
                        patch.dict(os.environ, {"NEXUS_PASSWORD": "synthetic"}), \
                        patch.dict(globals_, {
                            "NexusDashboard": MagicMock(return_value=client),
                            "load_switches": MagicMock(return_value=members),
                            "load_check_catalog": MagicMock(return_value=({}, checks)),
                            "ensure_check_catalog": MagicMock(return_value=checks),
                            "apply_plan": apply_plan,
                        }):
                    self.assertEqual(helpers["main"](), 1 if conflict else 0)
                if apply and not conflict:
                    applied = {call.args[1].group_name: call for call in apply_plan.call_args_list}
                    self.assertEqual(set(applied), {"mixed", "mixed-vpc"})
                    self.assertEqual(applied["mixed"].args[3], ["s"])
                    self.assertEqual(applied["mixed-vpc"].args[3], [])
                    self.assertEqual(applied["mixed"].args[1].serials, ["s"])
                    self.assertEqual(applied["mixed-vpc"].args[1].serials, ["v"])
                else:
                    apply_plan.assert_not_called()

    def test_image_selector_accepts_verified_and_present_images_from_nd(self):
        from nd_interfaces import nd_helpers
        helpers = nd_helpers()
        switch = helpers["Switch"]("S1", "dcmepbmsw001", "", "N9K-C93180YC-EX",
                                    "9.3(8)", "n9k", "", "", "F1")
        for version, filename, status in (
            ("9.3.16", "nxos.9.3.16.bin", "Verified"),
            ("10.3.10", "nxos64-cs.10.3.10.M.bin", "Present"),
            ("10.6.4", "nxos64-cs.10.6.4.M.bin", "Present"),
        ):
            for version_field in ("releaseVersion", "imageVersion", None):
                image = {"imageName": filename, "platform": "n9k",
                         "imagePresent": status, "imageSubType": "nx-os"}
                if version_field:
                    image[version_field] = version
                with self.subTest(version=version, version_field=version_field):
                    self.assertEqual(helpers["select_image"]({"images": [image]}, switch, version), filename)

    def test_image_mapping_disambiguates_without_bypassing_catalog_checks(self):
        from nd_interfaces import nd_helpers
        helpers = nd_helpers()
        switch = helpers["Switch"]("S1", "leaf", "", "N9K-C93180YC-FX",
                                    "10.3(8)", "n9k", "", "", "F1")
        image = {"imageName": "nxos64-cs.10.6.4.M.bin", "platform": "n9k",
                 "releaseVersion": "10.6.4", "imagePresent": "Verified", "imageSubType": "nx-os"}
        other = dict(image, imageName="nxos64-cs.10.6.4.other.bin")
        with self.assertRaisesRegex(ValueError, "Expected one uploaded"):
            helpers["select_image"]([image, other], switch, "10.6.4")
        plan = helpers["make_plan"]("leaf", [switch], [], [image, other],
                                    image_mappings={"10.6.4": image["imageName"]})
        self.assertEqual(plan.image_name, image["imageName"])
        for overrides in (
            {"platform": "n7k"}, {"releaseVersion": "9.3.16"},
            {"imagePresent": "Missing"}, {"imagePresent": "Downloading"},
            {"imageSubType": "kickStart"}, {"imageName": other["imageName"]},
        ):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ValueError, "Requested image"):
                helpers["select_image"]([dict(image, **overrides)], switch, "10.6.4", image["imageName"])
        with self.assertRaisesRegex(ValueError, "status=missing"):
            helpers["select_image"]([dict(image, imagePresent="Missing")], switch, "10.6.4")
        self.assertEqual(helpers["select_image"]([image, image], switch, "10.6.4"), image["imageName"])

    def test_image_mapping_editor_and_cli_validation(self):
        from automation_ui import nd_image_mappings_yaml
        from nd_interfaces import nd_helpers
        helpers = nd_helpers()
        text = 'image_mappings:\n  "9.3.16": nxos.9.3.16.bin\n'
        document = nd_image_mappings_yaml(text)
        self.assertEqual(nd_image_mappings_yaml("image_mappings: {}"), {"image_mappings": {}})
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "input.yaml"
            config.write_text(yaml.safe_dump({"nexus_dashboard": {"host": "nd.example.test"}, **document}))
            args = helpers["parse_args"](["--config", str(config)])
            self.assertEqual(args.image_mappings, document["image_mappings"])
            args = helpers["parse_args"](["--nd-url", "nd.example.test"])
            self.assertEqual(args.image_mappings, {})
        for text in ("", "[", "image_mappings: null", "image_mappings: []", "other: {}",
                     "image_mappings: {}\nother: {}"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                nd_image_mappings_yaml(text)
        for invalid in (None, [], {10.6: "nxos.bin"}, {"bad": "nxos.bin"},
                        {"10.6.4": None}, {"10.6.4": ""}, {"10.6.4": "../nxos.bin"},
                        {"10.6.4": "/tmp/nxos.bin"}, {"10.6.4": "nxos.bin;cmd"},
                        {"10.6.4": "nxos.txt"}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                helpers["load_image_mappings"](invalid)

    def test_image_mappings_reach_both_cli_plan_and_apply_planning(self):
        from nd_interfaces import nd_helpers
        helpers = nd_helpers()
        main = helpers["main"]
        # runpy's function globals, rather than the returned dictionary, drive main.
        globals_ = main.__globals__
        mapping = {"9.3.16": "nxos.9.3.16.bin"}
        checks = [{"reportCheckName": "nxos_mac_address", "cliCommand": "show mac address dynamic | sort"}]

        def request(method, path, payload=None):
            self.assertEqual(method, "GET")
            if path == helpers["SWITCHES"]:
                return [{"switchId": "S1", "switchName": "leaf", "switchModel": "N9K-C93180YC-EX",
                         "switchVersion": "9.3(8)", "switchPlatform": "n9k", "fabricName": "F1"}]
            if path == helpers["IMAGES"]:
                return [{"imageName": filename, "releaseVersion": "9.3.16", "platform": "n9k",
                         "imageSubType": "nx-os", "imagePresent": "Verified"}
                        for filename in ("nxos.9.3.16.bin", "nxos.9.3.16.other.bin")]
            return []

        for apply in (False, True):
            with self.subTest(apply=apply), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "input.yaml"
                config.write_text(yaml.safe_dump({
                    "nexus_dashboard": {"host": "nd.example.test"}, "switches": {"hosts": ["leaf"]},
                    "image_mappings": mapping,
                }))
                client = MagicMock()
                client.request.side_effect = request
                planner = MagicMock(wraps=helpers["make_plan"])
                apply_plan = MagicMock()
                argv = ["nd_stage_nexus_updates.py", "--config", str(config)] + (["--apply"] if apply else [])
                with patch.object(sys, "argv", argv), \
                        patch.dict(os.environ, {"NEXUS_PASSWORD": "synthetic"}), \
                        patch.dict(globals_, {
                            "NexusDashboard": MagicMock(return_value=client),
                            "load_check_catalog": MagicMock(return_value=({}, checks)),
                            "ensure_check_catalog": MagicMock(return_value=checks),
                            "make_plan": planner, "apply_plan": apply_plan,
                        }):
                    self.assertEqual(main(), 0)
                self.assertEqual(planner.call_count, 2 if apply else 1)
                self.assertTrue(all(call.args[-1] == mapping for call in planner.call_args_list))
                if apply:
                    self.assertEqual(apply_plan.call_args.args[1].image_name, "nxos.9.3.16.bin")
                else:
                    apply_plan.assert_not_called()

    def test_bundled_mac_check_is_created_without_existing_definition(self):
        import copy
        from nd_interfaces import nd_helpers
        helpers = nd_helpers()
        # Include every old source except mac_address to reproduce the reported ND catalog.
        sources = [
            {"reportCheckName": name, "checkType": "basic", "cliCommand": "show module",
             "postUpdateDelay": 0, "advancedChecks": [{"checkMustContains": ["preserve"]}]}
            for name in (*helpers["REQUESTED_CHECK_NAMES"], "mac_address")
            if name != "mac_address"
        ]
        original = copy.deepcopy(sources)
        catalog = {item["reportCheckName"]: item for item in sources}

        def request(method, path, payload=None):
            if method == "GET" and path == helpers["REPORT_CHECKS"]:
                return {"updateChecks": copy.deepcopy(list(catalog.values()))}
            if method == "GET":
                return copy.deepcopy(catalog[path.rsplit("/", 1)[-1]])
            if method == "POST":
                for check in payload["updateChecks"]:
                    catalog[check["reportCheckName"]] = copy.deepcopy(check)
                return {}
            if method == "PUT":
                catalog[payload["reportCheckName"]] = copy.deepcopy(payload)
                return {}
            self.fail(f"Unexpected ND call: {method} {path}")

        client = MagicMock()
        client.request.side_effect = request
        current, checks = helpers["load_check_catalog"](client)
        self.assertEqual(len(checks), 21)
        self.assertTrue(all(check["reportCheckName"].startswith("nxos_") for check in checks))
        mac = next(check for check in checks if check["reportCheckName"] == "nxos_mac_address")
        self.assertEqual(mac["cliCommand"], "show mac address dynamic | sort")
        self.assertEqual(mac["advancedChecks"], [])
        self.assertEqual(mac["postUpdateDelay"], 120)
        self.assertEqual(mac["checkType"], "custom")
        client.request.assert_called_once_with("GET", helpers["REPORT_CHECKS"])
        helpers["ensure_check_catalog"](client, current, checks)
        self.assertEqual([catalog[check["reportCheckName"]] for check in original], original)
        self.assertEqual(catalog["nxos_mac_address"], mac)
        self.assertTrue(all(catalog[check["reportCheckName"]]["postUpdateDelay"] == 120 for check in checks))
        for check in checks:
            catalog[check["reportCheckName"]]["postUpdateDelay"] = 360
        client.request.reset_mock()
        current, checks = helpers["load_check_catalog"](client)
        helpers["ensure_check_catalog"](client, current, checks)
        updates = [call for call in client.request.call_args_list if call.args[0] == "PUT"]
        self.assertEqual(len(updates), len(checks))
        self.assertTrue(all(call.args[2]["postUpdateDelay"] == 120 for call in updates))
        self.assertEqual([catalog[check["reportCheckName"]] for check in original], original)
        client.request.reset_mock()
        current, checks = helpers["load_check_catalog"](client)
        helpers["ensure_check_catalog"](client, current, checks)
        self.assertTrue(all(call.args[0] == "GET" for call in client.request.call_args_list))
        existing = dict(original[0], reportCheckName="mac_address", cliCommand="custom command")
        catalog["mac_address"] = copy.deepcopy(existing)
        current, checks = helpers["load_check_catalog"](client)
        helpers["ensure_check_catalog"](client, current, checks)
        self.assertEqual(catalog["mac_address"], existing)
        del catalog["OSPF_state"]
        with self.assertRaisesRegex(ValueError, "OSPF_state"):
            helpers["load_check_catalog"](client)

    def test_upgrade_rules_editor_validates_and_replaces_defaults(self):
        from automation_ui import nd_upgrade_rules_yaml
        from nd_interfaces import nd_helpers
        config = nd_upgrade_rules_yaml("""upgrade_rules:
  - models: ["N9K-C93240YC-FX2"]
    source_version: "10.6"
    target_version: "10.6.4"
""")
        helpers = nd_helpers()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.yaml"
            path.write_text(yaml.safe_dump({"nexus_dashboard": {"host": "nd.example.test"}, **config}))
            args = helpers["parse_args"](["--config", str(path)])
        switch = helpers["Switch"]("S1", "r143b-sw1", "", "N9K-C93240YC-FX2",
                                    "10.6(3)", "n9k", "", "", "F1")
        self.assertIsNone(helpers["target_for"](switch))
        self.assertEqual(helpers["target_for"](switch, args.upgrade_rules), "10.6.4")
        switch = helpers["Switch"]("S2", "other", "", "N9K-C93240YC-FX2",
                                    "10.3(8)", "n9k", "", "", "F1")
        self.assertIsNone(helpers["target_for"](switch, args.upgrade_rules))
        for text in ("", "[", "upgrade_rules: []", "upgrade_rules: null",
                     "switches: {}", "upgrade_rules: []\nother: true",
                     "upgrade_rules:\n- models: ['*']\n  source_version: 10.6\n  target_version: '10.6.4'"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                nd_upgrade_rules_yaml(text)

    def test_legacy_i_train_target_passes_ui_cli_and_exact_image_selection(self):
        from automation_ui import nd_image_mappings_yaml, nd_upgrade_rules_yaml
        from nd_interfaces import nd_helpers
        helpers = nd_helpers()
        target = "7.0.3.I7.10"
        name = "nxos.7.0.3.I7.10.bin"
        rules = nd_upgrade_rules_yaml(
            f"upgrade_rules:\n- models: ['*']\n  source_version: '7.0'\n  target_version: '{target}'")
        mappings = nd_image_mappings_yaml(f"image_mappings:\n  '{target}': {name}")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.yaml"
            path.write_text(yaml.safe_dump({"nexus_dashboard": {"host": "nd.example.test"}, **rules, **mappings}))
            args = helpers["parse_args"](["--config", str(path)])
        switch = helpers["Switch"]("S1", "dcmepibsw002", "", "N9K-C93180YC-EX",
                                   "7.0(3)I7(3)", "n9k", "", "", "F1")
        self.assertEqual(helpers["target_for"](switch, args.upgrade_rules), target)
        image = {"imageName": name, "platform": "n9k", "imagePresent": "Verified", "imageSubType": "nx-os"}
        other = {**image, "imageName": "nxos.7.0.3.I7.3.bin", "releaseVersion": "7.0.3.I7.3"}
        for release in (target, "7.0(3)I7(10)", None):
            catalog = [other, {**image, **({"releaseVersion": release} if release else {})}]
            with self.subTest(release=release):
                plan = helpers["make_plan"]("legacy", [switch], [], catalog, args.upgrade_rules, args.image_mappings)
                self.assertEqual(plan.image_name, name)
                self.assertEqual(plan.target_version, target)
                with self.assertRaisesRegex(ValueError, "found none"):
                    helpers["select_image"]([other], switch, target, other["imageName"])
        for invalid in ("7.0.3.I7", "7.0.3.I.10", "7.0.3.foo.10", "7.0.3.I7.10/evil", "7.0.3..I7.10"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                helpers["load_upgrade_rules"]([{"models": ["*"], "source_version": "7.0", "target_version": invalid}])
            with self.subTest(mapping=invalid), self.assertRaises(ValueError):
                helpers["load_image_mappings"]({invalid: name})

    def test_named_group_selection_matches_the_bundled_script(self):
        selection = nd_switch_selection("named", groups=[
            {"name": "leaf-fx-10_6_4", "hosts": "leaf101, leaf102\nleaf101"},
            {"name": "border-ex-10_3_10", "hosts": "192.0.2.21 192.0.2.22"}])
        self.assertEqual(selection, {"update_groups": {
            "leaf-fx-10_6_4": {"hosts": ["leaf101", "leaf102"]},
            "border-ex-10_3_10": {"hosts": ["192.0.2.21", "192.0.2.22"]}}})
        self.assertNotIn("switches", selection)
        from nd_interfaces import nd_helpers
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.yaml"
            path.write_text(yaml.safe_dump({"nexus_dashboard": {"host": "nd.example.test"}, **selection}, sort_keys=False))
            arguments = nd_helpers()["parse_args"](["--config", str(path)])
        self.assertEqual(arguments.update_groups[0], ("leaf-fx-10_6_4", ["leaf101", "leaf102"]))
        self.assertEqual(arguments.device, [])

    def test_group_selection_rejects_invalid_and_overlapping_groups(self):
        for groups in ([], [{"name": "bad name", "hosts": "leaf101"}], [{"name": "empty", "hosts": ""}],
                       [{"name": "same", "hosts": "leaf101"}, {"name": "same", "hosts": "leaf102"}],
                       [{"name": "first", "hosts": "leaf101"}, {"name": "second", "hosts": "LEAF101"}]):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                nd_switch_selection("named", groups=groups)
        self.assertEqual(nd_switch_selection("per_switch", "leaf101, leaf102 leaf101"),
                         {"switches": {"hosts": ["leaf101", "leaf102"]}})

    def test_staging_implementations_are_bundled_in_this_repository(self):
        directory = Path(__file__).resolve().parent / "nxos-scripts"
        for script in ("nd_stage_nexus_updates.py", "nxos_bootflash_stage.py"):
            path = directory / script
            self.assertTrue(path.is_file())
            result = subprocess.run([sys.executable, str(path), "--help"],
                                    capture_output=True, text=True, check=True)
            self.assertIn("usage:", result.stdout)
        with tempfile.TemporaryDirectory() as temporary:
            job = NXJob("nd", Path(temporary) / "job", {}, {"password": "synthetic"})
            self.assertEqual(job.script.parent, directory)

    def test_nd_defaults_to_plan_and_never_puts_password_in_arguments(self):
        with patch("nxos_jobs.Path.is_file", return_value=True):
            job = NXJob("nd", Path("/tmp/job"), {}, {"password": "top-secret"})
            self.assertNotIn("--apply", job.command())
            self.assertNotIn("top-secret", " ".join(job.command()))
            self.assertEqual(job.redact("token top-secret"), "token [REDACTED]")
            job.apply = True
            self.assertIn("--apply", job.command())

    def test_yaml_rejects_plaintext_passwords(self):
        with self.assertRaises(ValueError):
            reject_plaintext_passwords({"nexus_dashboard": {"password": "secret"}})
        with self.assertRaises(ValueError):
            reject_plaintext_passwords({"nexus_dashboard": {"vault_file": "/etc/private"}})

    def test_bootflash_rejects_custom_ssh_options(self):
        with self.assertRaises(ValueError):
            validate_bootflash_config({"switches": {"ssh_options": ["-oProxyCommand=evil"]}})


class NXProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_group_ui_loads_members_additions_and_invalidates_dashboard(self):
        import automation_ui as web
        from nicegui import ui
        from nicegui.client import Client

        async def io_bound(function, *args):
            return function(*args)

        async def click(button):
            handler = next(listener.handler for listener in button._event_listeners.values()
                           if listener.type == "click")
            await inspect.getclosurevars(handler).nonlocals["callback"]()

        service = MagicMock()
        service.update_groups.return_value = (
            [{"fabric": fabric, "name": "leaf", "members": [fabric + "-serial"]} for fabric in ("F1", "F2")],
            [{"fabric": fabric, "name": fabric + "-switch", "serial": fabric + "-serial"} for fabric in ("F1", "F2")],
        )
        job = MagicMock(cancelled=False)
        job.run = AsyncMock(return_value=0)
        storage = {}
        with tempfile.TemporaryDirectory() as directory, Client(ui.page("/_nd_existing_test")), \
                patch.object(web, "app", SimpleNamespace(storage=SimpleNamespace(user=storage))), \
                patch.object(web, "owner", return_value="operator"), \
                patch.object(web, "dashboard_picker",
                             side_effect=lambda label: ui.select({"nd": "ND", "nd2": "ND2"}, value="nd")), \
                patch.object(web, "STORE", create=True) as store, \
                patch.object(web, "saved_credentials", side_effect=lambda *args: {
                    "username": "netops", "domain": "local", "password": "synthetic"}), \
                patch.object(web, "InterfaceDescriptions", return_value=service) as client_type, \
                patch.object(web.run, "io_bound", side_effect=io_bound), \
                patch.object(web, "output_directory", return_value=Path(directory)), \
                patch.object(web, "NXJob", return_value=job) as factory, \
                patch.object(web, "confirm", new=AsyncMock(return_value=True)), \
                patch.object(web, "notify_error") as error:
            store.dashboards.return_value = [
                {"id": item, "address": item + ".example.test", "verify_tls": True} for item in ("nd", "nd2")]
            with ui.column() as container:
                web.nxos_panel("nd")
            elements = list(container.descendants())
            mode = next(item for item in elements if getattr(item, "options", {}).get("existing") == "Existing update groups")
            mode.value = "existing"
            load = next(item for item in elements if item._props.get("label") == "Load existing update groups")
            start = next(item for item in elements if item._props.get("label") == "Run staging")
            await click(start)
            factory.assert_not_called()
            error.assert_called_once()
            error.reset_mock()
            await click(load)
            client_type.assert_called_once_with("https://nd.example.test", "netops", "synthetic", True, "local")
            service.close.assert_called_once()
            elements = list(container.descendants())
            for fabric in ("F1", "F2"):
                next(item for item in elements if getattr(item, "text", "") == f"{fabric} / leaf").value = True
                self.assertTrue(any(getattr(item, "text", "") == f"Current members: {fabric}-switch [{fabric}-serial]"
                                    for item in elements))
            additions = [item for item in elements if item._props.get("label") == "Additional switches"]
            additions[0].value = "extra, extra"
            for apply in (False, True):
                next(item for item in elements if getattr(item, "text", "") == "Apply staging changes").value = apply
                await click(start)
                error.assert_not_called()
                config = factory.call_args.args[2]
                self.assertNotIn("update_groups", config)
                self.assertEqual(config["parallel_groups"], 10)
                self.assertEqual(config["existing_groups"], [
                    {"fabric": fabric, "name": "leaf", "members": [fabric + "-serial"],
                     "add_hosts": ["extra"] if fabric == "F1" else []} for fabric in ("F1", "F2")])
                self.assertEqual(factory.call_args.kwargs["apply"], apply)
            factory.reset_mock()
            profile = next(item for item in elements if getattr(item, "options", {}) == {"nd": "ND", "nd2": "ND2"})
            profile.value = "nd2"
            await click(start)
            factory.assert_not_called()
            error.assert_called_once()
            self.assertFalse(any(item._props.get("label") == "Additional switches" for item in container.descendants()))
            container.delete()

    async def test_nd_ui_passes_edited_rules_to_plan_and_apply(self):
        import automation_ui as web
        from nicegui import ui
        from nicegui.client import Client
        text = """upgrade_rules:
  - models: ["N9K-C93240YC-FX2"]
    source_version: "10.6"
    target_version: "10.6.4"
"""
        for apply in (False, True):
            with self.subTest(apply=apply), tempfile.TemporaryDirectory() as directory:
                images_text = 'image_mappings:\n  "10.6.4": nxos64-cs.10.6.4.M.bin\n'
                storage = {"nd_upgrade_rules_yaml": text, "nd_image_mappings_yaml": images_text}
                job = MagicMock(cancelled=False)
                job.run = AsyncMock(return_value=0)
                with Client(ui.page("/_nd_rules_test")), \
                        patch.object(web, "app", SimpleNamespace(storage=SimpleNamespace(user=storage))), \
                        patch.object(web, "owner", return_value="operator"), \
                        patch.object(web, "dashboard_picker",
                                     side_effect=lambda label: ui.select({"nd": "ND"}, value="nd")), \
                        patch.object(web, "STORE", create=True) as store, \
                        patch.object(web, "saved_credentials", return_value={
                            "username": "netops", "domain": "local", "password": "synthetic"}), \
                        patch.object(web, "output_directory", return_value=Path(directory)), \
                        patch.object(web, "NXJob", return_value=job) as factory, \
                        patch.object(web, "confirm", new=AsyncMock(return_value=True)), \
                        patch.object(web, "notify_error") as error:
                    store.dashboards.return_value = [{"id": "nd", "address": "nd.example.test", "verify_tls": True}]
                    with ui.column() as container:
                        web.nxos_panel("nd")
                    elements = list(container.descendants())
                    rules = next(element for element in elements
                                 if element._props.get("label") == "Upgrade rules YAML")
                    self.assertEqual(rules.value, text)
                    images = next(element for element in elements
                                  if element._props.get("label") == "Image mappings YAML")
                    self.assertEqual(images.value, images_text)
                    next(element for element in elements
                         if element._props.get("label") == "Update group name").value = "leaf"
                    next(element for element in elements
                         if element._props.get("label") == "Member switches").value = "r143b-sw1"
                    next(element for element in elements
                         if getattr(element, "text", "") == "Apply staging changes").value = apply
                    button = next(element for element in elements
                                  if element._props.get("label") == "Run staging")
                    handler = next(listener.handler for listener in button._event_listeners.values()
                                   if listener.type == "click")
                    start = inspect.getclosurevars(handler).nonlocals["callback"]
                    await start()
                    error.assert_not_called()
                    config = factory.call_args.args[2]
                    self.assertEqual(config["upgrade_rules"], yaml.safe_load(text)["upgrade_rules"])
                    self.assertEqual(config["image_mappings"], yaml.safe_load(images_text)["image_mappings"])
                    self.assertEqual(factory.call_args.kwargs["apply"], apply)
                    job.run.assert_awaited_once()
                    factory.reset_mock()
                    rules.value = "upgrade_rules: []"
                    await start()
                    error.assert_called_once()
                    factory.assert_not_called()
                    error.reset_mock()
                    rules.value = text
                    images.value = "image_mappings: []"
                    await start()
                    error.assert_called_once()
                    factory.assert_not_called()
                    container.delete()

    async def test_child_environment_is_isolated_and_console_is_redacted(self):
        with tempfile.TemporaryDirectory() as directory, patch("nxos_jobs.Path.is_file", return_value=True):
            job = NXJob("nd", Path(directory) / "job", {}, {"password": "synthetic-job-secret"})
            job.command = lambda: [sys.executable, "-c",
                "import os; print(os.environ['DC_ND_PASSWORD']); print('vault-key-inherited', 'DC_AUTOMATION_KEY' in os.environ)"]
            messages = []
            with patch.dict(os.environ, {"DC_AUTOMATION_KEY": "master-secret"}):
                code = await job.run(messages.append)
                self.assertEqual(os.environ["DC_AUTOMATION_KEY"], "master-secret")
                self.assertNotEqual(os.environ.get("DC_ND_PASSWORD"), "synthetic-job-secret")
            self.assertEqual(code, 0)
            self.assertEqual(messages, ["[REDACTED]", "vault-key-inherited False"])
            self.assertNotIn("synthetic-job-secret", (job.directory / "console.log").read_text())
            self.assertEqual(job.credentials, {})


class SnapshotTests(unittest.TestCase):
    @patch("aci_checks.capture_leaf_commands")
    @patch("aci_checks.ApicClient")
    def test_role_specific_capture_preserves_commands_and_uses_shared_dns(self, client_type, capture):
        client_type.return_value.get_class.side_effect = [[
            {"id": "101", "name": "leaf101", "role": "leaf"},
            {"id": "201", "name": "spine201", "role": "spine"},
        ], [{"id": "101", "oobMgmtAddr": "192.0.2.101"}]]

        def output(*args, commands):
            return {command: {"status": "OK", "output": "eth1/1 0 eth trunk up none 10G --"
                              if command == common.COMMAND else "stable"} for command in commands}

        capture.side_effect = output
        profile = {"id": "fabric", "address": "192.0.2.1", "verify_tls": True, "dns_suffix": "obsolete.test"}
        custom = {role: (*commands, "show version") for role, commands in common.ROLE_COMMANDS.items()}
        pre = capture_snapshot(profile, "user", "synthetic", role_commands=custom, dns_domain="corp.test")
        self.assertEqual(len(pre["nodes"][0]["commands"]), 10)
        self.assertEqual(len(pre["nodes"][1]["commands"]), 6)
        self.assertEqual(pre["nodes"][1]["target"], "spine201.corp.test")
        self.assertNotIn("show vpc", pre["nodes"][1]["commands"])
        post = capture_snapshot(profile, "user", "synthetic", baseline=pre, role="spine",
                                role_commands={"leaf": ["show clock"], "spine": ["show clock"]}, dns_domain="corp.test")
        self.assertEqual(len(post["nodes"]), 1)
        self.assertEqual(post["nodes"][0]["target"], "spine201.corp.test")
        self.assertIn("show version", post["nodes"][0]["commands"])
        self.assertNotIn("show clock", post["nodes"][0]["commands"])
        rows = snapshot_results(post, pre)
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(row["role"] == "spine" and row["state"] == "MATCH" for row in rows))
        self.assertEqual(summarize_results(rows)["spine_count"], 1)
        self.assertEqual(filter_results(rows, result="all", role="leaf"), [])

    def test_pre_output_is_only_in_pre_field_even_for_existing_snapshots(self):
        output = "eth1/1 0 eth trunk up none 10G --"
        snapshot = {"phase": "pre", "nodes": [{"leaf": {"node_id": "101", "name": "leaf101"},
                    "error": "", "commands": {common.COMMAND: {"status": "OK", "output": output}}}]}
        row = snapshot_results(snapshot)[0]
        self.assertEqual(row["pre"], output)
        self.assertEqual(row["post"], "")
        self.assertEqual(row["state"], "CAPTURED")

    @patch("aci_checks.capture_leaf_commands")
    @patch("aci_checks.ApicClient")
    def test_pre_post_round_trip_keeps_fabric_and_original_baseline(self, client_type, capture):
        client = client_type.return_value
        client.get_class.side_effect = [[{"id": "101", "name": "leaf101", "role": "leaf", "dn": "topology/pod-1/node-101"}],
                                        [{"id": "101", "oobMgmtAddr": "192.0.2.101"}]]
        capture.return_value = {command: {"status": "OK", "output": "stable"}
                                for command in common.DIAGNOSTIC_COMMANDS}
        capture.return_value[common.COMMAND]["output"] = "eth1/1 0 eth trunk up none 10G --"
        profile = {"id": "fabric", "address": "192.0.2.10", "verify_tls": True}
        pre = capture_snapshot(profile, "netops", "synthetic")
        with tempfile.TemporaryDirectory() as directory:
            path = save_snapshot(Path(directory), pre)
            original = path.read_bytes()
            post = capture_snapshot(profile, "netops", "synthetic", baseline=pre, group="odd")
            save_snapshot(Path(directory), post)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(all(row["state"] == "MATCH" for row in compare_snapshots(pre, post)))
        self.assertTrue(all(row["state"] == "NO_BASELINE"
                    for row in compare_snapshots({**pre, "nodes": []}, post)))
        self.assertEqual(post["baseline_id"], pre["id"])
        rows = {row["command"]: row for row in snapshot_results(post, pre)}
        for command in (common.COMMAND, "show environment"):
            self.assertEqual(rows[command]["post"], post["nodes"][0]["commands"][command]["output"])
        client.login.assert_called_once()
        client.logout.assert_called_once()
        with self.assertRaises(ValueError):
            capture_snapshot({**profile, "id": "other-fabric"}, "netops", "synthetic", baseline=pre)

    def test_capture_history_combines_shared_and_legacy_user_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            common_fields = {"apic_id": "fabric", "apic": "192.0.2.1", "nodes": []}
            legacy = {**common_fields, "id": "legacy", "phase": "pre",
                      "captured_at": "2026-01-01T00:00:00+00:00"}
            shared = {**common_fields, "id": "shared", "phase": "post",
                      "captured_at": "2026-01-02T00:00:00+00:00"}
            save_snapshot(root / "runs" / "user-a" / "aci" / "fabric", legacy)
            save_snapshot(root / "captures" / "aci" / "fabric", shared)
            snapshots = load_snapshots(root, "fabric", "192.0.2.1")
        self.assertEqual([snapshot["id"] for snapshot in snapshots], ["shared", "legacy"])

    def test_age_cleanup_removes_old_captures_but_keeps_baseline_for_retained_post(self):
        now = datetime(2026, 10, 15, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "runs" / "user-a" / "aci" / "fabric"
            shared = root / "captures" / "aci" / "fabric"

            def save(folder, snapshot_id, phase, age_days, baseline_id=None):
                return save_snapshot(folder, {
                    "id": snapshot_id, "phase": phase,
                    "captured_at": (now - timedelta(days=age_days)).isoformat(),
                    "baseline_id": baseline_id, "apic_id": "fabric",
                    "apic": "192.0.2.1", "nodes": [],
                })

            required_pre = save(legacy, "required-pre", "pre", 180)
            retained_post = save(shared, "retained-post", "post", 5, "required-pre")
            old_pre = save(shared, "old-pre", "pre", 120)
            old_post = save(legacy, "old-post", "post", 120, "old-pre")
            deleted = delete_old_snapshots(root, 90, now)
            self.assertEqual(deleted, 2)
            self.assertTrue(required_pre.exists())
            self.assertTrue(retained_post.exists())
            self.assertFalse(old_pre.exists())
            self.assertFalse(old_post.exists())

    def test_age_cleanup_rejects_zero_or_negative_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            for days in (0, -1):
                with self.subTest(days=days), self.assertRaises(ValueError):
                    delete_old_snapshots(Path(directory), days)


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"id": f"{node}:{command}", "node_id": str(node), "name": f"leaf{node}",
                      "command": command, "state": "MATCH", "detail": "", "pre": "large pre output",
                      "post": "large post output"} for node in range(101, 401)
                     for command in common.DIAGNOSTIC_COMMANDS]
        self.rows[0].update(state="REVIEW", detail="eth1/1: up -> down link-not-connected")
        self.rows[1].update(state="ERROR", detail="SSH timeout")
        self.rows[9].update(state="NO_BASELINE", detail="No pre output")

    def test_summary_counts_leaves_not_checks_and_prioritizes_incomplete_verification(self):
        summary = summarize_results(self.rows)
        self.assertEqual(summary["total"], 300)
        self.assertEqual(summary["attention"], 2)
        self.assertEqual(summary["matched"], 298)
        first = summary["leaves"][0]
        self.assertEqual(first["state"], "ERROR")
        self.assertEqual(first["review"], 1)
        self.assertEqual(first["errors"], 1)
        self.assertIn("up -> down", first["context"])

    def test_exact_result_filters_and_context_without_raw_output(self):
        reviews = filter_results(self.rows, result="REVIEW")
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["node_id"], "101")
        self.assertIn("1 port change", reviews[0]["context"])
        self.assertNotIn("pre", reviews[0])
        self.assertEqual(len(filter_results(self.rows)), 3)
        self.assertEqual(len(filter_results(self.rows, result="all", node_id="102")), 9)
        self.assertEqual(len(filter_results(self.rows, result="all", command=common.COMMAND)), 300)
        self.assertEqual(len(filter_results(self.rows, result="all", search="SSH timeout")), 1)

    def test_pre_captures_are_not_reported_as_post_matches(self):
        for row in self.rows:
            row.update(state="CAPTURED", detail="")
        summary = summarize_results(self.rows)
        self.assertEqual(summary["captured"], 300)
        self.assertEqual(summary["matched"], 0)
        self.assertEqual(summary["attention"], 0)
        self.assertEqual(summarize_results([])["total"], 0)


class CaptureTests(unittest.TestCase):
    def test_discovery_includes_leaf_and_spine_roles(self):
        from unittest.mock import MagicMock
        client = MagicMock()
        client.get_class.side_effect = [[
            {"id": "101", "name": "leaf101", "role": "leaf", "dn": "topology/pod-1/node-101"},
            {"id": "201", "name": "spine201", "role": "spine", "dn": "topology/pod-1/node-201"},
            {"id": "1", "role": "controller"},
        ], [{"id": "101", "oobMgmtAddr": "192.0.2.101"}, {"id": "201", "oobMgmtAddr": "192.0.2.201"}]]
        nodes = common.discover_active_nodes(client)
        self.assertEqual([node["role"] for node in nodes], ["leaf", "spine"])
        self.assertEqual(nodes[1]["oob_ip"], "192.0.2.201")
        self.assertIn('eq(fabricNode.role,"spine")', client.get_class.call_args_list[0].args[1])

    def test_role_defaults_and_safe_custom_commands(self):
        commands = common.validate_role_commands()
        self.assertEqual(set(commands["spine"]), set(common.SHARED_DIAGNOSTIC_COMMANDS))
        self.assertTrue(set(common.LEAF_ONLY_COMMANDS).issubset(commands["leaf"]))
        self.assertTrue(set(common.LEAF_ONLY_COMMANDS).isdisjoint(commands["spine"]))
        custom = common.validate_role_commands({"leaf": ["show version"], "spine": ["show version"]})
        self.assertEqual(custom["spine"], ("show version",))
        for command in ("show vpc", "SHOW  VPC", "show mac address-table dynamic"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                common.validate_role_commands({"leaf": ["show version"], "spine": [command]})
        for command in ("show version > bootflash:test", "show version & reload", "show version\t", "show version\\"):
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                common.assert_read_only(command)

    def test_only_exact_mac_pipeline_is_permitted(self):
        for command in common.DIAGNOSTIC_COMMANDS:
            common.assert_read_only(command)
        for command in ("configure terminal", "show vpc; reload", "show vpc\nreload",
                        "show vpc | bash", "show mac address-table dynamic | egrep -v tun; reload",
                        "show mac address-table dynamic | egrep -v tun\n"):
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                common.assert_read_only(command)

    @patch.object(common, "ConnectHandler")
    def test_bundle_uses_one_session_and_retains_invalid_output(self, connect):
        session = connect.return_value
        session.send_command.side_effect = ["eth1/1 0 eth trunk up none 10G --",
                                            "% Invalid command", "vPC status: up"]
        results = common.capture_leaf_commands(
            "192.0.2.1", "operator", "secret", commands=common.DIAGNOSTIC_COMMANDS[:3],
        )
        connect.assert_called_once()
        session.disconnect.assert_called_once()
        self.assertEqual(results["show environment"]["status"], "ERROR")
        self.assertEqual(results["show vpc"]["status"], "OK")

    @patch.object(common, "ConnectHandler")
    def test_mutating_command_is_rejected_before_connect(self, connect):
        with self.assertRaises(RuntimeError):
            common.capture_leaf_commands("host", "user", "secret", commands=("configure terminal",))
        connect.assert_not_called()

    def test_selection(self):
        leaves = [{"node_id": "101"}, {"node_id": "102"}]
        self.assertEqual(select_leaves(leaves, "odd"), leaves[:1])
        self.assertEqual(select_leaves(leaves, "even"), leaves[1:])
        self.assertEqual(select_leaves(leaves, "nodes", "102,102"), leaves[1:])
        with self.assertRaises(ValueError):
            select_leaves(leaves, "nodes", "999")

    def test_comparison_separates_interface_status_from_raw_review(self):
        import copy
        pre = {"apic_id": "fabric", "apic": "192.0.2.1", "nodes": [{
            "leaf": {"node_id": "101", "name": "leaf101"}, "error": "",
            "commands": {command: {"status": "OK", "output": "stable"}
                         for command in common.DIAGNOSTIC_COMMANDS}}]}
        pre["nodes"][0]["commands"][common.COMMAND]["output"] = "eth1/1 0 eth trunk up none 10G --"
        post = copy.deepcopy(pre)
        post["nodes"][0]["commands"][common.COMMAND]["output"] = "eth1/1 0 eth trunk down link 10G --"
        post["nodes"][0]["commands"]["show environment"]["output"] = "new temperature"
        post["nodes"][0]["commands"]["show vpc"]["status"] = "ERROR"
        rows = {row["command"]: row for row in compare_snapshots(pre, post)}
        self.assertIn("up -> down", rows[common.COMMAND]["detail"])
        self.assertEqual(rows["show environment"]["state"], "REVIEW")
        self.assertEqual(rows["show vpc"]["state"], "ERROR")
        self.assertEqual(rows["show module"]["state"], "MATCH")
        pre["nodes"][0]["commands"]["show module"]["status"] = "ERROR"
        self.assertEqual(compare_snapshots(pre, post)[6]["state"], "NO_BASELINE")

    def test_environment_comparison_ignores_power_draw_but_checks_model_and_status(self):
        import copy
        pre = {"apic_id": "fabric", "apic": "192.0.2.1", "nodes": [{
            "leaf": {"node_id": "101", "name": "leaf101"}, "error": "",
            "commands": {"show environment": {"status": "OK", "output": ""}},
        }]}
        pre_output = (
            "Supply    Model                    Output     Capacity    Status\n"
            "                                 (Watts )     (Watts )\n"
            "-------  -------------------  -----------  -----------  --------------\n"
            "1        NXA-PAC-1100W-PI2          132 W       1100 W        ok\n"
            "2        NXA-PAC-1100W-PI2          114 W       1100 W        ok\n\n"
            "Module     Model                     Draw    Allocated    Status\n"
            "                                  (Watts )     (Watts )\n"
            "--------  -------------------  -----------  -----------  --------------\n"
            "1         N9K-C9332C                 246 W        600 W    Powered-Up\n"
            "fan1      NXA-FAN-35CFM-PI             N/A          N/A    Powered-Up\n\n"
            "Total Power Capacity (based on configured mode)                2200 W\n"
            "Total Power of all Inputs (cumulative)                         2200 W\n"
            "Total Power Output (actual draw)                                246 W\n"
            "Total Power Allocated (budget)                                N/A\n"
            "Total Power Available for additional modules                  N/A\n"
        )
        pre["nodes"][0]["commands"]["show environment"]["output"] = pre_output
        post = copy.deepcopy(pre)
        post_output = (pre_output.replace("132 W", "134 W").replace("114 W", "116 W")
                       .replace("246 W", "250 W"))
        post["nodes"][0]["commands"]["show environment"]["output"] = post_output
        rows = {row["command"]: row for row in compare_snapshots(pre, post)}
        self.assertEqual(rows["show environment"]["state"], "MATCH")
        post_output = post_output.replace("N9K-C9332C", "N9K-C9336C")
        post["nodes"][0]["commands"]["show environment"]["output"] = post_output
        changed_model = {row["command"]: row for row in compare_snapshots(pre, post)}["show environment"]
        self.assertEqual(changed_model["state"], "REVIEW")
        self.assertIn("model=N9K-C9332C", changed_model["detail"])
        post_output = pre_output.replace("        ok", "        failed", 1)
        post["nodes"][0]["commands"]["show environment"]["output"] = post_output
        rows = {row["command"]: row for row in compare_snapshots(pre, post)}
        self.assertEqual(rows["show environment"]["state"], "REVIEW")

    def test_isis_comparison_ignores_hold_time_but_checks_adjacency_identity_and_state(self):
        import copy
        pre_output = (
            "IS-IS process: isis_infra VRF:overlay-1\n"
            "IS-IS adjacency database:\n"
            "System ID         SNPA            Level  State  Hold Time  Interface\n"
            "4370.4064.0000     N/A            1      UP     00:00:55   Ethernet1/31.35\n"
            "4270.4064.0000     N/A            1      UP     00:01:01   Ethernet1/32.36\n"
        )
        pre = {"apic_id": "fabric", "apic": "192.0.2.1", "nodes": [{
            "leaf": {"node_id": "101", "name": "leaf101"}, "error": "",
            "commands": {"show isis adjacency vrf all": {"status": "OK", "output": pre_output}},
        }]}
        post = copy.deepcopy(pre)
        post_output = pre_output.replace("00:00:55", "00:00:51").replace("00:01:01", "00:00:55")
        post["nodes"][0]["commands"]["show isis adjacency vrf all"]["output"] = post_output
        rows = {row["command"]: row for row in compare_snapshots(pre, post)}
        self.assertEqual(rows["show isis adjacency vrf all"]["state"], "MATCH")
        post_output = post_output.replace("N/A            1      UP", "changed-snpa    2      UP")
        post["nodes"][0]["commands"]["show isis adjacency vrf all"]["output"] = post_output
        rows = {row["command"]: row for row in compare_snapshots(pre, post)}
        self.assertEqual(rows["show isis adjacency vrf all"]["state"], "MATCH")
        post_output = post_output.replace("UP     00:00:51", "DOWN   00:00:51")
        post["nodes"][0]["commands"]["show isis adjacency vrf all"]["output"] = post_output
        changed_state = {row["command"]: row for row in compare_snapshots(pre, post)}["show isis adjacency vrf all"]
        self.assertEqual(changed_state["state"], "REVIEW")
        self.assertIn("state=DOWN", changed_state["detail"])
        post_output = pre_output.replace("Ethernet1/31.35", "Ethernet1/31.36")
        post["nodes"][0]["commands"]["show isis adjacency vrf all"]["output"] = post_output
        rows = {row["command"]: row for row in compare_snapshots(pre, post)}
        self.assertEqual(rows["show isis adjacency vrf all"]["state"], "REVIEW")

    @patch("aci_checks.capture_leaf_commands")
    def test_post_auth_rejection_stops_unproven_credentials(self, capture):
        from netmiko.exceptions import NetmikoAuthenticationException
        capture.side_effect = NetmikoAuthenticationException("rejected")
        baseline = {"id": "pre", "apic_id": "fabric", "apic": "192.0.2.1", "nodes": [
            {"leaf": {"node_id": str(node), "name": f"leaf{node}", "oob_ip": "192.0.2.2"}}
            for node in range(101, 105)]}
        snapshot = capture_snapshot({"id": "fabric", "address": "192.0.2.1"},
                                    "user", "wrong", baseline=baseline)
        capture.assert_called_once()
        self.assertTrue(all(entry["error"] for entry in snapshot["nodes"]))


class ProfileTests(unittest.TestCase):
    def test_login_domain_is_inherited_and_can_be_overridden_per_server(self):
        first = self.store.save_apic("First", "192.0.2.1")
        second = self.store.save_apic("Second", "192.0.2.2")
        shared = profile_credential_values({}, "netops", "synthetic", domain="SharedAAA")
        self.store.save_credentials("operator", "aci-default", shared)
        self.assertEqual(self.store.effective_credentials("operator", "apic", first)["domain"], "SharedAAA")
        special = profile_credential_values(shared, "netops", "", domain="ServerAAA")
        self.store.save_credentials("operator", "aci:" + first, special)
        self.assertEqual(self.store.effective_credentials("operator", "apic", first)["domain"], "ServerAAA")
        self.assertEqual(self.store.effective_credentials("operator", "apic", second)["domain"], "SharedAAA")
        self.store.save_credentials("operator", "nd-default", {**shared, "domain": "ND-LDAP", "rescue_password": "synthetic-rescue"})
        dashboard = self.store.save_dashboard("ND", "nd.example.test")
        self.assertEqual(self.store.effective_credentials("operator", "dashboard", dashboard)["domain"], "ND-LDAP")
        with self.assertRaises(ValueError):
            profile_credential_values(shared, "netops", "", domain="bad\ndomain")

    def test_existing_server_accounts_keep_their_original_login_domain(self):
        profile = self.store.save_apic("Legacy", "192.0.2.1", domain="OriginalAAA")
        self.store.save_credentials("operator", "aci:" + profile, {"username": "legacy", "password": "synthetic"})
        self.store.save_credentials("operator", "aci-default", {"username": "shared", "password": "synthetic", "domain": "SharedAAA"})
        self.assertEqual(self.store.effective_credentials("operator", "apic", profile)["domain"], "OriginalAAA")
        self.store.forget_credentials("operator", "aci:" + profile)
        self.assertEqual(self.store.effective_credentials("operator", "apic", profile)["domain"], "SharedAAA")

    def test_shared_accounts_and_server_overrides_are_scoped_per_user(self):
        first = self.store.save_apic("First", "192.0.2.1")
        second = self.store.save_apic("Second", "192.0.2.2")
        self.store.save_credentials("operator", "aci-default", {"username": "shared", "password": "shared-secret"})
        for profile_id in (first, second):
            self.assertEqual(self.store.effective_credentials("operator", "apic", profile_id)["username"], "shared")
        self.store.save_credentials("operator", "aci:" + first, {"username": "special", "password": "special-secret"})
        self.assertEqual(self.store.effective_credentials("operator", "apic", first)["username"], "special")
        self.assertEqual(self.store.effective_credentials("operator", "apic", second)["username"], "shared")
        self.assertEqual(self.store.effective_credentials("other-user", "apic", second), {})
        self.store.forget_credentials("operator", "aci:" + first)
        self.assertEqual(self.store.effective_credentials("operator", "apic", first)["password"], "shared-secret")
        self.store.save_credentials("operator", "nd-default", {"username": "nd-user", "password": "nd-secret", "rescue_password": "rescue-secret"})
        self.store.save_credentials("operator", "nd-profile:nd-one", {"rescue_password": "special-rescue"})
        resolved = self.store.effective_credentials("operator", "dashboard", "nd-one")
        self.assertEqual(resolved["username"], "nd-user")
        self.assertEqual(resolved["rescue_password"], "special-rescue")
        self.assertNotIn(b"shared-secret", self.store.path.read_bytes())

    def test_apic_login_domain_persists_and_invalidates_old_credentials(self):
        profile = self.store.save_apic("ACI", "192.0.2.1", domain="TACACS")
        self.store.save_credentials("operator", "aci:" + profile, {"username": "netops", "password": "synthetic"})
        self.store.save_apic("Renamed", "192.0.2.1", profile_id=profile)
        self.assertEqual(self.store.apics()[0]["domain"], "TACACS")
        self.assertTrue(self.store.credentials("operator", "aci:" + profile))
        self.store.save_apic("Renamed", "192.0.2.1", profile_id=profile, domain="local")
        self.assertEqual(self.store.credentials("operator", "aci:" + profile), {})
        self.assertEqual(common.aci_login_username("netops", "TACACS"), "apic:TACACS\\netops")
        self.assertEqual(common.aci_login_username("netops", "local"), "netops")

    def test_dashboard_inventory_and_credentials_are_independent_of_apics(self):
        profile = self.store.save_dashboard("ND Production", "https://ND.example.com/", domain="local")
        self.store.save_credentials("operator", "nd-profile:" + profile, {"username": "netops", "password": "nd-secret"})
        reopened = ProfileStore(self.root / "data", self.root / "keys" / "vault.key")
        self.assertEqual(reopened.dashboards(), [{"id": profile, "name": "ND Production", "address": "nd.example.com",
                                                 "domain": "local", "verify_tls": 1}])
        self.assertEqual(reopened.apics(), [])
        self.assertNotIn(b"nd-secret", self.store.path.read_bytes())
        self.store.save_dashboard("Renamed", "nd.example.com", profile_id=profile)
        self.assertTrue(self.store.credentials("operator", "nd-profile:" + profile))
        self.store.save_dashboard("Renamed", "nd.example.com", domain="external", profile_id=profile)
        self.assertEqual(self.store.credentials("operator", "nd-profile:" + profile), {})
        self.store.delete_dashboard(profile)
        self.assertEqual(self.store.dashboards(), [])

    def test_per_apic_command_lists_persist_and_validate(self):
        first = self.store.save_apic("First", "192.0.2.1")
        second = self.store.save_apic("Second", "192.0.2.2")
        self.store.save_aci_commands(first, {"leaf": ["show version"], "spine": ["show module"]})
        reopened = ProfileStore(self.root / "data", self.root / "keys" / "vault.key")
        self.assertEqual(reopened.aci_commands(first)["leaf"], ("show version",))
        self.assertIn("show vpc", reopened.aci_commands(second)["leaf"])
        with self.assertRaises(RuntimeError):
            self.store.save_aci_commands(first, {"leaf": ["reload"], "spine": ["show version"]})
        self.store.delete_apic(first)
        self.assertIn("show vpc", self.store.aci_commands(first)["leaf"])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = patch.dict(os.environ, {}, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop("DC_AUTOMATION_KEY", None)
        self.store = ProfileStore(self.root / "data", self.root / "keys" / "vault.key")
        self.store.add_user("operator", "test-web-password")

    def test_apic_list_survives_restart_without_secrets(self):
        profile = self.store.save_apic("Fabric A", "https://APIC.example.com/")
        reopened = ProfileStore(self.root / "data", self.root / "keys" / "vault.key")
        self.assertEqual(reopened.apics(), [{"id": profile, "name": "Fabric A",
                                            "address": "apic.example.com", "verify_tls": 1, "domain": "local"}])

    def test_shared_dns_domain_persists_independently_of_apic_profiles(self):
        first = self.store.save_apic("First", "192.0.2.1")
        second = self.store.save_apic("Second", "192.0.2.2")
        self.assertEqual(self.store.dns_domain(), "")
        self.store.set_dns_domain(".Corp.Example.NET.")
        self.store.save_apic("Renamed", "192.0.2.1", profile_id=first)
        reopened = ProfileStore(self.root / "data", self.root / "keys" / "vault.key")
        profiles = {profile["id"]: profile for profile in reopened.apics()}
        self.assertEqual(reopened.dns_domain(), "corp.example.net")
        self.assertNotIn("dns_suffix", profiles[first])
        self.assertNotIn("dns_suffix", profiles[second])
        self.assertEqual(common.fqdn("leaf101"), "leaf101")
        self.assertEqual(common.fqdn("leaf101", reopened.dns_domain()), "leaf101.corp.example.net")
        self.assertEqual(common.fqdn("leaf101.other.net", "corp.example.net"), "leaf101.other.net")
        self.assertEqual(common.fqdn("192.0.2.1", "corp.example.net"), "192.0.2.1")
        self.assertEqual(common.fqdn("2001:db8::1", "corp.example.net"), "2001:db8::1")
        with self.assertRaises(ValueError):
            self.store.set_dns_domain("https://domain.example")
        self.store.delete_apic(first)
        self.assertEqual(self.store.dns_domain(), "corp.example.net")
        self.store.set_dns_domain("")
        self.assertEqual(ProfileStore(self.root / "data", self.root / "keys" / "vault.key").dns_domain(), "")

    def test_legacy_domains_migrate_only_when_unambiguous(self):
        first = self.store.save_apic("First", "192.0.2.1")
        second = self.store.save_apic("Second", "192.0.2.2")
        with self.store.connection() as database:
            database.execute("ALTER TABLE apics ADD COLUMN dns_suffix TEXT NOT NULL DEFAULT ''")
            database.execute("UPDATE apics SET dns_suffix = 'corp.test'")
            database.execute("DELETE FROM settings WHERE key = 'dns_domain'")
        migrated = ProfileStore(self.root / "data", self.root / "keys" / "vault.key")
        self.assertEqual(migrated.dns_domain(), "corp.test")
        with migrated.connection() as database:
            database.execute("UPDATE apics SET dns_suffix = 'other.test' WHERE id = ?", (second,))
            database.execute("DELETE FROM settings WHERE key = 'dns_domain'")
        conflicted = ProfileStore(self.root / "data", self.root / "keys" / "vault.key")
        self.assertEqual(conflicted.dns_domain(), "")
        self.assertEqual(conflicted.dns_domain_conflicts(), ["corp.test", "other.test"])
        conflicted.set_dns_domain("shared.test")
        self.assertEqual(conflicted.dns_domain_conflicts(), [])
        self.assertEqual(ProfileStore(self.root / "data", self.root / "keys" / "vault.key").dns_domain(), "shared.test")

    def test_encrypted_credentials_are_scoped_to_user_and_apic(self):
        self.store.save_credentials("operator", "aci:one", {"username": "netops", "password": "device-secret"})
        self.assertEqual(self.store.credentials("operator", "aci:one")["password"], "device-secret")
        self.assertEqual(self.store.credentials("other", "aci:one"), {})
        self.assertEqual(self.store.credentials("operator", "aci:two"), {})
        self.assertNotIn(b"device-secret", self.store.path.read_bytes())
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        self.store.forget_credentials("operator", "aci:one")
        self.assertEqual(self.store.credentials("operator", "aci:one"), {})

    def test_authentication(self):
        self.assertTrue(self.store.authenticate("operator", "test-web-password"))
        self.assertFalse(self.store.authenticate("operator", "wrong"))
        self.assertFalse(self.store.authenticate("missing", "wrong"))
        account = self.store.login_account("operator", "test-web-password")
        self.assertEqual(set(account), {"username", "role", "auth_version", "theme"})
        self.assertEqual(self.store.login_account("operator", "wrong"), {})
        self.assertNotIn(b"test-web-password", self.store.path.read_bytes())

    def test_oidc_config_is_admin_only_group_mapped_and_secret_is_encrypted(self):
        self.store.add_user("administrator", "test-admin-password")
        self.store.create_user("operator", "regular", "test-regular-password", "operator")
        with self.assertRaises(ValueError):
            self.store.save_oidc_settings("regular", "https://issuer.example/tenant", "client", "secret",
                                          "admins", "operators", True)
        with self.assertRaises(ValueError):
            self.store.save_oidc_settings("administrator", "http://issuer.example/tenant", "client", "secret",
                                          "admins", "operators", True)
        with self.assertRaises(ValueError):
            self.store.save_oidc_settings("administrator", "https://issuer.example/tenant", "client", "secret",
                                          "same-group", "same-group", True)
        with self.assertRaises(ValueError):
            self.store.save_oidc_settings("administrator", "https://issuer.example/tenant", "client", "secret",
                                          "", "operators", True)
        config = self.store.save_oidc_settings("administrator", "https://issuer.example/tenant/", "client",
                                               "client-secret", "admins\nadmins", "operators", True)
        self.assertEqual(config["issuer"], "https://issuer.example/tenant")
        self.assertEqual(config["admin_groups"], ["admins"])
        self.assertEqual(self.store.oidc_client_secret(), "client-secret")
        self.assertNotIn(b"client-secret", self.store.path.read_bytes())
        self.assertEqual(self.store.save_oidc_settings("administrator", "https://issuer.example/tenant", "client",
                                                        "", "admins", "operators", True)["client_secret_saved"], True)

    def test_oidc_identity_uses_stable_subject_and_refreshes_role(self):
        first = self.store.login_oidc("https://issuer.example/tenant", "subject-1", "person@example.com",
                                      "Person Example", "admin")
        old_version = first["auth_version"]
        second = self.store.login_oidc("https://issuer.example/tenant", "subject-1", "new-name@example.com",
                                       "Person New", "operator")
        self.assertEqual(second["username"], first["username"])
        self.assertEqual(second["role"], "operator")
        self.assertEqual(second["auth_version"], old_version + 1)
        self.assertEqual(second["display_name"], "Person New")
        self.store.add_user("admin", "admin-web-password")
        collision = self.store.login_oidc("https://issuer.example/tenant", "subject-2", "admin",
                                          "Admin Imitator", "operator")
        self.assertNotEqual(collision["username"], "admin")
        self.assertEqual(self.store.user("admin")["role"], "admin")


    def test_group_mapping_requires_authorized_group_and_rejects_overage(self):
        config = validate_oidc_config("https://login.microsoftonline.com/tenant/v2.0", "client-id",
                                      "admin-group\nshared", "operator-group")
        self.assertEqual(role_from_claims({"groups": ["operator-group"]}, config), "operator")
        self.assertEqual(role_from_claims({"groups": ["shared"]}, config), "admin")
        for claims in ({"groups": ["unmapped"]}, {"_claim_names": {"groups": "src"}}, {"hasgroups": True}, {}):
            with self.subTest(claims=claims), self.assertRaises(OIDCLoginError):
                role_from_claims(claims, config)

    def test_oidc_client_uses_tenant_discovery_and_pkce(self):
        config = validate_oidc_config("https://login.microsoftonline.com/tenant/v2.0", "client-id",
                                      "admin-group", "operator-group")
        client = create_oidc_client(config, "client-secret")
        self.assertEqual(client.client_kwargs["code_challenge_method"], "S256")
        self.assertEqual(client._server_metadata_url,
                         "https://login.microsoftonline.com/tenant/v2.0/.well-known/openid-configuration")

    def test_release_asset_names_and_cli_instructions_are_versioned_and_verified(self):
        tag = "v1.2.3"
        archive = f"cisco-dc-operations-{tag}.tar.gz"
        release = release_details({"tag_name": tag, "name": "Stable release", "html_url": "https://github.com/example/release",
                                   "assets": [{"name": archive}, {"name": archive + ".sha256"}]})
        commands = install_instructions(release["tag"])
        self.assertEqual(release["archive_name"], archive)
        self.assertIn("sudo /usr/local/sbin/cisco-dc-update --version v1.2.3", commands)
        self.assertNotIn("curl", commands)
        self.assertNotIn("--yes", commands)
        with self.assertRaises(ValueError):
            release_details({"tag_name": "latest", "assets": []})
        with self.assertRaises(ValueError):
            release_details({"tag_name": tag, "assets": [{"name": archive}]})
        with self.assertRaises(ValueError):
            install_instructions("main")

    def test_update_checker_handles_no_releases_without_auth_or_secrets(self):
        response = type("Response", (), {"status_code": 404})()
        with patch("release_updates.requests.get", return_value=response) as get:
            with self.assertRaisesRegex(ValueError, "No published releases"):
                latest_release()
        get.assert_called_once_with(RELEASES_API, headers={"Accept": "application/vnd.github+json"}, timeout=10.0)

    def test_only_admin_can_create_users_and_duplicates_do_not_reset_passwords(self):
        self.store.create_user("operator", "engineer", "engineer-password")
        self.assertEqual(self.store.user("engineer")["role"], "operator")
        with self.assertRaises(ValueError):
            self.store.create_user("engineer", "intruder", "intruder-password", "admin")
        with self.assertRaises(ValueError):
            self.store.users("engineer")
        with self.assertRaises(ValueError):
            self.store.create_user("operator", "engineer", "replacement-password")
        self.assertTrue(self.store.authenticate("engineer", "engineer-password"))
        self.assertEqual(len(self.store.users("operator")), 2)

    def test_password_change_preserves_credentials_and_revokes_other_sessions(self):
        self.store.save_credentials("operator", "aci:test", {"password": "device-secret"})
        previous = self.store.user("operator")["auth_version"]
        for current, new, confirmation in (("wrong", "new-password-123", "new-password-123"),
                                            ("test-web-password", "short", "short"),
                                            ("test-web-password", "new-password-123", "mismatch"),
                                            ("test-web-password", "test-web-password", "test-web-password")):
            with self.subTest(current=current, new=new), self.assertRaises(ValueError):
                self.store.change_password("operator", current, new, confirmation)
        self.store.change_password("operator", "test-web-password", "new-password-123", "new-password-123")
        self.assertFalse(self.store.authenticate("operator", "test-web-password"))
        self.assertTrue(self.store.authenticate("operator", "new-password-123"))
        self.assertEqual(self.store.user("operator")["auth_version"], previous + 1)
        self.assertEqual(self.store.credentials("operator", "aci:test")["password"], "device-secret")

    def test_theme_persists_for_each_account(self):
        self.store.create_user("operator", "engineer", "engineer-password")
        self.store.set_theme("operator", "dark")
        reopened = ProfileStore(self.root / "data", self.root / "keys" / "vault.key")
        self.assertEqual(reopened.user("operator")["theme"], "dark")
        self.assertEqual(reopened.user("engineer")["theme"], "light")

    def test_existing_database_migrates_without_losing_accounts(self):
        legacy_dir = self.root / "legacy"
        legacy_dir.mkdir()
        with sqlite3.connect(legacy_dir / "profiles.sqlite3") as database:
            database.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT NOT NULL)")
            database.execute("INSERT INTO users VALUES ('first', 'existing-hash')")
            database.execute("INSERT INTO users VALUES ('second', 'existing-hash')")
        migrated = ProfileStore(legacy_dir, self.root / "keys" / "vault.key")
        self.assertEqual(migrated.user("first")["role"], "admin")
        self.assertEqual(migrated.user("second")["role"], "operator")

    def test_changing_apic_address_invalidates_credentials(self):
        profile = self.store.save_apic("Fabric", "192.0.2.1")
        self.store.save_credentials("operator", "aci:" + profile, {"password": "secret"})
        self.store.save_apic("Fabric", "192.0.2.2", profile_id=profile)
        self.assertEqual(self.store.credentials("operator", "aci:" + profile), {})
        self.store.delete_apic(profile)
        self.assertEqual(self.store.apics(), [])

    def test_reject_credentials_and_paths_in_apic_addresses(self):
        for address in ("http://apic", "https://user:password@apic", "apic/api", "apic?x=1", ""):
            with self.subTest(address=address), self.assertRaises(ValueError):
                normalize_apic(address)


if __name__ == "__main__":
    unittest.main()