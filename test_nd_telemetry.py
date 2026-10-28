import copy
import inspect
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from nd_telemetry import (TelemetryPush, TelemetrySSH, configuration_lines, discover_source,
                          push_plans, replace_source, selected_switches, source_interface,
                          telemetry_selection)


TEMPLATE = """
configure terminal
feature telemetry
feature grpc
telemetry
  destination-profile
    use-vrf default
    source-interface vlan64
  destination-group 500
    ip address 192.0.2.20 port 57500 protocol gRPC encoding GPB
  sensor-group 500
    data-source NX-API
    path "show processes cpu" depth unbounded
  sensor-group 501
    data-source DME
    path sys/ch query-condition query-target=subtree&target-subtree-class=eqptPsu
  subscription 500
    dst-grp 500
    snsr-grp 500 sample-interval 295000
end
"""
INVENTORY = [{"serial": "SERIAL1", "name": "leaf1", "address": "192.0.2.101", "fabric": "Fabric / A"},
             {"serial": "SERIAL2", "name": "leaf2", "address": "192.0.2.102", "fabric": "Fabric / A"}]
SELECTION = {"switches": {"username": "netops", "hosts": ["leaf1"]}, "source_interfaces": {}}


class TelemetryInputTests(unittest.TestCase):
    def test_yaml_requires_switch_username_hosts_and_rejects_embedded_passwords(self):
        valid = "switches:\n  username: netops\n  hosts: [leaf1]\nsource_interfaces:\n  leaf1: Vlan72\n"
        self.assertEqual(telemetry_selection(valid)["source_interfaces"], {"leaf1": "Vlan72"})
        for text in ("[]", "switches: {}", valid + "password: secret\n",
                     valid.replace("Vlan72", "'vlan72\\nreload'"),
                     valid.replace("leaf1: Vlan72", "other: Vlan72"),
                     valid.replace("[leaf1]", "[leaf1, LEAF1]"),
                     valid.replace("netops", "'-l other'"),
                     valid.replace("[leaf1]", "leaf1")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                telemetry_selection(text)

    def test_switch_resolution_accepts_name_serial_and_address_without_ambiguity(self):
        for host in ("LEAF1", "SERIAL1", "192.0.2.101"):
            self.assertEqual(selected_switches(INVENTORY, [host])[0]["serial"], "SERIAL1")
        for hosts in (["missing"], ["leaf1", "SERIAL1"]):
            with self.assertRaises(ValueError):
                selected_switches(INVENTORY, hosts)
        with self.assertRaises(ValueError):
            selected_switches(INVENTORY + [{**INVENTORY[1], "name": "leaf1"}], ["leaf1"])
        fqdn = [{**INVENTORY[0], "name": "Leaf1.corp.example"}]
        self.assertEqual(selected_switches(fqdn, ["leaf1"])[0]["serial"], "SERIAL1")
        with self.assertRaisesRegex(ValueError, r"found 0.*ND returned 1 switches: Leaf1\.corp\.example"):
            selected_switches(fqdn, ["leaf2"])
        with self.assertRaises(ValueError):
            selected_switches(fqdn, ["leaf1.other.example"])

    def test_source_discovery_matches_exact_management_ip_and_normalizes_aliases(self):
        output = ("IP Interface Status for VRF default(1)\n"
                  "Interface IP Address Interface Status\n"
                  "Vlan1 192.0.2.10 protocol-up/link-up/admin-up\n"
                  "Vlan72 192.0.2.101 protocol-up/link-up/admin-up\n"
                  "Eth1/1 192.0.2.200 protocol-up/link-up/admin-up\n")
        self.assertEqual(discover_source(output, "192.0.2.101"), "Vlan72")
        self.assertEqual(discover_source(output, "192.0.2.200"), "Ethernet1/1")
        self.assertEqual(discover_source("Lo0 192.0.2.101/32\n", "192.0.2.101"), "Loopback0")
        self.assertEqual(discover_source("Vlan72 [up/up]\n    2001:db8::1/64\n", "2001:db8::1"), "Vlan72")
        for text, address in ((output, "192.0.2.99"), (output, "switch.example"),
                              (output + "Vlan73 192.0.2.101\n", "192.0.2.101")):
            with self.subTest(address=address), self.assertRaises(ValueError):
                discover_source(text, address)

    def test_override_validation_blocks_management_interfaces_and_command_injection(self):
        for value in ("mgmt0", "vlan0", "vlan4095", "vlan64; reload", "vlan64\nreload", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                source_interface(value)
        self.assertEqual(source_interface("Po10"), "port-channel10")

    def test_only_destination_profile_source_is_replaced(self):
        self.assertEqual(replace_source(TEMPLATE, "Vlan72"), TEMPLATE.replace("source-interface vlan64", "source-interface Vlan72"))
        with self.assertRaises(ValueError):
            replace_source(TEMPLATE.replace("source-interface vlan64", "description absent"), "Vlan72")
        duplicate = TEMPLATE.replace("source-interface vlan64", "source-interface vlan64\n    source-interface vlan65")
        with self.assertRaises(ValueError):
            replace_source(duplicate, "Vlan72")
        other = TEMPLATE.replace("  subscription 500", "  source-interface vlan99\n  subscription 500")
        self.assertIn("  source-interface vlan99", replace_source(other, "Vlan72"))
        crlf = TEMPLATE.replace("\n", "\r\n")
        self.assertEqual(replace_source(crlf, "Vlan72"), crlf.replace("source-interface vlan64", "source-interface Vlan72"))

    def test_configuration_rejects_empty_or_unexpected_exec_commands(self):
        self.assertEqual(configuration_lines(TEMPLATE)[0], "feature telemetry")
        for template in ("", "reload", TEMPLATE.replace("feature grpc", "reload"),
                         TEMPLATE.replace("    dst-grp 500", "    do reload"),
                         TEMPLATE.replace("telemetry\n", "telemetry\t\n")):
            with self.subTest(template=template), self.assertRaises(ValueError):
                configuration_lines(template)


class TelemetryPreviewTests(unittest.TestCase):
    def service(self, vrf="default", template=TEMPLATE, valid=True, hosts=None):
        service = object.__new__(TelemetryPush)
        service.client = MagicMock()
        inventory = [{"switchId": switch["serial"], "switchName": switch["name"],
                      "switchIp": switch["address"], "fabricName": switch["fabric"]} for switch in INVENTORY]
        payload = {"softwareConfiguration": template, "validSoftwareConfiguration": valid}
        service.client.request.side_effect = [
            {"items": inventory}, {"telemetrySourceVrf": vrf},
            *[payload for _ in (hosts or [1])],
        ]
        return service

    @patch("nd_telemetry.TelemetrySSH")
    def test_management_preserves_template_byte_for_byte_without_ssh(self, ssh):
        service = self.service(vrf="management")
        plans = service.preview(SELECTION, "switch-secret", {"password": "rescue-secret"})
        self.assertEqual(plans[0]["template"], TEMPLATE)
        self.assertEqual(plans[0]["source"], "ND template unchanged")
        ssh.assert_not_called()
        paths = [call.args[1] for call in service.client.request.call_args_list]
        self.assertEqual(paths[1], "/manage/fabrics/Fabric%20%2F%20A")
        self.assertEqual(paths[2], "/analyze/telemetry/switchesConfig?fabricName=Fabric+%2F+A&switchId=SERIAL1")

    @patch("nd_telemetry.TelemetrySSH")
    def test_default_and_inband_discover_per_switch_and_close_both_hops(self, ssh):
        for vrf in ("default", "inband"):
            with self.subTest(vrf=vrf):
                ssh.reset_mock()
                ssh.return_value.discover.return_value = "Vlan72"
                jump = {"host": "nd.example", "password": "rescue-secret"}
                plans = self.service(vrf=vrf).preview(SELECTION, "switch-secret", jump)
                ssh.assert_called_once_with("192.0.2.101", "netops", "switch-secret", jump)
                ssh.return_value.discover.assert_called_once_with("192.0.2.101")
                ssh.return_value.disconnect.assert_called_once()
                self.assertIn("source-interface Vlan72", plans[0]["template"])
                self.assertEqual(plans[0]["source_interface"], "Vlan72")

    @patch("nd_telemetry.TelemetrySSH")
    def test_direct_discovery_connects_without_nd_rescue_credentials(self, ssh):
        ssh.return_value.discover.return_value = "Vlan72"
        plans = self.service().preview(SELECTION, "switch-secret", None)
        ssh.assert_called_once_with("192.0.2.101", "netops", "switch-secret", None)
        ssh.return_value.disconnect.assert_called_once()
        self.assertIn("source-interface Vlan72", plans[0]["template"])

    @patch("nd_telemetry.TelemetrySSH")
    def test_overrides_skip_discovery_and_fabric_is_cached(self, ssh):
        selection = copy.deepcopy(SELECTION)
        selection["switches"]["hosts"] = ["leaf1", "leaf2"]
        selection["source_interfaces"] = {"leaf1": "Vlan72", "leaf2": "Loopback0"}
        service = self.service(hosts=[1, 2])
        plans = service.preview(selection, "secret", {"password": "rescue"})
        self.assertEqual([plan["source_interface"] for plan in plans], ["Vlan72", "Loopback0"])
        self.assertEqual(service.client.request.call_count, 4)
        ssh.assert_not_called()

    @patch("nd_telemetry.TelemetrySSH")
    def test_discovery_failure_closes_session_and_never_pushes(self, ssh):
        ssh.return_value.discover.side_effect = ValueError("ambiguous address")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.service().preview(SELECTION, "secret", {"password": "rescue"})
        ssh.return_value.disconnect.assert_called_once()
        ssh.return_value.push.assert_not_called()

    @patch("nd_telemetry.TelemetrySSH")
    def test_missing_vrf_field_is_management(self, ssh):
        for vrf in (None, ""):
            with self.subTest(vrf=vrf):
                plans = self.service(vrf=vrf).preview(SELECTION, "switch-secret", None)
                self.assertEqual(plans[0]["source"], "ND template unchanged")
        ssh.assert_not_called()

    def test_invalid_fabric_or_template_blocks_preview(self):
        for args in ({"vrf": "unknown"}, {"valid": False}, {"template": ""},
                     {"template": TEMPLATE.replace("source-interface vlan64", "")}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                selection = {**SELECTION, "source_interfaces": {"leaf1": "Vlan72"}}
                self.service(**args).preview(selection, "secret", {"password": "rescue"})

    @patch("nd_telemetry.nd_helpers")
    def test_uses_saved_api_login_domain_and_tls_setting(self, helpers):
        profile = {"address": "nd.example:8443", "verify_tls": True}
        values = {"username": "operator", "password": "api-secret", "domain": "TACACS"}
        service = TelemetryPush(profile, values)
        helpers.return_value.__getitem__.return_value.assert_called_once_with(
            "https://nd.example:8443", "operator", "api-secret", True, 60, "TACACS")
        service.close()
        service.client.session.close.assert_called_once()


class TelemetryPushTests(unittest.TestCase):
    def connection(self):
        connection = object.__new__(TelemetrySSH)
        connection.session = MagicMock()
        connection.session.cmd.return_value = ""
        connection.session._capture_prompt.return_value = "leaf1#"
        return connection

    def test_push_respects_config_submode_indentation_and_never_saves_startup(self):
        connection = self.connection()
        connection.push(TEMPLATE)
        commands = [call.args[0] for call in connection.session.cmd.call_args_list]
        self.assertEqual(commands[:4], ["configure terminal", "feature telemetry", "feature grpc", "telemetry"])
        index = commands.index("destination-group 500")
        self.assertEqual(commands[index - 1], "exit")
        self.assertEqual(commands[-1], "end")
        self.assertEqual(commands.count("exit"), 4)
        self.assertNotIn("copy running-config startup-config", commands)
        self.assertIn('path "show processes cpu" depth unbounded', commands)
        self.assertRegex("leaf1(config-tm-dest)#", connection.session.sw_prompt_re)

    def test_cli_errors_abort_and_force_close_without_sending_later_commands(self):
        for message in ("% Invalid command at '^' marker.", "ERROR: denied", "% Permission denied"):
            with self.subTest(message=message):
                connection = self.connection()
                connection.session.cmd.side_effect = ["", "", message]
                with self.assertRaisesRegex(RuntimeError, "Switch rejected"):
                    connection.push(TEMPLATE)
                self.assertEqual(connection.session.cmd.call_count, 3)
                connection.session.child.close.assert_called_once_with(force=True)

    @patch("nd_telemetry.TelemetrySSH")
    def test_reports_partial_failure_redacts_secrets_and_stops_remaining_switches(self, ssh):
        plans = [{**switch, "template": TEMPLATE} for switch in INVENTORY]
        ssh.return_value.push.side_effect = RuntimeError("failed switch-secret rescue-secret")
        log = []
        results = push_plans(plans, "netops", "switch-secret", {"password": "rescue-secret"}, log.append)
        self.assertEqual([result["state"] for result in results], ["FAILED", "NOT_ATTEMPTED"])
        self.assertIn("partially applied", results[0]["detail"])
        self.assertNotIn("switch-secret", str(results) + str(log))
        self.assertNotIn("rescue-secret", str(results) + str(log))
        self.assertNotIn("template", results[0])
        ssh.assert_called_once()
        ssh.return_value.disconnect.assert_called_once()

    @patch("nd_telemetry.TelemetrySSH")
    def test_direct_push_success_and_failure_without_rescue_credentials(self, ssh):
        plans = [{**switch, "template": TEMPLATE} for switch in INVENTORY]
        log = []
        results = push_plans(plans, "netops", "switch-secret", None, log.append)
        self.assertEqual([result["state"] for result in results], ["PUSHED", "PUSHED"])
        self.assertEqual(ssh.call_args.args[-1], None)
        self.assertIn("connecting directly to switch", log[0])
        ssh.return_value.push.side_effect = RuntimeError("failed switch-secret")
        log.clear()
        results = push_plans(plans, "netops", "switch-secret", None, log.append)
        self.assertEqual([result["state"] for result in results], ["FAILED", "NOT_ATTEMPTED"])
        self.assertNotIn("switch-secret", str(results) + str(log))

    @patch("nd_telemetry.TelemetrySSH")
    def test_success_is_cli_acceptance_not_verified_nd_reception(self, ssh):
        results = push_plans([{**INVENTORY[0], "template": TEMPLATE}], "netops", "secret",
                             {"password": "rescue"}, lambda message: None)
        self.assertEqual(results[0]["state"], "PUSHED")
        self.assertIn("not been verified", results[0]["detail"])
        ssh.return_value.push.assert_called_once_with(TEMPLATE)
        ssh.return_value.disconnect.assert_called_once()


class DirectSSHTests(unittest.TestCase):
    @patch("aci_jump.jump_helpers")
    def test_direct_connection_spawns_switch_ssh_without_nd_login(self, helpers):
        session = MagicMock()
        session._capture_prompt.return_value = "leaf1#"
        helpers.return_value = {
            "SwitchStager": MagicMock(return_value=session), "StageError": RuntimeError,
            "SWITCH_GENERIC_PROMPT": r"leaf1#", "LEGACY_ERR_RE": re.compile("invalid key length"),
            "LEGACY_SSH_OPTIONS": ["-o", "HostKeyAlgorithms=+ssh-rsa"],
        }
        connection = TelemetrySSH("leaf1.example", "netops", "switch-secret", None)
        self.assertFalse(helpers.return_value["SwitchStager"].call_args.kwargs["via_nd"])
        arguments = session._spawn.call_args.args[0]
        self.assertEqual(arguments[-4:], ["-l", "netops", "--", "leaf1.example"])
        self.assertNotIn("switch-secret", str(arguments))
        session._authenticate.assert_called_once_with("switch-secret", r"leaf1#", "NX-OS switch", [])
        session.child.sendline.assert_not_called()
        connection.disconnect()
        session.disconnect.assert_called_once()

    @patch("aci_jump.jump_helpers")
    def test_direct_legacy_retry_reopens_local_ssh_and_auth_errors_close_session(self, helpers):
        from netmiko.exceptions import NetmikoAuthenticationException

        for failure, retry in (("invalid key length", True), ("password rejected", False)):
            with self.subTest(failure=failure):
                session = MagicMock()
                session._capture_prompt.return_value = "leaf1#"
                session._authenticate.side_effect = [RuntimeError(failure), None]
                helpers.return_value = {
                    "SwitchStager": MagicMock(return_value=session), "StageError": RuntimeError,
                    "SWITCH_GENERIC_PROMPT": r"leaf1#", "LEGACY_ERR_RE": re.compile("invalid key length"),
                    "LEGACY_SSH_OPTIONS": ["-o", "HostKeyAlgorithms=+ssh-rsa"],
                }
                if retry:
                    TelemetrySSH("leaf1.example", "netops", "secret", None)
                    self.assertEqual(session._spawn.call_count, 2)
                    self.assertIn("HostKeyAlgorithms=+ssh-rsa", session._spawn.call_args.args[0])
                    session.child.close.assert_called_once_with(force=True)
                    session.child.expect.assert_not_called()
                else:
                    with self.assertRaisesRegex(NetmikoAuthenticationException, "NX-OS switch rejected"):
                        TelemetrySSH("leaf1.example", "netops", "secret", None)
                    session.disconnect.assert_called_once()
                    self.assertEqual(session._spawn.call_count, 1)


class TelemetryUITests(unittest.IsolatedAsyncioTestCase):
    async def test_preview_confirmation_push_report_and_invalidation(self):
        await self.exercise_workflow(False)

    async def test_direct_mode_skips_rescue_credentials_and_requires_new_preview_on_route_change(self):
        await self.exercise_workflow(True)

    async def exercise_workflow(self, direct_connection):
        import automation_ui
        from nicegui import ui
        from nicegui.client import Client
        from nicegui.page import page

        profile = {"id": "nd1", "name": "ND", "address": "nd.example", "verify_tls": True}
        store = MagicMock()
        store.dashboards.return_value = [profile]
        store.credentials.return_value = {}
        plans = [{**INVENTORY[0], "vrf": "default", "source_interface": "Vlan72",
                  "source": "Discovered", "template": TEMPLATE, "state": "READY", "detail": ""}]
        preview_routes = []
        push_routes = []

        def capture_preview(selection, password, jump):
            preview_routes.append(None if jump is None else jump.copy())
            return plans

        def capture_push(plans, username, password, jump, notify):
            push_routes.append(None if jump is None else jump.copy())
            return [{**INVENTORY[0], "state": "PUSHED"}]

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(automation_ui, "STORE", store, create=True), \
                patch.object(automation_ui, "owner", return_value="tester"), \
                patch.object(automation_ui, "TelemetryPush") as service, \
                patch.object(automation_ui, "push_plans", side_effect=capture_push) as push, \
                patch.object(automation_ui, "confirm", new_callable=AsyncMock, return_value=True) as confirm, \
                patch.object(automation_ui, "saved_credentials", return_value={"username": "api", "password": "api-secret"}), \
                patch.object(automation_ui, "ssh_jump",
                             side_effect=lambda _: {"host": "nd.example", "password": "rescue-secret"}) as jump, \
                patch.object(automation_ui, "output_directory", return_value=Path(temporary)), \
                patch.object(automation_ui.run, "io_bound", new_callable=AsyncMock,
                             side_effect=lambda function, *args: function(*args)):
            service.return_value.preview.side_effect = capture_preview
            client = Client(page("/telemetry-test"))
            self.addCleanup(client.delete)
            with client, ui.column() as container:
                dashboard, changed = automation_ui.telemetry_push_panel()
                dashboard.value = "nd1"
                elements = list(container.descendants())
                yaml_field = next(element for element in elements if isinstance(element, ui.textarea))
                password = next(element for element in elements if isinstance(element, ui.input)
                                and element._props.get("label") == "Automation password")
                direct = next(element for element in elements if isinstance(element, ui.switch)
                              and element.text == "Connect directly to switches")
                self.assertFalse(direct.value)
                direct.value = direct_connection
                buttons = {element.text: element for element in elements if isinstance(element, ui.button)}
                yaml_field.value = "switches:\n  username: netops\n  hosts: [leaf1]\n"
                password.value = "switch-secret"
                def click_callback(button):
                    listener = next(listener for listener in button._event_listeners.values() if listener.type == "click")
                    return inspect.getclosurevars(listener.handler).nonlocals["callback"]

                preview = click_callback(buttons["Preview telemetry"])
                apply = click_callback(buttons["Push telemetry"])
                self.assertFalse(buttons["Push telemetry"].enabled)
                await preview()
                service.return_value.close.assert_called_once()
                expected_jump = None if direct_connection else {"host": "nd.example", "password": "rescue-secret"}
                self.assertEqual(preview_routes, [expected_jump])
                self.assertTrue(buttons["Push telemetry"].enabled)
                await apply()
                confirm.assert_awaited_once()
                push.assert_called_once()
                self.assertEqual(push.call_args.args[1:3], ("netops", "switch-secret"))
                self.assertEqual(push_routes, [expected_jump])
                self.assertIn("direct SSH" if direct_connection else "via Nexus Dashboard", confirm.call_args.args[0])
                if direct_connection:
                    jump.assert_not_called()
                else:
                    self.assertEqual(jump.call_count, 2)
                self.assertFalse(buttons["Push telemetry"].enabled)
                self.assertEqual(password.value, "")
                reports = list(Path(temporary).glob("telemetry/*/report.json"))
                self.assertEqual(len(reports), 1)
                self.assertNotIn("secret", reports[0].read_text())
                self.assertEqual(reports[0].stat().st_mode & 0o777, 0o600)
                password.value = "switch-secret"
                await preview()
                self.assertTrue(buttons["Push telemetry"].enabled)
                direct.value = not direct_connection
                self.assertFalse(buttons["Push telemetry"].enabled)
                direct.value = direct_connection
                await preview()
                changed()
                self.assertFalse(buttons["Push telemetry"].enabled)
                await preview()

                def change_route_during_confirmation(*args):
                    direct.value = not direct_connection
                    return True

                confirm.side_effect = change_route_during_confirmation
                push.reset_mock()
                await apply()
                push.assert_not_called()
                self.assertFalse(buttons["Push telemetry"].enabled)
            container.delete()


if __name__ == "__main__":
    unittest.main()
