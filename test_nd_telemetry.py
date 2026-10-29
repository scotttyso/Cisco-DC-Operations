import copy
import inspect
import re
import tempfile
import threading
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
    def service(self, vrf="default", template=TEMPLATE, valid=True, hosts=None, switch_vrf=None, switch_interface=None):
        service = self.last = object.__new__(TelemetryPush)
        service.client = MagicMock()
        inventory = [{"switchId": switch["serial"], "switchName": switch["name"],
                      "switchIp": switch["address"], "fabricName": switch["fabric"]} for switch in INVENTORY]
        payload = {"softwareConfiguration": template, "validSoftwareConfiguration": valid}
        extra = {"platformType": "nx-os", **({"sourceVrfName": switch_vrf} if switch_vrf else {}),
                 **({"sourceInterfaceName": switch_interface} if switch_interface else {})}
        detail = {"switches": [{"serialNumber": switch["serial"], "fabricName": switch["fabric"], "additionalData": extra}
                               for switch in INVENTORY], "meta": {"counts": {"remaining": 0, "total": len(INVENTORY)}}}

        def request(method, path, *args, **kwargs):
            if path.startswith("/manage/fabricSoftware"):
                return {"items": inventory}
            if path.startswith("/manage/inventory/switches"):
                return detail
            if path.startswith("/manage/fabrics/"):
                return {"telemetrySourceVrf": vrf}
            return payload
        service.client.request.side_effect = request
        return service

    def test_inventory_vrfs_are_paged_and_filtered_by_fabric(self):
        service = object.__new__(TelemetryPush)
        service.client = MagicMock()

        def row(serial, fabric, vrf):
            return {"serialNumber": serial, "fabricName": fabric,
                    "additionalData": {"platformType": "nx-os", "sourceVrfName": vrf}}
        service.client.request.side_effect = [
            {"switches": [row("A", "F1", "management"), row("B", "F2", "default")], "meta": {"counts": {"remaining": 1}}},
            {"switches": [row("C", "F1", "mgmt")], "meta": {"counts": {"remaining": 0}}},
        ]
        self.assertEqual(service.inventory_vrfs("F1"), {"A": ("management", ""), "C": ("management", "")})
        self.assertIn("offset=2", service.client.request.call_args_list[1].args[1])

    @patch("nd_telemetry.TelemetrySSH")
    def test_inventory_source_interface_skips_ssh_unless_overridden(self, ssh):
        service = self.service(vrf="management", switch_vrf="default", switch_interface="vlan64")
        plans = service.preview(SELECTION, "secret", None)
        self.assertEqual(plans[0]["source_interface"], "vlan64")
        self.assertEqual(plans[0]["source"], "ND inventory sourceInterfaceName")
        self.assertIn("source-interface vlan64", plans[0]["template"])
        ssh.assert_not_called()
        selection = {**SELECTION, "source_interfaces": {"leaf1": "Vlan72"}}
        plans = self.service(switch_vrf="default", switch_interface="vlan64").preview(selection, "secret", None)
        self.assertEqual((plans[0]["source_interface"], plans[0]["source"]), ("Vlan72", "YAML override"))

    @patch("nd_telemetry.TelemetrySSH")
    def test_switch_inventory_source_vrf_wins_over_fabric(self, ssh):
        plans = self.service(vrf="default", switch_vrf="management").preview(SELECTION, "secret", None)
        self.assertEqual(plans[0]["source"], "ND template unchanged")
        ssh.assert_not_called()
        paths = [call.args[1] for call in self.last.client.request.call_args_list]
        self.assertFalse(any(path.startswith("/manage/fabrics/") for path in paths))

    @patch("nd_telemetry.TelemetrySSH")
    def test_management_preserves_template_byte_for_byte_without_ssh(self, ssh):
        service = self.service(vrf="management")
        plans = service.preview(SELECTION, "switch-secret", {"password": "rescue-secret"})
        self.assertEqual(plans[0]["template"], TEMPLATE)
        self.assertEqual(plans[0]["source"], "ND template unchanged")
        ssh.assert_not_called()
        paths = [call.args[1] for call in service.client.request.call_args_list]
        self.assertEqual(paths[2], "/manage/fabrics/Fabric%20%2F%20A")
        self.assertEqual(paths[3], "/analyze/telemetry/switchesConfig?fabricName=Fabric+%2F+A&switchId=SERIAL1")

    @patch("nd_telemetry.TelemetrySSH")
    def test_default_and_inband_discover_per_switch_and_close_both_hops(self, ssh):
        for vrf in ("default", "inband"):
            with self.subTest(vrf=vrf):
                ssh.reset_mock()
                ssh.return_value.discover.return_value = "Vlan72"
                jump = {"host": "nd.example", "password": "rescue-secret"}
                plans = self.service(vrf=vrf).preview(SELECTION, "switch-secret", jump)
                ssh.assert_called_once_with("192.0.2.101", "netops", "switch-secret", jump, 60)
                ssh.return_value.discover.assert_called_once_with("192.0.2.101", 90)
                ssh.return_value.disconnect.assert_called_once()
                self.assertIn("source-interface Vlan72", plans[0]["template"])
                self.assertEqual(plans[0]["source_interface"], "Vlan72")

    @patch("nd_telemetry.TelemetrySSH")
    def test_direct_discovery_connects_without_nd_rescue_credentials(self, ssh):
        ssh.return_value.discover.return_value = "Vlan72"
        plans = self.service().preview(SELECTION, "switch-secret", None)
        ssh.assert_called_once_with("192.0.2.101", "netops", "switch-secret", None, 60)
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
        self.assertEqual(service.client.request.call_count, 5)
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
        for vrf in (None, "", "mgmt", "MGMT"):
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
    def test_parallel_pushes_are_bounded_ordered_and_keep_logs_isolated(self):
        barrier = threading.Barrier(3)
        lock = threading.Lock()
        active = 0
        peak = 0
        connections = []
        plans = [{**INVENTORY[0], "name": f"leaf{index}", "serial": f"SERIAL{index}",
                  "address": f"192.0.2.{index + 1}", "template": TEMPLATE} for index in range(6)]

        def connect(address, username, password, jump, connect_timeout):
            connection = MagicMock()
            connections.append(connection)
            self.assertEqual(connect_timeout, 41)

            def push(template, record, read_timeout):
                nonlocal active, peak
                self.assertEqual(read_timeout, 123)
                with lock:
                    active += 1
                    peak = max(peak, active)
                try:
                    barrier.wait(timeout=5)
                    record(f"response from {address}")
                finally:
                    with lock:
                        active -= 1
            connection.push.side_effect = push
            return connection

        with tempfile.TemporaryDirectory() as temporary, patch("nd_telemetry.TelemetrySSH", side_effect=connect):
            results = push_plans(plans, "netops", "secret", None, lambda _: None,
                                 Path(temporary), workers=3, connect_timeout=41, read_timeout=123)
            self.assertEqual(peak, 3)
            self.assertEqual([result["serial"] for result in results], [plan["serial"] for plan in plans])
            self.assertEqual([result["state"] for result in results], ["PUSHED"] * 6)
            for index, result in enumerate(results):
                text = (Path(temporary) / result["log_file"]).read_text()
                responses = [line for line in text.splitlines() if "response from" in line]
                self.assertEqual(len(responses), 1)
                self.assertIn(f"response from {plans[index]['address']}", responses[0])
            for connection in connections:
                connection.disconnect.assert_called_once()

    def test_parallel_failure_stops_new_connections_but_finishes_in_progress(self):
        barrier = threading.Barrier(2)
        failure_logged = threading.Event()
        plans = [{**INVENTORY[0], "name": f"leaf{index}", "serial": f"SERIAL{index}",
                  "address": f"192.0.2.{index + 1}", "template": TEMPLATE} for index in range(5)]
        connections = []

        def connect(address, *args):
            connection = MagicMock()
            connections.append(connection)

            def push(template, record, read_timeout):
                barrier.wait(timeout=5)
                if address == plans[0]["address"]:
                    raise RuntimeError("startup-config save failed")
                if not failure_logged.wait(timeout=5):
                    raise RuntimeError("Failure was not reported")
                record("Copy complete.")
            connection.push.side_effect = push
            return connection

        def notify(message):
            if "FAILED -" in message:
                failure_logged.set()

        with tempfile.TemporaryDirectory() as temporary, patch("nd_telemetry.TelemetrySSH", side_effect=connect) as ssh:
            results = push_plans(plans, "netops", "secret", None, notify, Path(temporary), workers=2)
            self.assertEqual(ssh.call_count, 2)
            self.assertEqual([result["state"] for result in results],
                             ["FAILED", "PUSHED", "NOT_ATTEMPTED", "NOT_ATTEMPTED", "NOT_ATTEMPTED"])
            self.assertEqual(len(list(Path(temporary).glob("*.log"))), 5)
            for connection in connections:
                connection.disconnect.assert_called_once()

    @patch("nd_telemetry.TelemetrySSH")
    def test_invalid_parallel_settings_fail_before_connecting(self, ssh):
        for settings in ({"workers": 0}, {"workers": 33}, {"workers": 1.5}, {"workers": True},
                         {"connect_timeout": 0}, {"read_timeout": -1}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                push_plans([{**INVENTORY[0], "template": TEMPLATE}], "netops", "secret",
                           None, lambda _: None, **settings)
        ssh.assert_not_called()

    def connection(self):
        connection = object.__new__(TelemetrySSH)
        connection.session = MagicMock()
        connection.session.cmd.side_effect = lambda command, **_: (
            "Copy complete." if command == "copy running-config startup-config" else "")
        connection.session._capture_prompt.return_value = "leaf1#"
        return connection

    def test_push_respects_config_submode_indentation_and_saves_startup_last(self):
        connection = self.connection()
        log = []
        connection.push(TEMPLATE, log.append)
        commands = [call.args[0] for call in connection.session.cmd.call_args_list]
        self.assertEqual(commands[:4], ["configure terminal", "feature telemetry", "feature grpc", "telemetry"])
        index = commands.index("destination-group 500")
        self.assertEqual(commands[index - 1], "exit")
        self.assertEqual(commands[-2:], ["end", "copy running-config startup-config"])
        self.assertEqual(commands.count("exit"), 4)
        self.assertEqual(connection.session.cmd.call_args.kwargs["timeout"], 300)
        self.assertEqual([line[2:] for line in log if line.startswith("> ")], commands)
        self.assertEqual(log[-1], "Copy complete.")
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
                self.assertNotIn("copy running-config startup-config",
                                 [call.args[0] for call in connection.session.cmd.call_args_list])

    def test_command_timeout_is_configurable_and_save_keeps_a_safe_minimum(self):
        for timeout in (45, 600):
            with self.subTest(timeout=timeout):
                connection = self.connection()
                connection.push(TEMPLATE, read_timeout=timeout)
                calls = connection.session.cmd.call_args_list
                self.assertTrue(all(call.kwargs["timeout"] == timeout for call in calls[:-1]))
                self.assertEqual(calls[-1].kwargs["timeout"], max(300, timeout))

    def test_save_errors_timeouts_and_missing_confirmation_are_failures(self):
        for output in ("% Error copying configuration", "Permission denied", "", "Copy failed",
                       TimeoutError("copy timed out")):
            with self.subTest(output=output):
                connection = self.connection()

                def command(text, **_):
                    if text == "copy running-config startup-config":
                        if isinstance(output, Exception):
                            raise output
                        return output
                    return ""

                connection.session.cmd.side_effect = command
                with self.assertRaisesRegex(RuntimeError, "startup-config save failed"):
                    connection.push(TEMPLATE)
                connection.session.child.close.assert_called_once_with(force=True)

    def test_command_error_output_and_timeout_partial_output_are_logged(self):
        for output in ("% Invalid command", TimeoutError("session timed out")):
            with self.subTest(output=output):
                connection = self.connection()
                connection.session.cmd.side_effect = ["", output]
                connection.session.child.before = "partial switch response"
                log = []
                with self.assertRaises((RuntimeError, TimeoutError)):
                    connection.push(TEMPLATE, log.append)
                self.assertIn("> feature telemetry", log)
                self.assertIn(output if isinstance(output, str) else "partial switch response", log)

    def test_persistent_logs_include_every_command_response_and_save_confirmation(self):
        connection = self.connection()
        connection.session.cmd.side_effect = lambda command, **_: (
            "Copy complete." if command == "copy running-config startup-config" else
            f"response for {command}\nswitch-secret rescue-secret")
        plans = [{**INVENTORY[0], "template": TEMPLATE}]
        with tempfile.TemporaryDirectory() as temporary, \
                patch("nd_telemetry.TelemetrySSH", return_value=connection):
            messages = []
            results = push_plans(plans, "netops", "switch-secret", {"password": "rescue-secret"},
                                 messages.append, Path(temporary))
            path = Path(temporary) / results[0]["log_file"]
            text = path.read_text()
            commands = [call.args[0] for call in connection.session.cmd.call_args_list]
            for command in commands:
                self.assertIn(f"> {command}\n", text)
                if command != "copy running-config startup-config":
                    self.assertIn(f"response for {command}\n", text)
            self.assertIn("Copy complete.", text)
            self.assertIn("PUSHED", text)
            self.assertIn("confirmed startup-config save", results[0]["detail"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("switch-secret", text + str(messages))
            self.assertNotIn("rescue-secret", text + str(messages))

    @patch("nd_telemetry.TelemetrySSH")
    def test_failed_and_unattempted_switches_have_separate_logs(self, ssh):
        def fail(template, record, read_timeout):
            record("> feature telemetry")
            record("% Permission denied switch-secret")
            raise RuntimeError("Switch rejected configuration switch-secret")

        ssh.return_value.push.side_effect = fail
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            results = push_plans([{**switch, "template": TEMPLATE} for switch in INVENTORY],
                                 "netops", "switch-secret", None, lambda _: None, directory)
            self.assertEqual([result["state"] for result in results], ["FAILED", "NOT_ATTEMPTED"])
            self.assertEqual(len(list(directory.glob("*.log"))), 2)
            failed, skipped = [(directory / result["log_file"]).read_text() for result in results]
            self.assertIn("% Permission denied [REDACTED]", failed)
            self.assertIn("FAILED", failed)
            self.assertIn("NOT_ATTEMPTED", skipped)
            self.assertNotIn("> feature telemetry", skipped)
            self.assertNotIn("copy running-config", failed)
            ssh.assert_called_once()

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
        self.assertIsNone(ssh.call_args.args[3])
        self.assertTrue(any("connecting directly to switch" in line for line in log))
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
        self.assertEqual(ssh.return_value.push.call_args.args[0], TEMPLATE)
        self.assertTrue(callable(ssh.return_value.push.call_args.args[1]))
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
    async def test_invalid_push_settings_prevent_preview(self):
        import automation_ui
        from nicegui import ui

        store = MagicMock()
        store.credentials.return_value = {}
        store.dashboards.return_value = [{"id": "nd1", "name": "ND", "address": "nd.example"}]
        with patch.object(automation_ui, "STORE", store, create=True), \
                patch.object(automation_ui, "owner", return_value="tester"), \
                patch.object(automation_ui, "TelemetryPush") as service, \
                patch.object(ui, "notify") as notify:
            elements, buttons, config, password = self.telemetry_form()
            dashboard = next(element for element in elements if isinstance(element, ui.select)
                             and element._props.get("label") == "Nexus Dashboard appliance")
            dashboard.value = "nd1"
            config.value = "switches:\n  username: netops\n  hosts: [leaf1]\n"
            numbers = {element._props.get("label"): element for element in elements if isinstance(element, ui.number)}
            for label, value in (("Parallel switches", 0), ("Parallel switches", 33), ("Parallel switches", 1.5),
                                 ("SSH connection timeout (seconds)", None), ("Per-command timeout (seconds)", 0)):
                with self.subTest(label=label, value=value):
                    field = numbers[label]
                    previous = field.value
                    field.value = value
                    await self.click_callback(buttons["Preview telemetry"])()
                    self.assertEqual(notify.call_args.kwargs["type"], "negative")
                    self.assertIn(label, notify.call_args.args[0])
                    field.value = previous
            service.assert_not_called()

    def telemetry_form(self):
        import automation_ui
        from nicegui import ui
        from nicegui.client import Client
        from nicegui.page import page

        client = Client(page("/telemetry-save-test"))
        self.addCleanup(client.delete)
        with client, ui.column() as container:
            automation_ui.telemetry_push_panel()
        elements = list(container.descendants())
        buttons = {element.text: element for element in elements if isinstance(element, ui.button)}
        config = next(element for element in elements if isinstance(element, ui.textarea))
        password = next(element for element in elements if isinstance(element, ui.input)
                        and element._props.get("label") == "Automation password")
        return elements, buttons, config, password

    @staticmethod
    def click_callback(button):
        listener = next(listener for listener in button._event_listeners.values() if listener.type == "click")
        return inspect.getclosurevars(listener.handler).nonlocals["callback"]

    async def test_explicit_saves_survive_reopening_and_are_private_to_account(self):
        import automation_ui
        from nicegui import ui
        from secure_profiles import ProfileStore

        text = "switches:\n  username: switch-admin\n  hosts: [leaf1]\nsource_interfaces:\n  leaf1: Vlan72\n"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            store = ProfileStore(directory / "data", directory / "vault.key")
            store.add_user("tester", "webui-test-password")
            store.add_user("other", "other-test-password")
            with patch.object(automation_ui, "STORE", store, create=True), \
                    patch.object(automation_ui, "owner", return_value="tester") as owner, \
                    patch.object(automation_ui, "TelemetryPush") as service, \
                    patch.object(ui, "notify") as notify:
                elements, buttons, config, password = self.telemetry_form()
                config.value = text
                password.value = "switch-secret"
                self.click_callback(buttons["Save YAML"])()
                self.assertEqual(store.credentials("tester", "nd-telemetry"), {})
                self.click_callback(buttons["Save switch credentials"])()
                self.assertEqual(store.credentials("tester", "nd-telemetry"),
                                 {"username": "switch-admin", "password": "switch-secret"})
                self.assertEqual(password.value, "")
                service.assert_not_called()
                notify.assert_called()

                reopened = ProfileStore(directory / "data", directory / "vault.key")
                with patch.object(automation_ui, "STORE", reopened):
                    elements, buttons, config, password = self.telemetry_form()
                    self.assertEqual(config.value, text)
                    self.assertEqual(password.value, "")
                    saved = next(element for element in elements if isinstance(element, ui.checkbox)
                                 and element.text == "Use saved switch credentials")
                    self.assertTrue(saved.value)
                    self.assertTrue(any("switch-admin" in getattr(element, "text", "") for element in elements))
                    self.assertFalse(buttons["Push telemetry"].enabled)
                    owner.return_value = "other"
                    elements, buttons, config, password = self.telemetry_form()
                    self.assertEqual(config.value, automation_ui.TELEMETRY_EXAMPLE)
                    self.assertEqual(reopened.credentials("other", "nd-telemetry"), {})

    async def test_saves_reject_invalid_yaml_and_mismatched_saved_username(self):
        import automation_ui
        from nicegui import ui

        store = MagicMock()
        store.credentials.side_effect = lambda _, scope: (
            {"username": "old-user", "password": "saved-secret"} if scope == "nd-telemetry" else {})
        with patch.object(automation_ui, "STORE", store, create=True), \
                patch.object(automation_ui, "owner", return_value="tester"), \
                patch.object(ui, "notify") as notify:
            elements, buttons, config, password = self.telemetry_form()
            config.value = "switches:\n  username: new-user\n  hosts: [leaf1]\npassword: forbidden\n"
            self.click_callback(buttons["Save YAML"])()
            store.save_credentials.assert_not_called()
            self.assertEqual(notify.call_args.kwargs["type"], "negative")
            config.value = "switches:\n  username: new-user\n  hosts: [leaf1]\n"
            self.click_callback(buttons["Save switch credentials"])()
            store.save_credentials.assert_not_called()
            self.assertEqual(notify.call_args.kwargs["type"], "negative")
            self.assertIn("old-user", notify.call_args.args[0])
            self.assertIn("new-user", notify.call_args.args[0])
            password.value = "replacement-secret"
            self.click_callback(buttons["Save switch credentials"])()
            store.save_credentials.assert_called_once_with(
                "tester", "nd-telemetry", {"username": "new-user", "password": "replacement-secret"})
            self.click_callback(buttons["Forget saved switch credentials"])()
            store.forget_credentials.assert_called_once_with("tester", "nd-telemetry")
            self.assertEqual(password.value, "")
            self.assertTrue(any(getattr(element, "text", "") == "No saved switch credentials"
                                for element in elements))

    async def test_preview_confirmation_push_report_and_invalidation(self):
        await self.exercise_workflow(False)

    async def test_direct_mode_skips_rescue_credentials_and_requires_new_preview_on_route_change(self):
        await self.exercise_workflow(True)

    async def test_saved_yaml_and_switch_password_work_without_reentering_credentials(self):
        await self.exercise_workflow(False, saved=True)

    async def test_remember_still_saves_credentials_during_preview(self):
        await self.exercise_workflow(False, remember_credentials=True)

    async def exercise_workflow(self, direct_connection, saved=False, remember_credentials=False):
        import automation_ui
        from nicegui import ui
        from nicegui.client import Client
        from nicegui.page import page

        profile = {"id": "nd1", "name": "ND", "address": "nd.example", "verify_tls": True}
        store = MagicMock()
        store.dashboards.return_value = [profile]
        username = "switch-admin" if saved else "netops"
        text = f"switches:\n  username: {username}\n  hosts: [leaf1]\n"
        store.credentials.side_effect = lambda _, scope: ({
            "nd-telemetry": {"username": username, "password": "switch-secret"},
            "nd-telemetry-settings": {"yaml": text},
        }.get(scope, {}) if saved else {})
        plans = [{**INVENTORY[0], "vrf": "default", "source_interface": "Vlan72",
                  "source": "Discovered", "template": TEMPLATE, "state": "READY", "detail": ""}]
        preview_routes = []
        push_routes = []

        def capture_preview(selection, password, jump, connect_timeout, read_timeout):
            self.assertEqual((connect_timeout, read_timeout), (20, 90))
            preview_routes.append(None if jump is None else jump.copy())
            return plans

        def capture_push(plans, username, password, jump, notify, directory, workers, connect_timeout, read_timeout):
            self.assertEqual((workers, connect_timeout, read_timeout), (4, 35, 150))
            push_routes.append(None if jump is None else jump.copy())
            path = directory / "switch-1.log"
            path.touch(mode=0o600)
            path.write_text("> feature telemetry\n> copy running-config startup-config\nCopy complete.\n")
            return [{**INVENTORY[0], "state": "PUSHED", "log_file": path.name}]

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
                numbers = {element._props.get("label"): element for element in elements if isinstance(element, ui.number)}
                self.assertEqual(numbers["Parallel switches"].value, 20)
                self.assertEqual(numbers["Parallel switches"]._props["min"], 1)
                self.assertEqual(numbers["Parallel switches"]._props["max"], 32)
                self.assertEqual(numbers["SSH connection timeout (seconds)"].value, 20)
                self.assertEqual(numbers["Per-command timeout (seconds)"].value, 90)
                if saved:
                    self.assertEqual(yaml_field.value, text)
                    self.assertEqual(password.value, "")
                else:
                    yaml_field.value = text
                    password.value = "switch-secret"
                remember = next(element for element in elements if isinstance(element, ui.switch)
                                and element.text == "Remember encrypted switch credentials")
                remember.value = remember_credentials
                def click_callback(button):
                    listener = next(listener for listener in button._event_listeners.values() if listener.type == "click")
                    return inspect.getclosurevars(listener.handler).nonlocals["callback"]

                preview = click_callback(buttons["Preview telemetry"])
                apply = click_callback(buttons["Push telemetry"])
                self.assertFalse(buttons["Push telemetry"].enabled)
                await preview()
                service.return_value.close.assert_called_once()
                if remember_credentials:
                    store.save_credentials.assert_called_once_with(
                        "tester", "nd-telemetry", {"username": username, "password": "switch-secret"})
                    use_saved = next(element for element in elements if isinstance(element, ui.checkbox)
                                     and element.text == "Use saved switch credentials")
                    self.assertTrue(use_saved.value)
                expected_jump = None if direct_connection else {"host": "nd.example", "password": "rescue-secret"}
                self.assertEqual(preview_routes, [expected_jump])
                self.assertTrue(buttons["Push telemetry"].enabled)
                numbers["Parallel switches"].value = 4
                numbers["SSH connection timeout (seconds)"].value = 35
                numbers["Per-command timeout (seconds)"].value = 150
                await apply()
                numbers["SSH connection timeout (seconds)"].value = 20
                numbers["Per-command timeout (seconds)"].value = 90
                confirm.assert_awaited_once()
                push.assert_called_once()
                self.assertEqual(push.call_args.args[1:3], (username, "switch-secret"))
                self.assertEqual(push_routes, [expected_jump])
                self.assertIn("direct SSH" if direct_connection else "via Nexus Dashboard", confirm.call_args.args[0])
                self.assertIn("ALL current running", confirm.call_args.args[0])
                self.assertIn("up to 4 parallel switches", confirm.call_args.args[0])
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
                switch_log = reports[0].parent / "switch-1.log"
                self.assertTrue(switch_log.is_file())
                self.assertTrue(any(isinstance(element, ui.code) and "Copy complete." in element.content
                                    for element in container.descendants()))
                download_button = next(element for element in container.descendants()
                                       if isinstance(element, ui.button) and element.text == "Download switch log")
                with patch.object(ui.download, "content") as download:
                    self.click_callback(download_button)()
                    download.assert_called_once_with(switch_log.read_bytes(), filename="switch-1.log")
                if not saved:
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
