"""Switch SSH connections, directly or through a Nexus Dashboard rescue-user shell."""

import contextlib
import re
import runpy
import shlex
from functools import cache
from pathlib import Path

from netmiko.exceptions import NetmikoAuthenticationException

from nxos_jobs import SCRIPTS_DIR


@cache
def jump_helpers():
    return runpy.run_path(str(SCRIPTS_DIR / "nxos_bootflash_stage.py"))


class NexusDashboardSSH:
    def __init__(self, target: str, username: str, password: str, jump: dict | None, timeout: int,
                 *, switch_label: str = "ACI switch"):
        hosts = (target, jump.get("host")) if jump is not None else (target,)
        if not all(re.fullmatch(r"[A-Za-z0-9_.:-]+", host or "") for host in hosts):
            raise ValueError("Invalid switch or Nexus Dashboard SSH hostname")
        if jump is not None and not jump.get("password"):
            raise ValueError("Save the rescue-user password on the Nexus Dashboards tab")
        helpers = jump_helpers()
        cfg = {"login_timeout": timeout, "nexus_dashboard": {}, "switches": {}}
        self.session = helpers["SwitchStager"](cfg, target, Path("."), dry_run=True, via_nd=jump is not None)
        self.session.note = lambda message: None
        options = ["-o", "PreferredAuthentications=keyboard-interactive,password", "-o", "PubkeyAuthentication=no",
                   "-o", f"ConnectTimeout={int(timeout)}", "-o", "ConnectionAttempts=1"]
        try:
            if jump is not None:
                self.session._spawn(options + ["-l", "rescue-user", "--", jump["host"]])
                self.session._authenticate(jump["password"], helpers["ND_GENERIC_PROMPT"], "Nexus Dashboard")
                prompt = self.session._capture_prompt(helpers["ND_GENERIC_PROMPT"])
                self.session.nd_prompt_re = re.escape(prompt) + r"\s*$"

            def switch_login(extra_options=()):
                arguments = [*options, *extra_options, "-l", username, "--", target]
                if jump is None:
                    self.session._spawn(arguments)
                else:
                    self.session.child.sendline(shlex.join(["ssh", *arguments]))
                self.session._authenticate(password, helpers["SWITCH_GENERIC_PROMPT"], switch_label,
                                           [self.session.nd_prompt_re] if jump is not None else [])

            try:
                switch_login()
            except helpers["StageError"] as error:
                if not helpers["LEGACY_ERR_RE"].search(str(error)):
                    raise
                if jump is None:
                    self.session.child.close(force=True)
                else:
                    self.session.child.expect(self.session.nd_prompt_re, timeout=timeout)
                switch_login(helpers["LEGACY_SSH_OPTIONS"])
            prompt = self.session._capture_prompt(helpers["SWITCH_GENERIC_PROMPT"])
            self.session.sw_prompt_re = re.escape(prompt) + r"\s*$"
            self.session.cmd("terminal length 0", timeout=timeout)
            self.session.cmd("terminal width 511", timeout=timeout)
        except Exception as error:
            self.disconnect()
            if re.search(r"password rejected|permission denied|authentication failed", str(error), re.IGNORECASE):
                label = f"Nexus Dashboard or {switch_label}" if jump is not None else switch_label
                raise NetmikoAuthenticationException(f"{label} rejected SSH credentials") from None
            raise

    def send_command(self, command: str, read_timeout: int, cmd_verify: bool = False) -> str:
        from aci_ifstatus_common import assert_read_only
        assert_read_only(command)
        return self.session.cmd(command, timeout=read_timeout)

    def disconnect(self):
        try:
            self.session.disconnect()
        except Exception:
            if self.session.child is not None:
                with contextlib.suppress(Exception):
                    self.session.child.close(force=True)