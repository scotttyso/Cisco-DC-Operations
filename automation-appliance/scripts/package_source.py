#!/usr/bin/env python3
"""Package only deployable source, never local accounts, keys, venvs or build settings."""

import argparse
import tarfile
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[2]
SOURCE_FILES = (
    "VERSION", "requirements.txt", "oidc_auth.py", "release_updates.py",
    "aci_ifstatus_common.py", "aci_leaf_ifstatus_pre.py",
    "aci_leaf_ifstatus_post.py", "aci_checks.py", "aci_jump.py", "secure_profiles.py", "nxos_jobs.py",
    "automation_ui.py", "nd_interfaces.py", "nd_telemetry.py", "interface_description_table.py", "interface_description_table.js",
    "nxos-scripts/nd_stage_nexus_updates.py",
    "nxos-scripts/nxos_bootflash_stage.py", "automation-appliance/install.sh", "automation-appliance/update.py",
    "automation-appliance/cisco-dc-automation.service", "automation-appliance/nginx-cisco-dc.conf",
    "automation-appliance/files/cisco-dc-config.py", "automation-appliance/files/cisco-dc-firstboot.service",
)


def package_source(destination: Path, project: Path = PROJECT_DIR) -> None:
    for name in SOURCE_FILES:
        path = project / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(project.resolve()):
            raise ValueError(f"Missing or unsafe source file: {name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w:gz") as archive:
        for name in SOURCE_FILES:
            archive.add(project / name, arcname=name, recursive=False)
    destination.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    package_source(arguments.destination)
    print(f"Packaged {len(SOURCE_FILES)} deployable source files: {arguments.destination}")


if __name__ == "__main__":
    main()