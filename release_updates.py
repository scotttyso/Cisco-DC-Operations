"""Discover published GitHub releases and produce administrator CLI instructions."""

from __future__ import annotations

import re
from pathlib import Path

import requests


REPOSITORY = "scotttyso/Cisco-DC-Operations"
RELEASES_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
VERSION_FILE = Path(__file__).with_name("VERSION")
TAG_PATTERN = re.compile(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\Z")


def installed_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "development"
    except OSError:
        return "development"


def release_details(payload: dict) -> dict:
    tag = payload.get("tag_name", "")
    if not isinstance(tag, str) or not TAG_PATTERN.fullmatch(tag):
        raise ValueError("Latest GitHub release has an unsupported version tag")
    assets = {asset.get("name"): asset for asset in payload.get("assets", []) if isinstance(asset, dict)}
    archive_name = f"cisco-dc-operations-{tag}.tar.gz"
    checksum_name = archive_name + ".sha256"
    if archive_name not in assets or checksum_name not in assets:
        raise ValueError("Latest release is missing its source archive or SHA-256 checksum")
    return {"tag": tag, "name": str(payload.get("name") or tag),
            "url": f"https://github.com/{REPOSITORY}/releases/tag/{tag}",
            "published_at": payload.get("published_at", ""),
            "notes": str(payload.get("body") or "No release notes provided."),
            "archive_name": archive_name, "checksum_name": checksum_name}


def latest_release(timeout: float = 10.0) -> dict:
    response = requests.get(RELEASES_API, headers={"Accept": "application/vnd.github+json"}, timeout=timeout)
    if response.status_code == 404:
        raise ValueError("No published releases found for this repository yet")
    response.raise_for_status()
    return release_details(response.json())


def install_instructions(tag: str) -> str:
    if not TAG_PATTERN.fullmatch(tag):
        raise ValueError("Invalid release version")
    return f'''# Finish ALL active jobs and use a trusted published release.
# Run these commands on the application server from a normal admin shell.
# The updater verifies SHA-256, confirms the outage, backs up code/state/key,
# runs install.sh, and validates the service. Failures leave it stopped.
sudo /usr/local/sbin/cisco-dc-update --version {tag}
'''