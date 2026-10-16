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
    archive = f"cisco-dc-operations-{tag}.tar.gz"
    release_url = f"https://github.com/{REPOSITORY}/releases/download/{tag}"
    return f'''# Finish active jobs and back up application data and the vault key separately first.
# Run these commands on the application server from a normal admin shell.
set -euo pipefail
RELEASE_TAG={tag}
ARCHIVE={archive}
BASE_URL={release_url}
WORK_DIR="$HOME/cisco-dc-operations-updates/$RELEASE_TAG"
mkdir -p "$WORK_DIR/source"
cd "$WORK_DIR"
curl --fail --location --output "$ARCHIVE" "$BASE_URL/$ARCHIVE"
curl --fail --location --output "$ARCHIVE.sha256" "$BASE_URL/$ARCHIVE.sha256"
sha256sum --check "$ARCHIVE.sha256"
tar -xzf "$ARCHIVE" -C source
sudo systemctl stop cisco-dc-automation.service
sudo bash "$WORK_DIR/source/automation-appliance/install.sh"
sudo systemctl start cisco-dc-automation.service
sudo systemctl --no-pager --full status cisco-dc-automation.service
'''