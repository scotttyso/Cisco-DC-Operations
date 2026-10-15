#!/usr/bin/env python3
"""Build this appliance's vApp-enabled OVA and optional qcow2 from a vSphere export."""

import argparse
import hashlib
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlsplit


OVF = "http://schemas.dmtf.org/ovf/envelope/1"
PROPERTIES = Path(__file__).with_name("ovf-properties.xml")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def add_vapp_properties(ovf: Path, version: str) -> list[Path]:
    for _, namespace in ET.iterparse(ovf, events=("start-ns",)):
        prefix, address = namespace
        if not prefix.startswith("ns"):
            ET.register_namespace(prefix, address)
    tree = ET.parse(ovf)
    root = tree.getroot()
    virtual_system = root.find(f".//{{{OVF}}}VirtualSystem")
    if virtual_system is None:
        raise ValueError("OVF VirtualSystem element not found")
    references = []
    for entry in root.findall(f"{{{OVF}}}References/{{{OVF}}}File"):
        href = entry.get(f"{{{OVF}}}href", "")
        parsed = urlsplit(href)
        path = (ovf.parent / unquote(parsed.path)).resolve()
        if (parsed.scheme or parsed.netloc or not href or not path.is_relative_to(ovf.parent.resolve())
                or not path.is_file()):
            raise ValueError(f"Unsafe or missing OVF file reference: {href}")
        references.append(path)
    wrapper = ET.fromstring(f'<wrapper xmlns="{OVF}" xmlns:ovf="{OVF}">{PROPERTIES.read_text(encoding="utf-8")}</wrapper>')
    product = wrapper[0]
    product.find(f"{{{OVF}}}Version").text = version
    existing = virtual_system.find(f"{{{OVF}}}ProductSection")
    if existing is not None:
        virtual_system.remove(existing)
    virtual_system.append(product)
    hardware = virtual_system.find(f"{{{OVF}}}VirtualHardwareSection")
    if hardware is not None:
        hardware.set(f"{{{OVF}}}transport", "com.vmware.guestInfo")
    ET.indent(tree, space="  ")
    tree.write(ovf, encoding="utf-8", xml_declaration=True)
    return references


def build_artifacts(export_dir: Path, version: str, skip_qcow2: bool = False) -> Path:
    ovfs = list(export_dir.glob("*.ovf"))
    if len(ovfs) != 1:
        raise ValueError(f"Expected one .ovf in {export_dir}; found {len(ovfs)}")
    ovf = ovfs[0]
    references = add_vapp_properties(ovf, version)
    manifest = ovf.with_suffix(".mf")
    manifest.write_text("".join(f"SHA256({path.relative_to(export_dir.resolve()).as_posix()})= {sha256(path)}\n"
                                for path in [ovf.resolve(), *references]), encoding="utf-8")
    ova = export_dir.parent / f"{ovf.stem}-{version}.ova"
    with tarfile.open(ova, "w", format=tarfile.USTAR_FORMAT) as archive:
        for path in [ovf, manifest, *references]:
            archive.add(path, arcname=path.resolve().relative_to(export_dir.resolve()).as_posix())
    print(f"OVA: {ova}")
    if not skip_qcow2:
        if not shutil.which("qemu-img"):
            raise ValueError("qemu-img is required for qcow2; install it or use --skip-qcow2")
        disks = [path for path in references if path.suffix.lower() == ".vmdk"]
        if len(disks) != 1:
            raise ValueError("qcow2 conversion requires exactly one referenced VMDK")
        qcow2 = export_dir.parent / f"{ovf.stem}-{version}.qcow2"
        subprocess.run(["qemu-img", "convert", "-p", "-c", "-O", "qcow2", str(disks[0]), str(qcow2)], check=True)
        print(f"qcow2: {qcow2}")
    return ova


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export_dir", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--skip-qcow2", action="store_true")
    arguments = parser.parse_args()
    try:
        build_artifacts(arguments.export_dir, arguments.version, arguments.skip_qcow2)
    except (ValueError, OSError, ET.ParseError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()