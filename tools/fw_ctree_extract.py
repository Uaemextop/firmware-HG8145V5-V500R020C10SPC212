#!/usr/bin/env python3
"""Extract hw_ctree.xml and configuration files from Huawei HWNP firmware images.

Downloads (or reads local) firmware images, locates SquashFS rootfs partitions,
and extracts all configuration files from ``/etc/wap/``.

The main configuration tree (``hw_ctree.xml``) is AES-256-CBC encrypted with a
device-specific key derived from the hardware e-fuse, so it cannot be decrypted
without physical device access.  However, many other configuration files are
stored in plaintext XML and reveal the original factory configuration structure:

* ``hw_aes_tree.xml`` – Defines which XML paths contain encrypted fields
* ``hw_flashcfg.xml`` – Flash partition layout (UBI volumes, NAND geometry)
* ``hw_boardinfo``    – Device identity (board ID, MACs, product info)
* ``hw_firewall_v5.xml`` – Default firewall rules
* ``keyconfig.xml``   – Hardware key/reset button configuration
* ``UpgradeCheck.xml`` – Firmware upgrade compatibility checks

Usage::

    python tools/fw_ctree_extract.py firmware.bin -o output_dir
    python tools/fw_ctree_extract.py --url https://...bin -o output_dir
    python tools/fw_ctree_extract.py --all -o configs_output

The ``--all`` flag downloads and processes all known V2 release firmwares.
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple

# ── Constants ────────────────────────────────────────────────────────────────

SQUASHFS_MAGIC_LE = b"hsqs"
SQUASHFS_MAGIC_BE = b"sqsh"

V2_FIRMWARE_URLS = [
    "https://github.com/Uaemextop/HuaweiFirmwareTool/"
    "releases/download/V2/5611_HG8145V5V500R020C10SPC212.bin",
    "https://github.com/Uaemextop/HuaweiFirmwareTool/"
    "releases/download/V2/EG8145V5-V500R022C00SPC340B019.bin",
    "https://github.com/Uaemextop/HuaweiFirmwareTool/"
    "releases/download/V2/HN8145XRV500R022C10SPC160.1.bin",
    "https://github.com/Uaemextop/HuaweiFirmwareTool/"
    "releases/download/V2/HG8245C.rar",
]

CONFIG_FILES_OF_INTEREST = [
    "hw_ctree.xml",
    "hw_default_ctree.xml",
    "hw_aes_tree.xml",
    "hw_flashcfg.xml",
    "hw_boardinfo",
    "hw_firewall_v5.xml",
    "keyconfig.xml",
    "cfgpartreset.xml",
    "hw_bootcfg.xml",
    "UpgradeCheck.xml",
    "tde_zone0.xml",
    "tde_zone1.xml",
    "WifiConfig.xml",
    "CoverActionConfig.xml",
    "HighTmperatureConfig.xml",
    "HighTemperatureConfig.xml",
    "hw_cli.xml",
    "hw_err.xml",
    "hw_boardinfo_readme.txt",
    "passwd",
    "group",
]


# ── Helpers ──────────────────────────────────────────────────────────────────


def find_squashfs(data: bytes) -> List[Tuple[int, int]]:
    """Return list of ``(offset, bytes_used)`` for every SquashFS image."""
    results: list[Tuple[int, int]] = []
    for magic in (SQUASHFS_MAGIC_LE, SQUASHFS_MAGIC_BE):
        idx = 0
        while True:
            pos = data.find(magic, idx)
            if pos == -1:
                break
            if pos + 48 <= len(data):
                bytes_used = struct.unpack_from("<Q", data, pos + 40)[0]
                if 0 < bytes_used <= len(data) - pos:
                    results.append((pos, bytes_used))
            idx = pos + 1
    results.sort(key=lambda t: t[1], reverse=True)
    return results


def extract_squashfs(img_path: str, dest: str) -> bool:
    """Run ``unsquashfs`` and return True on success."""
    result = subprocess.run(
        ["unsquashfs", "-no-xattrs", "-ignore-errors", "-d", dest, "-f", img_path],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return os.path.isdir(dest)


def download(url: str, dest: str) -> str:
    """Download *url* to *dest* and return the file path."""
    fname = os.path.join(dest, os.path.basename(url))
    if os.path.isfile(fname):
        print(f"  Already downloaded: {fname}")
        return fname
    print(f"  Downloading {os.path.basename(url)} …")
    urllib.request.urlretrieve(url, fname)
    return fname


def classify_file(path: str) -> str:
    """Return a short format description for a config file."""
    with open(path, "rb") as fh:
        head = fh.read(32)
    if not head:
        return "empty"
    if head[:5] == b"<?xml" or (head[:1] == b"<" and b">" in head[:50] and head[:1] != b"\x00"):
        return "XML"
    if head[:3] == b"\xef\xbb\xbf" and b"<" in head[:10]:
        return "XML (BOM)"
    if head[:4] == b"\x01\x00\x00\x00":
        return "encrypted"
    if head[:4] == b"AEST":
        return "AEST"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    return "binary"


# ── Extraction ───────────────────────────────────────────────────────────────


def extract_configs_from_firmware(fw_path: str, out_dir: str) -> Dict[str, str]:
    """Extract config files from an HWNP firmware image.

    Returns a dict mapping filename → format description.
    """
    os.makedirs(out_dir, exist_ok=True)

    with open(fw_path, "rb") as fh:
        data = fh.read()

    squashfs_list = find_squashfs(data)
    if not squashfs_list:
        print(f"  No SquashFS found in {os.path.basename(fw_path)}")
        return {}

    extracted: Dict[str, str] = {}

    for offset, size in squashfs_list:
        with tempfile.TemporaryDirectory() as tmp:
            img_path = os.path.join(tmp, "partition.sqfs")
            rootfs_dir = os.path.join(tmp, "rootfs")

            with open(img_path, "wb") as fh:
                fh.write(data[offset : offset + size])

            if not extract_squashfs(img_path, rootfs_dir):
                continue

            # Search /etc/wap/ for config files
            wap_dir = os.path.join(rootfs_dir, "etc", "wap")
            if not os.path.isdir(wap_dir):
                continue

            for fn in os.listdir(wap_dir):
                src = os.path.join(wap_dir, fn)
                if not os.path.isfile(src):
                    continue
                if fn in extracted:
                    continue

                dst = os.path.join(out_dir, fn)
                shutil.copy2(src, dst)
                fmt = classify_file(dst)
                extracted[fn] = fmt

            # Also check /etc/ for additional XML configs
            etc_dir = os.path.join(rootfs_dir, "etc")
            for fn in os.listdir(etc_dir):
                if fn in extracted:
                    continue
                src = os.path.join(etc_dir, fn)
                if not os.path.isfile(src):
                    continue
                if fn.endswith(".xml") or "ctree" in fn.lower():
                    dst = os.path.join(out_dir, fn)
                    shutil.copy2(src, dst)
                    fmt = classify_file(dst)
                    extracted[fn] = fmt

    return extracted


def print_report(label: str, extracted: Dict[str, str]) -> None:
    """Print a summary of extracted configuration files."""
    print(f"\n{'─' * 60}")
    print(f"  {label}")
    print(f"{'─' * 60}")

    if not extracted:
        print("  No configuration files found.")
        return

    # Separate by format
    xml_files = {k: v for k, v in extracted.items() if v in ("XML", "XML (BOM)")}
    enc_files = {k: v for k, v in extracted.items() if v in ("encrypted", "AEST")}
    other_files = {k: v for k, v in extracted.items() if v not in ("XML", "XML (BOM)", "encrypted", "AEST")}

    if xml_files:
        print(f"\n  Plaintext XML configs ({len(xml_files)}):")
        for fn in sorted(xml_files):
            print(f"    ✓ {fn}")

    if enc_files:
        print(f"\n  Encrypted configs ({len(enc_files)}):")
        for fn in sorted(enc_files):
            print(f"    🔒 {fn} ({enc_files[fn]})")

    if other_files:
        print(f"\n  Other files ({len(other_files)}):")
        for fn in sorted(other_files):
            print(f"    • {fn} ({other_files[fn]})")


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract hw_ctree.xml and configs from Huawei HWNP firmware"
    )
    parser.add_argument("firmware", nargs="?", help="Path to firmware .bin")
    parser.add_argument("--url", default=None, help="Download URL")
    parser.add_argument("--all", action="store_true", help="Process all V2 release firmwares")
    parser.add_argument("-o", "--output", default="fw_configs", help="Output directory")
    args = parser.parse_args()

    if args.all:
        dl_dir = tempfile.mkdtemp()
        print("Downloading all V2 release firmwares …\n")

        for url in V2_FIRMWARE_URLS:
            fname = os.path.basename(url)
            fw_path = download(url, dl_dir)

            if fname.endswith(".rar"):
                # Extract RAR
                rar_dir = os.path.join(dl_dir, "rar_contents")
                subprocess.run(
                    ["7z", "x", fw_path, f"-o{rar_dir}", "-y"],
                    capture_output=True,
                )
                for rf in sorted(os.listdir(rar_dir)):
                    rfp = os.path.join(rar_dir, rf)
                    if os.path.getsize(rfp) > 10000:
                        label = rf.replace(".bin", "").replace(" ", "_")
                        out = os.path.join(args.output, label)
                        extracted = extract_configs_from_firmware(rfp, out)
                        print_report(f"HG8245C: {rf}", extracted)
            else:
                label = fname.split(".")[0].replace("-", "_")
                out = os.path.join(args.output, label)
                extracted = extract_configs_from_firmware(fw_path, out)
                print_report(fname, extracted)

    elif args.firmware:
        extracted = extract_configs_from_firmware(args.firmware, args.output)
        print_report(os.path.basename(args.firmware), extracted)

    elif args.url:
        dl_dir = tempfile.mkdtemp()
        fw_path = download(args.url, dl_dir)
        extracted = extract_configs_from_firmware(fw_path, args.output)
        print_report(os.path.basename(args.url), extracted)

    else:
        parser.print_help()
        sys.exit(1)

    print(f"\nExtraction complete → {args.output}")


if __name__ == "__main__":
    main()
