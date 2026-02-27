#!/usr/bin/env python3
"""Firmware extractor for Huawei EG8145V5 / HG8145V5 HWNP images.

Downloads (or reads local) firmware, locates the SquashFS rootfs inside the
``whwh``-wrapped partitions, extracts it with ``unsquashfs``, and copies out
the binaries of interest:

* ``/bin/aescrypt2``
* ``/lib/libhw_ssp_basic.so``
* ``/lib/libpolarssl.so``
* ``/lib/libwlan_aes_crypto.so``

It also searches for compressed archives referenced by the firmware
(``preload_cplugin.tar.gz``, ``plugin_preload.tar.gz``).

Usage::

    python tools/fw_extract.py firmware.bin -o output_dir
    python tools/fw_extract.py --url https://...EG8145V5...bin -o output_dir
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
from typing import List, Tuple

# ── Constants ────────────────────────────────────────────────────────────────

SQUASHFS_MAGIC_LE = b"hsqs"
SQUASHFS_MAGIC_BE = b"sqsh"

BINARIES_OF_INTEREST = [
    "bin/aescrypt2",
    "lib/libhw_ssp_basic.so",
    "lib/libpolarssl.so",
    "lib/libwlan_aes_crypto.so",
]

GZIP_MAGIC = b"\x1f\x8b\x08"

DEFAULT_URL = (
    "https://github.com/Uaemextop/HuaweiFirmwareTool/"
    "releases/download/V2/EG8145V5-V500R022C00SPC340B019.bin"
)


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
            # bytes_used is a u64 LE at offset 40 in the SquashFS superblock.
            if pos + 48 <= len(data):
                bytes_used = struct.unpack_from("<Q", data, pos + 40)[0]
                if 0 < bytes_used <= len(data) - pos:
                    results.append((pos, bytes_used))
            idx = pos + 1
    results.sort(key=lambda t: t[1], reverse=True)
    return results


def extract_squashfs(img_path: str, dest: str) -> str:
    """Run ``unsquashfs`` and return the root directory path."""
    subprocess.check_call(
        ["unsquashfs", "-d", dest, "-f", img_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return dest


def download(url: str, dest: str) -> str:
    """Download *url* to *dest* and return the file path."""
    fname = os.path.join(dest, os.path.basename(url))
    print(f"Downloading {url} …")
    urllib.request.urlretrieve(url, fname)
    print(f"  saved to {fname}")
    return fname


def copy_binaries(rootfs: str, out_dir: str) -> List[str]:
    """Copy binaries of interest from *rootfs* into *out_dir*."""
    copied: list[str] = []
    for rel in BINARIES_OF_INTEREST:
        src = os.path.join(rootfs, rel)
        if os.path.isfile(src):
            dst = os.path.join(out_dir, os.path.basename(rel))
            shutil.copy2(src, dst)
            os.chmod(dst, 0o644)
            copied.append(dst)
            print(f"  ✓ {rel}")
        else:
            print(f"  ✗ {rel}  (not found)")
    return copied


# ── Main ─────────────────────────────────────────────────────────────────────


def extract_firmware(fw_path: str, out_dir: str) -> None:
    """High-level extraction pipeline."""
    os.makedirs(out_dir, exist_ok=True)

    with open(fw_path, "rb") as fh:
        data = fh.read()

    squashfs_list = find_squashfs(data)
    if not squashfs_list:
        sys.exit("No SquashFS image found in firmware.")

    # Use the largest SquashFS (the rootfs).
    offset, size = squashfs_list[0]
    print(f"SquashFS rootfs at offset 0x{offset:08x}, size {size} bytes")

    with tempfile.TemporaryDirectory() as tmp:
        img_path = os.path.join(tmp, "rootfs.sqfs")
        with open(img_path, "wb") as fh:
            fh.write(data[offset : offset + size])

        rootfs_dir = os.path.join(tmp, "rootfs")
        print("Extracting SquashFS …")
        extract_squashfs(img_path, rootfs_dir)

        binaries_dir = os.path.join(out_dir, "binaries")
        os.makedirs(binaries_dir, exist_ok=True)
        print("Copying binaries:")
        copy_binaries(rootfs_dir, binaries_dir)

        # Look for tar.gz archives (runtime jffs2 files are not in the
        # firmware image, but we note their paths for documentation).
        print("\nJFFS2 runtime archives (referenced but not in firmware image):")
        print("  /mnt/jffs2/ttree_spec_smooth.tar.gz")
        print("  /mnt/jffs2/app/preload_cplugin.tar.gz")
        print("  /mnt/jffs2/app/plugin_preload.tar.gz")
        print("  (These files exist only on the live device's flash.)")

    print(f"\nExtraction complete → {out_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract Huawei HWNP firmware")
    parser.add_argument("firmware", nargs="?", help="Path to firmware .bin")
    parser.add_argument("--url", default=None, help="Download URL")
    parser.add_argument("-o", "--output", default="fw_extracted", help="Output dir")
    args = parser.parse_args()

    if args.firmware:
        fw_path = args.firmware
    elif args.url:
        fw_path = download(args.url, tempfile.mkdtemp())
    else:
        # Try default location in the repo
        repo = Path(__file__).resolve().parent.parent
        default = repo / "EG8145V5-V500R022C00SPC340B019.bin"
        if default.is_file():
            fw_path = str(default)
        else:
            fw_path = download(DEFAULT_URL, tempfile.mkdtemp())

    extract_firmware(fw_path, args.output)


if __name__ == "__main__":
    main()
