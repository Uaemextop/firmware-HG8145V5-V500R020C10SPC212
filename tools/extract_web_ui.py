#!/usr/bin/env python3
"""Extract web UI (HTML/JS/CSS/ASP) and configs from firmware SquashFS rootfs.

Extracts the /html/ web interface and /etc/wap/ configurations from each
firmware image's SquashFS rootfs.

Usage:
    python tools/extract_web_ui.py --firmware-dir DIR --output-dir DIR
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys


FIRMWARE_MAP = {
    "HG8145V5": {
        "filename": "5611_HG8145V5V500R020C10SPC212.bin",
        "config_name": "HG8145V5-V500R020C10SPC212",
    },
    "EG8145V5": {
        "filename": "EG8145V5-V500R022C00SPC340B019.bin",
        "config_name": "EG8145V5-V500R022C00SPC340B019",
    },
    "HN8145XR": {
        "filename": "HN8145XRV500R022C10SPC160.1.bin",
        "config_name": "HN8145XR-V500R022C10SPC160",
    },
}

RAR_FIRMWARES = {
    "HG8145C-V5R019C00S105": "8145C-V5R019C00S105-EN-BLUE.bin",
    "HG8245C-8145C-BLUE-R019-xpon": "8245c-8145c-BLUE-R019-EN-xpon.bin",
    "HG8145C_17120_ENG": "HG8145C_17120_ENG.bin",
}


def find_squashfs(data):
    """Find SquashFS filesystems in firmware image."""
    results = []
    for magic in [b'hsqs', b'sqsh']:
        pos = 0
        while True:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            if idx + 96 <= len(data):
                inode_count = struct.unpack_from('<I', data, idx + 4)[0]
                bytes_used = struct.unpack_from('<Q', data, idx + 40)[0]
                if inode_count > 10 and bytes_used > 100000 and bytes_used < len(data):
                    results.append((idx, bytes_used, inode_count))
            pos = idx + 4
    return results


def extract_squashfs(fw_path, work_dir):
    """Extract largest SquashFS from firmware image."""
    with open(fw_path, 'rb') as f:
        data = f.read()

    sqfs_list = find_squashfs(data)
    if not sqfs_list:
        print(f"  No SquashFS found in {fw_path}")
        return None

    sqfs_list.sort(key=lambda x: x[1], reverse=True)
    offset, size, inodes = sqfs_list[0]
    print(f"  SquashFS at 0x{offset:08x}, {size:,} bytes, {inodes} inodes")

    sqfs_path = os.path.join(work_dir, "rootfs.sqfs")
    with open(sqfs_path, 'wb') as f:
        f.write(data[offset:offset + size])

    rootfs_dir = os.path.join(work_dir, "rootfs")
    os.makedirs(rootfs_dir, exist_ok=True)

    result = subprocess.run(
        ["sudo", "unsquashfs", "-f", "-d", rootfs_dir,
         "-no-xattrs", "-ignore-errors", sqfs_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  unsquashfs warning: {result.stderr[:200]}")

    os.unlink(sqfs_path)
    return rootfs_dir


def copy_web_ui(rootfs_dir, output_dir, name):
    """Copy web UI from rootfs /html/ to output directory."""
    html_src = os.path.join(rootfs_dir, "html")
    if not os.path.isdir(html_src):
        print(f"  No /html/ directory in {name}")
        return 0

    web_dest = os.path.join(output_dir, name, "web")
    os.makedirs(web_dest, exist_ok=True)

    count = 0
    for root, dirs, files in os.walk(html_src):
        rel = os.path.relpath(root, html_src)
        dest_dir = os.path.join(web_dest, rel) if rel != "." else web_dest
        os.makedirs(dest_dir, exist_ok=True)
        for f in files:
            src = os.path.join(root, f)
            dst = os.path.join(dest_dir, f)
            try:
                shutil.copy2(src, dst)
                count += 1
            except (PermissionError, OSError):
                try:
                    subprocess.run(["sudo", "cp", "-a", src, dst],
                                   capture_output=True, check=True)
                    count += 1
                except subprocess.CalledProcessError:
                    pass
    return count


def copy_configs(rootfs_dir, output_dir, name):
    """Copy /etc/wap/ config files to output directory."""
    wap_src = os.path.join(rootfs_dir, "etc", "wap")
    if not os.path.isdir(wap_src):
        print(f"  No /etc/wap/ directory in {name}")
        return 0

    cfg_dest = os.path.join(output_dir, name, "configs")
    os.makedirs(cfg_dest, exist_ok=True)

    count = 0
    for f in os.listdir(wap_src):
        src = os.path.join(wap_src, f)
        if os.path.isfile(src):
            dst = os.path.join(cfg_dest, f)
            try:
                shutil.copy2(src, dst)
                count += 1
            except (PermissionError, OSError):
                try:
                    subprocess.run(["sudo", "cp", "-a", src, dst],
                                   capture_output=True, check=True)
                    count += 1
                except subprocess.CalledProcessError:
                    pass
    return count


def main():
    parser = argparse.ArgumentParser(description="Extract web UI from firmware")
    parser.add_argument("--firmware-dir", default="/tmp/firmwares",
                        help="Directory with downloaded firmware files")
    parser.add_argument("--output-dir", default="firmware_web_ui",
                        help="Output directory for extracted content")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    for short_name, info in FIRMWARE_MAP.items():
        fw_path = os.path.join(args.firmware_dir, info["filename"])
        if not os.path.isfile(fw_path):
            print(f"[SKIP] {short_name}: {fw_path} not found")
            continue

        print(f"\n=== {short_name} ({info['config_name']}) ===")
        work_dir = os.path.join("/tmp", f"fw_extract_{short_name}")
        os.makedirs(work_dir, exist_ok=True)

        rootfs_dir = extract_squashfs(fw_path, work_dir)
        if not rootfs_dir:
            continue

        web_count = copy_web_ui(rootfs_dir, args.output_dir,
                                info["config_name"])
        cfg_count = copy_configs(rootfs_dir, args.output_dir,
                                 info["config_name"])
        print(f"  Extracted {web_count} web files, {cfg_count} config files")

        shutil.rmtree(work_dir, ignore_errors=True)

    # Handle RAR-extracted firmwares
    rar_path = os.path.join(args.firmware_dir, "HG8245C.rar")
    if os.path.isfile(rar_path):
        rar_dir = os.path.join("/tmp", "rar_extract")
        os.makedirs(rar_dir, exist_ok=True)
        subprocess.run(["unrar", "x", "-o+", rar_path, rar_dir],
                        capture_output=True)

        for config_name, bin_name in RAR_FIRMWARES.items():
            bin_path = os.path.join(rar_dir, bin_name)
            if not os.path.isfile(bin_path):
                print(f"[SKIP] {config_name}: {bin_name} not found in RAR")
                continue

            print(f"\n=== {config_name} ===")
            work_dir = os.path.join("/tmp", f"fw_extract_{config_name}")
            os.makedirs(work_dir, exist_ok=True)

            rootfs_dir = extract_squashfs(bin_path, work_dir)
            if not rootfs_dir:
                continue

            web_count = copy_web_ui(rootfs_dir, args.output_dir, config_name)
            cfg_count = copy_configs(rootfs_dir, args.output_dir, config_name)
            print(f"  Extracted {web_count} web files, {cfg_count} config files")

            shutil.rmtree(work_dir, ignore_errors=True)

        shutil.rmtree(rar_dir, ignore_errors=True)

    print("\n=== Done ===")
    for d in sorted(os.listdir(args.output_dir)):
        full = os.path.join(args.output_dir, d)
        if os.path.isdir(full):
            web_dir = os.path.join(full, "web")
            cfg_dir = os.path.join(full, "configs")
            web_n = sum(1 for _, _, fs in os.walk(web_dir) for _ in fs) \
                if os.path.isdir(web_dir) else 0
            cfg_n = len(os.listdir(cfg_dir)) if os.path.isdir(cfg_dir) else 0
            print(f"  {d}: {web_n} web, {cfg_n} configs")


if __name__ == "__main__":
    main()
