#!/usr/bin/env python3
"""Download firmware images from GitHub releases.

Downloads all firmware .bin files and the HG8245C .rar archive
to the specified output directory.

Usage:
    python tools/download_firmwares.py [--output-dir DIR]
"""

import argparse
import hashlib
import os
import sys
import urllib.error
import urllib.request

FIRMWARES = [
    {
        "name": "HG8145V5",
        "filename": "5611_HG8145V5V500R020C10SPC212.bin",
        "url": "https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/5611_HG8145V5V500R020C10SPC212.bin",
        "md5": "ed450e26d03d39bd8193dd7c8f810d05",
        "size": 50233629,
    },
    {
        "name": "EG8145V5",
        "filename": "EG8145V5-V500R022C00SPC340B019.bin",
        "url": "https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/EG8145V5-V500R022C00SPC340B019.bin",
        "md5": "7768ad910c0d9d5a7f9a9d36246e1aec",
        "size": 42959989,
    },
    {
        "name": "HN8145XR",
        "filename": "HN8145XRV500R022C10SPC160.1.bin",
        "url": "https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/HN8145XRV500R022C10SPC160.1.bin",
        "md5": "c589cc81e548439d7c8773f7b86085a8",
        "size": 91046961,
    },
    {
        "name": "HG8245C",
        "filename": "HG8245C.rar",
        "url": "https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/HG8245C.rar",
        "md5": "3691ec67d6cc10c558ecabb124f6892e",
        "size": 72836524,
    },
]


def _calculate_md5(filepath):
    """Calculate MD5 hash of a file."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def download_file(url, dest, expected_md5=None):
    """Download a file with progress reporting and MD5 verification."""
    print(f"  Downloading {os.path.basename(dest)}...")
    try:
        urllib.request.urlretrieve(url, dest)
    except (urllib.error.URLError, OSError) as e:
        print(f"  ERROR: Failed to download from {url}: {e}")
        return False
    actual_size = os.path.getsize(dest)
    print(f"  Size: {actual_size:,} bytes")

    if expected_md5:
        actual_md5 = _calculate_md5(dest)
        if actual_md5 != expected_md5:
            print(f"  WARNING: MD5 mismatch! expected={expected_md5}, got={actual_md5}")
            return False
        print(f"  MD5: {actual_md5} ✓")
    return True


def main():
    parser = argparse.ArgumentParser(description="Download Huawei firmware images")
    parser.add_argument(
        "--output-dir",
        default="firmwares",
        help="Output directory (default: firmwares/)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if file exists with correct MD5",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Downloading {len(FIRMWARES)} firmware images to {args.output_dir}/\n")

    downloaded_count = 0
    for fw in FIRMWARES:
        dest = os.path.join(args.output_dir, fw["filename"])
        print(f"[{fw['name']}]")

        # Skip if already exists with correct MD5
        if os.path.exists(dest) and not args.force:
            if _calculate_md5(dest) == fw["md5"]:
                print(f"  Already exists with correct MD5, skipping")
                downloaded_count += 1
                continue

        if download_file(fw["url"], dest, fw["md5"]):
            downloaded_count += 1
        print()

    print(f"\nDone: {downloaded_count}/{len(FIRMWARES)} firmwares downloaded successfully")
    return 0 if downloaded_count == len(FIRMWARES) else 1


if __name__ == "__main__":
    sys.exit(main())
