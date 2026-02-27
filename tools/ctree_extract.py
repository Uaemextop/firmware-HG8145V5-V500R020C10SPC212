#!/usr/bin/env python3
"""Extract and analyse hw_ctree.xml and config files from Huawei firmware images.

Downloads (or reads local) firmware images, locates the SquashFS rootfs,
extracts configuration files (``hw_ctree.xml``, ``hw_default_ctree.xml``,
flash layout XML, hardware DSP configs, per-model WiFi INI files), and
attempts decryption of the encrypted ctree using known chip-ID keys.

Usage::

    # Analyse all four release firmwares
    python tools/ctree_extract.py -o /tmp/fw_configs

    # Analyse a single local file
    python tools/ctree_extract.py firmware.bin -o /tmp/fw_configs

The tool produces:
* ``<out>/configs/<model>/``  – extracted raw config files per firmware
* ``<out>/FIRMWARE_CONFIGS.md`` – Markdown analysis report
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Allow running from repo root or tools/
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from hwflash.core.crypto import (  # noqa: E402
    KNOWN_CHIP_IDS,
    decrypt_config,
    try_decrypt_all_keys,
)

# ── Constants ────────────────────────────────────────────────────────────────

SQUASHFS_MAGIC_LE = b"hsqs"
SQUASHFS_MAGIC_BE = b"sqsh"

RELEASE_BASE = (
    "https://github.com/Uaemextop/HuaweiFirmwareTool/releases/download/V2/"
)

DEFAULT_FIRMWARES: Dict[str, str] = {
    "HG8145V5": RELEASE_BASE + "5611_HG8145V5V500R020C10SPC212.bin",
    "EG8145V5": RELEASE_BASE + "EG8145V5-V500R022C00SPC340B019.bin",
    "HN8145XR": RELEASE_BASE + "HN8145XRV500R022C10SPC160.1.bin",
    "HG8245C":  RELEASE_BASE + "HG8245C.rar",
}

CONFIG_GLOBS = [
    "etc/wap/hw_ctree.xml",
    "etc/wap/hw_default_ctree.xml",
    "etc/hw_flashcfg_shaopian.xml",
    "etc/wap/CoverActionConfig.xml",
    "etc/version",
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def find_squashfs(data: bytes) -> List[Tuple[int, int]]:
    """Return ``(offset, bytes_used)`` for every SquashFS image found."""
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


def _download(url: str, dest_dir: str) -> str:
    """Download *url* into *dest_dir*, return local path."""
    fname = os.path.join(dest_dir, os.path.basename(url))
    if os.path.isfile(fname):
        return fname
    print(f"  Downloading {os.path.basename(url)} …")
    urllib.request.urlretrieve(url, fname)
    return fname


def _extract_rar(rar_path: str, dest_dir: str) -> List[str]:
    """Extract a RAR archive, return list of .bin files inside."""
    subprocess.check_call(
        ["7z", "x", "-y", rar_path, f"-o{dest_dir}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    bins: list[str] = []
    for root, _dirs, files in os.walk(dest_dir):
        for f in files:
            if f.lower().endswith(".bin"):
                bins.append(os.path.join(root, f))
    bins.sort(key=lambda p: os.path.getsize(p), reverse=True)
    return bins


def _extract_squashfs(sqfs_data: bytes, dest: str) -> str:
    """Write SquashFS image and run ``unsquashfs``."""
    with tempfile.NamedTemporaryFile(suffix=".sqfs", delete=False) as tmp:
        tmp.write(sqfs_data)
        tmp_path = tmp.name
    try:
        subprocess.check_call(
            ["unsquashfs", "-d", dest, "-f", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    finally:
        os.unlink(tmp_path)
    return dest


def _read_file_maybe_root(path: str) -> Optional[bytes]:
    """Read a file, falling back to ``sudo cat`` if permission denied."""
    try:
        return Path(path).read_bytes()
    except PermissionError:
        try:
            return subprocess.check_output(["sudo", "cat", path])
        except Exception:
            return None


def _maybe_gunzip(blob: bytes) -> bytes:
    """Decompress gzip if the blob has gzip magic."""
    if len(blob) >= 2 and blob[0] == 0x1F and blob[1] == 0x8B:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(blob)) as gz:
                return gz.read()
        except OSError:
            pass
    return blob


def _looks_like_xml(blob: bytes) -> bool:
    """Heuristic check for XML content."""
    if not blob:
        return False
    head = blob[:512].lstrip(b"\x00\t\r\n \xef\xbb\xbf\xff\xfe\xfe\xff")
    return head.startswith(b"<?xml") or head.startswith(b"<")


# ── Per-firmware analysis ────────────────────────────────────────────────────


class FirmwareConfig:
    """Holds analysis results for one firmware image."""

    def __init__(self, model: str, path: str):
        self.model = model
        self.path = path
        self.version = ""
        self.sqfs_count = 0
        self.rootfs_size = 0
        self.ctree_files: Dict[str, bytes] = {}  # relpath → raw bytes
        self.ctree_decrypted: Dict[str, Optional[Tuple[str, bytes]]] = {}
        self.flash_layout: Optional[str] = None
        self.ini_configs: List[str] = []
        self.xml_configs: List[str] = []
        self.hardware_dirs: List[str] = []
        self.has_aescrypt2 = False

    def analyse_rootfs(self, rootfs_dir: str) -> None:
        """Walk the extracted rootfs and collect config information."""
        # Version
        ver_path = os.path.join(rootfs_dir, "etc/version")
        ver_data = _read_file_maybe_root(ver_path)
        if ver_data:
            self.version = ver_data.decode("utf-8", errors="replace").strip()

        # aescrypt2 presence
        self.has_aescrypt2 = os.path.exists(
            os.path.join(rootfs_dir, "bin/aescrypt2")
        )

        # Flash layout
        flash_path = os.path.join(rootfs_dir, "etc/hw_flashcfg_shaopian.xml")
        flash_data = _read_file_maybe_root(flash_path)
        if flash_data:
            self.flash_layout = flash_data.decode("utf-8", errors="replace")

        # Ctree files
        for name in ("etc/wap/hw_ctree.xml", "etc/wap/hw_default_ctree.xml"):
            full = os.path.join(rootfs_dir, name)
            data = _read_file_maybe_root(full)
            if data:
                self.ctree_files[name] = data

        # Try decrypting each ctree
        for relpath, raw in self.ctree_files.items():
            self._try_decrypt_ctree(relpath, raw)

        # INI and XML configs
        wap_dir = os.path.join(rootfs_dir, "etc/wap")
        if os.path.isdir(wap_dir):
            for fn in sorted(os.listdir(wap_dir)):
                if fn.endswith(".ini"):
                    self.ini_configs.append(fn)
                elif fn.endswith(".xml") and "ctree" not in fn:
                    self.xml_configs.append(fn)

        # Hardware board directories
        hw_dir = os.path.join(rootfs_dir, "etc/ont/hardware")
        if os.path.isdir(hw_dir):
            self.hardware_dirs = sorted(os.listdir(hw_dir))

    def _try_decrypt_ctree(self, relpath: str, raw: bytes) -> None:
        """Attempt decryption with chip-ID keys, with and without header."""
        for skip in (0, 4):
            chunk = raw[skip:]
            # Align to AES block size
            remainder = len(chunk) % 16
            if remainder:
                chunk = chunk[: len(chunk) - remainder]
            if len(chunk) < 16:
                continue

            results = try_decrypt_all_keys(chunk)
            if results:
                chip_id, decrypted = results[0]
                decrypted = _maybe_gunzip(decrypted)
                if _looks_like_xml(decrypted):
                    self.ctree_decrypted[relpath] = (chip_id, decrypted)
                    return

        self.ctree_decrypted[relpath] = None


def analyse_firmware(
    model: str, fw_path: str, out_dir: str
) -> FirmwareConfig:
    """Full analysis pipeline for one firmware binary."""
    cfg = FirmwareConfig(model, fw_path)

    data = Path(fw_path).read_bytes()
    sqfs_list = find_squashfs(data)
    cfg.sqfs_count = len(sqfs_list)

    if not sqfs_list:
        print(f"  ⚠ No SquashFS found in {os.path.basename(fw_path)}")
        return cfg

    offset, size = sqfs_list[0]
    cfg.rootfs_size = size
    sqfs_data = data[offset : offset + size]

    rootfs_dir = tempfile.mkdtemp(prefix=f"rootfs_{model}_")
    try:
        _extract_squashfs(sqfs_data, rootfs_dir)
        cfg.analyse_rootfs(rootfs_dir)
        _copy_configs(cfg, rootfs_dir, out_dir)
    except subprocess.CalledProcessError as exc:
        print(f"  ⚠ unsquashfs failed for {model}: {exc}")
    finally:
        shutil.rmtree(rootfs_dir, ignore_errors=True)

    return cfg


def _copy_configs(cfg: FirmwareConfig, rootfs: str, out_dir: str) -> None:
    """Copy interesting config files to the output directory."""
    model_dir = os.path.join(out_dir, "configs", cfg.model)
    os.makedirs(model_dir, exist_ok=True)

    # Raw ctree files
    for relpath, raw in cfg.ctree_files.items():
        dst = os.path.join(model_dir, os.path.basename(relpath))
        Path(dst).write_bytes(raw)

    # Decrypted ctree (if any)
    for relpath, result in cfg.ctree_decrypted.items():
        if result is not None:
            _chip_id, xml_data = result
            base = os.path.basename(relpath).replace(".xml", "_decrypted.xml")
            dst = os.path.join(model_dir, base)
            Path(dst).write_bytes(xml_data)

    # Flash layout
    if cfg.flash_layout:
        dst = os.path.join(model_dir, "hw_flashcfg_shaopian.xml")
        Path(dst).write_text(cfg.flash_layout)

    # Per-model INI configs (copy first 3 matching model name)
    wap_dir = os.path.join(rootfs, "etc/wap")
    copied_ini = 0
    for ini in cfg.ini_configs:
        if copied_ini >= 3:
            break
        src = os.path.join(wap_dir, ini)
        data = _read_file_maybe_root(src)
        if data:
            Path(os.path.join(model_dir, ini)).write_bytes(data)
            copied_ini += 1


# ── Report generation ────────────────────────────────────────────────────────


def _generate_report(
    configs: List[FirmwareConfig], out_dir: str
) -> str:
    """Generate FIRMWARE_CONFIGS.md and return its content."""
    lines: list[str] = []
    lines.append("# Huawei Firmware Configuration Analysis")
    lines.append("")
    lines.append("Auto-generated report of `hw_ctree.xml` and configuration ")
    lines.append("files extracted from Huawei ONT firmware images.")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Model | Version | Rootfs | Ctree Size | Encrypted | "
                 "Decryptable | INI Configs | HW Boards |")
    lines.append("|-------|---------|--------|------------|-----------|"
                 "-------------|-------------|-----------|")
    for c in configs:
        ct_size = ""
        encrypted = ""
        decryptable = ""
        if c.ctree_files:
            first_raw = next(iter(c.ctree_files.values()))
            ct_size = f"{len(first_raw):,} B"
            encrypted = "Yes" if first_raw[:1] != b"<" else "No"
            first_key = next(iter(c.ctree_files))
            dec = c.ctree_decrypted.get(first_key)
            if dec is not None:
                decryptable = f"Yes ({dec[0]})"
            else:
                decryptable = "No (device key)"
        rootfs_str = f"{c.rootfs_size / 1024 / 1024:.1f} MB" if c.rootfs_size else "N/A"
        lines.append(
            f"| {c.model} | {c.version or 'N/A'} | {rootfs_str} | "
            f"{ct_size} | {encrypted} | {decryptable} | "
            f"{len(c.ini_configs)} | {len(c.hardware_dirs)} |"
        )
    lines.append("")

    # Per-firmware details
    for c in configs:
        lines.append(f"## {c.model}")
        lines.append("")
        if c.version:
            lines.append(f"**Firmware version:** `{c.version}`")
            lines.append("")
        lines.append(f"- **SquashFS images:** {c.sqfs_count}")
        if c.rootfs_size:
            lines.append(
                f"- **Rootfs size:** {c.rootfs_size:,} bytes "
                f"({c.rootfs_size / 1024 / 1024:.1f} MB)"
            )
        lines.append(f"- **aescrypt2 binary:** {'Yes' if c.has_aescrypt2 else 'No'}")
        lines.append("")

        # Ctree analysis
        if c.ctree_files:
            lines.append("### Configuration Tree (hw_ctree.xml)")
            lines.append("")
            for relpath, raw in c.ctree_files.items():
                lines.append(f"**{relpath}** — {len(raw):,} bytes")
                lines.append("")
                lines.append(f"- Header: `{raw[:16].hex()}`")
                has_header = raw[:4] == b"\x01\x00\x00\x00"
                lines.append(
                    f"- 4-byte header (0x01000000): {'Yes' if has_header else 'No'}"
                )
                dec = c.ctree_decrypted.get(relpath)
                if dec is not None:
                    chip_id, xml_data = dec
                    lines.append(
                        f"- **Decrypted** with chip ID `{chip_id}` → "
                        f"{len(xml_data):,} bytes XML"
                    )
                    # Show first few lines
                    preview = xml_data[:500].decode("utf-8", errors="replace")
                    lines.append("")
                    lines.append("```xml")
                    for line in preview.split("\n")[:15]:
                        lines.append(line)
                    lines.append("```")
                else:
                    lines.append(
                        "- **Not decryptable** with known chip-ID keys. "
                        "The key is derived from the device's hardware e-fuse "
                        "and is unique per device/firmware version."
                    )
                lines.append("")

        # Flash layout
        if c.flash_layout:
            lines.append("### Flash Layout")
            lines.append("")
            lines.append("```xml")
            for line in c.flash_layout.strip().split("\n"):
                lines.append(line)
            lines.append("```")
            lines.append("")

        # INI configs
        if c.ini_configs:
            lines.append("### WiFi / Hardware INI Configs")
            lines.append("")
            for ini in c.ini_configs:
                lines.append(f"- `{ini}`")
            lines.append("")

        # Hardware board directories
        if c.hardware_dirs:
            lines.append("### Supported Hardware Boards")
            lines.append("")
            for d in c.hardware_dirs:
                lines.append(f"- `{d}`")
            lines.append("")

    # Encryption note
    lines.append("## Encryption Details")
    lines.append("")
    lines.append(
        "The `hw_ctree.xml` files in firmware images are encrypted with "
        "AES and cannot be decrypted without the device-specific key."
    )
    lines.append("")
    lines.append("### Key Derivation Chain")
    lines.append("")
    lines.append("```")
    lines.append("e-fuse (hardware root key, per-device)")
    lines.append("  └─→ keyfile partition (encrypted work key)")
    lines.append("       └─→ AES-256-CBC key for hw_ctree.xml")
    lines.append("```")
    lines.append("")
    lines.append(
        "The simple chip-ID key method (`Df7!ui%s9(lmV1L8`) used for "
        "config backups exported via the web interface does **not** work "
        "for the factory-default ctree in firmware images."
    )
    lines.append("")
    lines.append("### Known Chip IDs (for backup config decryption)")
    lines.append("")
    for cid in KNOWN_CHIP_IDS:
        lines.append(f"- `{cid}`")
    lines.append("")

    report = "\n".join(lines)
    report_path = os.path.join(out_dir, "FIRMWARE_CONFIGS.md")
    Path(report_path).write_text(report)
    return report


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and analyse hw_ctree.xml from Huawei firmware"
    )
    parser.add_argument(
        "firmware",
        nargs="*",
        help="Path(s) to firmware .bin file(s). "
        "If omitted, downloads the four default release firmwares.",
    )
    parser.add_argument(
        "-o", "--output", default="fw_configs", help="Output directory"
    )
    args = parser.parse_args()

    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)

    results: list[FirmwareConfig] = []

    if args.firmware:
        # Analyse explicitly provided files
        for fpath in args.firmware:
            model = Path(fpath).stem
            print(f"\n{'='*60}")
            print(f"Analysing: {model}")
            cfg = analyse_firmware(model, fpath, out_dir)
            results.append(cfg)
    else:
        # Download and analyse all default firmwares
        dl_dir = tempfile.mkdtemp(prefix="fw_dl_")
        try:
            for model, url in DEFAULT_FIRMWARES.items():
                print(f"\n{'='*60}")
                print(f"Firmware: {model}")
                local = _download(url, dl_dir)

                if url.endswith(".rar"):
                    # Extract RAR, analyse each .bin inside
                    rar_dir = os.path.join(dl_dir, f"{model}_rar")
                    bins = _extract_rar(local, rar_dir)
                    if not bins:
                        print(f"  ⚠ No .bin files found in {url}")
                        continue
                    # Take the largest bin that has SquashFS
                    for bpath in bins:
                        bname = Path(bpath).stem
                        sub_model = f"{model}_{bname}"
                        print(f"  Sub-image: {bname}")
                        cfg = analyse_firmware(sub_model, bpath, out_dir)
                        if cfg.sqfs_count > 0:
                            results.append(cfg)
                else:
                    # Also check if the file exists locally in the repo
                    repo_path = _REPO / os.path.basename(url)
                    if repo_path.is_file():
                        local = str(repo_path)
                    cfg = analyse_firmware(model, local, out_dir)
                    results.append(cfg)
        finally:
            shutil.rmtree(dl_dir, ignore_errors=True)

    # Generate report
    print(f"\n{'='*60}")
    print("Generating analysis report …")
    _generate_report(results, out_dir)

    print(f"\nResults saved to {out_dir}/")
    print(f"  configs/  – extracted config files per firmware")
    print(f"  FIRMWARE_CONFIGS.md – analysis report")

    # Print summary
    for c in results:
        status = "✓ decrypted" if any(
            v is not None for v in c.ctree_decrypted.values()
        ) else "✗ encrypted (device key)"
        print(f"  {c.model}: {c.version or 'N/A'} → {status}")


if __name__ == "__main__":
    main()
