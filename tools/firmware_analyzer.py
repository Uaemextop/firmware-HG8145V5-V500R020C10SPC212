#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob as globmod
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import capstone
except ImportError:
    sys.exit("capstone not installed – run:  pip install capstone")


@dataclass
class Section:
    name: str
    sh_type: int
    addr: int
    offset: int
    size: int


@dataclass
class DynSym:
    name: str
    value: int
    size: int
    bind: int
    stype: int
    shndx: int


@dataclass
class ElfInfo:
    entry: int
    sections: Dict[str, Section] = field(default_factory=dict)
    dynsyms: List[DynSym] = field(default_factory=list)
    plt_map: Dict[int, str] = field(default_factory=dict)
    exported: Dict[int, str] = field(default_factory=dict)
    strings_map: Dict[int, str] = field(default_factory=dict)


ELF_MAGIC = b"\x7fELF"


def _read_str(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end == -1:
        return ""
    return data[offset:end].decode("ascii", errors="replace")


def parse_elf32(data: bytes) -> Optional[ElfInfo]:
    if len(data) < 52 or data[:4] != ELF_MAGIC:
        return None
    if data[4] != 1 or data[5] != 1:
        return None

    e_entry = struct.unpack_from("<I", data, 24)[0]
    e_shoff = struct.unpack_from("<I", data, 32)[0]
    e_shentsize = struct.unpack_from("<H", data, 46)[0]
    e_shnum = struct.unpack_from("<H", data, 48)[0]
    e_shstrndx = struct.unpack_from("<H", data, 50)[0]

    if e_shoff == 0 or e_shnum == 0:
        return None

    info = ElfInfo(entry=e_entry)

    shstr_base = e_shoff + e_shstrndx * e_shentsize
    if shstr_base + 20 > len(data):
        return None
    shstr_off = struct.unpack_from("<I", data, shstr_base + 16)[0]

    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if base + 24 > len(data):
            break
        sh_name_idx = struct.unpack_from("<I", data, base)[0]
        sh_type = struct.unpack_from("<I", data, base + 4)[0]
        sh_addr = struct.unpack_from("<I", data, base + 12)[0]
        sh_offset = struct.unpack_from("<I", data, base + 16)[0]
        sh_size = struct.unpack_from("<I", data, base + 20)[0]
        name = _read_str(data, shstr_off + sh_name_idx)
        info.sections[name] = Section(name, sh_type, sh_addr, sh_offset, sh_size)

    if ".dynsym" in info.sections and ".dynstr" in info.sections:
        dsym = info.sections[".dynsym"]
        dstr = info.sections[".dynstr"]
        for i in range(dsym.size // 16):
            base = dsym.offset + i * 16
            if base + 16 > len(data):
                break
            st_name = struct.unpack_from("<I", data, base)[0]
            st_value = struct.unpack_from("<I", data, base + 4)[0]
            st_size = struct.unpack_from("<I", data, base + 8)[0]
            st_info = data[base + 12]
            st_shndx = struct.unpack_from("<H", data, base + 14)[0]
            name = _read_str(data, dstr.offset + st_name)
            sym = DynSym(name, st_value, st_size, st_info >> 4, st_info & 0xF, st_shndx)
            if name:
                info.dynsyms.append(sym)
                if st_value and st_shndx:
                    info.exported[st_value] = name

    _build_plt_map(data, info)

    if ".rodata" in info.sections:
        sec = info.sections[".rodata"]
        rd = data[sec.offset: sec.offset + sec.size]
        i = 0
        while i < len(rd):
            end = rd.find(b"\x00", i)
            if end == -1:
                break
            s = rd[i:end]
            if len(s) >= 4 and all(32 <= b < 127 for b in s):
                info.strings_map[sec.addr + i] = s.decode("ascii")
            i = end + 1

    return info


def _build_plt_map(data: bytes, info: ElfInfo) -> None:
    if ".plt" not in info.sections or ".got" not in info.sections:
        return
    plt = info.sections[".plt"]
    imports = [s for s in info.dynsyms if s.shndx == 0 and s.stype == 2]
    plt_header_size = 20
    plt_entry_size = 12
    num_entries = (plt.size - plt_header_size) // plt_entry_size
    for i in range(min(num_entries, len(imports))):
        stub_addr = plt.addr + plt_header_size + i * plt_entry_size
        info.plt_map[stub_addr] = imports[i].name


def capstone_analyze_binary(filepath: str, max_instructions: int = 500) -> dict:
    result = {
        "file": os.path.basename(filepath),
        "path": filepath,
        "error": None,
        "sections": [],
        "imports": [],
        "exports": [],
        "security_strings": [],
        "http_strings": [],
        "debug_strings": [],
        "plt_functions": [],
        "disasm_snippet": [],
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (OSError, IOError) as e:
        result["error"] = str(e)
        return result

    elf = parse_elf32(data)
    if elf is None:
        result["error"] = "Not a valid 32-bit ARM ELF"
        return result

    result["entry_point"] = f"0x{elf.entry:08x}"
    result["sections"] = [
        {"name": s.name, "addr": f"0x{s.addr:08x}", "size": s.size}
        for s in elf.sections.values()
        if s.name
    ]
    result["imports"] = [
        s.name for s in elf.dynsyms if s.shndx == 0 and s.stype == 2
    ]
    result["exports"] = [
        {"name": s.name, "addr": f"0x{s.value:08x}", "size": s.size}
        for s in elf.dynsyms
        if s.shndx != 0 and s.stype == 2 and s.size > 0
    ]
    result["plt_functions"] = [
        {"addr": f"0x{addr:08x}", "name": name}
        for addr, name in sorted(elf.plt_map.items())
    ]

    sec_patterns = re.compile(
        r"(?i)(aes|rsa|sha|md5|hmac|encrypt|decrypt|password|passwd|key|cert|"
        r"sign|verify|token|auth|session|cookie|salt|pbkdf|kmc|efuse)"
    )
    http_patterns = re.compile(
        r"(?i)(http|https|port|listen|bind|server|443|8080|8443|7547|cwmp|tr069|"
        r"\.asp|\.cgi|login|index|frame|proxy|redirect)"
    )
    debug_patterns = re.compile(
        r"(?i)(debug|telnet|ssh|engineer|factory|maintenance|UserLevel|"
        r"X_HW_DEBUG|TelnetSwitch|SshSwitch|admin|chipdebug|restore)"
    )

    for addr, s in sorted(elf.strings_map.items()):
        if sec_patterns.search(s):
            result["security_strings"].append({"addr": f"0x{addr:08x}", "value": s})
        if http_patterns.search(s):
            result["http_strings"].append({"addr": f"0x{addr:08x}", "value": s})
        if debug_patterns.search(s):
            result["debug_strings"].append({"addr": f"0x{addr:08x}", "value": s})

    if ".text" in elf.sections:
        text = elf.sections[".text"]
        code = data[text.offset: text.offset + text.size]
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        md.detail = True

        func_addrs = {
            s.value: s.name
            for s in elf.dynsyms
            if s.stype == 2 and s.shndx != 0 and s.size > 0
        }

        count = 0
        for ins in md.disasm(code, text.addr):
            if count >= max_instructions:
                break
            comment = ""
            if ins.mnemonic in ("bl", "blx", "b"):
                try:
                    target = int(ins.op_str.lstrip("#"), 0)
                    if target in elf.plt_map:
                        comment = f"  -> {elf.plt_map[target]}"
                    elif target in func_addrs:
                        comment = f"  -> {func_addrs[target]}"
                except ValueError:
                    pass

            label = ""
            if ins.address in func_addrs:
                label = f"\n<{func_addrs[ins.address]}>:\n"

            result["disasm_snippet"].append(
                f"{label}  0x{ins.address:08x}: {ins.mnemonic:12s} {ins.op_str}{comment}"
            )
            count += 1

    return result


def scan_web_interfaces(base_dir: str) -> dict:
    web_dir = os.path.join(base_dir, "web")
    result = {
        "frame_variants": [],
        "menu_xmls": [],
        "no_auth_pages": [],
        "portal_pages": [],
        "debug_pages": [],
        "hidden_elements": [],
        "all_asp_pages": [],
    }

    if not os.path.isdir(web_dir):
        return result

    for entry in sorted(os.listdir(web_dir)):
        full = os.path.join(web_dir, entry)
        if os.path.isdir(full) and entry.startswith("frame_"):
            pages = []
            for root, dirs, files in os.walk(full):
                for f in files:
                    if f.endswith((".asp", ".html", ".htm")):
                        pages.append(os.path.relpath(os.path.join(root, f), web_dir))
            result["frame_variants"].append({"name": entry, "pages": pages})

    aisap = os.path.join(web_dir, "FrameAISAP")
    if os.path.isdir(aisap):
        pages = []
        for root, dirs, files in os.walk(aisap):
            for f in files:
                if f.endswith((".asp", ".html", ".htm")):
                    pages.append(os.path.relpath(os.path.join(root, f), web_dir))
        result["frame_variants"].append({"name": "FrameAISAP", "pages": pages})

    menu_dir = os.path.join(web_dir, "menu")
    if os.path.isdir(menu_dir):
        result["menu_xmls"] = sorted(os.listdir(menu_dir))

    for root, dirs, files in os.walk(web_dir):
        for f in files:
            if f.endswith(".asp"):
                fpath = os.path.join(root, f)
                relpath = os.path.relpath(fpath, web_dir)
                result["all_asp_pages"].append(relpath)
                try:
                    with open(fpath, "r", errors="ignore") as fh:
                        content = fh.read()
                    if re.search(r"(?i)debug|X_HW_DEBUG", content):
                        result["debug_pages"].append(relpath)
                    if re.search(r"(?i)portal|captive|redirect", content):
                        result["portal_pages"].append(relpath)
                    hidden_matches = re.findall(
                        r'(?i)(display\s*:\s*none|visibility\s*:\s*hidden|type\s*=\s*["\']hidden["\'])',
                        content,
                    )
                    if hidden_matches:
                        result["hidden_elements"].append(
                            {"page": relpath, "count": len(hidden_matches)}
                        )
                except (OSError, IOError):
                    pass

    return result


def scan_port_services(base_dir: str) -> dict:
    result = {
        "web_service": {},
        "cwmp_tr069": {},
        "cups_printing": {},
        "dlna": {},
        "ssh": {},
        "telnet": {},
        "upnp": {},
        "other_ports": [],
        "no_auth_pages": [],
        "https_features": [],
        "per_isp_ports": [],
    }

    spec_base = os.path.join(base_dir, "configs", "spec", "ssmp", "base_ssmp_spec.cfg")
    if os.path.isfile(spec_base):
        try:
            with open(spec_base, "r", errors="ignore") as f:
                content = f.read()
            for line in content.splitlines():
                if "SSMP_SPEC_WEB_PORTNUM" in line:
                    m = re.search(r'spec\.value="(\d+)"', line)
                    if m:
                        result["web_service"]["lan_port"] = int(m.group(1))
                if "SSMP_SPEC_WEB_OUTPORTNUM" in line:
                    m = re.search(r'spec\.value="(\d+)"', line)
                    if m:
                        result["web_service"]["wan_port"] = int(m.group(1))
                if "SSMP_SPEC_WEB_FRAME" in line:
                    m = re.search(r'spec\.value="([^"]+)"', line)
                    if m:
                        result["web_service"]["default_frame"] = m.group(1)
                if "SSMP_SPEC_WEB_MENUXML" in line:
                    m = re.search(r'spec\.value="([^"]+)"', line)
                    if m:
                        result["web_service"]["menu_xml"] = m.group(1)
                if "SSMP_SPEC_WEB_LISTENMODE" in line:
                    m = re.search(r'spec\.value="(\d+)"', line)
                    if m:
                        result["web_service"]["listen_mode"] = int(m.group(1))
                if "SSMP_SPEC_CWMP_HTTPSERVERPORTID" in line:
                    m = re.search(r'spec\.value="(\d+)"', line)
                    if m:
                        result["cwmp_tr069"]["http_port"] = int(m.group(1))
                if "SSMP_SPEC_CWMP_SERVER_PORT" in line:
                    m = re.search(r'spec\.value="(\d+)"', line)
                    if m:
                        result["cwmp_tr069"]["server_port"] = int(m.group(1))
                if "SSMP_SPEC_CLI_TELNETPORTID" in line:
                    m = re.search(r'spec\.value="(\d+)"', line)
                    if m:
                        result["telnet"]["port"] = int(m.group(1))
                if "SPEC_DLNA_SERVER_PORT" in line:
                    m = re.search(r'spec\.value="(\d+)"', line)
                    if m:
                        result["dlna"]["server_port"] = int(m.group(1))
                if "SPEC_DLNA_CLIENT_PORT" in line:
                    m = re.search(r'spec\.value="(\d+)"', line)
                    if m:
                        result["dlna"]["client_port"] = int(m.group(1))
        except (OSError, IOError):
            pass

    result["ssh"]["binary"] = "dropbear"
    result["ssh"]["default_port"] = 22
    result["cups_printing"]["config"] = "configs/cups/cupsd.conf"
    result["cups_printing"]["socket"] = "/var/run/cups/cups.sock"
    result["cups_printing"]["port"] = 631
    result["cups_printing"]["note"] = "Listens on Unix socket by default, TCP 631 commented out"
    result["upnp"]["binary"] = "upnpd"
    result["upnp"]["ssdp_port"] = 1900

    spec_dir = os.path.join(base_dir, "configs", "spec", "ssmp")
    if os.path.isdir(spec_dir):
        for fname in sorted(os.listdir(spec_dir)):
            fpath = os.path.join(spec_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                for line in content.splitlines():
                    if "SSMP_SPEC_WEB_NO_AUTH_PAGE" in line:
                        m = re.search(r'spec\.value="([^"]+)"', line)
                        if m:
                            pages = [p.strip() for p in m.group(1).split(";") if p.strip()]
                            result["no_auth_pages"].append(
                                {"spec_file": fname, "pages": pages}
                            )
            except (OSError, IOError):
                pass

    customize_dir = os.path.join(base_dir, "configs", "customize", "common")
    if os.path.isdir(customize_dir):
        for fname in sorted(os.listdir(customize_dir)):
            fpath = os.path.join(customize_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                for line in content.splitlines():
                    if "CWMP_HTTPSERVERPORTID" in line:
                        m = re.search(r'spec\.value="(\d+)"', line)
                        if m:
                            result["per_isp_ports"].append({
                                "isp_config": fname,
                                "service": "CWMP/TR-069",
                                "port": int(m.group(1)),
                            })
                    if "SSMP_SPEC_WEB_OUTCHANGEPORT" in line:
                        m = re.search(r'spec\.value="(\d+)"', line)
                        if m:
                            val = int(m.group(1))
                            if val != 80:
                                result["per_isp_ports"].append({
                                    "isp_config": fname,
                                    "service": "Web (external)",
                                    "port": val,
                                })
                    if re.search(r"INDEPEND_HTTPS_PORT|LAN_HTTPS_E|CLOSE_HTTPS|SMOOTH_HTTPS|HTTPSWANENABLE", line):
                        m_name = re.search(r'feature\.name="([^"]+)"', line)
                        m_en = re.search(r'feature\.enable="(\d+)"', line)
                        if m_name and m_en:
                            result["https_features"].append({
                                "isp_config": fname,
                                "feature": m_name.group(1),
                                "enabled": m_en.group(1) == "1",
                            })
            except (OSError, IOError):
                pass

    return result


def scan_debug_modes(base_dir: str) -> dict:
    result = {
        "x_hw_debug_paths": [],
        "cli_debug_commands": [],
        "debug_scripts": [],
        "gpio_scripts": [],
        "factory_reset": [],
        "user_levels": [],
        "activation_methods": [],
    }

    cli_xml = os.path.join(base_dir, "configs", "hw_cli.xml")
    if os.path.isfile(cli_xml):
        try:
            with open(cli_xml, "r", errors="ignore") as f:
                content = f.read()
            cmd_pattern = re.compile(
                r'<Cmd\s+[^>]*CmdName="([^"]+)"[^>]*ObjPath="([^"]*)"[^>]*/?>',
                re.DOTALL,
            )
            for m in cmd_pattern.finditer(content):
                cmd_name = m.group(1)
                obj_path = m.group(2)
                if "X_HW_DEBUG" in obj_path or "debug" in cmd_name.lower():
                    result["cli_debug_commands"].append({
                        "command": cmd_name,
                        "obj_path": obj_path,
                    })
        except (OSError, IOError):
            pass

    result["x_hw_debug_paths"] = [
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.TelnetSwitch",
            "purpose": "Enable/disable Telnet (0=off, 1=on)",
            "access": "cfgtool or TR-069",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.SshSwitch",
            "purpose": "Enable/disable SSH (0=off, 1=on)",
            "access": "cfgtool or TR-069",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.AMP.Optic",
            "purpose": "Optical diagnostics",
            "access": "CLI: display optic",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.AMP.UDM",
            "purpose": "UDM debug module",
            "access": "CLI: set udm debug / display udm debug",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.AMP.LedTest",
            "purpose": "LED control test",
            "access": "CLI: set led",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.AMP.DDRTest",
            "purpose": "DDR memory test",
            "access": "CLI: mtest",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.AMP.GetSelfTest",
            "purpose": "Hardware self-test",
            "access": "CLI: get testself",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.AMP.WifiFactoryInfo",
            "purpose": "WiFi factory information",
            "access": "CLI: display wifi factory",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.LSW_DEBUG.STAT",
            "purpose": "LAN switch debug statistics",
            "access": "CLI: amp show",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.VSPA.voicedebug",
            "purpose": "Voice/DSP debug",
            "access": "CLI: vspa debug",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.VSPA.debugdsprecord",
            "purpose": "DSP recording (1-1440 min)",
            "access": "CLI: debugging dsp record",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard",
            "purpose": "Board reset",
            "access": "Web FrameAISAP or TR-069",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.BBSP.ExtendPortTransCheck",
            "purpose": "Extended port translation check",
            "access": "Web or TR-069",
        },
        {
            "path": "InternetGatewayDevice.X_HW_DEBUG.AMP.WifiCoverSetWlanBasic",
            "purpose": "WiFi cover WLAN basic settings",
            "access": "Web debug interface",
        },
    ]

    debug_scripts = [
        ("bin/chipdebug", "Chip-level diagnostics: PLOAM, optic, LED, GPIO, GPON"),
        ("bin/getwifidebug.sh", "Read WiFi debug flags"),
        ("bin/setwifidebug.sh", "Set WiFi debug flags (creates /var/wifidebugon)"),
        ("bin/debugupmsg.sh", "Debug upstream messaging"),
        ("bin/debugdownmsg.sh", "Debug downstream messaging"),
        ("bin/debugdsp.sh", "DSP debug"),
        ("bin/wap.ssp.debugfs.sh", "DebugFS mount + GPIO/kernel module loading"),
        ("bin/open_print_log.sh", "Enable debug log printing"),
        ("bin/LdspCmd.sh", "Low-level DSP commands (GPIO, optic, LED, PLOAM)"),
        ("bin/LdspCmdA.sh", "Extended DSP commands (GPIO, optic, regulator)"),
    ]
    for script, purpose in debug_scripts:
        fpath = os.path.join(base_dir, script)
        if os.path.isfile(fpath):
            result["debug_scripts"].append({"script": script, "purpose": purpose})

    factory_scripts = [
        ("bin/hw_restore_manufactory.sh", "Factory reset trigger"),
        ("bin/hw_restore_manufactory_exec.sh", "Factory restore execution (board info, ctree, CRC)"),
        ("bin/Equip.sh", "Equipment init: loads GPIO/kernel modules, board config"),
    ]
    for script, purpose in factory_scripts:
        fpath = os.path.join(base_dir, script)
        if os.path.isfile(fpath):
            result["factory_reset"].append({"script": script, "purpose": purpose})

    result["user_levels"] = [
        {"level": 0, "name": "basic", "description": "Limited user — restricted menu"},
        {"level": 1, "name": "normal", "description": "Standard user — most features visible"},
        {"level": 2, "name": "admin/telecomadmin", "description": "Full access — all menus and debug pages"},
    ]

    result["activation_methods"] = [
        {
            "method": "TR-069 (Remote via ISP ACS)",
            "description": "ISP can set X_HW_DEBUG.TelnetSwitch=1 and X_HW_DEBUG.SshSwitch=1 via TR-069 CWMP protocol",
            "port": 7547,
            "access": "Requires ISP ACS server credentials",
        },
        {
            "method": "cfgtool CLI (Local via Telnet/SSH/Serial)",
            "description": "cfgtool SetPara InternetGatewayDevice.X_HW_DEBUG.TelnetSwitch 1",
            "access": "Requires shell access (serial console, existing telnet, or firmware mod)",
        },
        {
            "method": "hw_ctree.xml modification",
            "description": "Decrypt hw_ctree.xml, modify TelnetSwitch/SshSwitch to 1, re-encrypt and flash",
            "access": "Requires firmware extraction + aescrypt2 decryption + re-flash",
        },
        {
            "method": "Web UserLevel escalation",
            "description": "Login as admin (UserLevel=2) exposes debug pages. Default admin: admin/telecomadmin. Modify UserLevel in browser JS or intercept with mitmproxy",
            "access": "http://192.168.100.1 — login with telecomadmin credentials",
        },
        {
            "method": "Serial UART console",
            "description": "Connect to UART pins on PCB (3.3V TTL, 115200 baud). Provides root shell during boot",
            "access": "Hardware: USB-TTL adapter on UART pads (TX, RX, GND)",
        },
        {
            "method": "Factory reset button (hardware)",
            "description": "Hold RESET button 10+ seconds during power-on. Restores hw_default_ctree.xml. Does NOT enable debug by default",
            "access": "Physical reset button on device",
        },
        {
            "method": "WiFi debug flag",
            "description": "setwifidebug.sh creates /var/wifidebugon flag file. getwifidebug.sh reads debug state",
            "access": "Shell access required",
        },
        {
            "method": "GPIO/chipdebug (hardware interaction)",
            "description": "chipdebug script controls PLOAM, optic, LED, GPIO. LdspCmd.sh provides low-level DSP/GPIO access",
            "access": "Shell access + physical device",
        },
    ]

    return result


def analyze_menu_xmls(base_dir: str) -> list:
    menu_dir = os.path.join(base_dir, "web", "menu")
    results = []
    if not os.path.isdir(menu_dir):
        return results

    for fname in sorted(os.listdir(menu_dir)):
        if not fname.endswith(".xml"):
            continue
        fpath = os.path.join(menu_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8-sig", errors="ignore") as fh:
                xml_content = fh.read()
            pages = set()
            features = set()
            try:
                root = ET.fromstring(xml_content)
                for item in root.iter("Item"):
                    url = item.get("url", "")
                    feat = item.get("featurectrl", "")
                    if url:
                        pages.add(url)
                    if feat:
                        for fc in feat.split("|"):
                            features.add(fc.strip())
            except ET.ParseError:
                for m in re.finditer(r'url="([^"]+\.asp[^"]*)"', xml_content):
                    pages.add(m.group(1))
                for m in re.finditer(r'featurectrl="([^"]+)"', xml_content):
                    for fc in m.group(1).split("|"):
                        features.add(fc.strip())
            results.append({
                "xml": fname,
                "total_pages": len(pages),
                "total_features": len(features),
                "pages": sorted(pages)[:20],
                "features": sorted(features)[:20],
            })
        except OSError:
            results.append({"xml": fname, "error": "Read error"})

    return results


def generate_report(base_dir: str, output_file: str, binaries: list, libraries: list) -> None:
    out = []

    def w(line=""):
        out.append(line)

    w("=" * 80)
    w("HUAWEI HG8145V5 FIRMWARE ANALYSIS REPORT")
    w("=" * 80)

    w("\n" + "=" * 80)
    w("SECTION 1: WEB PAGES AND SERVICES")
    w("=" * 80)

    ports = scan_port_services(base_dir)

    w("\n--- 1.1 Main Web Service (192.168.100.1) ---")
    ws = ports["web_service"]
    w(f"  LAN Port:       {ws.get('lan_port', 'N/A')} (HTTP)")
    w(f"  WAN Port:       {ws.get('wan_port', 'N/A')} (HTTP external)")
    w(f"  Listen Mode:    {ws.get('listen_mode', 'N/A')} (0=LAN only, 1=WAN+LAN)")
    w(f"  Default Frame:  {ws.get('default_frame', 'N/A')}")
    w(f"  Menu XML:       {ws.get('menu_xml', 'N/A')}")
    w(f"  Access:         http://192.168.100.1/")
    w(f"  Binary:         bin/web (ARM ELF, musl libc)")

    w("\n--- 1.2 Other Services and Ports ---")

    w("\n  [TR-069/CWMP — ISP Remote Management]")
    tr = ports["cwmp_tr069"]
    w(f"    HTTP Port:    {tr.get('http_port', 'N/A')}")
    w(f"    Server Port:  {tr.get('server_port', 'N/A')}")
    w(f"    Access:       http://192.168.100.1:{tr.get('http_port', 7547)}/ (ISP ACS only)")
    w(f"    Protocol:     CWMP (CPE WAN Management Protocol)")
    w(f"    Auth:         Digest authentication")
    w(f"    Web page:     html/ssmp/tr069/tr069.asp")

    w("\n  [SSH — Dropbear]")
    w(f"    Port:         {ports['ssh']['default_port']}")
    w(f"    Binary:       {ports['ssh']['binary']}")
    w(f"    Access:       ssh root@192.168.100.1 (requires TelnetSwitch/SshSwitch=1)")
    w(f"    Status:       Disabled by default (X_HW_DEBUG.SshSwitch=0)")

    w("\n  [Telnet — CLI]")
    w(f"    Port:         {ports['telnet'].get('port', 23)}")
    w(f"    Access:       telnet 192.168.100.1 (requires X_HW_DEBUG.TelnetSwitch=1)")
    w(f"    Status:       Disabled by default")

    w("\n  [CUPS — Print Service]")
    w(f"    Socket:       {ports['cups_printing']['socket']}")
    w(f"    TCP Port:     {ports['cups_printing']['port']} (commented out in config)")
    w(f"    Config:       {ports['cups_printing']['config']}")
    w(f"    Access:       Internal only (Unix socket). If TCP enabled: http://192.168.100.1:631/")
    w(f"    Admin:        http://192.168.100.1:631/admin (if TCP enabled)")
    w(f"    Note:         {ports['cups_printing']['note']}")

    w("\n  [DLNA — Media Sharing]")
    w(f"    Server Port:  {ports['dlna'].get('server_port', 'N/A')}")
    w(f"    Client Port:  {ports['dlna'].get('client_port', 'N/A')}")
    w(f"    Access:       DLNA client auto-discovery (UPnP SSDP)")

    w("\n  [UPnP — Universal Plug and Play]")
    w(f"    SSDP Port:    {ports['upnp']['ssdp_port']}")
    w(f"    Binary:       {ports['upnp']['binary']}")
    w(f"    Access:       Auto-discovery via multicast 239.255.255.250:1900")

    if ports["per_isp_ports"]:
        w("\n--- 1.3 ISP-Specific Port Variations ---")
        for p in ports["per_isp_ports"]:
            w(f"  {p['isp_config']:40s} {p['service']:20s} Port {p['port']}")

    if ports["https_features"]:
        w("\n--- 1.4 HTTPS Features (per ISP) ---")
        for h in ports["https_features"]:
            status = "ENABLED" if h["enabled"] else "disabled"
            w(f"  {h['isp_config']:40s} {h['feature']:45s} [{status}]")

    if ports["no_auth_pages"]:
        w("\n--- 1.5 No-Authentication Pages (accessible without login) ---")
        for na in ports["no_auth_pages"]:
            w(f"  Spec: {na['spec_file']}")
            for p in na["pages"]:
                w(f"    http://192.168.100.1/{p}")

    w("\n" + "=" * 80)
    w("SECTION 2: WEB INTERFACE VARIANTS")
    w("=" * 80)

    web = scan_web_interfaces(base_dir)
    for fv in web["frame_variants"]:
        w(f"\n  [{fv['name']}] — {len(fv['pages'])} pages")
        for p in fv["pages"][:10]:
            w(f"    {p}")
        if len(fv["pages"]) > 10:
            w(f"    ... and {len(fv['pages']) - 10} more")

    w(f"\n  Total Menu XMLs: {len(web['menu_xmls'])}")
    w(f"  Total ASP pages: {len(web['all_asp_pages'])}")

    if web["debug_pages"]:
        w(f"\n  Debug-related pages ({len(web['debug_pages'])}):")
        for p in web["debug_pages"]:
            w(f"    http://192.168.100.1/{p}")

    if web["portal_pages"]:
        w(f"\n  Portal/redirect pages ({len(web['portal_pages'])}):")
        for p in web["portal_pages"][:15]:
            w(f"    http://192.168.100.1/{p}")

    w("\n" + "=" * 80)
    w("SECTION 3: DEBUG / ENGINEER / DEVELOPER MODE ACTIVATION")
    w("=" * 80)

    debug = scan_debug_modes(base_dir)

    w("\n--- 3.1 User Levels ---")
    for ul in debug["user_levels"]:
        w(f"  Level {ul['level']}: {ul['name']:25s} — {ul['description']}")

    w("\n--- 3.2 Activation Methods ---")
    for i, am in enumerate(debug["activation_methods"], 1):
        w(f"\n  Method {i}: {am['method']}")
        w(f"    {am['description']}")
        w(f"    Access: {am['access']}")
        if "port" in am:
            w(f"    Port: {am['port']}")

    w("\n--- 3.3 X_HW_DEBUG Configuration Paths ---")
    for xp in debug["x_hw_debug_paths"]:
        w(f"  {xp['path']}")
        w(f"    Purpose: {xp['purpose']}")
        w(f"    Access:  {xp['access']}")

    if debug["cli_debug_commands"]:
        w(f"\n--- 3.4 CLI Debug Commands ({len(debug['cli_debug_commands'])}) ---")
        for cmd in debug["cli_debug_commands"]:
            w(f"  {cmd['command']:40s} → {cmd['obj_path']}")

    if debug["debug_scripts"]:
        w(f"\n--- 3.5 Debug Scripts ---")
        for ds in debug["debug_scripts"]:
            w(f"  {ds['script']:45s} — {ds['purpose']}")

    if debug["factory_reset"]:
        w(f"\n--- 3.6 Factory Reset Scripts ---")
        for fr in debug["factory_reset"]:
            w(f"  {fr['script']:45s} — {fr['purpose']}")

    w("\n" + "=" * 80)
    w("SECTION 4: CAPSTONE BINARY ANALYSIS")
    w("=" * 80)

    for binary_path in binaries:
        full_path = os.path.join(base_dir, binary_path)
        if not os.path.isfile(full_path):
            w(f"\n  [SKIP] {binary_path} — file not found")
            continue

        w(f"\n{'─' * 60}")
        w(f"  Binary: {binary_path}")
        w(f"{'─' * 60}")
        analysis = capstone_analyze_binary(full_path)
        if analysis["error"]:
            w(f"  Error: {analysis['error']}")
            continue

        w(f"  Entry Point: {analysis.get('entry_point', 'N/A')}")
        w(f"  Sections:    {len(analysis['sections'])}")
        w(f"  Imports:     {len(analysis['imports'])}")
        w(f"  Exports:     {len(analysis['exports'])}")
        w(f"  PLT stubs:   {len(analysis['plt_functions'])}")

        if analysis["imports"]:
            w(f"\n  Imported functions ({len(analysis['imports'])}):")
            for imp in sorted(analysis["imports"])[:30]:
                w(f"    {imp}")
            if len(analysis["imports"]) > 30:
                w(f"    ... and {len(analysis['imports']) - 30} more")

        if analysis["exports"]:
            w(f"\n  Exported functions ({len(analysis['exports'])}):")
            for exp in analysis["exports"][:20]:
                w(f"    {exp['addr']} {exp['name']} ({exp['size']} bytes)")
            if len(analysis["exports"]) > 20:
                w(f"    ... and {len(analysis['exports']) - 20} more")

        if analysis["security_strings"]:
            w(f"\n  Security-related strings ({len(analysis['security_strings'])}):")
            for ss in analysis["security_strings"][:20]:
                w(f"    {ss['addr']}: {ss['value']}")

        if analysis["http_strings"]:
            w(f"\n  HTTP/Web-related strings ({len(analysis['http_strings'])}):")
            for hs in analysis["http_strings"][:20]:
                w(f"    {hs['addr']}: {hs['value']}")

        if analysis["debug_strings"]:
            w(f"\n  Debug/Engineer-related strings ({len(analysis['debug_strings'])}):")
            for ds in analysis["debug_strings"][:20]:
                w(f"    {ds['addr']}: {ds['value']}")

        if analysis["disasm_snippet"]:
            w(f"\n  Disassembly (first {min(len(analysis['disasm_snippet']), 100)} instructions):")
            for line in analysis["disasm_snippet"][:100]:
                w(f"    {line}")

    w("\n" + "=" * 80)
    w("SECTION 5: CAPSTONE LIBRARY ANALYSIS")
    w("=" * 80)

    for lib_path in libraries:
        full_path = os.path.join(base_dir, lib_path)
        if not os.path.isfile(full_path):
            w(f"\n  [SKIP] {lib_path} — file not found")
            continue

        w(f"\n{'─' * 60}")
        w(f"  Library: {lib_path}")
        w(f"{'─' * 60}")
        analysis = capstone_analyze_binary(full_path, max_instructions=200)
        if analysis["error"]:
            w(f"  Error: {analysis['error']}")
            continue

        w(f"  Sections:    {len(analysis['sections'])}")
        w(f"  Imports:     {len(analysis['imports'])}")
        w(f"  Exports:     {len(analysis['exports'])}")

        if analysis["exports"]:
            w(f"\n  Exported functions ({len(analysis['exports'])}):")
            for exp in analysis["exports"][:30]:
                w(f"    {exp['addr']} {exp['name']} ({exp['size']} bytes)")
            if len(analysis["exports"]) > 30:
                w(f"    ... and {len(analysis['exports']) - 30} more")

        if analysis["security_strings"]:
            w(f"\n  Security-related strings ({len(analysis['security_strings'])}):")
            for ss in analysis["security_strings"][:15]:
                w(f"    {ss['addr']}: {ss['value']}")

        if analysis["http_strings"]:
            w(f"\n  HTTP/Web-related strings ({len(analysis['http_strings'])}):")
            for hs in analysis["http_strings"][:15]:
                w(f"    {hs['addr']}: {hs['value']}")

        if analysis["debug_strings"]:
            w(f"\n  Debug-related strings ({len(analysis['debug_strings'])}):")
            for ds in analysis["debug_strings"][:15]:
                w(f"    {ds['addr']}: {ds['value']}")

        if analysis["disasm_snippet"]:
            w(f"\n  Disassembly snippet (first {min(len(analysis['disasm_snippet']), 50)} instructions):")
            for line in analysis["disasm_snippet"][:50]:
                w(f"    {line}")

    w("\n" + "=" * 80)
    w("SECTION 6: MENU XML ANALYSIS")
    w("=" * 80)

    menus = analyze_menu_xmls(base_dir)
    for menu in menus:
        if "error" in menu:
            w(f"\n  {menu['xml']}: {menu['error']}")
            continue
        w(f"\n  {menu['xml']}: {menu['total_pages']} pages, {menu['total_features']} features")
        if menu.get("features"):
            w(f"    Features: {', '.join(menu['features'][:10])}")

    w("\n" + "=" * 80)
    w("END OF REPORT")
    w("=" * 80)

    report_text = "\n".join(out)
    with open(output_file, "w") as f:
        f.write(report_text)

    print(report_text)
    print(f"\nReport saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Huawei ONT Firmware Analyzer")
    parser.add_argument(
        "-d", "--dir",
        default=".",
        help="Base directory of extracted firmware",
    )
    parser.add_argument(
        "-o", "--output",
        default="firmware_analysis_report.txt",
        help="Output report file",
    )
    parser.add_argument(
        "-b", "--binaries",
        nargs="*",
        default=["bin/web", "bin/aescrypt2", "bin/cfgtool", "bin/dropbear", "bin/httpc", "bin/ret_server"],
        help="ARM ELF binaries to analyze with Capstone",
    )
    parser.add_argument(
        "-l", "--libraries",
        nargs="*",
        default=[
            "lib/libhw_web_dll.so",
            "lib/libhw_ssp_basic.so",
            "lib/libhw_ssp_ssl.so",
            "lib/libhttps.so",
            "lib/libhw_smp_web_base.so",
            "lib/libhw_smp_httpclient.so",
            "lib/libhw_bbsp_web.so",
            "lib/libhw_swm_dll.so",
            "lib/libpolarssl.so",
        ],
        help="ARM ELF libraries to analyze with Capstone",
    )
    args = parser.parse_args()

    generate_report(args.dir, args.output, args.binaries, args.libraries)


if __name__ == "__main__":
    main()
