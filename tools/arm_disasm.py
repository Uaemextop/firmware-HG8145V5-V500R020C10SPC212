#!/usr/bin/env python3
"""ARM disassembler / pseudo-decompiler using Capstone.

Reads a 32-bit ARM ELF binary, resolves PLT → dynamic symbol names, and
produces:

1. An annotated assembly listing (``*.asm``).
2. A pseudo-C reconstruction (``*.pseudo.c``) with function signatures,
   control-flow annotations, and PLT calls resolved to their symbol names.

Requires: ``capstone`` (``pip install capstone``).

Usage::

    python tools/arm_disasm.py binary_file [-o output_dir]
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import capstone  # type: ignore
except ImportError:
    sys.exit("capstone not installed – run:  pip install capstone")

# ── ELF 32-bit structures ────────────────────────────────────────────────────

ELF_MAGIC = b"\x7fELF"


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


def _read_str(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end == -1:
        return ""
    return data[offset:end].decode("ascii", errors="replace")


def parse_elf32(data: bytes) -> ElfInfo:
    """Parse a 32-bit little-endian ARM ELF."""
    assert data[:4] == ELF_MAGIC, "Not an ELF file"
    assert data[4] == 1, "Not 32-bit"  # EI_CLASS
    assert data[5] == 1, "Not little-endian"  # EI_DATA

    e_entry = struct.unpack_from("<I", data, 24)[0]
    e_shoff = struct.unpack_from("<I", data, 32)[0]
    e_shentsize = struct.unpack_from("<H", data, 46)[0]
    e_shnum = struct.unpack_from("<H", data, 48)[0]
    e_shstrndx = struct.unpack_from("<H", data, 50)[0]

    info = ElfInfo(entry=e_entry)

    # Section header string table
    shstr_base = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from("<I", data, shstr_base + 16)[0]

    # Parse sections
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from("<I", data, base)[0]
        sh_type = struct.unpack_from("<I", data, base + 4)[0]
        sh_addr = struct.unpack_from("<I", data, base + 12)[0]
        sh_offset = struct.unpack_from("<I", data, base + 16)[0]
        sh_size = struct.unpack_from("<I", data, base + 20)[0]
        name = _read_str(data, shstr_off + sh_name_idx)
        sec = Section(name, sh_type, sh_addr, sh_offset, sh_size)
        info.sections[name] = sec

    # Dynamic symbol table
    if ".dynsym" in info.sections and ".dynstr" in info.sections:
        dsym = info.sections[".dynsym"]
        dstr = info.sections[".dynstr"]
        for i in range(dsym.size // 16):
            base = dsym.offset + i * 16
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

    # Build PLT stub → symbol mapping
    _build_plt_map(data, info)

    # Extract .rodata strings
    if ".rodata" in info.sections:
        sec = info.sections[".rodata"]
        rd = data[sec.offset : sec.offset + sec.size]
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
    """Map PLT stub addresses to their imported symbol names."""
    if ".plt" not in info.sections or ".got" not in info.sections:
        return

    plt = info.sections[".plt"]
    got = info.sections[".got"]

    # Imported symbols (shndx == 0) in order of .dynsym
    imports = [s for s in info.dynsyms if s.shndx == 0 and s.stype == 2]

    # Each PLT entry is 12 bytes (3 instructions) after the initial 20-byte header
    plt_header_size = 20
    plt_entry_size = 12
    num_entries = (plt.size - plt_header_size) // plt_entry_size

    for i in range(min(num_entries, len(imports))):
        stub_addr = plt.addr + plt_header_size + i * plt_entry_size
        info.plt_map[stub_addr] = imports[i].name


def disassemble(
    data: bytes, elf: ElfInfo
) -> Tuple[List[str], List[str]]:
    """Disassemble .text and produce (asm_lines, pseudo_c_lines)."""
    if ".text" not in elf.sections:
        return ["No .text section found"], ["/* No .text section */"]

    text = elf.sections[".text"]
    code = data[text.offset : text.offset + text.size]

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = True

    asm_lines: list[str] = []
    pseudo_lines: list[str] = []

    # Find function boundaries from exported symbols
    func_addrs: dict[int, str] = {}
    for sym in elf.dynsyms:
        if sym.stype == 2 and sym.shndx != 0 and sym.size > 0:
            func_addrs[sym.value] = sym.name

    current_func: Optional[str] = None

    for ins in md.disasm(code, text.addr):
        addr = ins.address
        mnem = ins.mnemonic
        ops = ins.op_str

        # Function label
        if addr in func_addrs:
            fname = func_addrs[addr]
            if current_func:
                asm_lines.append("")
                pseudo_lines.append("}\n")
            current_func = fname
            asm_lines.append(f"\n; ── {fname} ──")
            pseudo_lines.append(f"/* 0x{addr:08x} */")
            pseudo_lines.append(f"int {fname}(int argc, char **argv) {{")

        # Resolve PLT calls
        comment = ""
        if mnem in ("bl", "blx", "b"):
            try:
                target = int(ops.lstrip("#"), 0)
                if target in elf.plt_map:
                    comment = f"  ; → {elf.plt_map[target]}"
                elif target in func_addrs:
                    comment = f"  ; → {func_addrs[target]}"
            except ValueError:
                pass

        asm_lines.append(f"  0x{addr:08x}:  {mnem:12s} {ops}{comment}")

    if current_func:
        pseudo_lines.append("}")

    return asm_lines, pseudo_lines


def write_output(
    asm_lines: List[str],
    pseudo_lines: List[str],
    elf: ElfInfo,
    binary_name: str,
    out_dir: str,
) -> Tuple[str, str]:
    """Write .asm and .pseudo.c to *out_dir*."""
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(binary_name)[0]

    asm_path = os.path.join(out_dir, f"{base}.asm")
    with open(asm_path, "w") as f:
        f.write(f"; Disassembly of {binary_name}\n")
        f.write(f"; Entry point: 0x{elf.entry:08x}\n")
        f.write(f"; Sections: {', '.join(elf.sections.keys())}\n")
        f.write(f"; Dynamic imports:\n")
        for s in elf.dynsyms:
            if s.shndx == 0 and s.stype == 2:
                f.write(f";   {s.name}\n")
        f.write(f"; PLT mapping:\n")
        for addr, name in sorted(elf.plt_map.items()):
            f.write(f";   0x{addr:08x} → {name}\n")
        f.write(";\n")
        if elf.strings_map:
            f.write("; .rodata strings:\n")
            for addr, s in sorted(elf.strings_map.items()):
                f.write(f';   0x{addr:04x}: "{s}"\n')
            f.write(";\n")
        f.write("\n".join(asm_lines))
        f.write("\n")

    pseudo_path = os.path.join(out_dir, f"{base}.pseudo.c")
    with open(pseudo_path, "w") as f:
        f.write(f"/* Pseudo-C reconstruction of {binary_name} */\n")
        f.write("/* Generated by arm_disasm.py using Capstone */\n\n")
        for s in elf.dynsyms:
            if s.shndx == 0 and s.stype == 2:
                f.write(f"extern int {s.name}();\n")
        f.write("\n")
        f.write("\n".join(pseudo_lines))
        f.write("\n")

    return asm_path, pseudo_path


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="ARM ELF disassembler (Capstone)")
    parser.add_argument("binary", help="Path to ARM ELF binary")
    parser.add_argument("-o", "--output", default="disasm_out", help="Output dir")
    args = parser.parse_args()

    with open(args.binary, "rb") as f:
        data = f.read()

    elf = parse_elf32(data)
    asm_lines, pseudo_lines = disassemble(data, elf)
    binary_name = os.path.basename(args.binary)
    asm_path, pseudo_path = write_output(
        asm_lines, pseudo_lines, elf, binary_name, args.output
    )

    print(f"Assembly listing:  {asm_path}")
    print(f"Pseudo-C output:   {pseudo_path}")
    print(f"Functions found:   {sum(1 for s in elf.dynsyms if s.size > 0 and s.shndx != 0 and s.stype == 2)}")
    print(f"PLT imports:       {len(elf.plt_map)}")
    print(f".rodata strings:   {len(elf.strings_map)}")


if __name__ == "__main__":
    main()
