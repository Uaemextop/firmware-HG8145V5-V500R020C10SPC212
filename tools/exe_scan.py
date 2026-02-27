import re
import struct
from pathlib import Path

EXES = [Path('1211.exe'), Path('ONT-tool.exe')]


def extract_ascii(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    buf: bytearray = bytearray()
    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                out.append(bytes(buf).decode('ascii', 'ignore'))
            buf.clear()
    if len(buf) >= min_len:
        out.append(bytes(buf).decode('ascii', 'ignore'))
    return out


def extract_utf16le(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(data) - 2:
        if 32 <= data[i] <= 126 and data[i + 1] == 0:
            j = i
            chars = bytearray()
            while j < len(data) - 1 and 32 <= data[j] <= 126 and data[j + 1] == 0:
                chars.append(data[j])
                j += 2
            if len(chars) >= min_len:
                out.append(bytes(chars).decode('ascii', 'ignore'))
            i = j
        else:
            i += 1
    return out


def pe_imports(path: Path) -> list[str]:
    data = path.read_bytes()
    if data[:2] != b'MZ':
        return []
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\0\0':
        return []

    opt_magic = struct.unpack_from('<H', data, e_lfanew + 24)[0]
    is64 = opt_magic == 0x20B
    opt_off = e_lfanew + 24
    dd_off = opt_off + (0x70 if is64 else 0x60)

    # import directory = data dir #1
    imp_rva, _imp_size = struct.unpack_from('<II', data, dd_off + 8 * 1)

    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    size_opt = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    sec_off = opt_off + size_opt

    sections: list[tuple[int, int, int]] = []
    for si in range(num_sections):
        off = sec_off + 40 * si
        vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', data, off + 8)
        sections.append((vaddr, max(vsize, rsize), roff))

    def rva_to_off(rva: int) -> int | None:
        for vaddr, vs, roff in sections:
            if vaddr <= rva < vaddr + vs:
                return roff + (rva - vaddr)
        return None

    imp_off = rva_to_off(imp_rva)
    if imp_off is None:
        return []

    imports: set[str] = set()
    for _ in range(4096):
        if imp_off + 20 > len(data):
            break
        orig_thunk, time, fwd, name_rva, thunk = struct.unpack_from('<IIIII', data, imp_off)
        if (orig_thunk, time, fwd, name_rva, thunk) == (0, 0, 0, 0, 0):
            break
        name_off = rva_to_off(name_rva)
        if name_off is None:
            break
        end = data.find(b'\0', name_off)
        dll = data[name_off:end].decode('ascii', 'ignore') if end != -1 else ''
        if dll:
            imports.add(dll)
        imp_off += 20

    return sorted(imports)


KEYWORDS = re.compile(
    r'(HWNP|SIGN|SIGNINFO|CRC|RSA|sha|md5|telnet|ssh|winsock|ws2_32|pcap|adapter|npf|wlan|ether|OBSC|udp|tcp|http|https|192\.168|password|admin|upgrade|firmware)',
    re.I,
)


def main() -> int:
    for exe in EXES:
        print(f"\n=== {exe} ===")
        if not exe.exists():
            print("missing")
            continue
        data = exe.read_bytes()
        print("size", len(data))
        imps = pe_imports(exe)
        print("imports", ", ".join(imps) if imps else "(none)")

        s = extract_ascii(data, 5)
        u = extract_utf16le(data, 5)
        hits = sorted({x for x in s + u if KEYWORDS.search(x)})
        print("keyword_hits", len(hits))
        for line in hits[:250]:
            print(" ", line)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
