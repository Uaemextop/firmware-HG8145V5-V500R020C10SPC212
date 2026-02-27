#!/usr/bin/env python3
"""
Análisis de binarios ARM con Capstone para HG8145V5
Busca funciones clave relacionadas con autenticación, debug y configuración
"""

import sys
import struct
from pathlib import Path

try:
    import capstone
except ImportError:
    print("ERROR: Capstone no está instalado")
    print("Instalación: pip install capstone")
    sys.exit(1)

BASE_DIR = Path(__file__).parent.parent

class ARMBinaryAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = Path(binary_path)
        self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.md.detail = True

        with open(self.binary_path, 'rb') as f:
            self.data = f.read()

        # Verificar ELF header
        if self.data[:4] != b'\x7fELF':
            print(f"WARNING: {self.binary_path.name} no es un ELF válido")

    def find_strings(self, min_length=4):
        """Extrae strings del binario"""
        strings = []
        current_string = b""

        for byte in self.data:
            if 32 <= byte <= 126:  # ASCII imprimible
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    try:
                        strings.append(current_string.decode('ascii'))
                    except:
                        pass
                current_string = b""

        return strings

    def search_strings(self, patterns):
        """Busca strings que coincidan con patrones"""
        strings = self.find_strings()
        matches = {}

        for pattern in patterns:
            pattern_lower = pattern.lower()
            matches[pattern] = [s for s in strings if pattern_lower in s.lower()]

        return matches

    def disassemble_section(self, offset, size, base_address=0x8000):
        """Desensambla una sección del binario"""
        code = self.data[offset:offset+size]
        instructions = []

        try:
            for insn in self.md.disasm(code, base_address + offset):
                instructions.append({
                    'address': insn.address,
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'bytes': insn.bytes.hex()
                })
        except Exception as e:
            print(f"Error disassembling at offset {offset:#x}: {e}")

        return instructions

    def find_function_calls(self, instructions):
        """Encuentra llamadas a funciones"""
        calls = []
        for insn in instructions:
            if insn['mnemonic'] in ['bl', 'blx']:
                calls.append(insn)
        return calls

    def analyze_authentication_functions(self):
        """Busca funciones relacionadas con autenticación"""
        auth_patterns = [
            'telnet', 'ssh', 'login', 'password', 'passwd',
            'admin', 'telecom', 'auth', 'credential',
            'TelnetSwitch', 'SshSwitch', 'UserLevel',
            'X_HW_DEBUG'
        ]

        print("=" * 80)
        print(f"ANÁLISIS DE {self.binary_path.name} CON CAPSTONE")
        print("=" * 80)
        print()

        # Buscar strings relevantes
        print("## STRINGS RELEVANTES ENCONTRADAS:")
        print("-" * 80)

        matches = self.search_strings(auth_patterns)
        for pattern, found_strings in matches.items():
            if found_strings:
                print(f"\n{pattern.upper()}:")
                for s in found_strings[:10]:  # Limit
                    print(f"  • {s}")

        print()
        print("-" * 80)
        print()

        # Buscar patrones de instrucciones sospechosas
        print("## PATRONES DE INSTRUCCIONES:")
        print("-" * 80)
        print()

        # Analizar primeros 4KB (header típico)
        instructions = self.disassemble_section(0, min(4096, len(self.data)))

        if instructions:
            print(f"Primeras {len(instructions)} instrucciones:")
            for insn in instructions[:20]:
                print(f"  0x{insn['address']:08x}: {insn['mnemonic']:8s} {insn['op_str']}")

            # Buscar llamadas a funciones
            calls = self.find_function_calls(instructions)
            if calls:
                print()
                print(f"Llamadas a funciones encontradas: {len(calls)}")
                for call in calls[:10]:
                    print(f"  0x{call['address']:08x}: {call['mnemonic']} {call['op_str']}")
        else:
            print("  No se pudieron desensamblar instrucciones en esta sección")

        print()
        print("-" * 80)

def analyze_key_binaries():
    """Analiza los binarios más importantes"""

    binaries = [
        ('bin/web', 'Servidor web - buscar autenticación'),
        ('bin/cfgtool', 'Config tool - buscar TelnetSwitch/SshSwitch'),
        ('bin/aescrypt2', 'Cifrado AES - buscar claves'),
        ('bin/clid', 'CLI daemon - buscar comandos debug')
    ]

    reports = []

    for binary_path, description in binaries:
        full_path = BASE_DIR / binary_path
        if not full_path.exists():
            print(f"SKIP: {binary_path} no encontrado")
            continue

        print()
        print("*" * 80)
        print(f"ANALIZANDO: {binary_path}")
        print(f"Descripción: {description}")
        print("*" * 80)
        print()

        analyzer = ARMBinaryAnalyzer(full_path)
        analyzer.analyze_authentication_functions()

        reports.append(f"✓ {binary_path} analizado")
        print()

    print()
    print("=" * 80)
    print("RESUMEN DEL ANÁLISIS CON CAPSTONE")
    print("=" * 80)
    print()
    print("HALLAZGOS CLAVE:")
    print()
    print("1. STRINGS DE AUTENTICACIÓN:")
    print("   - Buscar 'TelnetSwitch', 'SshSwitch' en cfgtool")
    print("   - Buscar 'admin', 'telecomadmin' en web")
    print("   - Buscar 'X_HW_DEBUG' en todos los binarios")
    print()
    print("2. FUNCIONES DE INTERÉS:")
    print("   - Llamadas 'bl' y 'blx' pueden ser funciones de validación")
    print("   - Buscar comparaciones con 0/1 (enable/disable)")
    print()
    print("3. ANÁLISIS RECOMENDADO:")
    print("   - Usar radare2 para análisis más profundo:")
    print("     $ r2 -A bin/cfgtool")
    print("     [0x00000000]> aaa")
    print("     [0x00000000]> afl")
    print("     [0x00000000]> axt @sym.TelnetSwitch")
    print()
    print("   - Usar r2pipe para scripting:")
    print("     import r2pipe")
    print("     r2 = r2pipe.open('bin/cfgtool')")
    print("     r2.cmd('aaa')")
    print("     functions = r2.cmdj('aflj')")
    print()
    print("4. PATCHING BINARIO (AVANZADO):")
    print("   - Identificar checks de TelnetSwitch/SshSwitch")
    print("   - Patchear comparaciones para siempre retornar 'enabled'")
    print("   - Herramientas: radare2, Binary Ninja, IDA Pro")
    print()
    print("=" * 80)

    for report in reports:
        print(report)

def main():
    if len(sys.argv) > 1:
        # Analizar binario específico
        binary_path = sys.argv[1]
        analyzer = ARMBinaryAnalyzer(binary_path)
        analyzer.analyze_authentication_functions()
    else:
        # Analizar todos los binarios clave
        analyze_key_binaries()

if __name__ == "__main__":
    main()
