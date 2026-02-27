#!/usr/bin/env python3
"""
Análisis completo del firmware HG8145V5 - V500R020C10SPC212
Busca interfaces web alternativas, puertos, y métodos de activación de modo debug/engineer
"""

import os
import re
import struct
from pathlib import Path
from typing import Dict, List, Set, Tuple

BASE_DIR = Path(__file__).parent.parent

class FirmwareAnalyzer:
    def __init__(self):
        self.web_interfaces = []
        self.ports = set()
        self.debug_features = []
        self.button_combinations = []
        self.cli_commands = []

    def analyze_web_directories(self):
        """Analiza los directorios web disponibles"""
        web_dir = BASE_DIR / "web"
        if web_dir.exists():
            for item in web_dir.iterdir():
                if item.is_dir():
                    self.web_interfaces.append({
                        'name': item.name,
                        'path': str(item),
                        'description': self._identify_web_interface(item.name)
                    })

    def _identify_web_interface(self, name):
        """Identifica el propósito de cada interfaz web"""
        patterns = {
            'frame_huawei': 'Interfaz web estándar Huawei (192.168.100.1)',
            'FrameAISAP': 'Interfaz AIS Tailandia',
            'frame_Stc': 'Interfaz STC Arabia Saudita',
            'frame_qtel': 'Interfaz Qtel Qatar',
            'frame_zain': 'Interfaz Zain',
            'frame_argentina': 'Interfaz Argentina',
            'frame_Arabic': 'Interfaz árabe',
            'frame_pccw': 'Interfaz PCCW Hong Kong',
            'frame_XGPON': 'Interfaz XGPON',
            'frame_IraqO3': 'Interfaz Iraq O3',
            'frame_xgponglobe': 'Interfaz Globe Philippines',
            'AllUsers': 'Recursos compartidos todas las interfaces'
        }
        return patterns.get(name, 'Interfaz desconocida')

    def extract_ports(self):
        """Extrae todos los puertos configurados"""

        # Puertos conocidos TR-069/CWMP
        self.ports.add(('TR-069 CWMP', 7547, 'TCP'))

        # Buscar en archivos de configuración
        config_files = [
            BASE_DIR / "configs" / "spec" / "ssmp" / "base_ssmp_spec.cfg",
            BASE_DIR / "etc" / "wap" / "spec" / "ssmp" / "base_ssmp_spec.cfg"
        ]

        for cfg_file in config_files:
            if cfg_file.exists():
                content = cfg_file.read_text(errors='ignore')

                # Web ports
                if match := re.search(r'SSMP_SPEC_WEB_PORTNUM.*value="(\d+)"', content):
                    self.ports.add(('HTTP Web', int(match.group(1)), 'TCP'))

                if match := re.search(r'SSMP_SPEC_WEB_OUTPORTNUM.*value="(\d+)"', content):
                    self.ports.add(('HTTP Web (Externa)', int(match.group(1)), 'TCP'))

                if match := re.search(r'SSMP_SPEC_CWMP_HTTPSERVERPORTID.*value="(\d+)"', content):
                    self.ports.add(('TR-069 CWMP Server', int(match.group(1)), 'TCP'))

        # HTTPS ports (de archivos ASP)
        https_files = list((BASE_DIR / "web").rglob("httpsdirect.asp"))
        for asp_file in https_files:
            content = asp_file.read_text(errors='ignore')
            if "SSLPort = '7017'" in content:
                self.ports.add(('HTTPS Web', 7017, 'TCP'))

        # Puertos adicionales
        self.ports.add(('HTTP Web', 80, 'TCP'))
        self.ports.add(('HTTPS Web', 443, 'TCP'))
        self.ports.add(('Telnet', 23, 'TCP'))
        self.ports.add(('SSH', 22, 'TCP'))
        self.ports.add(('FTP', 21, 'TCP'))
        self.ports.add(('FTP Pasivo', (12000, 12100), 'TCP'))

    def find_debug_activation_methods(self):
        """Encuentra métodos para activar modo debug/engineer"""

        # Método 1: Modificación de hw_ctree.xml
        self.debug_features.append({
            'method': 'Modificación de configuración',
            'type': 'SOFTWARE',
            'difficulty': 'AVANZADO',
            'description': 'Descifrar y modificar hw_ctree.xml',
            'steps': [
                '1. Extraer firmware con HuaweiFirmwareTool',
                '2. Descifrar hw_ctree.xml usando aescrypt2 en chroot',
                '3. Modificar parámetros X_HW_DEBUG:',
                '   - TelnetSwitch: 0 → 1 (activar Telnet)',
                '   - SshSwitch: 0 → 1 (activar SSH)',
                '4. Re-cifrar y flashear firmware modificado',
                '5. Acceder via telnet 192.168.100.1 puerto 23',
                '6. Usuario: root (password del admin web)'
            ],
            'xpaths': [
                '/configuration/InternetGatewayDevice/X_HW_DEBUG/TelnetSwitch',
                '/configuration/InternetGatewayDevice/X_HW_DEBUG/SshSwitch'
            ]
        })

        # Método 2: Interfaz web oculta
        self.debug_features.append({
            'method': 'Páginas web ocultas X_HW_DEBUG',
            'type': 'SOFTWARE',
            'difficulty': 'MEDIO',
            'description': 'Acceder a páginas de diagnóstico ocultas',
            'steps': [
                '1. Iniciar sesión como telecomadmin (nivel 2)',
                '2. Acceder a URLs ocultas:',
                '   - http://192.168.100.1/html/X_HW_DEBUG.asp',
                '   - Buscar en web/FrameAISAP/index.asp referencias X_HW_DEBUG',
                '3. Características disponibles:',
                '   - AMP.Optic: Diagnóstico óptico (RxPower, TxPower)',
                '   - SMP.DM.ResetBoard: Reset del dispositivo',
                '   - AccessModeDisp: Modo de acceso PON/EPON',
                '   - GetOptTxMode: Modo TX óptico'
            ]
        })

        # Método 3: CLI oculto
        self.debug_features.append({
            'method': 'Comandos CLI ocultos',
            'type': 'SOFTWARE',
            'difficulty': 'MEDIO',
            'description': 'Comandos de debug via telnet/SSH',
            'steps': [
                '1. Habilitar telnet/SSH (ver método 1)',
                '2. Conectar: telnet 192.168.100.1',
                '3. Login: root / <password_admin>',
                '4. Comandos útiles:',
                '   - display access mode',
                '   - get optic txmode',
                '   - set wlan enable laninst 1 enable 1',
                '   - load pack by tftp/ftp/https (upgrade)',
                '   - debugging <subsystem>'
            ],
            'commands': [
                'display access mode',
                'get optic txmode',
                'display 8021x status',
                'debugging dsp diagnose',
                'capture start mode all'
            ]
        })

        # Método 4: Botón reset
        self.debug_features.append({
            'method': 'Combinación de botón Reset',
            'type': 'HARDWARE',
            'difficulty': 'FÁCIL',
            'description': 'Reset a valores de fábrica',
            'steps': [
                '1. Con el ONT encendido',
                '2. Mantener botón RESET presionado 10 segundos',
                '3. El ONT se reiniciará con configuración de fábrica',
                '4. Credenciales default:',
                '   - Usuario: admin / telecomadmin',
                '   - Password: admin / admintelecom (varía según ISP)',
                'Nota: keyconfig.xml define InvalidCount=4 para HG8245C'
            ]
        })

        # Método 5: WPS Button para modo pairing
        self.debug_features.append({
            'method': 'Botón WPS/WiFi',
            'type': 'HARDWARE',
            'difficulty': 'FÁCIL',
            'description': 'Activar WPS pairing',
            'steps': [
                '1. Presionar botón WPS/WiFi 2-3 segundos',
                '2. LED WPS parpadeará por 2 minutos',
                '3. Modo WPS-PBC activo para conectar dispositivos',
                '4. Mantener presionado >10s puede activar WiFi On/Off'
            ]
        })

        # Método 6: UART/Serial (avanzado)
        self.debug_features.append({
            'method': 'Puerto Serial UART',
            'type': 'HARDWARE',
            'difficulty': 'EXPERTO',
            'description': 'Acceso bootloader via UART',
            'steps': [
                '1. Abrir el ONT (anula garantía)',
                '2. Localizar pads UART (TX, RX, GND)',
                '3. Conectar adaptador USB-TTL 3.3V',
                '4. Configuración: 115200 8N1',
                '5. Acceso a U-Boot al encender',
                '6. Comandos U-Boot para modificar variables de entorno'
            ],
            'warning': '¡PUEDE BRICKEAR EL DISPOSITIVO!'
        })

    def extract_cli_commands(self):
        """Extrae comandos CLI importantes"""
        cli_file = BASE_DIR / "configs" / "hw_cli.xml"
        if cli_file.exists():
            content = cli_file.read_text(errors='ignore')

            # Buscar comandos relevantes
            patterns = [
                (r'CmdStr="(display.*?)"', 'Info'),
                (r'CmdStr="(set.*debug.*?)"', 'Debug'),
                (r'CmdStr="(get.*?)"', 'Get'),
                (r'CmdStr="(debugging.*?)"', 'Debug'),
                (r'CmdStr="(load pack.*?)"', 'Upgrade')
            ]

            for pattern, category in patterns:
                matches = re.findall(pattern, content)
                for match in matches[:20]:  # Limit
                    self.cli_commands.append((category, match))

    def analyze_binaries(self):
        """Analiza binarios clave con información básica"""
        bin_dir = BASE_DIR / "bin"
        important_bins = ['web', 'cfgtool', 'aescrypt2', 'clid']

        binary_info = []
        for bin_name in important_bins:
            bin_path = bin_dir / bin_name
            if bin_path.exists():
                size = bin_path.stat().st_size

                # Leer primeros bytes para identificar tipo
                with open(bin_path, 'rb') as f:
                    header = f.read(4)

                elf_magic = b'\x7fELF'
                is_elf = header == elf_magic

                binary_info.append({
                    'name': bin_name,
                    'path': str(bin_path),
                    'size': size,
                    'type': 'ELF ARM' if is_elf else 'Desconocido',
                    'description': self._describe_binary(bin_name)
                })

        return binary_info

    def _describe_binary(self, name):
        """Describe la función de cada binario"""
        descriptions = {
            'web': 'Servidor web principal (Boa/lighttpd)',
            'cfgtool': 'Herramienta de gestión de configuración',
            'aescrypt2': 'Cifrado/descifrado AES-256-CBC para hw_ctree.xml',
            'clid': 'Demonio CLI (telnet/SSH)'
        }
        return descriptions.get(name, 'Binario desconocido')

    def generate_report(self):
        """Genera reporte completo"""
        self.analyze_web_directories()
        self.extract_ports()
        self.find_debug_activation_methods()
        self.extract_cli_commands()
        binaries = self.analyze_binaries()

        report = []
        report.append("=" * 80)
        report.append("ANÁLISIS FIRMWARE HG8145V5-V500R020C10SPC212")
        report.append("Huawei ONT - Optical Network Terminal")
        report.append("=" * 80)
        report.append("")

        # Interfaces web
        report.append("## 1. INTERFACES WEB DISPONIBLES")
        report.append("-" * 80)
        report.append("")
        report.append("Además de la interfaz principal en 192.168.100.1, el firmware")
        report.append("contiene múltiples interfaces web para diferentes ISPs:")
        report.append("")

        for idx, iface in enumerate(self.web_interfaces, 1):
            report.append(f"{idx}. {iface['name']}")
            report.append(f"   Descripción: {iface['description']}")
            report.append(f"   Ruta: {iface['path']}")
            report.append("")

        report.append("NOTA: Todas estas interfaces escuchan en los mismos puertos,")
        report.append("la interfaz activa depende de la configuración del ISP en hw_ctree.xml")
        report.append("")

        # Puertos
        report.append("## 2. PUERTOS Y SERVICIOS")
        report.append("-" * 80)
        report.append("")
        report.append("Puertos TCP/UDP utilizados por el dispositivo:")
        report.append("")

        for service, port, protocol in sorted(self.ports, key=lambda x: str(x[1])):
            if isinstance(port, tuple):
                report.append(f"  • {service:30s} Rango: {port[0]}-{port[1]} ({protocol})")
            else:
                report.append(f"  • {service:30s} Puerto: {port} ({protocol})")

        report.append("")
        report.append("ACCESO A LAS INTERFACES:")
        report.append("  • HTTP:  http://192.168.100.1:80")
        report.append("  • HTTPS: https://192.168.100.1:443")
        report.append("  • HTTPS: https://192.168.100.1:7017  (Qatar/algunas variantes)")
        report.append("")
        report.append("CREDENCIALES DEFAULT:")
        report.append("  • Usuario: admin / Password: admin")
        report.append("  • Usuario: telecomadmin / Password: admintelecom")
        report.append("  • El password puede variar según ISP")
        report.append("")

        # Modo debug/engineer
        report.append("## 3. MÉTODOS DE ACTIVACIÓN MODO DEBUG/ENGINEER/DEVELOPER")
        report.append("-" * 80)
        report.append("")

        for idx, method in enumerate(self.debug_features, 1):
            report.append(f"### MÉTODO {idx}: {method['method']}")
            report.append(f"Tipo: {method['type']} | Dificultad: {method['difficulty']}")
            report.append("")
            report.append(f"Descripción: {method['description']}")
            report.append("")
            report.append("Pasos:")
            for step in method['steps']:
                report.append(f"  {step}")

            if 'xpaths' in method:
                report.append("")
                report.append("XPaths en hw_ctree.xml:")
                for xpath in method['xpaths']:
                    report.append(f"  - {xpath}")

            if 'commands' in method:
                report.append("")
                report.append("Comandos CLI útiles:")
                for cmd in method['commands']:
                    report.append(f"  $ {cmd}")

            if 'warning' in method:
                report.append("")
                report.append(f"⚠️  ADVERTENCIA: {method['warning']}")

            report.append("")
            report.append("-" * 80)
            report.append("")

        # Comandos CLI
        report.append("## 4. COMANDOS CLI IMPORTANTES (vía Telnet/SSH)")
        report.append("-" * 80)
        report.append("")

        categories = {}
        for category, cmd in self.cli_commands:
            if category not in categories:
                categories[category] = []
            categories[category].append(cmd)

        for category, commands in categories.items():
            report.append(f"### {category}:")
            for cmd in commands[:10]:  # Limit
                report.append(f"  $ {cmd}")
            report.append("")

        # Binarios
        report.append("## 5. BINARIOS CLAVE PARA ANÁLISIS")
        report.append("-" * 80)
        report.append("")

        for binary in binaries:
            report.append(f"• {binary['name']}")
            report.append(f"  Tipo: {binary['type']}")
            report.append(f"  Tamaño: {binary['size']:,} bytes")
            report.append(f"  Descripción: {binary['description']}")
            report.append(f"  Ruta: {binary['path']}")
            report.append("")

        report.append("Para análisis con Capstone:")
        report.append("  $ python tools/arm_disasm.py bin/<binary>")
        report.append("")
        report.append("Para análisis con radare2:")
        report.append("  $ r2 -A bin/<binary>")
        report.append("  [0x00000000]> aaa    # Analizar")
        report.append("  [0x00000000]> afl    # Listar funciones")
        report.append("  [0x00000000]> pdf @sym.main  # Desensamblar main")
        report.append("")

        # Resumen
        report.append("## 6. RESUMEN Y RECOMENDACIONES")
        report.append("-" * 80)
        report.append("")
        report.append("OPCIÓN MÁS FÁCIL (Sin modificar firmware):")
        report.append("  1. Probar credenciales default: admin/admin, telecomadmin/admintelecom")
        report.append("  2. Buscar páginas web ocultas en /html/X_HW_DEBUG.asp")
        report.append("  3. Revisar nivel de usuario (0=básico, 1=normal, 2=admin)")
        report.append("")
        report.append("OPCIÓN INTERMEDIA (Requiere acceso web admin):")
        report.append("  1. Usar mitmproxy para interceptar y modificar UserLevel a 2")
        report.append("  2. Acceder a características X_HW_DEBUG ocultas")
        report.append("  3. Ver repositorio: huawei_proxy/proxy.py")
        report.append("")
        report.append("OPCIÓN AVANZADA (Requiere flasheo firmware):")
        report.append("  1. Extraer firmware con HuaweiFirmwareTool")
        report.append("  2. Descifrar hw_ctree.xml con aescrypt2 en chroot qemu-arm")
        report.append("  3. Modificar TelnetSwitch/SshSwitch a 1")
        report.append("  4. Re-cifrar y flashear")
        report.append("  5. Acceso completo via telnet/SSH")
        report.append("")
        report.append("OPCIÓN EXPERTO (Requiere hardware):")
        report.append("  1. Soldar cables a pads UART internos")
        report.append("  2. Acceso a U-Boot bootloader")
        report.append("  3. Modificar variables de entorno")
        report.append("  ⚠️  Riesgo de brick permanente")
        report.append("")
        report.append("=" * 80)
        report.append("Análisis generado por firmware_analysis.py")
        report.append("Repositorio: Uaemextop/firmware-HG8145V5-V500R020C10SPC212")
        report.append("=" * 80)

        return "\n".join(report)

def main():
    analyzer = FirmwareAnalyzer()
    report = analyzer.generate_report()

    # Guardar reporte
    output_file = BASE_DIR / "FIRMWARE_ANALYSIS.md"
    output_file.write_text(report, encoding='utf-8')

    print(report)
    print(f"\n✓ Reporte guardado en: {output_file}")

if __name__ == "__main__":
    main()
