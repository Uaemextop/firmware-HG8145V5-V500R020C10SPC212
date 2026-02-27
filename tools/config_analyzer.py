#!/usr/bin/env python3
"""
config_analyzer.py — Firmware config analysis and unified config generator.

Analyzes decrypted hw_ctree.xml files from multiple Huawei ONT firmwares,
extracts common and firmware-specific configuration parameters, and generates
a unified configuration XML that combines all settings.

Usage:
    python tools/config_analyzer.py [--configs-dir DIR] [--output FILE]

The tool:
1. Parses all hw_ctree_decrypted.xml files in extracted_configs/
2. Analyzes the InternetGatewayDevice XML tree structure
3. Identifies common vs firmware-specific parameters
4. Generates a unified config XML based on the most complete firmware
5. Produces a markdown report with config differences
"""

import xml.etree.ElementTree as ET
import os
import sys
import copy
import argparse
import hashlib


def parse_firmware_configs(configs_dir):
    """Parse all decrypted hw_ctree.xml files from extracted_configs/."""
    firmwares = {}
    for d in sorted(os.listdir(configs_dir)):
        xml_path = os.path.join(configs_dir, d, 'hw_ctree_decrypted.xml')
        if os.path.isfile(xml_path):
            try:
                tree = ET.parse(xml_path)
                root = tree.getroot()
                elem_count = sum(1 for _ in root.iter())
                attr_count = sum(len(e.attrib) for e in root.iter())
                firmwares[d] = {
                    'root': root,
                    'elements': elem_count,
                    'attributes': attr_count,
                    'size': os.path.getsize(xml_path),
                }
            except ET.ParseError as e:
                print(f"  WARNING: {d}: parse error: {e}", file=sys.stderr)
    return firmwares


def get_paths(elem, prefix=""):
    """Get all TR-069 style paths from an XML element tree."""
    paths = set()
    tag = elem.tag
    path = f"{prefix}.{tag}" if prefix else tag
    paths.add(path)
    for attr in elem.attrib:
        paths.add(f"{path}@{attr}")
    for child in elem:
        paths.update(get_paths(child, path))
    return paths


def find_differences(firmwares):
    """Find parameters that differ across firmwares."""
    all_paths = {}
    for fw_name, fw_data in firmwares.items():
        all_paths[fw_name] = get_paths(fw_data['root'])

    if not all_paths:
        return [], set(), set()

    common = set.intersection(*all_paths.values())
    union = set.union(*all_paths.values())

    # Find value differences for common attributes
    diffs = []

    def compare_attrs(elems_by_fw, path=""):
        all_attrs = set()
        for fw, elem in elems_by_fw.items():
            all_attrs.update(elem.attrib.keys())

        for attr in sorted(all_attrs):
            values = {}
            for fw, elem in elems_by_fw.items():
                if attr in elem.attrib:
                    values[fw] = elem.attrib[attr]

            unique = set(values.values())
            if len(unique) > 1:
                diffs.append({
                    'path': f"{path}@{attr}",
                    'values': values,
                    'unique_count': len(unique),
                })

        # Recurse into children
        all_tags = set()
        for fw, elem in elems_by_fw.items():
            for child in elem:
                all_tags.add(child.tag)

        for tag in sorted(all_tags):
            child_elems = {}
            for fw, elem in elems_by_fw.items():
                child = elem.find(tag)
                if child is not None:
                    child_elems[fw] = child
            if child_elems:
                compare_attrs(child_elems, f"{path}.{tag}" if path else tag)

    root_elems = {fw: data['root'] for fw, data in firmwares.items()}
    compare_attrs(root_elems, "InternetGatewayDevice")

    return diffs, common, union


def create_unified_config(firmwares, base_fw=None):
    """Create unified config from the most complete firmware, merging others."""
    if not firmwares:
        return None

    # Auto-select base: prefer most elements
    if base_fw is None:
        base_fw = max(firmwares, key=lambda x: firmwares[x]['elements'])

    base_root = copy.deepcopy(firmwares[base_fw]['root'])

    def add_missing(unified, other, other_name):
        added = 0
        existing_keys = set()
        for child in unified:
            inst_id = child.get('InstanceID', '')
            key = f"{child.tag}[{inst_id}]" if inst_id else child.tag
            existing_keys.add(key)

        for child in other:
            inst_id = child.get('InstanceID', '')
            key = f"{child.tag}[{inst_id}]" if inst_id else child.tag

            if key not in existing_keys:
                new_child = copy.deepcopy(child)
                new_child.set('_source', other_name)
                unified.append(new_child)
                added += 1
            else:
                for existing in unified:
                    e_inst = existing.get('InstanceID', '')
                    e_key = f"{existing.tag}[{e_inst}]" if e_inst else existing.tag
                    if e_key == key:
                        for attr, val in child.attrib.items():
                            if attr not in existing.attrib:
                                existing.set(attr, val)
                        added += add_missing(existing, child, other_name)
                        break
        return added

    for fw_name, fw_data in firmwares.items():
        if fw_name == base_fw:
            continue
        add_missing(base_root, fw_data['root'], fw_name)

    return base_root


def generate_report(firmwares, diffs, common, union, unified_root):
    """Generate markdown analysis report."""
    lines = []
    lines.append("# Unified Firmware Configuration Analysis\n")
    lines.append("Generated from decrypted `hw_ctree.xml` across all firmware images.\n")

    # Firmware summary
    lines.append("## Firmware Summary\n")
    lines.append("| Firmware | Elements | Attributes | Size |")
    lines.append("|----------|----------|------------|------|")
    for fw_name, data in sorted(firmwares.items()):
        lines.append(
            f"| {fw_name} | {data['elements']:,} | "
            f"{data['attributes']:,} | {data['size']:,} B |"
        )

    # Unified stats
    u_elem = sum(1 for _ in unified_root.iter())
    u_attr = sum(len(e.attrib) for e in unified_root.iter())
    lines.append(f"\n**Unified config**: {u_elem:,} elements, {u_attr:,} attributes\n")

    # Path analysis
    lines.append("## Path Analysis\n")
    lines.append(f"- Common paths (all firmwares): **{len(common):,}**")
    lines.append(f"- Total unique paths (union): **{len(union):,}**")
    lines.append(f"- Parameters with different values: **{len(diffs)}**\n")

    # Differences
    if diffs:
        lines.append("## Configuration Differences\n")
        lines.append("Parameters that have different values across firmwares:\n")
        for d in sorted(diffs, key=lambda x: x['path']):
            lines.append(f"### `{d['path']}`\n")
            lines.append("| Firmware | Value |")
            lines.append("|----------|-------|")
            for fw, val in sorted(d['values'].items()):
                # Truncate long values
                display = val[:80] + "..." if len(val) > 80 else val
                lines.append(f"| {fw} | `{display}` |")
            lines.append("")

    # Config tree structure overview
    lines.append("## Configuration Tree Structure\n")
    lines.append("Top-level sections in `<InternetGatewayDevice>`:\n")
    lines.append("| Section | Children | Description |")
    lines.append("|---------|----------|-------------|")

    section_descriptions = {
        'LANDevice': 'LAN interface settings (Ethernet, WiFi, DHCP)',
        'WANDevice': 'WAN connection settings (PPPoE, DHCP, routing)',
        'Service': 'Voice/VoIP service configuration',
        'UserInterface': 'Web and CLI user accounts',
        'X_HW_ProductInfo': 'Product identity and version info',
        'X_HW_Security': 'Security settings (firewall, ACL, SSH)',
        'X_HW_SSMPPDT': 'SSMP product-specific settings',
        'X_HW_LswPortInfo': 'Ethernet switch port configuration',
        'X_HW_OmciInfo': 'OMCI (GPON management) settings',
        'DeviceInfo': 'Device information and diagnostics',
        'Layer3Forwarding': 'IP routing and forwarding rules',
    }

    for child in unified_root:
        tag = child.tag
        num_children = len(list(child))
        desc = section_descriptions.get(tag, '')
        lines.append(f"| `{tag}` | {num_children} | {desc} |")

    # Config generation flow
    lines.append("\n## Config Generation Flow\n")
    lines.append("How `hw_ctree.xml` is generated, stored, and used:\n")
    lines.append("```")
    lines.append("┌─────────────────────────────────────────────────────────┐")
    lines.append("│                    FIRMWARE BUILD                       │")
    lines.append("│                                                         │")
    lines.append("│  hw_default_ctree.xml (factory defaults)                │")
    lines.append("│       │                                                 │")
    lines.append("│       ▼                                                 │")
    lines.append("│  gzip compress → AES-256-CBC encrypt                    │")
    lines.append("│       │         (PBKDF2 key from kmc_store)             │")
    lines.append("│       ▼                                                 │")
    lines.append("│  hw_ctree.xml (encrypted, in /etc/wap/)                 │")
    lines.append("│  hw_default_ctree.xml (encrypted, identical at factory) │")
    lines.append("└─────────────────────────────────────────────────────────┘")
    lines.append("")
    lines.append("┌─────────────────────────────────────────────────────────┐")
    lines.append("│                   DEVICE BOOT                           │")
    lines.append("│                                                         │")
    lines.append("│  1. /bin/aescrypt2 1 hw_ctree.xml → decrypt             │")
    lines.append("│  2. gunzip → plaintext XML                              │")
    lines.append("│  3. HW_XML_DBInit() → parse into in-memory DOM tree     │")
    lines.append("│  4. HW_XML_DBTreeInit() → build TTree (template tree)   │")
    lines.append("│  5. HW_XML_DataMapInit() → attach data map overlays     │")
    lines.append("│  6. Services read config via HW_XML_DBGetSiglePara()    │")
    lines.append("└─────────────────────────────────────────────────────────┘")
    lines.append("")
    lines.append("┌─────────────────────────────────────────────────────────┐")
    lines.append("│                  CONFIG SAVE                            │")
    lines.append("│                                                         │")
    lines.append("│  1. Service calls HW_XML_DBSetSiglePara() to update     │")
    lines.append("│  2. HW_XML_DBSave() → serialize DOM to XML             │")
    lines.append("│  3. gzip compress → AES-256-CBC encrypt                 │")
    lines.append("│  4. Write to /mnt/jffs2/hw_ctree.xml (flash)            │")
    lines.append("│  5. Backup: XML_BakCtree() → /var/backKey/              │")
    lines.append("└─────────────────────────────────────────────────────────┘")
    lines.append("")
    lines.append("┌─────────────────────────────────────────────────────────┐")
    lines.append("│                CONFIG IMPORT/EXPORT                     │")
    lines.append("│                                                         │")
    lines.append("│  Import (Web/TR-069):                                   │")
    lines.append("│    1. Upload encrypted .xml file                        │")
    lines.append("│    2. HW_XML_CFGFileSecurity() → validate + decrypt     │")
    lines.append("│    3. HW_XML_ParseFile() → parse XML                    │")
    lines.append("│    4. Merge into current config tree                    │")
    lines.append("│    5. HW_XML_DBSave() → re-encrypt + save              │")
    lines.append("│                                                         │")
    lines.append("│  Export (Web/TR-069):                                   │")
    lines.append("│    1. HW_XML_DomCtreeToXml() → serialize current tree   │")
    lines.append("│    2. HW_XML_CFGFileEncryptWithKey() → encrypt          │")
    lines.append("│    3. Download encrypted .xml file                      │")
    lines.append("│                                                         │")
    lines.append("│  cfgtool CLI:                                           │")
    lines.append("│    cfgtool get deftree <path> → read parameter          │")
    lines.append("│    cfgtool set deftree <path> <attr> <value> → write    │")
    lines.append("│    cfgtool add/del deftree <path> → add/remove instance │")
    lines.append("│    cfgtool clone deftree <path> <file> → export subset  │")
    lines.append("│    cfgtool batch deftree <file> → batch import          │")
    lines.append("└─────────────────────────────────────────────────────────┘")
    lines.append("```\n")

    # Key functions
    lines.append("## Key Library Functions\n")
    lines.append("From `libhw_ssp_basic.so` analysis:\n")
    lines.append("| Function | Purpose |")
    lines.append("|----------|---------|")
    lines.append("| `OS_AescryptEncrypt` | Encrypt file (AEST format: AES-256-CBC + HMAC-SHA-256) |")
    lines.append("| `OS_AescryptDecrypt` | Decrypt AEST file |")
    lines.append("| `HW_XML_GetEncryptedKey` | Get AES key from KMC keystore |")
    lines.append("| `HW_XML_DBInit` | Initialize config database from XML |")
    lines.append("| `HW_XML_DBSave` | Save config database to encrypted XML |")
    lines.append("| `HW_XML_DBSaveCTreeXmlToFlash` | Write encrypted ctree to flash |")
    lines.append("| `HW_XML_DBSaveToFlash` | Save all config trees to flash |")
    lines.append("| `HW_XML_CFGFileSecurity` | Validate and decrypt config file |")
    lines.append("| `HW_XML_CFGFileEncryptWithKey` | Encrypt config file for export |")
    lines.append("| `HW_XML_DomCtreeToXml` | Serialize DOM tree to XML string |")
    lines.append("| `HW_XML_ParseFile` | Parse XML file into DOM tree |")
    lines.append("| `HW_XML_DBUnCompressFile` | Decompress gzipped config |")
    lines.append("| `HW_XML_DBZipFile` | Compress config with gzip |")
    lines.append("| `XML_BakCtree` | Backup ctree to /var/backKey/ |")
    lines.append("| `HW_KMC_GetAppointKey` | Get encryption key from KMC store |")
    lines.append("| `HW_CFGTOOL_GetXMLValByPath` | cfgtool: read parameter by path |")
    lines.append("| `HW_CFGTOOL_SetXMLValByPath` | cfgtool: write parameter by path |")
    lines.append("| `HW_CFGTOOL_AddXMLValByPath` | cfgtool: add instance by path |")
    lines.append("| `HW_CFGTOOL_DelXMLValByPath` | cfgtool: delete instance by path |")
    lines.append("| `HW_CFGTOOL_CloneXMLValByPath` | cfgtool: export subtree to file |")
    lines.append("")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Analyze firmware configs')
    parser.add_argument('--configs-dir', default='extracted_configs',
                        help='Directory with extracted firmware configs')
    parser.add_argument('--output', default=None,
                        help='Output unified config XML path')
    parser.add_argument('--report', default=None,
                        help='Output analysis report path')
    args = parser.parse_args()

    # Find configs dir
    if not os.path.isabs(args.configs_dir):
        # Try relative to script location
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_dir = os.path.dirname(script_dir)
        args.configs_dir = os.path.join(repo_dir, args.configs_dir)

    print(f"Configs directory: {args.configs_dir}")

    # Parse all firmwares
    firmwares = parse_firmware_configs(args.configs_dir)
    if not firmwares:
        print("ERROR: No firmware configs found", file=sys.stderr)
        sys.exit(1)

    print(f"Parsed {len(firmwares)} firmwares:")
    for fw, data in sorted(firmwares.items()):
        print(f"  {fw}: {data['elements']} elements, "
              f"{data['attributes']} attributes, {data['size']:,} B")

    # Analyze differences
    diffs, common, union = find_differences(firmwares)
    print(f"\nCommon paths: {len(common)}, Union: {len(union)}, "
          f"Differences: {len(diffs)}")

    # Create unified config
    unified_root = create_unified_config(firmwares)
    u_elem = sum(1 for _ in unified_root.iter())
    u_attr = sum(len(e.attrib) for e in unified_root.iter())
    print(f"Unified config: {u_elem} elements, {u_attr} attributes")

    # Write unified config
    output_path = args.output or os.path.join(args.configs_dir,
                                               'unified_config.xml')
    tree = ET.ElementTree(unified_root)
    ET.indent(tree, space='\t')
    tree.write(output_path, encoding='unicode', xml_declaration=False)
    print(f"Written unified config: {output_path}")

    # Generate and write report
    report = generate_report(firmwares, diffs, common, union, unified_root)
    report_path = args.report or os.path.join(args.configs_dir,
                                               'CONFIG_ANALYSIS.md')
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"Written analysis report: {report_path}")


if __name__ == '__main__':
    main()
