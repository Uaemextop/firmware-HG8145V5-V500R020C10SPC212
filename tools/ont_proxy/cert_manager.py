#!/usr/bin/env python3
"""
cert_manager.py — SSL CA certificate generation and Windows installation.

Generates a self-signed CA certificate for the ONT proxy to intercept HTTPS
traffic. On Windows 11, installs the CA into the machine Root certificate
store via PowerShell (requires Administrator).

Usage:
    python -m tools.ont_proxy.cert_manager [--install] [--uninstall]
"""

import os
import sys
import subprocess
import datetime
import argparse

from . import config


def generate_ca_certificate():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    os.makedirs(config.CERT_DIR, exist_ok=True)

    if os.path.exists(config.CA_KEY_FILE) and os.path.exists(config.CA_CERT_FILE):
        print(f"[*] CA certificate already exists at {config.CA_CERT_FILE}")
        return config.CA_CERT_FILE, config.CA_KEY_FILE

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jalisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ONT Proxy"),
        x509.NameAttribute(NameOID.COMMON_NAME, config.CA_CERT_NAME),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=config.CA_VALIDITY_DAYS)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(config.CA_KEY_FILE, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(config.CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] CA certificate generated: {config.CA_CERT_FILE}")
    print(f"[+] CA private key generated: {config.CA_KEY_FILE}")
    return config.CA_CERT_FILE, config.CA_KEY_FILE


def generate_host_certificate(hostname):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress

    host_key_file = os.path.join(config.CERT_DIR, f"{hostname}.key")
    host_cert_file = os.path.join(config.CERT_DIR, f"{hostname}.crt")

    if os.path.exists(host_key_file) and os.path.exists(host_cert_file):
        return host_cert_file, host_key_file

    with open(config.CA_KEY_FILE, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(config.CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    san_names = [x509.DNSName(hostname)]
    try:
        san_names.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
        )
        .issuer_name(ca_cert.subject)
        .public_key(host_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(host_key_file, "wb") as f:
        f.write(
            host_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(host_cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return host_cert_file, host_key_file


def install_ca_windows():
    if sys.platform != "win32":
        print("[!] CA installation via PowerShell is only supported on Windows")
        print(f"[*] Manually import {config.CA_CERT_FILE} into your browser/system")
        return False

    cert_path = os.path.abspath(config.CA_CERT_FILE).replace("/", "\\")
    ps_script = (
        f'$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("{cert_path}")\n'
        f'$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")\n'
        f'$store.Open("ReadWrite")\n'
        f'$store.Add($cert)\n'
        f'$store.Close()\n'
        f'Write-Host "[+] CA certificate installed in Root store"'
    )

    import tempfile
    ps1_path = os.path.join(tempfile.gettempdir(), "ont_proxy_install_ca.ps1")
    try:
        with open(ps1_path, "w", encoding="utf-8") as f:
            f.write(ps_script)

        result = subprocess.run(
            [
                "powershell", "-Command",
                f'Start-Process powershell -Verb RunAs -Wait -ArgumentList '
                f'"-ExecutionPolicy Bypass -File \\"{ps1_path}\\""',
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            print("[+] CA certificate installation initiated (UAC prompt may appear)")
            return True
        print(f"[!] PowerShell returned code {result.returncode}: {result.stderr}")
        return False
    except FileNotFoundError:
        print("[!] PowerShell not found — not running on Windows?")
        return False
    except subprocess.TimeoutExpired:
        print("[!] PowerShell timed out")
        return False
    finally:
        if os.path.exists(ps1_path):
            os.remove(ps1_path)


def uninstall_ca_windows():
    if sys.platform != "win32":
        print("[!] CA uninstallation via PowerShell is only supported on Windows")
        return False

    ps_script = (
        f'$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")\n'
        f'$store.Open("ReadWrite")\n'
        f'$certs = $store.Certificates | Where-Object {{ $_.Subject -like "*{config.CA_CERT_NAME}*" }}\n'
        f'foreach ($c in $certs) {{ $store.Remove($c) }}\n'
        f'$store.Close()\n'
        f'Write-Host "[+] CA certificate removed from Root store"'
    )

    import tempfile
    ps1_path = os.path.join(tempfile.gettempdir(), "ont_proxy_uninstall_ca.ps1")
    try:
        with open(ps1_path, "w", encoding="utf-8") as f:
            f.write(ps_script)

        result = subprocess.run(
            [
                "powershell", "-Command",
                f'Start-Process powershell -Verb RunAs -Wait -ArgumentList '
                f'"-ExecutionPolicy Bypass -File \\"{ps1_path}\\""',
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            print("[+] CA certificate uninstallation initiated")
            return True
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    finally:
        if os.path.exists(ps1_path):
            os.remove(ps1_path)


def main():
    parser = argparse.ArgumentParser(description="ONT Proxy CA Certificate Manager")
    parser.add_argument("--install", action="store_true", help="Install CA in Windows Root store")
    parser.add_argument("--uninstall", action="store_true", help="Remove CA from Windows Root store")
    args = parser.parse_args()

    cert_file, key_file = generate_ca_certificate()

    if args.install:
        install_ca_windows()
    elif args.uninstall:
        uninstall_ca_windows()
    else:
        print(f"[*] CA cert: {cert_file}")
        print(f"[*] CA key:  {key_file}")
        print("[*] Use --install to add to Windows Root store")
        print("[*] Use --uninstall to remove from Windows Root store")


if __name__ == "__main__":
    main()
