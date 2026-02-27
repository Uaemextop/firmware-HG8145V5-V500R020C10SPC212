#!/usr/bin/env python3
"""
chrome_launcher.py — Chrome profile creation with proxy injection.

Creates an isolated Chrome profile configured to route traffic through the
ONT proxy. Launches Chrome with the proxy settings and custom CA certificate.

Usage:
    python -m tools.ont_proxy.chrome_launcher [--launch]
"""

import os
import sys
import json
import subprocess
import argparse

from . import config


def find_chrome_binary():
    if sys.platform == "win32":
        candidates = [
            os.path.join(os.environ.get("PROGRAMFILES", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
        ]
    elif sys.platform == "darwin":
        candidates = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    else:
        candidates = ["/usr/bin/google-chrome", "/usr/bin/chromium-browser", "/usr/bin/chromium"]

    for path in candidates:
        if path and os.path.exists(path):
            return path

    return None


def create_chrome_profile():
    os.makedirs(config.CHROME_PROFILE_DIR, exist_ok=True)

    prefs = {
        "profile": {
            "name": "ONT Proxy - Megacable",
            "default_content_setting_values": {
                "notifications": 2,
            },
        },
        "net": {
            "network_prediction_options": 2,
        },
        "dns_prefetching": {
            "enabled": False,
        },
        "safebrowsing": {
            "enabled": False,
        },
        "translate": {
            "enabled": False,
        },
        "browser": {
            "check_default_browser": False,
        },
    }

    default_dir = os.path.join(config.CHROME_PROFILE_DIR, "Default")
    os.makedirs(default_dir, exist_ok=True)

    prefs_file = os.path.join(default_dir, "Preferences")
    with open(prefs_file, "w", encoding="utf-8") as f:
        json.dump(prefs, f, indent=2)

    print(f"[+] Chrome profile created at {config.CHROME_PROFILE_DIR}")
    return config.CHROME_PROFILE_DIR


def build_chrome_args(chrome_path, profile_dir):
    proxy_addr = f"{config.PROXY_LISTEN_HOST}:{config.PROXY_LISTEN_PORT}"
    target_url = f"http://{config.ONT_HOST}/"

    args = [
        chrome_path,
        f"--user-data-dir={profile_dir}",
        f"--proxy-server={proxy_addr}",
        f"--proxy-bypass-list=<-loopback>",
        "--ignore-certificate-errors",
        "--disable-extensions",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-translate",
        "--disable-features=TranslateUI",
        "--disable-component-update",
        target_url,
    ]

    return args


def launch_chrome(profile_dir=None):
    chrome_path = find_chrome_binary()
    if not chrome_path:
        print("[!] Chrome not found. Install Google Chrome or set path manually.")
        print("[*] You can manually configure proxy in your browser:")
        print(f"    Proxy: {config.PROXY_LISTEN_HOST}:{config.PROXY_LISTEN_PORT}")
        print(f"    Target: http://{config.ONT_HOST}/")
        return None

    if profile_dir is None:
        profile_dir = create_chrome_profile()

    args = build_chrome_args(chrome_path, profile_dir)

    print(f"[+] Launching Chrome with proxy {config.PROXY_LISTEN_HOST}:{config.PROXY_LISTEN_PORT}")
    print(f"[+] Target: http://{config.ONT_HOST}/")
    print(f"[+] Profile: {profile_dir}")

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"[+] Chrome launched (PID: {proc.pid})")
        return proc
    except OSError as e:
        print(f"[!] Failed to launch Chrome: {e}")
        return None


def generate_proxy_pac(output_path=None):
    if output_path is None:
        output_path = os.path.join(config.CHROME_PROFILE_DIR, "proxy.pac")

    pac_content = f"""function FindProxyForURL(url, host) {{
    if (host === "{config.ONT_HOST}" ||
        dnsDomainIs(host, "{config.ONT_HOST}")) {{
        return "PROXY {config.PROXY_LISTEN_HOST}:{config.PROXY_LISTEN_PORT}";
    }}
    return "DIRECT";
}}
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(pac_content)

    print(f"[+] PAC file generated: {output_path}")
    return output_path


def main():
    parser = argparse.ArgumentParser(description="ONT Proxy Chrome Launcher")
    parser.add_argument("--launch", action="store_true", help="Launch Chrome with proxy")
    parser.add_argument("--pac", action="store_true", help="Generate proxy PAC file only")
    args = parser.parse_args()

    if args.pac:
        generate_proxy_pac()
    elif args.launch:
        create_chrome_profile()
        launch_chrome()
    else:
        profile_dir = create_chrome_profile()
        generate_proxy_pac()
        print(f"\n[*] To launch Chrome with proxy:")
        chrome = find_chrome_binary()
        if chrome:
            cmd_args = build_chrome_args(chrome, profile_dir)
            print(f'    {" ".join(cmd_args)}')
        else:
            print(f"    Configure proxy {config.PROXY_LISTEN_HOST}:{config.PROXY_LISTEN_PORT} in your browser")


if __name__ == "__main__":
    main()
