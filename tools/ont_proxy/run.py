#!/usr/bin/env python3
"""
run.py — Main entry point for the ONT Proxy.

Starts a mitmproxy instance that intercepts and modifies HTTP traffic
from the Huawei ONT router (192.168.100.1) to unlock hidden admin
features for Megacable ISP users.

Usage (Windows 11):
    python -m tools.ont_proxy.run [--install-cert] [--launch-chrome] [--port PORT]

Requirements:
    pip install mitmproxy cryptography

Flow:
    1. Generate CA certificate (auto on first run)
    2. Optionally install CA in Windows Root store (--install-cert)
    3. Start mitmproxy on 127.0.0.1:8080
    4. Optionally launch Chrome with proxy (--launch-chrome)
    5. All traffic to 192.168.100.1 is intercepted and modified
"""

import os
import sys
import signal
import argparse

from . import config
from .cert_manager import generate_ca_certificate, install_ca_windows
from .chrome_launcher import create_chrome_profile, launch_chrome, generate_proxy_pac


def check_dependencies():
    missing = []
    try:
        import mitmproxy  # noqa: F401
    except ImportError:
        missing.append("mitmproxy")
    try:
        import cryptography  # noqa: F401
    except ImportError:
        missing.append("cryptography")

    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}")
        print(f"    Install with: pip install {' '.join(missing)}")
        return False
    return True


def start_proxy(listen_host=None, listen_port=None):
    from mitmproxy.tools.main import mitmdump

    if listen_host is None:
        listen_host = config.PROXY_LISTEN_HOST
    if listen_port is None:
        listen_port = config.PROXY_LISTEN_PORT

    addon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "response_modifier.py")

    args = [
        "--listen-host", listen_host,
        "--listen-port", str(listen_port),
        "--mode", f"reverse:http://{config.ONT_HOST}:{config.ONT_PORT}/",
        "--set", f"confdir={config.CERT_DIR}",
        "--ssl-insecure",
        "-s", addon_path,
    ]

    print(f"[+] Starting ONT Proxy")
    print(f"    Listen: {listen_host}:{listen_port}")
    print(f"    Target: http://{config.ONT_HOST}:{config.ONT_PORT}/")
    print(f"    ISP:    {config.ISP_NAME}")
    print(f"    Menu:   {config.MENU_XML}")
    print(f"    Logs:   {config.LOG_FILE}")
    print(f"    Addon:  {addon_path}")
    print()
    print(f"[*] Open http://{listen_host}:{listen_port}/ in your browser")
    print(f"[*] Or use --launch-chrome to auto-configure Chrome")
    print(f"[*] Press Ctrl+C to stop")
    print()

    mitmdump(args)


def start_proxy_standalone(listen_host=None, listen_port=None):
    from mitmproxy import options, proxy
    from mitmproxy.tools.dump import DumpMaster
    from .response_modifier import ONTResponseModifier

    if listen_host is None:
        listen_host = config.PROXY_LISTEN_HOST
    if listen_port is None:
        listen_port = config.PROXY_LISTEN_PORT

    opts = options.Options(
        listen_host=listen_host,
        listen_port=listen_port,
        mode=[f"reverse:http://{config.ONT_HOST}:{config.ONT_PORT}/"],
        ssl_insecure=True,
        confdir=config.CERT_DIR,
    )

    master = DumpMaster(opts)
    master.addons.add(ONTResponseModifier())

    print(f"[+] Starting ONT Proxy (standalone mode)")
    print(f"    Listen: {listen_host}:{listen_port}")
    print(f"    Target: http://{config.ONT_HOST}:{config.ONT_PORT}/")
    print(f"    ISP:    {config.ISP_NAME}")
    print()

    try:
        master.run()
    except KeyboardInterrupt:
        master.shutdown()


def main():
    parser = argparse.ArgumentParser(
        description="ONT Proxy — Unlock hidden Huawei ONT features (Megacable)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m tools.ont_proxy.run
  python -m tools.ont_proxy.run --install-cert --launch-chrome
  python -m tools.ont_proxy.run --port 9090
  python -m tools.ont_proxy.run --host 0.0.0.0 --port 8080

Environment Variables:
  ONT_HOST    Target ONT IP (default: 192.168.100.1)
  ONT_PORT    Target ONT port (default: 80)
  PROXY_HOST  Proxy listen address (default: 127.0.0.1)
  PROXY_PORT  Proxy listen port (default: 8080)
""",
    )
    parser.add_argument("--host", default=None, help="Proxy listen host")
    parser.add_argument("--port", type=int, default=None, help="Proxy listen port")
    parser.add_argument("--install-cert", action="store_true", help="Install CA cert in Windows Root store")
    parser.add_argument("--launch-chrome", action="store_true", help="Launch Chrome with proxy profile")
    parser.add_argument("--standalone", action="store_true", help="Use standalone proxy mode (no mitmdump CLI)")
    parser.add_argument("--generate-pac", action="store_true", help="Generate PAC file and exit")

    args = parser.parse_args()

    if not check_dependencies():
        sys.exit(1)

    cert_file, key_file = generate_ca_certificate()
    print(f"[+] CA Certificate: {cert_file}")

    if args.install_cert:
        install_ca_windows()

    if args.generate_pac:
        generate_proxy_pac()
        sys.exit(0)

    listen_host = args.host or config.PROXY_LISTEN_HOST
    listen_port = args.port or config.PROXY_LISTEN_PORT

    chrome_proc = None
    if args.launch_chrome:
        profile_dir = create_chrome_profile()
        generate_proxy_pac()
        chrome_proc = launch_chrome(profile_dir)

    def signal_handler(sig, frame):
        print("\n[*] Shutting down...")
        if chrome_proc and chrome_proc.poll() is None:
            chrome_proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    if args.standalone:
        start_proxy_standalone(listen_host, listen_port)
    else:
        start_proxy(listen_host, listen_port)


if __name__ == "__main__":
    main()
