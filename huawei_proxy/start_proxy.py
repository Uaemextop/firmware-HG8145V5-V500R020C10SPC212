import subprocess
import sys
import os
import time

def start_proxy(port=8080, verbose=True):
    print("=" * 60)
    print("Huawei ONT Traffic Interceptor - Starting Proxy")
    print("=" * 60)
    print("")

    if not os.path.exists("proxy.py"):
        print("ERROR: proxy.py not found in current directory")
        print("Please run this script from the huawei_proxy directory")
        return False

    print(f"Starting mitmproxy on port {port}...")
    print(f"Target device: 192.168.100.1")
    print(f"Captured traffic will be saved to: ./captured_traffic/")
    print("")
    print("Features enabled:")
    print("  - User level elevation (admin access)")
    print("  - Telnet/SSH switch unlocking")
    print("  - X_HW_DEBUG features unlocking")
    print("  - Hidden menu unhiding")
    print("  - Traffic logging and capture")
    print("")
    print("Configure your Chrome profile to use this proxy:")
    print(f"  HTTP Proxy: 127.0.0.1:{port}")
    print(f"  HTTPS Proxy: 127.0.0.1:{port}")
    print("")
    print("Or run: powershell -ExecutionPolicy Bypass -File setup_chrome_profile.ps1")
    print("")
    print("-" * 60)
    print("Press Ctrl+C to stop the proxy")
    print("-" * 60)
    print("")

    try:
        cmd = [
            "mitmdump",
            "-s", "proxy.py",
            "--listen-port", str(port),
            "--set", "block_global=false",
            "--set", "ssl_insecure=true"
        ]

        if verbose:
            cmd.extend(["--set", "flow_detail=2"])

        subprocess.run(cmd)

    except KeyboardInterrupt:
        print("\n\nProxy stopped by user")
        return True
    except FileNotFoundError:
        print("ERROR: mitmproxy not found")
        print("Please install requirements: pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"ERROR: Failed to start proxy: {e}")
        return False

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Huawei ONT Traffic Interceptor")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Proxy port (default: 8080)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (less verbose)")

    args = parser.parse_args()

    start_proxy(port=args.port, verbose=not args.quiet)
