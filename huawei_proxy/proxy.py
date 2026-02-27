import asyncio
from mitmproxy import http, ctx
from mitmproxy.tools.main import mitmdump
import json
import re
from datetime import datetime
import os

class HuaweiONTInterceptor:
    def __init__(self):
        self.target_ip = "192.168.100.1"
        self.log_dir = "captured_traffic"
        os.makedirs(self.log_dir, exist_ok=True)

        self.hidden_features = {
            "X_HW_DEBUG": {
                "TelnetSwitch": "1",
                "SshSwitch": "1",
                "AMP.OntOnlineStatus": "enabled",
                "SMP.DM.ResetBoard": "enabled"
            },
            "UserLevel": "2",
            "admin_features": True
        }

        ctx.log.info("Huawei ONT Traffic Interceptor initialized")
        ctx.log.info(f"Target IP: {self.target_ip}")
        ctx.log.info(f"Log directory: {self.log_dir}")

    def request(self, flow: http.HTTPFlow) -> None:
        if self.target_ip not in flow.request.pretty_host:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

        ctx.log.info(f"[REQUEST] {flow.request.method} {flow.request.pretty_url}")

        if flow.request.method == "POST":
            self._modify_request(flow)

        self._log_request(flow, timestamp)

    def response(self, flow: http.HTTPFlow) -> None:
        if self.target_ip not in flow.request.pretty_host:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

        ctx.log.info(f"[RESPONSE] {flow.request.pretty_url} - Status: {flow.response.status_code}")

        self._modify_response(flow)
        self._log_response(flow, timestamp)

    def _modify_request(self, flow: http.HTTPFlow) -> None:
        request_content = flow.request.get_text()

        if "login.cgi" in flow.request.path or "UserLogin" in request_content:
            ctx.log.info("[MODIFY] Login request detected")
            flow.request.headers["X-Requested-With"] = "XMLHttpRequest"
            flow.request.headers["X-Admin-Override"] = "true"

        if any(param in flow.request.path for param in ["set.cgi", "get.cgi", "SendGetInfo.cgi"]):
            ctx.log.info(f"[MODIFY] API request: {flow.request.path}")
            if request_content:
                try:
                    modified_content = request_content.replace('"UserLevel":"0"', '"UserLevel":"2"')
                    modified_content = modified_content.replace('"UserLevel":"1"', '"UserLevel":"2"')
                    if modified_content != request_content:
                        flow.request.text = modified_content
                        ctx.log.info("[MODIFY] UserLevel elevated to admin (2)")
                except Exception as e:
                    ctx.log.error(f"Error modifying request: {e}")

    def _modify_response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return

        content_type = flow.response.headers.get("content-type", "")

        if "text/html" in content_type or "application/javascript" in content_type:
            try:
                response_text = flow.response.get_text()
                modified = False

                if "Userlevel" in response_text or "UserLevel" in response_text:
                    response_text = re.sub(r'var\s+Userlevel\s*=\s*[0-1];', 'var Userlevel = 2;', response_text)
                    response_text = re.sub(r'var\s+UserLevel\s*=\s*[0-1];', 'var UserLevel = 2;', response_text)
                    response_text = re.sub(r'"UserLevel"\s*:\s*"[0-1]"', '"UserLevel":"2"', response_text)
                    modified = True
                    ctx.log.info("[MODIFY] UserLevel elevated in response")

                if "display:none" in response_text or "display: none" in response_text:
                    for feature in ["telnet", "ssh", "debug", "advanced", "X_HW_DEBUG"]:
                        pattern = rf'id=["\'].*{feature}.*["\'][^>]*style=["\']display:\s*none["\']'
                        if re.search(pattern, response_text, re.IGNORECASE):
                            response_text = re.sub(pattern,
                                lambda m: m.group(0).replace("display:none", "display:block").replace("display: none", "display: block"),
                                response_text, flags=re.IGNORECASE)
                            modified = True
                            ctx.log.info(f"[MODIFY] Unhidden feature: {feature}")

                if "disabled=\"disabled\"" in response_text or "disabled='disabled'" in response_text:
                    for feature in ["telnet", "ssh", "debug", "advanced"]:
                        pattern = rf'id=["\'].*{feature}.*["\'][^>]*disabled=["\']disabled["\']'
                        if re.search(pattern, response_text, re.IGNORECASE):
                            response_text = re.sub(pattern,
                                lambda m: m.group(0).replace('disabled="disabled"', '').replace("disabled='disabled'", ''),
                                response_text, flags=re.IGNORECASE)
                            modified = True
                            ctx.log.info(f"[MODIFY] Enabled feature: {feature}")

                hidden_menu_patterns = [
                    (r'<div[^>]*id=["\']menu_debug["\'][^>]*style=["\']display:\s*none["\']',
                     lambda m: m.group(0).replace("display:none", "display:block")),
                    (r'<li[^>]*class=["\'].*hidden.*["\']',
                     lambda m: m.group(0).replace("hidden", "visible")),
                ]

                for pattern, replacement in hidden_menu_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        response_text = re.sub(pattern, replacement, response_text, flags=re.IGNORECASE)
                        modified = True
                        ctx.log.info("[MODIFY] Unhidden menu item")

                if "X_HW_DEBUG" in flow.request.path or "TelnetSwitch" in response_text or "SshSwitch" in response_text:
                    response_text = re.sub(r'"TelnetSwitch"\s*:\s*"0"', '"TelnetSwitch":"1"', response_text)
                    response_text = re.sub(r'"SshSwitch"\s*:\s*"0"', '"SshSwitch":"1"', response_text)
                    modified = True
                    ctx.log.info("[MODIFY] Enabled Telnet/SSH switches")

                if modified:
                    flow.response.text = response_text
                    ctx.log.info("[SUCCESS] Response modified successfully")

            except Exception as e:
                ctx.log.error(f"Error modifying response: {e}")

        elif "application/json" in content_type:
            try:
                response_text = flow.response.get_text()
                data = json.loads(response_text)
                modified = False

                if isinstance(data, dict):
                    if "UserLevel" in str(data):
                        def update_user_level(obj):
                            if isinstance(obj, dict):
                                for key, value in obj.items():
                                    if key == "UserLevel" and value in ["0", "1", 0, 1]:
                                        obj[key] = "2"
                                        nonlocal modified
                                        modified = True
                                    elif isinstance(value, (dict, list)):
                                        update_user_level(value)
                            elif isinstance(obj, list):
                                for item in obj:
                                    update_user_level(item)

                        update_user_level(data)

                    if "X_HW_DEBUG" in str(data):
                        def enable_debug_features(obj):
                            if isinstance(obj, dict):
                                for key, value in obj.items():
                                    if "TelnetSwitch" in key or "SshSwitch" in key:
                                        obj[key] = "1"
                                        nonlocal modified
                                        modified = True
                                    elif isinstance(value, (dict, list)):
                                        enable_debug_features(value)
                            elif isinstance(obj, list):
                                for item in obj:
                                    enable_debug_features(item)

                        enable_debug_features(data)

                    if modified:
                        flow.response.text = json.dumps(data)
                        ctx.log.info("[SUCCESS] JSON response modified successfully")

            except json.JSONDecodeError:
                pass
            except Exception as e:
                ctx.log.error(f"Error modifying JSON response: {e}")

    def _log_request(self, flow: http.HTTPFlow, timestamp: str) -> None:
        try:
            log_file = os.path.join(self.log_dir, f"request_{timestamp}.txt")
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"Method: {flow.request.method}\n")
                f.write(f"URL: {flow.request.pretty_url}\n")
                f.write(f"Host: {flow.request.pretty_host}\n")
                f.write(f"Path: {flow.request.path}\n")
                f.write("\nHeaders:\n")
                for key, value in flow.request.headers.items():
                    f.write(f"  {key}: {value}\n")
                f.write("\nBody:\n")
                body = flow.request.get_text()
                f.write(body if body else "(empty)")
        except Exception as e:
            ctx.log.error(f"Error logging request: {e}")

    def _log_response(self, flow: http.HTTPFlow, timestamp: str) -> None:
        try:
            log_file = os.path.join(self.log_dir, f"response_{timestamp}.txt")
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"URL: {flow.request.pretty_url}\n")
                f.write(f"Status: {flow.response.status_code}\n")
                f.write("\nHeaders:\n")
                for key, value in flow.response.headers.items():
                    f.write(f"  {key}: {value}\n")
                f.write("\nBody:\n")
                body = flow.response.get_text()
                f.write(body if body else "(empty)")
        except Exception as e:
            ctx.log.error(f"Error logging response: {e}")


addons = [HuaweiONTInterceptor()]
