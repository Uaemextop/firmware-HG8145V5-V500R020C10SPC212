#!/usr/bin/env python3
"""
response_modifier.py — mitmproxy addon for ONT traffic interception.

Intercepts HTTP/HTTPS responses from the Huawei ONT (192.168.100.1) and
modifies them to unlock hidden/admin-only features for normal user sessions.

Modifications performed:
  1. User type escalation: curUserType '1' → '0' (normal → admin)
  2. Menu array injection: replaces normal-user menu with full admin menu
  3. Feature flag forcing: enables all feature control flags
  4. ACL/security page unlock: reveals all access control options
  5. Header rewriting: removes restrictive cache/security headers

This addon is loaded by mitmproxy via: mitmdump -s response_modifier.py
"""

import re
import os
import sys
import json
import datetime

try:
    from . import config
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import config


class ONTResponseModifier:

    def __init__(self):
        os.makedirs(config.LOG_DIR, exist_ok=True)
        self._log_file = open(config.LOG_FILE, "a", encoding="utf-8")
        self._menu_cache = None
        self._build_admin_menu()

    def _log(self, method, url, status, modified, details=""):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        flag = "MOD" if modified else "---"
        line = f"[{ts}] [{flag}] {method} {url} -> {status}"
        if details:
            line += f" | {details}"
        self._log_file.write(line + "\n")
        self._log_file.flush()

    def _build_admin_menu(self):
        items = []
        items.append(self._menu_item("Home Page", "MainPage", 1, url="CustomApp/mainpage.asp",
                                     deficon="images/mainpagedef.jpg", clickicon="images/mainpagepress.jpg"))
        items.append(self._menu_item("One-Click Diagnosis", "OntCheck", 1,
                                     url="html/ssmp/maintain/smartdiagnose.asp",
                                     deficon="images/checkdef.jpg", clickicon="images/checkpress.jpg"))

        sysinfo = self._menu_item("System Information", "Systeminfo", 1,
                                  deficon="images/systemdef.jpg", clickicon="images/systempress.jpg")
        sysinfo["subMenus"] = [
            self._menu_item("Device", "deviceinfo", 2, url="html/ssmp/deviceinfo/deviceinfo.asp"),
            self._menu_item("WAN", "waninfo", 2, url="html/bbsp/waninfo/waninfo.asp"),
            self._menu_item("Optical", "opticinfo", 2, url="html/amp/opticinfo/opticinfo.asp"),
            self._menu_item("Service Provisioning Status", "bssinfo", 2, url="html/ssmp/bss/bssinfo.asp"),
            self._menu_item("VoIP", "voipinfo", 2, url="html/voip/status/voipmaintain.asp"),
            self._menu_item("Eth Port", "ethinfo", 2, url="html/amp/ethinfo/ethinfo.asp"),
            self._menu_item("WLAN", "wlaninfo", 2, url="html/amp/wlaninfo/wlaninfo.asp"),
            self._menu_item("Home Network", "wlancoverinfo", 2, url="html/amp/wificoverinfo/wlancoverinfo.asp"),
        ]
        items.append(sysinfo)

        advanced = self._menu_item("Advanced", "addconfig", 1,
                                   deficon="images/addvdef.jpg", clickicon="images/addvpress.jpg")
        advanced["subMenus"] = []

        wan_item = self._menu_item("WAN", "wanconfig", 2, url="html/bbsp/wan/wan.asp")
        advanced["subMenus"].append(wan_item)

        lan_item = self._menu_item("LAN", "lanconfig", 2)
        lan_item["subMenus"] = [
            self._menu_item("Layer 2/3 Port", "lanportconfig", 3, url="html/bbsp/layer3/layer3.asp"),
            self._menu_item("LAN Host", "lanhostconfig", 3, url="html/bbsp/dhcp/dhcp.asp"),
            self._menu_item("DHCP Server", "landhcp", 3, url="html/bbsp/dhcpservercfg/dhcp2.asp"),
            self._menu_item("DHCP Static IP", "landhcpstatic", 3, url="html/bbsp/dhcpstatic/dhcpstatic.asp"),
            self._menu_item("DHCPv6 Server", "landhcpv6", 3, url="html/bbsp/lanaddress/lanaddress.asp"),
            self._menu_item("DHCPv6 Static IP", "landhcpv6static", 3, url="html/bbsp/dhcpstaticaddr/dhcpstaticaddress.asp"),
            self._menu_item("DHCPv6 Information", "landhcpv6info", 3, url="html/bbsp/dhcpv6info/dhcpv6info.asp"),
        ]
        advanced["subMenus"].append(lan_item)

        security_item = self._menu_item("Security", "securityconfig", 2)
        security_item["subMenus"] = [
            self._menu_item("Firewall Level", "ipv4firewalllevel", 3, url="html/bbsp/firewalllevel/firewalllevel.asp"),
            self._menu_item("IPv4 Filtering", "ipincoming", 3, url="html/bbsp/ipincoming/ipincoming.asp"),
            self._menu_item("MAC Filtering", "macfilter", 3, url="html/bbsp/macfilter/macfilter.asp"),
            self._menu_item("Wi-Fi MAC Filtering", "wlanmacfilter", 3, url="html/bbsp/wlanmacfilter/wlanmacfilter.asp"),
            self._menu_item("Parental Control", "parentalctrl", 3, url="html/bbsp/parentalctrl/parentalctrlstatus.asp"),
            self._menu_item("DoS Configuration", "dos", 3, url="html/bbsp/Dos/Dos.asp"),
            self._menu_item("Device Access Control", "ontaccess", 3, url="html/bbsp/acl/aclsmart.asp"),
            self._menu_item("Full Access Control", "fullaclconfig", 3, url="html/bbsp/acl/acl.asp"),
            self._menu_item("WAN Access Control", "wanacl", 3, url="html/bbsp/wanacl/wanacl.asp"),
            self._menu_item("IPv6 Filtering", "ipv6ipincoming", 3, url="html/bbsp/ipv6ipincoming/ipv6ipincoming.asp"),
        ]
        advanced["subMenus"].append(security_item)

        route_item = self._menu_item("Route", "routeconfig", 2)
        route_item["subMenus"] = [
            self._menu_item("Default IPv4 Route", "ipv4defaultroute", 3, url="html/bbsp/route/route.asp"),
            self._menu_item("IPv4 Static Route", "ipv4staticroute", 3, url="html/bbsp/staticroute/staticroute.asp"),
            self._menu_item("IPv4 Dynamic Route", "ipv4dynamicroute", 3, url="html/bbsp/dynamicroute/dynamicroute.asp"),
            self._menu_item("IPv4 VLAN Binding", "ipv4vlanbind", 3, url="html/bbsp/vlanctc/vlanctc.asp"),
            self._menu_item("IPv4 Service Route", "ipv4serviceroute", 3, url="html/bbsp/serviceroute/serviceroute.asp"),
            self._menu_item("IPv4 Routing Table", "ipv4routeinfo", 3, url="html/bbsp/routeinfo/routeinfo.asp"),
            self._menu_item("Default IPv6 Route", "ipv6defaultroute", 3, url="html/bbsp/ipv6defaultroute/defaultroute.asp"),
            self._menu_item("IPv6 Static Route", "ipv6staticroute", 3, url="html/bbsp/ipv6staticroute/ipv6staticroute.asp"),
        ]
        advanced["subMenus"].append(route_item)

        fwd_item = self._menu_item("Forward Rules", "forwardrules", 2)
        fwd_item["subMenus"] = [
            self._menu_item("DMZ Function", "dmz", 3, url="html/bbsp/dmz/dmz.asp"),
            self._menu_item("IPv4 Port Mapping", "portmapping", 3, url="html/bbsp/portmapping/portmapping.asp"),
            self._menu_item("Port Trigger", "porttrigger", 3, url="html/bbsp/porttrigger/porttrigger.asp"),
        ]
        advanced["subMenus"].append(fwd_item)

        app_item = self._menu_item("Application", "application", 2)
        app_item["subMenus"] = [
            self._menu_item("USB Application", "usbapplication", 3, url="html/ssmp/usbftp/usbhost.asp"),
            self._menu_item("Time Setting", "sntpmngt", 3, url="html/ssmp/sntp/sntp.asp"),
            self._menu_item("Media Sharing", "dlnashare", 3, url="html/ssmp/dlna/dlna.asp"),
            self._menu_item("ALG", "alg", 3, url="html/bbsp/alg/alg.asp"),
            self._menu_item("DDNS", "ddns", 3, url="html/bbsp/ddns/ddns.asp"),
            self._menu_item("UPnP", "upnp", 3, url="html/bbsp/upnp/upnp.asp"),
            self._menu_item("IGMP", "igmp", 3, url="html/bbsp/igmp/igmp.asp"),
            self._menu_item("Intelligent Channel", "qossmart", 3, url="html/bbsp/qossmart/qossmart.asp"),
            self._menu_item("ARP Ping", "arp", 3, url="html/bbsp/arpping/arpping.asp"),
            self._menu_item("Static DNS", "dnsconfiguration", 3, url="html/bbsp/dnsconfiguration/dnsconfigcommon.asp"),
            self._menu_item("DSCP-to-Pbit Mapping", "DSCPMapping", 3, url="html/bbsp/dscptopbit/dscptopbit.asp"),
            self._menu_item("LAN Port Multi-service", "lanservicecfg", 3, url="html/bbsp/lanservicecfg/lanservicecfg.asp"),
        ]
        advanced["subMenus"].append(app_item)

        wlan_item = self._menu_item("WLAN", "wlanconfig", 2)
        wlan_item["subMenus"] = [
            self._menu_item("WLAN Basic", "wlanbasic", 3, url="html/amp/wlanbasic/WlanBasic.asp"),
            self._menu_item("WLAN Advanced", "wlanadv", 3, url="html/amp/wlanadv/WlanAdvance.asp"),
            self._menu_item("2.4G Basic Network Settings", "wlan2basic", 3, url="html/amp/wlanbasic/WlanBasic.asp?2G"),
            self._menu_item("2.4G Advanced Network Settings", "wlan2adv", 3, url="html/amp/wlanadv/WlanAdvance.asp?2G"),
            self._menu_item("5G Basic Network Settings", "wlan5basic", 3, url="html/amp/wlanbasic/WlanBasic.asp?5G"),
            self._menu_item("5G Advanced Network Settings", "wlan5adv", 3, url="html/amp/wlanadv/WlanAdvance.asp?5G"),
            self._menu_item("Automatic Wi-Fi Shutdown", "wlanschedule", 3, url="html/amp/wifische/WlanSchedule.asp"),
            self._menu_item("Wi-Fi Coverage", "wificover", 3, url="html/amp/wificovercfg/wifiCover.asp"),
        ]
        advanced["subMenus"].append(wlan_item)

        voip_item = self._menu_item("Voice", "voip", 2)
        voip_item["subMenus"] = [
            self._menu_item("VoIP Basic", "voipinterface", 3, url="html/voip/voipinterface/voipinterface.asp"),
            self._menu_item("VoIP Advanced", "voipuser", 3, url="html/voip/voipuser/voipuser.asp"),
            self._menu_item("SIP/H.248 Conversion", "changeprotocol", 3, url="html/voip/changeprotocol/voipchangeprotocol.asp"),
        ]
        advanced["subMenus"].append(voip_item)

        systool_item = self._menu_item("System Management", "systool", 2)
        systool_item["subMenus"] = [
            self._menu_item("TR-069", "tr069config", 3, url="html/ssmp/tr069/tr069.asp"),
            self._menu_item("Account Management", "userconfig", 3, url="html/ssmp/accoutcfg/accountadmin.asp"),
            self._menu_item("Open Source Software Notice", "noticeinfo", 3, url="html/ssmp/softnotice/opensfnotice.asp"),
            self._menu_item("ONT Authentication", "passwordcommon", 3, url="html/amp/ontauth/passwordcommon.asp"),
        ]
        advanced["subMenus"].append(systool_item)

        maint_item = self._menu_item("Maintenance Diagnosis", "maintaininfo", 2)
        maint_item["subMenus"] = [
            self._menu_item("Software Upgrade", "fireware", 3, url="html/ssmp/fireware/firmware.asp"),
            self._menu_item("Configuration File Management", "cfgconfig", 3, url="html/ssmp/cfgfile/cfgfile.asp"),
            self._menu_item("Configuration File (Root)", "cfgconfigroot", 3, url="html/ssmp/cfgfile/cfgfileroot.asp"),
            self._menu_item("Maintenance", "maintainconfig", 3, url="html/bbsp/maintenance/diagnosecommon.asp"),
            self._menu_item("User Log", "userlog", 3, url="html/ssmp/userlog/logview.asp"),
            self._menu_item("Firewall Log", "firewalllog", 3, url="html/bbsp/firewalllog/firewalllogview.asp"),
            self._menu_item("Debug Log", "debuglog", 3, url="html/ssmp/debuglog/debuglogview.asp"),
            self._menu_item("Intelligent Channel Statistics", "qossmartstatistics", 3, url="html/bbsp/qossmartstatistics/qossmartstatistics.asp"),
            self._menu_item("Fault Info Collection", "collectconfig", 3, url="html/ssmp/collect/collectInfo.asp"),
            self._menu_item("Remote Mirror", "remotepktmirror", 3, url="html/bbsp/remotepktmirror/remotepktmirror.asp"),
            self._menu_item("Home Network Speedtest", "testspeed", 3, url="html/ssmp/testspeed/testspeed.asp"),
            self._menu_item("Segment Speedtest", "sectionspeed", 3, url="html/ssmp/Sectionspeed/Sectionspeed.asp"),
            self._menu_item("Indicator Status Management", "indicator", 3, url="html/ssmp/ledcfg/ledcfg.asp"),
            self._menu_item("VoIP Statistics", "voipstatistic", 3, url="html/voip/statistic/voipstatistic.asp"),
            self._menu_item("VoIP Diagnosis", "voipdiagnosis", 3, url="html/voip/diagnose/voipdiagnose.asp"),
        ]
        advanced["subMenus"].append(maint_item)

        items.append(advanced)
        self._menu_cache = json.dumps(items)

    def _menu_item(self, name, menu_id, level, url="", deficon="", clickicon=""):
        item = {"name": name, "id": menu_id, "level": level, "url": url}
        if deficon:
            item["deficon"] = deficon
        if clickicon:
            item["clickicon"] = clickicon
        return item

    def request(self, flow):
        if flow.request.host != config.ONT_HOST:
            return
        flow.request.headers.pop("If-Modified-Since", None)
        flow.request.headers.pop("If-None-Match", None)
        flow.request.headers["Cache-Control"] = "no-cache"
        flow.request.headers["User-Agent"] = config.ONT_USER_AGENT
        flow.request.headers["Host"] = config.ONT_HOST
        if "Accept" not in flow.request.headers:
            flow.request.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        if "Referer" in flow.request.headers:
            flow.request.headers["Referer"] = re.sub(
                r"https?://[^/]+",
                f"http://{config.ONT_HOST}",
                flow.request.headers["Referer"],
            )
        if "Origin" in flow.request.headers:
            flow.request.headers["Origin"] = f"http://{config.ONT_HOST}"

    def response(self, flow):
        if flow.request.host != config.ONT_HOST:
            return

        url = flow.request.pretty_url
        content_type = flow.response.headers.get("Content-Type", "")
        modified = False
        details = []

        flow.response.headers.pop("X-Frame-Options", None)
        flow.response.headers.pop("Content-Security-Policy", None)
        flow.response.headers.pop("X-Content-Type-Options", None)
        flow.response.headers["Cache-Control"] = "no-cache, no-store"

        if self._is_user_type_endpoint(flow):
            flow.response.set_text(config.ADMIN_USER_TYPE)
            modified = True
            details.append("UserType->0")

        elif self._is_menu_endpoint(flow):
            if self._menu_cache:
                flow.response.set_text(self._menu_cache)
                flow.response.headers["Content-Type"] = "application/json"
                modified = True
                details.append("MenuArray->Admin")

        elif self._is_asp_or_html(content_type):
            text = flow.response.get_text()
            if text:
                new_text, mods = self._modify_asp_response(text, url)
                if mods:
                    flow.response.set_text(new_text)
                    modified = True
                    details.extend(mods)

        if modified:
            flow.response.headers.pop("Content-Length", None)
            flow.response.headers["X-ONT-Proxy"] = "modified"

        self._log(flow.request.method, url, flow.response.status_code, modified, "; ".join(details))

    def _is_user_type_endpoint(self, flow):
        return "getCurUserType.asp" in flow.request.path

    def _is_menu_endpoint(self, flow):
        return "getMenuArray.asp" in flow.request.path

    def _is_asp_or_html(self, content_type):
        return any(t in content_type.lower() for t in ["text/html", "text/asp", "application/x-asp", "text/plain"])

    def _modify_asp_response(self, text, url):
        mods = []

        if "<head" in text.lower():
            early_js = self._get_early_inject_js()
            text = re.sub(
                r"(<head[^>]*>)",
                r"\1" + early_js,
                text,
                count=1,
                flags=re.IGNORECASE,
            )
            mods.append("early_js_injected")

        new_text = re.sub(
            r"var\s+curUserType\s*=\s*'1'",
            "var curUserType = '0'",
            text,
        )
        if new_text != text:
            mods.append("curUserType->0")
            text = new_text

        new_text = re.sub(
            r"(<%HW_WEB_GetUserType\(\);%>)",
            "0",
            text,
        )
        if new_text != text:
            mods.append("HW_WEB_GetUserType->0")
            text = new_text

        new_text = re.sub(
            r"var\s+curUserType\s*=\s*'<%HW_WEB_GetUserType\(\);%>'",
            "var curUserType = '0'",
            text,
        )
        if new_text != text and "curUserType->0" not in mods:
            mods.append("curUserType_tpl->0")
            text = new_text

        new_text = re.sub(
            r"(curUserType\s*!=\s*sysUserType)",
            "false",
            text,
        )
        if new_text != text:
            mods.append("bypass_usertype_check")
            text = new_text

        new_text = re.sub(
            r"(curUserType\s*==\s*sysUserType)",
            "true",
            text,
        )
        if new_text != text:
            mods.append("force_admin_check")
            text = new_text

        new_text = re.sub(
            r"function\s+IsAdminUser\s*\(\s*\)\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}",
            "function IsAdminUser() { return true; }",
            text,
        )
        if new_text != text:
            mods.append("IsAdminUser->true")
            text = new_text

        new_text = re.sub(
            r"IsAdminUser\s*\(\s*\)\s*==\s*false",
            "false",
            text,
        )
        if new_text != text:
            mods.append("IsAdminUser_false->false")
            text = new_text

        new_text = re.sub(
            r"IsAdminUser\s*\(\s*\)\s*==\s*true",
            "true",
            text,
        )
        if new_text != text:
            mods.append("IsAdminUser_true->true")
            text = new_text

        new_text = re.sub(
            r"(curUserType\s*==\s*['\"]?)1(['\"]?)",
            r"\g<1>0\2",
            text,
        )
        if new_text != text:
            mods.append("curUserType_eq1->0")
            text = new_text

        new_text = re.sub(
            r"(curUserType\s*!=\s*['\"]?)0(['\"]?)",
            r"\g<1>__NEVER__\2",
            text,
        )
        if new_text != text:
            mods.append("curUserType_ne0->never")
            text = new_text

        feature_pattern = re.compile(
            r"var\s+(wlanFlag|tdeModeFlag|SonetFlag|RosFlag)\s*=\s*'0'"
        )
        new_text = feature_pattern.sub(
            lambda m: f"var {m.group(1)} = '1'",
            text,
        )
        if new_text != text:
            mods.append("feature_flags_enabled")
            text = new_text

        index_flags = re.compile(
            r"var\s+(IsModifiedPwd|pwdModifyFlag)\s*=\s*'0'"
        )
        new_text = index_flags.sub(
            lambda m: f"var {m.group(1)} = '1'",
            text,
        )
        if new_text != text:
            mods.append("pwd_modified_flag->1")
            text = new_text

        new_text = re.sub(
            r"var\s+ConfigFlag\s*=\s*'[^']*'",
            "var ConfigFlag = '1#1#1'",
            text,
        )
        if new_text != text:
            mods.append("ConfigFlag->1#1#1")
            text = new_text

        new_text = re.sub(
            r"var\s+supportPrivacyStatement\s*=\s*['\"]1['\"]",
            "var supportPrivacyStatement = '0'",
            text,
        )
        if new_text != text:
            mods.append("privacy_statement->0")
            text = new_text

        new_text = re.sub(
            r"var\s+normalUserType\s*=\s*'1'",
            "var normalUserType = '999'",
            text,
        )
        if new_text != text:
            mods.append("normalUserType->999")
            text = new_text

        new_text = re.sub(
            r"var\s+apghnfeature\s*=\s*'1'",
            "var apghnfeature = '0'",
            text,
        )
        if new_text != text:
            mods.append("apghnfeature->0")
            text = new_text

        wifi_sub = re.compile(
            r"var\s+IsSupportWifi\s*=\s*'0'"
        )
        new_text = wifi_sub.sub("var IsSupportWifi = '1'", text)
        if new_text != text:
            mods.append("IsSupportWifi->1")
            text = new_text

        new_text = re.sub(
            r'var\s+IsWebLoadConfigfile\s*=\s*["\']0["\']',
            'var IsWebLoadConfigfile = "1"',
            text,
        )
        if new_text != text:
            mods.append("IsWebLoadConfigfile->1")
            text = new_text

        new_text = re.sub(
            r'var\s+NormalUpdownCfg\s*=\s*["\']0["\']',
            'var NormalUpdownCfg = "1"',
            text,
        )
        if new_text != text:
            mods.append("NormalUpdownCfg->1")
            text = new_text

        new_text = re.sub(
            r'var\s+AutoUpdateEnable\s*=\s*["\']0["\']',
            'var AutoUpdateEnable = "1"',
            text,
        )
        if new_text != text:
            mods.append("AutoUpdateEnable->1")
            text = new_text

        new_text = re.sub(
            r"(UserLevel\s*==\s*)1",
            r"\g<1>0",
            text,
        )
        if new_text != text:
            mods.append("UserLevel->0")
            text = new_text

        new_text = re.sub(
            r'(\.UserLevel\s*=\s*")1(")',
            r'\g<1>0\2',
            text,
        )
        if new_text != text:
            mods.append("UserLevel_assign->0")
            text = new_text

        new_text = re.sub(
            r"(UserLevel\s*!=\s*)0",
            r"\g<1>__NEVER__",
            text,
        )
        if new_text != text:
            mods.append("UserLevel_ne0->never")
            text = new_text

        login_lock_pattern = re.compile(
            r"var\s+(FailStat|LoginTimes|LockLeftTime|ModeCheckTimes)\s*=\s*'[^']*'"
        )
        new_text = login_lock_pattern.sub(
            lambda m: f"var {m.group(1)} = '0'",
            text,
        )
        if new_text != text:
            mods.append("login_lock_bypass")
            text = new_text

        acl_fields = [
            "TelnetLanEnable", "TELNETLanEnable", "TelnetWanEnable", "TELNETWanEnable",
            "TelnetWifiEnable", "TELNETWifiEnable",
            "SSHLanEnable", "SSHWanEnable",
            "FtpLanEnable", "FTPLanEnable", "FtpWanEnable", "FTPWanEnable",
            "HttpLanEnable", "HTTPLanEnable", "HttpWanEnable", "HTTPWanEnable",
            "HttpWifiEnable", "HTTPWifiEnable",
            "HttpsLanEnable", "HTTPSLanEnable", "HttpsWanEnable", "HTTPSWanEnable",
        ]
        for field in acl_fields:
            pattern = re.compile(rf'((?:this\.)?{field}\s*=\s*["\']?)0(["\']?[;,\s)])')
            new_text = pattern.sub(r'\g<1>1\2', text)
            if new_text != text:
                mods.append(f"{field}->1")
                text = new_text

        new_text = re.sub(
            r'(<body[^>]*)\s+style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\']',
            r'\1',
            text,
            flags=re.IGNORECASE,
        )
        if new_text != text:
            mods.append("unhide_body")
            text = new_text

        new_text = re.sub(
            r'(<form[^>]*)\s+style\s*=\s*["\']display\s*:\s*none\s*;?\s*["\']',
            r'\1 style="display:block"',
            text,
            flags=re.IGNORECASE,
        )
        if new_text != text:
            mods.append("unhide_forms")
            text = new_text

        config_panels = [
            "ConfigForm", "ConfigPanel", "ListConfigPanel", "TableConfigInfo",
            "OntReset", "OntRestore", "tableautoupgrade", "localtext",
            "uploadConfig", "downloadConfig", "saveConfig", "SaveCfgInfo",
            "downloadApConfig", "ApDeviceListInfo", "downloadApConfigTable",
            "websslpage", "lan_table", "wan_table", "wifi_table", "DivMain",
            "DivWRR", "DivSP", "DivQueueManagement", "DivAuthentication",
            "wlaninfo", "itmsinfo", "divdiagnose", "diagnoseresult",
            "content", "pwdvalue1", "pwdvalue2", "pwdvalue5",
            "tPwdGponValue", "tHexPwdValue", "checkinfo1", "userpwdsafe",
        ]
        for panel_id in config_panels:
            pattern = re.compile(
                rf'(<(?:div|table|td|tr|form|fieldset)[^>]*\bid\s*=\s*["\']'
                + re.escape(panel_id) +
                r'["\'][^>]*)\s+style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\']',
                re.IGNORECASE,
            )
            new_text = pattern.sub(r'\1 style="display:block"', text)
            if new_text != text:
                mods.append(f"unhide_{panel_id}")
                text = new_text

        new_text = re.sub(
            r"setDisplay\s*\(\s*['\"][^'\"]+['\"]\s*,\s*0\s*\)",
            lambda m: m.group(0).replace(", 0)", ", 1)"),
            text,
        )
        if new_text != text:
            mods.append("setDisplay_all->1")
            text = new_text

        new_text = re.sub(
            r"setDisable\s*\(\s*['\"][^'\"]+['\"]\s*,\s*1\s*\)",
            lambda m: m.group(0).replace(", 1)", ", 0)"),
            text,
        )
        if new_text != text:
            mods.append("setDisable_all->0")
            text = new_text

        new_text = re.sub(
            r"TelnetOptionAvaliable\s*\(\s*\)\s*==\s*true",
            "true",
            text,
        )
        if new_text != text:
            mods.append("TelnetOption->true")
            text = new_text

        new_text = re.sub(
            r"TelnetOptionAvaliable\s*\(\s*\)\s*==\s*false",
            "false",
            text,
        )
        if new_text != text:
            mods.append("TelnetOption_false->false")
            text = new_text

        new_text = re.sub(
            r"function\s+TelnetOptionAvaliable\s*\(\s*\)\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}",
            "function TelnetOptionAvaliable() { return true; }",
            text,
        )
        if new_text != text:
            mods.append("TelnetOptionAvaliable->true")
            text = new_text

        new_text = re.sub(
            r"function\s+IsOSKNormalUser\s*\(\s*\)\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\}",
            "function IsOSKNormalUser() { return false; }",
            text,
        )
        if new_text != text:
            mods.append("IsOSKNormalUser->false")
            text = new_text

        new_text = re.sub(
            r"function\s+filterUserInfo\s*\([^)]*\)\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\}",
            "function filterUserInfo(userInfo) { return userInfo.Enable != 1; }",
            text,
        )
        if new_text != text:
            mods.append("filterUserInfo->all")
            text = new_text

        if "</body>" in text.lower():
            text = text.replace("</body>", self._get_inject_js() + "</body>")
            text = text.replace("</BODY>", self._get_inject_js() + "</BODY>")
            mods.append("js_injected")

        return text, mods

    def _get_early_inject_js(self):
        return """<script type="text/javascript">
(function(){
var _origDefineProperty=Object.defineProperty;
Object.defineProperty=function(obj,prop,desc){
if(prop==='curUserType'&&desc&&desc.value){desc.value='0';}
return _origDefineProperty.call(this,obj,prop,desc);
};
window.__ontProxyAdmin=true;
})();
</script>"""

    def _get_inject_js(self):
        return """<script type="text/javascript">
(function(){
try{
if(typeof window.curUserType!=='undefined'){window.curUserType='0';}
if(typeof window.sysUserType!=='undefined'){window.sysUserType='0';}
if(typeof window.jumptomodifypwd!=='undefined'){window.jumptomodifypwd=1;}
if(typeof window.PwdModifyFlag!=='undefined'){window.PwdModifyFlag=0;}
if(typeof window.IsModifiedPwd!=='undefined'){window.IsModifiedPwd='1';}
if(typeof window.pwdModifyFlag!=='undefined'){window.pwdModifyFlag='1';}
if(typeof window.ConfigFlag!=='undefined'&&window.ConfigFlag){window.ConfigFlag='1#1#1';}
if(typeof window.wlanFlag!=='undefined'){window.wlanFlag='1';}
if(typeof window.tdeModeFlag!=='undefined'){window.tdeModeFlag='1';}
if(typeof window.RosFlag!=='undefined'){window.RosFlag='1';}
if(typeof window.SonetFlag!=='undefined'){window.SonetFlag='1';}
if(typeof window.IsSupportWifi!=='undefined'){window.IsSupportWifi='1';}
if(typeof window.IsPTVDFFlag!=='undefined'){window.IsPTVDFFlag='0';}
if(typeof window.IsPTVDF!=='undefined'){window.IsPTVDF='0';}
if(typeof window.IsSmartDev!=='undefined'){window.IsSmartDev='0';}
if(typeof window.smartlanfeature!=='undefined'){window.smartlanfeature='0';}
if(typeof window.apcmodefeature!=='undefined'){window.apcmodefeature='0';}
if(typeof window.apghnfeature!=='undefined'){window.apghnfeature='0';}
if(typeof window.supportPrivacyStatement!=='undefined'){window.supportPrivacyStatement='0';}
if(typeof window.DirectGuideFlag!=='undefined'){window.DirectGuideFlag='1';}
if(typeof window.mngttype!=='undefined'){window.mngttype='0';}
if(typeof window.mngtpccwtype!=='undefined'){window.mngtpccwtype='0';}
if(typeof window.TedataGuide!=='undefined'){window.TedataGuide='0';}
if(typeof window.normalUserType!=='undefined'){window.normalUserType='999';}
if(typeof window.FailStat!=='undefined'){window.FailStat='0';}
if(typeof window.LoginTimes!=='undefined'){window.LoginTimes='0';}
if(typeof window.LockLeftTime!=='undefined'){window.LockLeftTime='0';}
if(typeof window.ModeCheckTimes!=='undefined'){window.ModeCheckTimes='0';}
window.IsAdminUser=function(){return true;};
window.TelnetOptionAvaliable=function(){return true;};
window.IsOSKNormalUser=function(){return false;};
window.IsE8cFrame=function(){return false;};
window.gotoGuidePage=function(){};
window.dbaa1AllowGotoGuidePage=function(){return false;};
window.hideClaroFastsetting=function(){return false;};
var _modalBlacklist=['modifyPwdBox','base_mask','pwd_modify','zhezhao',
'showcmode','showcmode1','DivErrPage','DivErrPage2',
'DivUpload','DivUploadMsg','DivInstalling','DivRestart',
'DivFail','DivSuccess','DivCfgUpload','DivCfgProgress'];
if(typeof window.setDisplay==='function'){
var _origSD=window.setDisplay;
window.setDisplay=function(id,sh){
if(sh===0||sh==='0'){
for(var i=0;i<_modalBlacklist.length;i++){
if(id===_modalBlacklist[i]){return _origSD(id,0);}
}
return _origSD(id,1);
}
return _origSD(id,sh);
};}
if(typeof window.setDisable==='function'){
var _origSDis=window.setDisable;
window.setDisable=function(id,flag){
if(flag===1||flag==='1'){return _origSDis(id,0);}
return _origSDis(id,flag);
};}
if(typeof window.setVisible==='function'){
var _origSV=window.setVisible;
window.setVisible=function(id,sh){
if(sh===0||sh==='0'||sh===false){
for(var i=0;i<_modalBlacklist.length;i++){
if(id===_modalBlacklist[i]){return _origSV(id,false);}
}
return _origSV(id,true);
}
return _origSV(id,sh);
};}
function unhideAll(){
var els=document.querySelectorAll('[style]');
for(var i=0;i<els.length;i++){
if(els[i].style.display==='none'){
var dominated=false;
for(var b=0;b<_modalBlacklist.length;b++){
if(els[i].id===_modalBlacklist[b]){dominated=true;break;}
}
if(!dominated){
var tag=els[i].tagName.toLowerCase();
if(tag==='form'||tag==='div'||tag==='tr'||tag==='td'||
tag==='table'||tag==='li'||tag==='fieldset'||tag==='section'||
tag==='span'||tag==='p'||tag==='input'||tag==='select'||
tag==='button'||tag==='textarea'){
els[i].style.display='';
}
}
}
if(els[i].style.visibility==='hidden'){
els[i].style.visibility='visible';
}
}
var disabled=document.querySelectorAll('[disabled]');
for(var j=0;j<disabled.length;j++){
var t=disabled[j].tagName.toLowerCase();
if(t==='input'||t==='select'||t==='button'||t==='textarea'){
disabled[j].disabled=false;
disabled[j].removeAttribute('disabled');
disabled[j].classList.remove('osgidisable');
disabled[j].classList.remove('Disable');
disabled[j].style.removeProperty('background-color');
}
}
var readOnly=document.querySelectorAll('[readonly]');
for(var r=0;r<readOnly.length;r++){
readOnly[r].removeAttribute('readonly');
}
var collapsed=document.querySelectorAll('.Menuhide,.collapsed,.hide');
for(var c=0;c<collapsed.length;c++){
collapsed[c].classList.remove('Menuhide');
collapsed[c].classList.remove('collapsed');
collapsed[c].classList.remove('hide');
}
var menuIframe=document.getElementById('menuIframe');
if(menuIframe&&(!menuIframe.src||menuIframe.src===''||menuIframe.src==='about:blank')){
if(typeof window.menuJsonData!=='undefined'&&window.menuJsonData&&window.menuJsonData.length>0){
var firstUrl='';
for(var k=0;k<window.menuJsonData.length;k++){
if(window.menuJsonData[k].submenu){
for(var l=0;l<window.menuJsonData[k].submenu.length;l++){
var sm=window.menuJsonData[k].submenu[l];
if(sm.url&&sm.url!==''){firstUrl=sm.url;break;}
if(sm.submenu){
for(var m=0;m<sm.submenu.length;m++){
if(sm.submenu[m].url){firstUrl=sm.submenu[m].url;break;}
}
if(firstUrl)break;
}
}
if(firstUrl)break;
}
}
if(firstUrl){menuIframe.src=firstUrl;}
else{menuIframe.src='CustomApp/mainpage.asp';}
}else{menuIframe.src='CustomApp/mainpage.asp';}
}
}
if(document.readyState==='loading'){
document.addEventListener('DOMContentLoaded',function(){setTimeout(unhideAll,100);});
}else{
setTimeout(unhideAll,100);
}
setTimeout(unhideAll,500);
setTimeout(unhideAll,1500);
setTimeout(unhideAll,3000);
setTimeout(unhideAll,6000);
var _observer=new MutationObserver(function(mutations){
for(var i=0;i<mutations.length;i++){
var m=mutations[i];
if(m.type==='attributes'){
var el=m.target;
var dominated=false;
for(var b=0;b<_modalBlacklist.length;b++){
if(el.id===_modalBlacklist[b]){dominated=true;break;}
}
if(!dominated){
if(m.attributeName==='style'&&el.style.display==='none'){
el.style.display='';
}
if(m.attributeName==='disabled'&&el.disabled){
el.disabled=false;
el.removeAttribute('disabled');
}
}
}
}
});
_observer.observe(document.documentElement,{
attributes:true,attributeFilter:['style','disabled','class'],
subtree:true
});
}catch(e){}
})();
</script>"""


addons = [ONTResponseModifier()]
