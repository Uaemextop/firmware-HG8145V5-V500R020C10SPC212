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
import json
import datetime

from . import config


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
            self._menu_item("Cloud Platform Status", "osgiplugin", 2, url="html/ssmp/osgiplugin/pluginstatusabroad.asp"),
            self._menu_item("PoE", "poeinfo", 2, url="html/amp/poeinfo/poeStats.asp"),
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
            self._menu_item("LAN-PON Link Binding", "lanponbind", 3, url="html/amp/ethponbind/ethponbind.asp"),
            self._menu_item("DHCP Server", "landhcp", 3, url="html/bbsp/dhcpservercfg/dhcp2.asp"),
            self._menu_item("DHCP Static IP", "landhcpstatic", 3, url="html/bbsp/dhcpstatic/dhcpstatic.asp"),
            self._menu_item("DHCPv6 Server", "landhcpv6", 3, url="html/bbsp/lanaddress/lanaddress.asp"),
            self._menu_item("DHCPv6 Static IP", "landhcpv6static", 3, url="html/bbsp/dhcpstaticaddr/dhcpstaticaddress.asp"),
            self._menu_item("DHCPv6 Information", "landhcpv6info", 3, url="html/bbsp/dhcpv6info/dhcpv6info.asp"),
            self._menu_item("Port Locating", "option82", 3, url="html/bbsp/dhcp/option82.asp"),
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
            self._menu_item("Precise Device Access Control", "portacl", 3, url="html/bbsp/portacl/newacl.asp"),
            self._menu_item("Device Access Control", "ontaccess", 3, url="html/bbsp/acl/aclsmart.asp"),
            self._menu_item("WAN Access Control", "wanacl", 3, url="html/bbsp/wanacl/wanacl.asp"),
            self._menu_item("IPv6 Filtering", "ipv6ipincoming", 3, url="html/bbsp/ipv6ipincoming/ipv6ipincoming.asp"),
            self._menu_item("Internet Access Control", "internetcontrol", 3, url="html/bbsp/internetcontrol/internetcontrol.asp"),
            self._menu_item("802.1X Global Configuration", "globalcontrol", 3, url="html/bbsp/8021x/8021x_global.asp"),
            self._menu_item("802.1X Port Configuration", "portcontrol", 3, url="html/bbsp/8021x/8021x_port.asp"),
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
            self._menu_item("IPv6 Port Mapping", "ipv6portmapping", 3, url="html/bbsp/ipv6portmapping/ipv6portmapping.asp"),
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
            self._menu_item("Video Device Identification", "video", 3, url="html/bbsp/video/video.asp"),
            self._menu_item("ARP Ping", "arp", 3, url="html/bbsp/arpping/arpping.asp"),
            self._menu_item("Static DNS", "dnsconfiguration", 3, url="html/bbsp/dnsconfiguration/dnsconfigcommon.asp"),
            self._menu_item("Device Type Identification", "deviceidfy", 3, url="html/bbsp/deviceidentify/deviceidentification.asp"),
            self._menu_item("DSCP-to-Pbit Mapping", "DSCPMapping", 3, url="html/bbsp/dscptopbit/dscptopbit.asp"),
            self._menu_item("LAN Port Multi-service", "lanservicecfg", 3, url="html/bbsp/lanservicecfg/lanservicecfg.asp"),
            self._menu_item("LLDP", "lldp", 3, url="html/bbsp/lldp/lldp.asp"),
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
            self._menu_item("Upstream Port", "upportconfig", 3, url="html/ssmp/mainupportcfg/mainupportconfig.asp"),
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

        poe_item = self._menu_item("PoE Configuration", "poecfg", 2, url="html/amp/poecfg/poecfg.asp")
        advanced["subMenus"].append(poe_item)

        powercube_item = self._menu_item("PowerCube", "powercube", 2)
        powercube_item["subMenus"] = [
            self._menu_item("PowerCube Basic Information", "energybaseinfo", 3, url="html/ssmp/energybaseinfo/energybaseinfo.asp"),
            self._menu_item("PowerCube Battery Information", "energybasebatteryinfo", 3, url="html/ssmp/energybasebatteryinfo/energybasebatteryinfo.asp"),
            self._menu_item("PowerCube Alarms", "energybasewarning", 3, url="html/ssmp/energybasewarning/energybasewarning.asp"),
            self._menu_item("PowerCube Configuration", "energybasecfg", 3, url="html/ssmp/energybasecfg/energybasecfg.asp"),
        ]
        advanced["subMenus"].append(powercube_item)

        bundle_item = self._menu_item("Bundle", "bundleconfig", 2)
        bundle_item["subMenus"] = [
            self._menu_item("Bundle Load", "bundle", 3, url="html/ssmp/smartontinfo/bundle.asp"),
            self._menu_item("Bundle", "bundleinfo", 3, url="html/ssmp/smartontinfo/bundleinfo.asp"),
            self._menu_item("Bundle Information", "bundlestatus", 3, url="html/ssmp/smartontinfo/bundlestatus.asp"),
            self._menu_item("JVM Resource Monitoring", "jvmtatus", 3, url="html/ssmp/smartontinfo/JVMResourceMonitoring.asp"),
        ]
        advanced["subMenus"].append(bundle_item)

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
        pass

    def response(self, flow):
        if flow.request.host != config.ONT_HOST:
            return

        url = flow.request.pretty_url
        content_type = flow.response.headers.get("Content-Type", "")
        modified = False
        details = []

        if self._is_user_type_endpoint(flow):
            original = flow.response.get_text()
            if original and original.strip() == config.NORMAL_USER_TYPE:
                flow.response.set_text(config.ADMIN_USER_TYPE)
                modified = True
                details.append("UserType 1->0")

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

        feature_pattern = re.compile(
            r"var\s+(wlanFlag|tdeModeFlag|SonetFlag|IsSmartDev|IsPTVDF|IsSmartLanDev|RosFlag)\s*=\s*'0'"
        )
        new_text = feature_pattern.sub(
            lambda m: f"var {m.group(1)} = '1'",
            text,
        )
        if new_text != text:
            mods.append("feature_flags_enabled")
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

        if "acl" in url.lower() or "access" in url.lower():
            for field in ["TelnetLanEnable", "TelnetWanEnable", "TelnetWifiEnable",
                          "SSHLanEnable", "SSHWanEnable",
                          "FtpLanEnable", "FtpWanEnable",
                          "HttpsLanEnable", "HttpsWanEnable"]:
                pattern = re.compile(rf'({field}\s*=\s*")0(")')
                new_text = pattern.sub(r'\g<1>1\2', text)
                if new_text != text:
                    mods.append(f"{field}->1")
                    text = new_text

        new_text = re.sub(
            r"(style\s*=\s*[\"'])([^\"']*display\s*:\s*none[^\"']*?)([\"'])",
            lambda m: m.group(1) + m.group(2).replace("display:none", "display:block").replace("display: none", "display: block") + m.group(3)
            if "admin" in url.lower() or "acl" in url.lower() or "debug" in url.lower()
            else m.group(0),
            text,
        )
        if new_text != text:
            mods.append("unhide_elements")
            text = new_text

        return text, mods


addons = [ONTResponseModifier()]
