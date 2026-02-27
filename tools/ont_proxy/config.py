#!/usr/bin/env python3
import os

ONT_HOST = os.environ.get("ONT_HOST", "192.168.100.1")
ONT_PORT = int(os.environ.get("ONT_PORT", "80"))
PROXY_LISTEN_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PROXY_LISTEN_PORT = int(os.environ.get("PROXY_PORT", "8080"))

ISP_NAME = "Megacable"
MENU_XML = "MenuMegacablePwd.xml"

CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
CA_KEY_FILE = os.path.join(CERT_DIR, "ont_proxy_ca.key")
CA_CERT_FILE = os.path.join(CERT_DIR, "ont_proxy_ca.crt")
CA_CERT_NAME = "ONT Proxy CA"
CA_VALIDITY_DAYS = 3650

CHROME_PROFILE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "chrome_profile"
)

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "traffic.log")

ADMIN_USER_TYPE = "0"
NORMAL_USER_TYPE = "1"

ADMIN_ONLY_MENU_ITEMS = [
    {
        "MenuLevel": "2",
        "MenuName": "WAN",
        "MenuID": "wanconfig",
        "featurectrl": "BBSP_FT_WAN",
        "url": "html/bbsp/wan/wan.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Layer 2/3 Port",
        "MenuID": "lanportconfig",
        "featurectrl": "BBSP_FT_L3",
        "url": "html/bbsp/layer3/layer3.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "LAN-PON Link Binding",
        "MenuID": "lanponbind",
        "featurectrl": "HW_AMP_FEATURE_ETHPON_BIND",
        "url": "html/amp/ethponbind/ethponbind.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "DHCP Static IP",
        "MenuID": "landhcpstatic",
        "featurectrl": "BBSP_FT_DHCP_MAIN",
        "url": "html/bbsp/dhcpstatic/dhcpstatic.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "DHCPv6 Static IP",
        "MenuID": "landhcpv6static",
        "featurectrl": "BBSP_FT_IPV6_DHCP6S",
        "url": "html/bbsp/dhcpstaticaddr/dhcpstaticaddress.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Port Locating",
        "MenuID": "option82",
        "featurectrl": "BBSP_FT_DHCP_OPTION82",
        "url": "html/bbsp/dhcp/option82.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Firewall Level",
        "MenuID": "ipv4firewalllevel",
        "featurectrl": "BBSP_FT_FIREWALL|BBSP_FT_FIREWALL_COMMONV5",
        "url": "html/bbsp/firewalllevel/firewalllevel.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "DoS Configuration",
        "MenuID": "dos",
        "featurectrl": "BBSP_FT_DOS_COMMONV5|BBSP_FT_WAN",
        "url": "html/bbsp/Dos/Dos.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Device Access Control",
        "MenuID": "ontaccess",
        "featurectrl": "BBSP_FT_ACCESS_CONTROL",
        "url": "html/bbsp/acl/aclsmart.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "WAN Access Control",
        "MenuID": "wanacl",
        "featurectrl": "BBSP_FT_WAN_COMMONV5",
        "url": "html/bbsp/wanacl/wanacl.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Internet Access Control",
        "MenuID": "internetcontrol",
        "featurectrl": "BBSP_FT_EBG_INTERNETCONTROL",
        "url": "html/bbsp/internetcontrol/internetcontrol.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "802.1X Global Configuration",
        "MenuID": "globalcontrol",
        "featurectrl": "HW_BBSP_FEATURE_8021X",
        "url": "html/bbsp/8021x/8021x_global.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "802.1X Port Configuration",
        "MenuID": "portcontrol",
        "featurectrl": "HW_BBSP_FEATURE_8021X",
        "url": "html/bbsp/8021x/8021x_port.asp",
    },
]

ADMIN_ONLY_ROUTES = [
    {
        "MenuLevel": "3",
        "MenuName": "Default IPv4 Route",
        "MenuID": "ipv4defaultroute",
        "featurectrl": "BBSP_FT_ROUTE",
        "url": "html/bbsp/route/route.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "IPv4 Static Route",
        "MenuID": "ipv4staticroute",
        "featurectrl": "BBSP_FT_ROUTE_STATIC",
        "url": "html/bbsp/staticroute/staticroute.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "IPv4 VLAN Binding",
        "MenuID": "ipv4vlanbind",
        "featurectrl": "BBSP_FT_ROUTE_POLICY",
        "url": "html/bbsp/vlanctc/vlanctc.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "IPv4 Service Route",
        "MenuID": "ipv4serviceroute",
        "featurectrl": "BBSP_FT_ROUTE_POLICY",
        "url": "html/bbsp/serviceroute/serviceroute.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "IPv4 Routing Table",
        "MenuID": "ipv4routeinfo",
        "featurectrl": "BBSP_FT_ROUTE",
        "url": "html/bbsp/routeinfo/routeinfo.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Default IPv6 Route",
        "MenuID": "ipv6defaultroute",
        "featurectrl": "BBSP_FT_IPV6_ROUTE",
        "url": "html/bbsp/ipv6defaultroute/defaultroute.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "IPv6 Static Route",
        "MenuID": "ipv6staticroute",
        "featurectrl": "BBSP_FT_IPV6_ROUTE",
        "url": "html/bbsp/ipv6staticroute/ipv6staticroute.asp",
    },
]

ADMIN_ONLY_FORWARD_RULES = [
    {
        "MenuLevel": "3",
        "MenuName": "DMZ Function",
        "MenuID": "dmz",
        "featurectrl": "BBSP_FT_DMZ_IP",
        "url": "html/bbsp/dmz/dmz.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "IPv4 Port Mapping",
        "MenuID": "portmapping",
        "featurectrl": "BBSP_FT_PORTMAP_IP",
        "url": "html/bbsp/portmapping/portmapping.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Port Trigger",
        "MenuID": "porttrigger",
        "featurectrl": "BBSP_FT_PORTTRIGGER_IP",
        "url": "html/bbsp/porttrigger/porttrigger.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "IPv6 Port Mapping",
        "MenuID": "ipv6portmapping",
        "featurectrl": "BBSP_FT_IPV6_PORTMAPPING",
        "url": "html/bbsp/ipv6portmapping/ipv6portmapping.asp",
    },
]

ADMIN_ONLY_APPS = [
    {
        "MenuLevel": "3",
        "MenuName": "Time Setting",
        "MenuID": "sntpmngt",
        "featurectrl": "BBSP_FT_SNTP",
        "url": "html/ssmp/sntp/sntp.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "ALG",
        "MenuID": "alg",
        "featurectrl": "BBSP_FT_ALG",
        "url": "html/bbsp/alg/alg.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "IGMP",
        "MenuID": "igmp",
        "featurectrl": "BBSP_FT_MULTICAST_WANPROXY",
        "url": "html/bbsp/igmp/igmp.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Intelligent Channel",
        "MenuID": "qossmart",
        "featurectrl": "BBSP_FT_QOS_CFG",
        "url": "html/bbsp/qossmart/qossmart.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Video Device Identification",
        "MenuID": "video",
        "featurectrl": "BBSP_FT_VIDEO_CFG",
        "url": "html/bbsp/video/video.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "ARP Ping",
        "MenuID": "arp",
        "featurectrl": "BBSP_FT_ARP_COMMONV5|BBSP_FT_WAN",
        "url": "html/bbsp/arpping/arpping.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Static DNS",
        "MenuID": "dnsconfiguration",
        "featurectrl": "BBSP_FT_L3_ALL",
        "url": "html/bbsp/dnsconfiguration/dnsconfigcommon.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Device Type Identification",
        "MenuID": "deviceidfy",
        "featurectrl": "FT_UNI_DEVICE_DETETION",
        "url": "html/bbsp/deviceidentify/deviceidentification.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "LLDP",
        "MenuID": "lldp",
        "featurectrl": "HW_BBSP_FT_LLDP",
        "url": "html/bbsp/lldp/lldp.asp",
    },
]

ADMIN_ONLY_SYSTEM = [
    {
        "MenuLevel": "3",
        "MenuName": "TR-069",
        "MenuID": "tr069config",
        "featurectrl": "HW_SSMP_FEATURE_TR069",
        "url": "html/ssmp/tr069/tr069.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "ONT Authentication",
        "MenuID": "passwordcommon",
        "featurectrl": "HW_AMP_FEATURE_OPTIC",
        "url": "html/amp/ontauth/passwordcommon.asp",
    },
]

ADMIN_ONLY_MAINTENANCE = [
    {
        "MenuLevel": "3",
        "MenuName": "Software Upgrade",
        "MenuID": "fireware",
        "url": "html/ssmp/fireware/firmware.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Configuration File Management",
        "MenuID": "cfgconfig",
        "url": "html/ssmp/cfgfile/cfgfile.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Upstream Port",
        "MenuID": "upportconfig",
        "featurectrl": "FT_PON_UPPORT_CONFIG",
        "url": "html/ssmp/mainupportcfg/mainupportconfig.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "User Log",
        "MenuID": "userlog",
        "url": "html/ssmp/userlog/logview.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Firewall Log",
        "MenuID": "firewalllog",
        "featurectrl": "BBSP_FT_FIREWALL_FLOW_LOG",
        "url": "html/bbsp/firewalllog/firewalllogview.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Debug Log",
        "MenuID": "debuglog",
        "url": "html/ssmp/debuglog/debuglogview.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Intelligent Channel Statistics",
        "MenuID": "qossmartstatistics",
        "featurectrl": "BBSP_FT_QOS_CFG",
        "url": "html/bbsp/qossmartstatistics/qossmartstatistics.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Fault Info Collection",
        "MenuID": "collectconfig",
        "url": "html/ssmp/collect/collectInfo.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Remote Mirror",
        "MenuID": "remotepktmirror",
        "featurectrl": "BBSP_FT_WAN",
        "url": "html/bbsp/remotepktmirror/remotepktmirror.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Home Network Speedtest",
        "MenuID": "testspeed",
        "featurectrl": "FT_WEB_SPEED_DIAG&!BBSP_FT_IS_BIN5",
        "url": "html/ssmp/testspeed/testspeed.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "Segment Speedtest",
        "MenuID": "sectionspeed",
        "featurectrl": "FT_IPERF_TEST&!BBSP_FT_IS_BIN5",
        "url": "html/ssmp/Sectionspeed/Sectionspeed.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "VoIP Statistics",
        "MenuID": "voipstatistic",
        "featurectrl": "HW_VSPA_FEATURE_VOIP",
        "url": "html/voip/statistic/voipstatistic.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "VoIP Diagnosis",
        "MenuID": "voipdiagnosis",
        "featurectrl": "HW_VSPA_FEATURE_VOIP",
        "url": "html/voip/diagnose/voipdiagnose.asp",
    },
]

ADMIN_ONLY_VOIP = [
    {
        "MenuLevel": "3",
        "MenuName": "VoIP Basic",
        "MenuID": "voipinterface",
        "featurectrl": "HW_VSPA_FEATURE_VOIP",
        "url": "html/voip/voipinterface/voipinterface.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "VoIP Advanced",
        "MenuID": "voipuser",
        "featurectrl": "HW_VSPA_FEATURE_VOIP",
        "url": "html/voip/voipuser/voipuser.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "SIP/H.248 Conversion",
        "MenuID": "changeprotocol",
        "featurectrl": "HW_VSPA_FEATURE_VOIP",
        "url": "html/voip/changeprotocol/voipchangeprotocol.asp",
    },
]
