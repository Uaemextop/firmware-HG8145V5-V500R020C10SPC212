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

ONT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

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
        "MenuName": "Full Access Control",
        "MenuID": "fullaclconfig",
        "url": "html/bbsp/acl/acl.asp",
    },
    {
        "MenuLevel": "3",
        "MenuName": "WAN Access Control",
        "MenuID": "wanacl",
        "featurectrl": "BBSP_FT_WAN_COMMONV5",
        "url": "html/bbsp/wanacl/wanacl.asp",
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

KNOWN_CREDENTIALS = [
    {
        "user": "root",
        "password": "<encrypted in hw_ctree.xml>",
        "level": "shell",
        "source": "configs/passwd (root:*:0:0 nologin, CLI via CLIUserInfo.1)",
        "notes": "root account disabled for login (nologin shell). "
                 "CLI root password in hw_ctree.xml: "
                 "InternetGatewayDevice.UserInterface.X_HW_CLIUserInfo.1.Userpassword (encrypted)",
    },
    {
        "user": "admin",
        "password": "<per-device from hw_ctree.xml>",
        "level": "UserLevel=1 (normal web user)",
        "source": "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.X_HW_WebUserInfoInstance.1",
        "notes": "Standard web user. "
                 "Megacable sets password via recover_megacable_pwd.sh from customize file. "
                 "HW_WEB_GetWebUserNamePwd reads from DB. "
                 "Password stored AES-encrypted in hw_ctree.xml",
    },
    {
        "user": "telecomadmin",
        "password": "<ISP-configured, not in this firmware>",
        "level": "UserLevel=0 (admin, full access)",
        "source": "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.X_HW_WebUserInfoInstance.2",
        "notes": "ISP admin account. UserLevel=0 grants full menu access. "
                 "Megacable firmware does NOT include this account by default. "
                 "Can be provisioned via TR-069 or cfgtool",
    },
    {
        "user": "<WebUserInfo.3>",
        "password": "<per-ISP>",
        "level": "UserLevel varies",
        "source": "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.X_HW_WebUserInfoInstance.3",
        "notes": "Third web user slot. Used by some ISPs for diagnostics or guest",
    },
    {
        "user": "<WebUserInfo.4>",
        "password": "<per-ISP>",
        "level": "UserLevel varies",
        "source": "InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.X_HW_WebUserInfoInstance.4",
        "notes": "Fourth web user slot. Rarely used",
    },
]

KNOWN_CLI_USERS = [
    {
        "instance": "CLIUserInfo.1",
        "path": "InternetGatewayDevice.UserInterface.X_HW_CLIUserInfo.1.Userpassword",
        "notes": "Primary CLI/Telnet user (admin level). Password encrypted in hw_ctree.xml",
    },
    {
        "instance": "CLIUserInfo.2",
        "path": "InternetGatewayDevice.UserInterface.X_HW_CLIUserInfo.2.Userpassword",
        "notes": "Secondary CLI/Telnet user (root level). Password encrypted in hw_ctree.xml",
    },
]

HARDCODED_SERVICE_CREDENTIALS = [
    {
        "service": "Samba/SMB file sharing",
        "user": "huawei",
        "password": "hw-123-1",
        "source": "lib/libhw_usb_mngt.so:0x1f912 (hw_samba_mngt.c)",
        "notes": "Hardcoded Samba default user. Created via "
                 "'adduser -DH -h <path> -g tr140_user -s /bin/false -G samba'. "
                 "Password set via 'smbpasswd -a huawei hw-123-1'. "
                 "Used for USB storage network sharing. "
                 "Additional share names: hw-123 (base), hw-123-2 (NTFS), hw-123-3 (FAT)",
    },
    {
        "service": "Samba/SMB guest",
        "user": "root (guest account)",
        "password": "<none - guest access>",
        "source": "configs/samba/smb.conf: guest account = root",
        "notes": "Samba configured with 'guest account = root' and 'security = user'. "
                 "Unauthenticated SMB connections map to root context. "
                 "Printer share at /var/spool/cups is browseable with guest ok = Yes",
    },
    {
        "service": "Samba/SMB access levels",
        "user": "admin / support / anonymous",
        "password": "<from hw_ctree.xml>",
        "source": "lib/libhw_usb_mngt.so:0x20c33 (ustorage_cfg_networkserver.c)",
        "notes": "USB storage network server recognizes these user types: "
                 "admin, support, anonymous, web, upnp, cwmp, telnetd, console, dhcps, osgi, cli. "
                 "Each maps to different permission levels for USB file access",
    },
    {
        "service": "FTP (bftpd)",
        "user": "<system users>",
        "password": "<from /etc/passwd>",
        "source": "etc/bftpd.conf: DENY_LOGIN=no, ADMIN_PASS=x",
        "notes": "FTP server (bftpd) with DENY_LOGIN=no allows system user login. "
                 "ADMIN_PASS=x means admin commands disabled. "
                 "Passive ports: 12000-12100. "
                 "Controlled by AclServices.FTPLanEnable / FTPWanEnable",
    },
    {
        "service": "CWMP bootstrap",
        "user": "<device serial>",
        "password": "123456",
        "source": "lib/libhw_smp_cwmp_core.so:0xa836f",
        "notes": "TR-069 bootstrap connection request password. "
                 "Used as fallback when no SPEC_PROD_REQUEST_PASSWORD configured. "
                 "Active until ISP provisions real credentials via first CWMP session",
    },
    {
        "service": "WiFi HAL",
        "user": "root:root",
        "password": "N/A (chown command)",
        "source": "lib/libhw_wifi_hal.so:0x55725",
        "notes": "Not a login credential. Context: 'chown root:root /var/ctcwifi'. "
                 "WiFi HAL creates /var/ctcwifi directory owned by root",
    },
]

HIDDEN_RUNTIME_FILES = {
    "/var/sftppassword": {
        "service": "SFTP",
        "source": "bin/dropbear, lib/libhw_sftp_service.so",
        "notes": "Runtime SFTP password file. Created when SFTP service starts",
    },
    "/var/ghnftpdpassword": {
        "service": "FTP (ghnbftpd)",
        "source": "lib/libhw_dm_pdt_ap.so",
        "notes": "Internal FTP daemon password file",
    },
    "/var/passwordsetflag": {
        "service": "Web UI",
        "source": "bin/web",
        "notes": "Flag indicating initial password has been set",
    },
    "/var/web_skipsetpwd_flag": {
        "service": "Web UI",
        "source": "bin/web, lib/libhw_web_dll.so",
        "notes": "Flag to skip password setup wizard",
    },
    "/mnt/jffs2/hw_ctree.xml": {
        "service": "Main config",
        "source": "AES-256-CBC encrypted",
        "notes": "All user credentials stored here. "
                 "Decrypt with: aescrypt2 1 hw_ctree.xml out.xml && gunzip out.xml.gz",
    },
    "/mnt/jffs2/hw_default_ctree.xml": {
        "service": "Factory defaults",
        "source": "AES-256-CBC encrypted",
        "notes": "Factory default config with default passwords",
    },
    "/mnt/jffs2/chgpwd_file": {
        "service": "Password change flag",
        "source": "recover scripts",
        "notes": "Presence indicates password has been changed from factory default",
    },
    "/mnt/jffs2/webroot.crt": {
        "service": "Web SSL cert",
        "source": "lib/libhw_web_dll.so",
        "notes": "Web server root certificate. Can be decrypted: "
                 "'aescrypt2 0 /mnt/jffs2/webroot.crt /var/cert.aes'",
    },
    "/mnt/jffs2/data/weakpwdlist.cfg": {
        "service": "Weak password list",
        "source": "bin/web",
        "notes": "List of weak/banned passwords checked during password change",
    },
}

NETWORK_CONFIG = {
    "lan_interface": {
        "interface": "br0",
        "default_ip": "192.168.100.1",
        "subnet_mask": "255.255.255.0",
        "dhcp_range": "192.168.100.2 - 192.168.100.254",
        "gateway": "192.168.100.1",
        "source": "lib/libl3_base.so (busybox ifconfig br0), hw_ctree.xml",
        "notes": "Primary LAN bridge. All LAN ports (ETH1-4) and WiFi bridged here. "
                 "Client laptop gets IP via DHCP from this range",
    },
    "client_requirements": {
        "ip_range": "192.168.100.2 - 192.168.100.254",
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.100.1",
        "dns": "192.168.100.1",
        "notes": "Laptop MUST be in 192.168.100.0/24 subnet to access ONT web UI. "
                 "DHCP auto-assigns correct values. "
                 "Static: IP=192.168.100.x, Mask=255.255.255.0, GW=192.168.100.1",
    },
    "ssh_interface": {
        "interface": "sshif",
        "ip": "192.168.2.2",
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.2.1",
        "source": "lib/libl3_base.so:0x2942d2",
        "notes": "Dedicated SSH interface. Separate subnet from LAN. "
                 "To access: configure laptop with 192.168.2.x/24 and connect directly. "
                 "SSH must be enabled: AclServices.SSHLanEnable=1",
    },
    "smartont_interface": {
        "ip": "192.168.168.168",
        "alternate_ip": "192.168.100.100",
        "source": "lib/libsmartont_bbsp.so, lib/libl3_ext.so",
        "notes": "SmartONT management subsystem. "
                 "192.168.168.168 is alternate management IP. "
                 "192.168.100.100 is default client IP for traffic monitor",
    },
    "fallback_gateway": {
        "ip": "192.168.1.1",
        "source": "lib/libhw_smp_web_base.so:0x27e3e, bin/web, lib/libl2_ext.so",
        "notes": "Hardcoded fallback gateway IP. Used when br0 has no address. "
                 "libl2_ext.so contains 'http://192.168.1.1/upgrade.cgi' for OTA upgrades",
    },
    "link_local": {
        "ip_range": "169.254.0.1 - 169.254.0.254",
        "source": "lib/libl3_ext.so:0x279d82",
        "notes": "Link-local fallback range used when DHCP fails completely",
    },
    "multicast": {
        "upnp_ssdp": "239.255.255.250:1900",
        "igmp_multicast": "239.0.0.0/8",
        "mdns": "224.0.0.251:5353",
        "source": "lib/libl3_ext.so, lib/libupnp.so, lib/libl3_tr181.so",
        "notes": "Multicast routes auto-added: "
                 "'route add -net 239.0.0.0 netmask 255.0.0.0 br0'",
    },
}

TR069_CREDENTIAL_SPECS = [
    {
        "spec": "SPEC_PROD_USERNAME",
        "path": "InternetGatewayDevice.ManagementServer.Username",
        "notes": "Production TR-069 ACS username (empty in base spec, set per-ISP)",
    },
    {
        "spec": "SPEC_PROD_PASSWORD",
        "path": "InternetGatewayDevice.ManagementServer.Password",
        "notes": "Production TR-069 ACS password (empty in base spec, set per-ISP)",
    },
    {
        "spec": "SPEC_PROD_REQUEST_USERNAME",
        "path": "InternetGatewayDevice.ManagementServer.ConnectionRequestUsername",
        "notes": "TR-069 connection request auth username",
    },
    {
        "spec": "SPEC_PROD_REQUEST_PASSWORD",
        "path": "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword",
        "notes": "TR-069 connection request auth password",
    },
    {
        "spec": "SPEC_STAG_USERNAME",
        "notes": "Staging environment TR-069 username",
    },
    {
        "spec": "SPEC_STAG_PASSWORD",
        "notes": "Staging environment TR-069 password",
    },
]

HIDDEN_DEFAULT_PASSWORDS = {
    "cwmp_bootstrap": {
        "value": "123456",
        "source": "lib/libhw_smp_cwmp_core.so:0xa836f",
        "context": "Used as fallback/bootstrap TR-069 connection request password "
                   "when no SPEC_PROD_REQUEST_PASSWORD is configured",
    },
    "ploam_password": {
        "cli_cmd": "display ploam-password",
        "path": "InternetGatewayDevice.X_HW_Ploam.Value",
        "notes": "GPON PLOAM authentication password. "
                 "Readable via CLI: 'display ploam-password'. "
                 "Can be set via: 'set sninfo password <pwd>'",
    },
    "pon_password": {
        "path": "InternetGatewayDevice.X_HW_PonPassword",
        "cli_cmd": "display password",
        "notes": "PON authentication password. Stored in hw_ctree.xml. "
                 "Some ISPs derive from MAC address (see recover_aissingle.sh)",
    },
    "sftp_password": {
        "file": "/var/sftppassword",
        "source": "bin/dropbear, lib/libhw_sftp_service.so",
        "notes": "SFTP service password stored in /var/sftppassword at runtime",
    },
    "ftp_password": {
        "file": "/var/ghnftpdpassword",
        "source": "lib/libhw_dm_pdt_ap.so",
        "notes": "Internal FTP service password stored in /var/ghnftpdpassword",
    },
}

HIDDEN_NETWORK_IPS = {
    "ont_management": {
        "ip": "192.168.100.1",
        "port": 80,
        "service": "HTTP Web UI",
        "source": "configs/spec/ssmp/base_ssmp_spec.cfg (SSMP_SPEC_WEB_PORTNUM=80)",
        "notes": "Default ONT management IP. "
                 "Web server binds to br0 interface. "
                 "HW_WEB_CheckUserAgent validates User-Agent before serving pages",
    },
    "lan_gateway_fallback": {
        "ip": "192.168.1.1",
        "port": 80,
        "service": "Fallback gateway",
        "source": "lib/libhw_smp_web_base.so:0x27e3e, bin/web, lib/libl2_ext.so",
        "notes": "Hardcoded fallback gateway IP in multiple binaries. "
                 "libl2_ext.so has 'http://192.168.1.1/upgrade.cgi'. "
                 "Used as g_acCTBr0IP when br0 has no 192.168.100.x",
    },
    "ssh_interface": {
        "ip": "192.168.2.2",
        "port": 22,
        "service": "SSH (Dropbear)",
        "source": "lib/libl3_base.so (busybox ifconfig sshif 192.168.2.2)",
        "notes": "Dedicated SSH interface 'sshif' with subnet 192.168.2.0/24. "
                 "Gateway at 192.168.2.1. "
                 "Only accessible if SSH is enabled via X_HW_Security.AclServices.SSHLanEnable=1",
    },
    "smartont_client": {
        "ip": "192.168.100.100",
        "service": "SmartONT traffic monitor default client",
        "source": "lib/libsmartont_bbsp.so:0x4909c",
        "notes": "Default client IP used by SmartONT traffic monitoring subsystem",
    },
    "smartont_alternate": {
        "ip": "192.168.168.168",
        "service": "SmartONT alternate",
        "source": "lib/libsmartont_bbsp.so, lib/libl3_ext.so",
        "notes": "Alternate SmartONT management IP",
    },
    "link_local_range": {
        "ip": "169.254.0.1 - 169.254.0.254",
        "service": "Link-local fallback",
        "source": "lib/libl3_ext.so",
        "notes": "Link-local IP range used when DHCP fails",
    },
    "loopback_cli": {
        "ip": "127.1.1.1",
        "service": "CLI proxy loopback",
        "source": "lib/libl3_base.so",
        "notes": "Non-standard loopback used for internal CLI proxy communication",
    },
    "multicast_upnp": {
        "ip": "239.255.255.250",
        "port": 1900,
        "service": "UPnP/SSDP",
        "source": "lib/libl3_ext.so, lib/libupnp.so",
        "notes": "UPnP SSDP multicast address. "
                 "NAT rule: PRE_DNAT -i br+ -p udp -d * --dport 1900 -j DNAT --to 239.255.255.250:1900",
    },
    "mdns": {
        "ip": "224.0.0.251",
        "port": 5353,
        "service": "mDNS",
        "source": "lib/libl3_tr181.so",
        "notes": "mDNS multicast address",
    },
}

HIDDEN_PORTS = {
    "web_http": {
        "port": 80,
        "spec": "SSMP_SPEC_WEB_PORTNUM",
        "notes": "Main web UI port",
    },
    "web_http_external": {
        "port": 80,
        "spec": "SSMP_SPEC_WEB_OUTPORTNUM",
        "notes": "External web port (WAN side, if HTTPWanEnable=1)",
    },
    "tr069_cwmp": {
        "port": 7547,
        "spec": "SSMP_SPEC_CWMP_SERVER_PORT",
        "notes": "TR-069/CWMP connection request listener",
    },
    "ssh_dropbear": {
        "port": 22,
        "notes": "Dropbear SSH server. Controlled by AclServices.SSHLanEnable",
    },
    "telnet": {
        "port": 23,
        "notes": "Telnet server. Controlled by X_HW_DEBUG.TelnetSwitch "
                 "and AclServices.TelnetLanEnable",
    },
    "telnet_extended": {
        "port": 2323,
        "notes": "UNE Telnet extended port (referenced in bin4_wifi_5116.cfg). "
                 "Not enabled on Megacable firmware",
    },
    "inner_http": {
        "port": 8080,
        "notes": "UNE INNER port (referenced in bin4_wifi_5116.cfg). "
                 "Feature flag: HW_FT_WEB_INDEPEND_HTTPS_PORT",
    },
    "radius_auth": {
        "port": 1812,
        "notes": "RADIUS authentication server port (hw_hostapd.conf)",
    },
    "radius_acct": {
        "port": 1813,
        "notes": "RADIUS accounting server port (hw_hostapd.conf)",
    },
    "dlna_server": {
        "port": 56001,
        "spec": "SPEC_DLNA_SERVER_PORT",
        "notes": "DLNA media server port",
    },
    "dlna_client": {
        "port": 56002,
        "spec": "SPEC_DLNA_CLIENT_PORT",
        "notes": "DLNA media client port",
    },
    "upnp_ssdp": {
        "port": 1900,
        "notes": "UPnP/SSDP discovery port",
    },
    "locate_port1": {
        "port": 17999,
        "notes": "China Unicom locate port (recover scripts). Not on Megacable",
    },
    "locate_port2": {
        "port": 17998,
        "notes": "China Unicom locate port 2 (recover scripts). Not on Megacable",
    },
}

BYPASS_FEATURES = {
    "FT_SSMP_WEB_LOGIN_WITHOUT_PWD": {
        "notes": "Skip password check on login",
        "source": "lib/libhw_web_dll.so",
    },
    "FT_WEB_AP_SKIP_SETPWD": {
        "notes": "Skip initial password setup on first boot",
        "source": "bin/web",
    },
    "FT_WEB_FORCE_PASSWORD": {
        "notes": "Force password change on first login",
        "source": "bin/web",
    },
    "HW_SSMP_FEATURE_RESET_NO_LOGIN": {
        "notes": "Allow factory reset without login",
        "source": "bin/web",
    },
    "FT_SSMP_CLR_WEB_LOGIN_FAILCNT": {
        "notes": "Clear login fail counter",
        "source": "lib/libhw_web_dll.so",
    },
    "HW_SSMP_FEATURE_ADMIN_LOGIN": {
        "notes": "Control admin login availability",
        "source": "lib/libhw_web_dll.so",
    },
    "FT_WEB_SUPPORT_SAME_USER_LOGIN": {
        "notes": "Allow multiple sessions with same user",
        "source": "lib/libhw_web_dll.so",
    },
}

PRIVILEGE_ESCALATION_PATHS = {
    "web_proxy": {
        "method": "MITM proxy (this tool)",
        "steps": [
            "1. Proxy intercepts HTTP between browser and ONT",
            "2. Modifies curUserType='0' in ASP responses",
            "3. Overrides IsAdminUser() to return true",
            "4. Injects JS to unhide all admin elements",
            "5. Hooks setDisplay/setDisable to prevent hiding controls",
            "6. Forces User-Agent: Mozilla/Chrome to pass HW_WEB_CheckUserAgent",
        ],
    },
    "tr069_provision": {
        "method": "TR-069 config push",
        "steps": [
            "1. Set X_HW_DEBUG.TelnetSwitch=1 via TR-069 SetParameterValues",
            "2. Set X_HW_DEBUG.SshSwitch=1",
            "3. Set AclServices.TelnetLanEnable=1",
            "4. Set AclServices.SSHLanEnable=1",
            "5. Set WebUserInfo.2.UserLevel=0 (admin)",
        ],
    },
    "cfgtool_cli": {
        "method": "CLI cfgtool (requires telnet/SSH access)",
        "commands": [
            "cfgtool SetPara InternetGatewayDevice.X_HW_DEBUG TelnetSwitch 1",
            "cfgtool SetPara InternetGatewayDevice.X_HW_DEBUG SshSwitch 1",
            "cfgtool SetPara InternetGatewayDevice.X_HW_Security.AclServices TelnetLanEnable 1",
            "cfgtool SetPara InternetGatewayDevice.X_HW_Security.AclServices SSHLanEnable 1",
        ],
    },
    "hw_ctree_modify": {
        "method": "Decrypt, modify, re-encrypt hw_ctree.xml",
        "steps": [
            "1. Decrypt: aescrypt2 1 hw_ctree.xml out.xml && gunzip out.xml.gz",
            "2. Edit XML: change TelnetSwitch=1, SshSwitch=1, UserLevel=0",
            "3. Re-encrypt: gzip out.xml && aescrypt2 0 out.xml.gz hw_ctree.xml",
            "4. Flash back to device",
        ],
    },
}

SYSTEM_USERS = [
    {"user": "root", "uid": 0, "shell": "/sbin/nologin", "notes": "System root, login disabled"},
    {"user": "srv_amp", "uid": 3003, "shell": "/bin/false", "notes": "AMP service daemon"},
    {"user": "srv_web", "uid": 3004, "shell": "/bin/false", "notes": "Web server daemon (bin/web runs as this user)"},
    {"user": "srv_igmp", "uid": 3006, "shell": "/bin/false", "notes": "IGMP multicast daemon"},
    {"user": "cfg_cwmp", "uid": 3007, "shell": "/bin/false", "notes": "TR-069/CWMP config daemon"},
    {"user": "srv_ssmp", "uid": 3008, "shell": "/bin/false", "notes": "SSMP service daemon (bin/ssmp)"},
    {"user": "cfg_cli", "uid": 3010, "shell": "/bin/false", "notes": "CLI config daemon"},
    {"user": "srv_bbsp", "uid": 3012, "shell": "/bin/false", "notes": "BBSP broadband service daemon"},
    {"user": "srv_kmc", "uid": 3020, "shell": "/bin/false", "notes": "KMC key management daemon"},
    {"user": "srv_voice", "uid": 4002, "shell": "/bin/false", "notes": "VoIP service daemon"},
    {"user": "osgi_proxy", "uid": 3005, "shell": "/bin/false", "notes": "OSGi Java proxy"},
]
