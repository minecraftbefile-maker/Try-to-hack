# thm_scanner.py
import os
import asyncio
import aiohttp
import socket
from datetime import datetime
from dotenv import load_dotenv
import subprocess
import sys
import ipaddress
from typing import List, Dict, Any, Tuple
import argparse
import time

# Load environment variables
load_dotenv()

class AllPortsScanner:
    """
    TryHackMe machine scanner that can scan ALL 65535 ports
    """
    
    def __init__(self):
        # Load configuration from environment
        self.site_domain = os.getenv('SITE_DOMAIN')
        self.scan_all_ports = os.getenv('SCAN_ALL_PORTS', 'false').lower() == 'true'
        
        # Port scanning settings
        self.start_port = int(os.getenv('START_PORT', '1'))
        self.end_port = int(os.getenv('END_PORT', '65535'))
        self.scan_speed = os.getenv('PORT_SCAN_SPEED', 'fast')
        self.concurrent_scans = int(os.getenv('CONCURRENT_SCANS', '500'))
        self.common_ports = [int(p.strip()) for p in os.getenv('COMMON_PORTS', '80,443,22').split(',')]
        
        # Connection settings
        self.timeout = int(os.getenv('REQUEST_TIMEOUT', '3'))
        self.max_concurrent = int(os.getenv('MAX_CONCURRENT', '10'))
        self.max_retries = int(os.getenv('MAX_RETRIES', '2'))
        self.conn_timeout = int(os.getenv('CONNECTION_TIMEOUT', '2'))
        
        # VPN settings
        self.vpn_interface = os.getenv('THM_VPN_INTERFACE', 'tun0')
        self.user_agent = os.getenv('USER_AGENT', 'Mozilla/5.0')
        self.banner_grab = os.getenv('BANNER_GRAB', 'true').lower() == 'true'
        self.verify_ssl = os.getenv('VERIFY_SSL', 'false').lower() == 'true'
        self.scan_depth = os.getenv('SCAN_DEPTH', 'normal')
        
        # Scan statistics
        self.open_ports = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.total_scanned = 0
        
        # Validate configuration
        self._validate_config()
        
        # Check VPN connection
        self._check_vpn()
        
        # Display configuration
        self._show_config()
    
    def _validate_config(self):
        """Validate environment variables"""
        if not self.site_domain:
            print("❌ SITE_DOMAIN not set in .env file")
            print("Please add: SITE_DOMAIN=your_tryhackme_ip")
            sys.exit(1)
        
        try:
            # Validate IP address format
            ipaddress.ip_address(self.site_domain)
        except ValueError:
            print(f"⚠️  Warning: {self.site_domain} may not be a valid IP")
    
    def _check_vpn(self):
        """Verify TryHackMe VPN connection"""
        try:
            result = subprocess.run(
                ["ip", "addr", "show", self.vpn_interface],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"⚠️  Not connected to TryHackMe VPN ({self.vpn_interface})")
                print("Connect using: sudo openvpn your_config.ovpn")
                response = input("Continue anyway? (y/n): ")
                if response.lower() != 'y':
                    sys.exit(1)
            else:
                print(f"✅ Connected to TryHackMe VPN via {self.vpn_interface}")
        except Exception as e:
            print(f"⚠️  Could not verify VPN: {e}")
    
    def _show_config(self):
        """Display current configuration"""
        print("\n" + "="*60)
        print("🔧 Scanner Configuration")
        print("="*60)
        print(f"Target: {self.site_domain}")
        
        if self.scan_all_ports:
            print(f"Ports: ALL ({self.start_port}-{self.end_port})")
            print(f"Scan Speed: {self.scan_speed}")
            print(f"Concurrent Scans: {self.concurrent_scans}")
        else:
            print(f"Ports: Common only ({len(self.common_ports)} ports)")
        
        print(f"Timeout: {self.timeout}s")
        print(f"Banner Grab: {self.banner_grab}")
        print("="*60)
    
    async def scan_port(self, port: int) -> Tuple[int, bool, Dict]:
        """
        Scan a single port and get service info
        """
        result = {
            'port': port,
            'open': False,
            'service': 'unknown',
            'banner': None,
            'response_time': None
        }
        
        start_time = time.time()
        
        for attempt in range(self.max_retries):
            try:
                # Try TCP connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.conn_timeout)
                
                result_code = sock.connect_ex((self.site_domain, port))
                
                if result_code == 0:
                    result['open'] = True
                    result['response_time'] = (time.time() - start_time) * 1000
                    
                    # Try to grab banner if enabled
                    if self.banner_grab:
                        banner = self._grab_banner(sock, port)
                        if banner:
                            result['banner'] = banner
                            result['service'] = self._detect_service_from_banner(port, banner)
                    
                    sock.close()
                    
                    # Basic service detection
                    if not result['service'] or result['service'] == 'unknown':
                        result['service'] = self._detect_service(port)
                    
                    break
                
                sock.close()
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    pass  # Silent fail on last attempt
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        self.total_scanned += 1
        
        # Progress indicator (every 1000 ports)
        if self.total_scanned % 1000 == 0:
            elapsed = time.time() - self.scan_start_time
            ports_per_sec = self.total_scanned / elapsed if elapsed > 0 else 0
            print(f"   Progress: {self.total_scanned}/{self.total_ports} ports "
                  f"({(self.total_scanned/self.total_ports)*100:.1f}%) "
                  f"[{ports_per_sec:.0f} ports/sec]", end='\r')
        
        return port, result['open'], result
    
    def _grab_banner(self, sock, port: int) -> str:
        """
        Try to grab service banner
        """
        try:
            # Common probes for different services
            if port == 80 or port == 8080 or port == 8000:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:  # FTP
                pass  # Banner is usually sent on connect
            elif port == 22:  # SSH
                pass  # Banner is usually sent on connect
            elif port == 25:  # SMTP
                sock.send(b"EHLO scan.local\r\n")
            elif port == 443 or port == 8443:  # HTTPS
                return "SSL/TLS"
            else:
                # Generic probe
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100]  # Limit banner length
            
        except:
            return None
    
    def _detect_service(self, port: int) -> str:
        """Basic service detection by port number"""
        common_services = {
            20: "FTP-data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            69: "TFTP",
            80: "HTTP",
            81: "HTTP-alt",
            88: "Kerberos",
            110: "POP3",
            111: "RPC",
            113: "Ident",
            119: "NNTP",
            123: "NTP",
            135: "RPC",
            137: "NetBIOS-ns",
            138: "NetBIOS-dgm",
            139: "NetBIOS-ssn",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP-trap",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            465: "SMTPS",
            500: "IKE",
            512: "exec",
            513: "login",
            514: "shell",
            515: "printer",
            520: "RIP",
            521: "RIPng",
            525: "timed",
            530: "courier",
            531: "chat",
            532: "netnews",
            533: "netwall",
            540: "UUCP",
            548: "AFP",
            554: "RTSP",
            563: "NNTPs",
            587: "SMTP-sub",
            591: "FileMaker",
            593: "RPC",
            631: "IPP",
            636: "LDAPs",
            639: "MSDP",
            646: "LDP",
            647: "DHCPfailover",
            648: "RRP",
            651: "IEEE-MMS",
            653: "IEEE-MMS-SSL",
            654: "IEEE-MMS",
            655: "IEEE-MMS",
            657: "RMC",
            660: "MacOSX-admin",
            666: "Doom",
            993: "IMAPs",
            995: "POP3s",
            1025: "NFS-or-IIS",
            1026: "LSA-or-nterm",
            1027: "IIS",
            1028: "IIS",
            1029: "IIS",
            1030: "IIS",
            1080: "SOCKS",
            1080: "MyDoom",
            1194: "OpenVPN",
            1214: "KAZAA",
            1241: "Nessus",
            1311: "Dell-OA",
            1337: "WASTE",
            1433: "MSSQL",
            1434: "MSSQL-udp",
            1512: "WINS",
            1521: "Oracle",
            1524: "ingreslock",
            1604: "Citrix",
            1645: "radius",
            1646: "radacct",
            1701: "L2TP",
            1718: "h323gatestat",
            1719: "h323hostcall",
            1720: "H.323",
            1723: "PPTP",
            1755: "RTSP",
            1812: "radius",
            1813: "radacct",
            1900: "UPnP",
            2000: "Cisco-SCCP",
            2002: "Cisco-SCCP",
            2049: "NFS",
            2082: "Infowave",
            2083: "Infowave-SSL",
            2100: "Oracle-XDB",
            2222: "DirectAdmin",
            2302: "Freelancer",
            2483: "Oracle",
            2484: "Oracle-SSL",
            2745: "Bagle.H",
            2967: "Symantec-AV",
            3050: "Interbase",
            3074: "Xbox",
            3128: "Squid",
            3260: "iSCSI",
            3306: "MySQL",
            3389: "RDP",
            3689: "DAAP",
            3690: "SVN",
            3700: "LISA",
            3724: "ClubBox",
            3784: "VoIP",
            3785: "VoIP",
            4333: "mSQL",
            4444: "Blaster",
            4500: "IPSEC",
            4662: "EDonkey",
            4899: "Radmin",
            5000: "UPnP",
            5001: "iperf",
            5004: "RTP",
            5005: "RTP",
            5050: "MMCC",
            5060: "SIP",
            5061: "SIP-TLS",
            5093: "SPA",
            5101: "ADP",
            5121: "Neverwinter",
            5154: "BFD",
            5190: "AOL",
            5222: "XMPP",
            5223: "XMPP",
            5269: "XMPP",
            5432: "PostgreSQL",
            5500: "VNC",
            5554: "Sasser",
            5555: "Freeciv",
            5601: "Kibana",
            5631: "pcAnywhere",
            5632: "pcAnywhere",
            5666: "NRPE",
            5672: "AMQP",
            5800: "VNC-HTTP",
            5900: "VNC",
            6000: "X11",
            6001: "X11",
            6112: "Battle.net",
            6129: "DameWare",
            6257: "WinMX",
            6346: "Gnutella",
            6379: "Redis",
            6389: "EMC",
            6481: "SunService",
            6502: "Danware",
            6543: "JetDirect",
            6665: "IRC",
            6666: "IRC",
            6667: "IRC",
            6668: "IRC",
            6669: "IRC",
            6697: "IRC-SSL",
            6881: "BitTorrent",
            6901: "WindowsLive",
            6970: "Quicktime",
            7000: "Azureus",
            7001: "Azureus",
            7004: "Azureus",
            7005: "Azureus",
            7006: "Azureus",
            7010: "Azureus",
            7070: "RealServer",
            7100: "XFont",
            7171: "Tibia",
            7200: "FODMS",
            7212: "GhostSurf",
            7281: "Aventail",
            7306: "ZWorks",
            7307: "ZWorks",
            7308: "ZWorks",
            7396: "WebEx",
            7420: "OpenFire",
            7421: "OpenFire",
            7422: "OpenFire",
            7423: "OpenFire",
            7424: "OpenFire",
            7425: "OpenFire",
            7426: "OpenFire",
            7427: "OpenFire",
            7428: "OpenFire",
            7547: "CWMP",
            7575: "PCAnywhere",
            7597: "Azereus",
            7624: "Indii",
            7659: "Polly",
            7676: "Imesh",
            7680: "pando",
            7707: "Kazaa2",
            7741: "MediaPortal",
            7777: "Unreal",
            7778: "Unreal",
            7779: "Unreal",
            7780: "Unreal",
            7781: "Unreal",
            7782: "Unreal",
            7783: "Unreal",
            7784: "Unreal",
            7785: "Unreal",
            7786: "Unreal",
            7787: "Unreal",
            7788: "Unreal",
            7789: "Unreal",
            7790: "Unreal",
            7791: "Unreal",
            7792: "Unreal",
            7793: "Unreal",
            7794: "Unreal",
            7795: "Unreal",
            7796: "Unreal",
            7797: "Unreal",
            7798: "Unreal",
            7799: "Unreal",
            8000: "HTTP-alt",
            8008: "HTTP-alt",
            8009: "Ajp13",
            8010: "XMPP",
            8074: "Gadu-Gadu",
            8080: "HTTP-alt",
            8081: "HTTP-alt",
            8086: "Kademlia",
            8087: "Kademlia",
            8090: "HTTP-alt",
            8118: "Privoxy",
            8200: "VMware",
            8220: "VMware",
            8222: "VMware",
            8291: "Winbox",
            8300: "HTTP-alt",
            8333: "Bitcoin",
            8443: "HTTPS-alt",
            8500: "ColdFusion",
            8765: "Nexus",
            8787: "OpenFire",
            8800: "Sun",
            8880: "WebSphere",
            8888: "HTTP-alt",
            8899: "SPADES",
            9000: "CSDB",
            9001: "Tor",
            9002: "Tor",
            9030: "Tor",
            9040: "Tor",
            9050: "Tor",
            9051: "Tor",
            9080: "WebSphere",
            9090: "WebLogic",
            9100: "JetDirect",
            9119: "MXit",
            9191: "Sierra",
            9200: "Elasticsearch",
            9217: "iPass",
            9292: "HPCC",
            9293: "HPCC",
            9294: "HPCC",
            9295: "HPCC",
            9400: "OpcServer",
            9418: "Git",
            9500: "ISMserver",
            9502: "ISMserver",
            9503: "ISMserver",
            9535: "man",
            9593: "cba",
            9594: "cba",
            9595: "cba",
            9800: "WebDAV",
            9876: "RTSD",
            9898: "MonkeyCom",
            9988: "RAdmin",
            9999: "Java",
            10000: "Webmin",
            10001: "Webmin",
            10002: "Webmin",
            10003: "Webmin",
            10004: "Webmin",
            10005: "Webmin",
            10006: "Webmin",
            10007: "Webmin",
            10008: "Webmin",
            10009: "Webmin",
            10010: "Webmin",
            10011: "Webmin",
            10012: "Webmin",
            10013: "Webmin",
            10014: "Webmin",
            10015: "Webmin",
            10016: "Webmin",
            10017: "Webmin",
            10018: "Webmin",
            10019: "Webmin",
            10020: "Webmin",
            10113: "NetIQ",
            10114: "NetIQ",
            10115: "NetIQ",
            10116: "NetIQ",
            11000: "IRISA",
            11111: "Viral",
            11211: "Memcached",
            11371: "OpenPGP",
            12000: "Albert",
            12345: "NetBus",
            13720: "NetBackup",
            13721: "NetBackup",
            14567: "Battlefield",
            15118: "Oblivion",
            15567: "Battlefield2",
            15345: "XPilot",
            16000: "Oracle",
            16080: "HTTP-alt",
            16384: "IronMountain",
            16567: "Battlefield2",
            16992: "Intel-AMT",
            16993: "Intel-AMT",
            16994: "Intel-AMT",
            16995: "Intel-AMT",
            17000: "Children",
            17472: "SWAT",
            17500: "Dropbox",
            18080: "Monitoring",
            18101: "RDP",
            18102: "RDP",
            18103: "RDP",
            18104: "RDP",
            18105: "RDP",
            18106: "RDP",
            18107: "RDP",
            18108: "RDP",
            18109: "RDP",
            18110: "RDP",
            18111: "RDP",
            18112: "RDP",
            18113: "RDP",
            18114: "RDP",
            18115: "RDP",
            18116: "RDP",
            18117: "RDP",
            18118: "RDP",
            18119: "RDP",
            18120: "RDP",
            18121: "RDP",
            18122: "RDP",
            18123: "RDP",
            18124: "RDP",
            18125: "RDP",
            18126: "RDP",
            18127: "RDP",
            18128: "RDP",
            18129: "RDP",
            18130: "RDP",
            18131: "RDP",
            18132: "RDP",
            18133: "RDP",
            18134: "RDP",
            18135: "RDP",
            18136: "RDP",
            18137: "RDP",
            18138: "RDP",
            18139: "RDP",
            18140: "RDP",
            18141: "RDP",
            18142: "RDP",
            18143: "RDP",
            18144: "RDP",
            18145: "RDP",
            18146: "RDP",
            18147: "RDP",
            18148: "RDP",
            18149: "RDP",
            18150: "RDP",
            18151: "RDP",
            18152: "RDP",
            18153: "RDP",
            18154: "RDP",
            18155: "RDP",
            18156: "RDP",
            18157: "RDP",
            18158: "RDP",
            18159: "RDP",
            18160: "RDP",
            18161: "RDP",
            18162: "RDP",
            18163: "RDP",
            18164: "RDP",
            18165: "RDP",
            18166: "RDP",
            18167: "RDP",
            18168: "RDP",
            18169: "RDP",
            18170: "RDP",
            18171: "RDP",
            18172: "RDP",
            18173: "RDP",
            18174: "RDP",
            18175: "RDP",
            18176: "RDP",
            18177: "RDP",
            18178: "RDP",
            18179: "RDP",
            18180: "RDP",
            18181: "RDP",
            18182: "RDP",
            18183: "RDP",
            18184: "RDP",
            18185: "RDP",
            18186: "RDP",
            18187: "RDP",
            18188: "RDP",
            18189: "RDP",
            18190: "RDP",
            18191: "RDP",
            18192: "RDP",
            18193: "RDP",
            18194: "RDP",
            18195: "RDP",
            18196: "RDP",
            18197: "RDP",
            18198: "RDP",
            18199: "RDP",
            18200: "RDP",
            18201: "RDP",
            18202: "RDP",
            18203: "RDP",
            18204: "RDP",
            18205: "RDP",
            18206: "RDP",
            18207: "RDP",
            18208: "RDP",
            18209: "RDP",
            18210: "RDP",
            18211: "RDP",
            18212: "RDP",
            18213: "RDP",
            18214: "RDP",
            18215: "RDP",
            18216: "RDP",
            18217: "RDP",
            18218: "RDP",
            18219: "RDP",
            18220: "RDP",
            18221: "RDP",
            18222: "RDP",
            18223: "RDP",
            18224: "RDP",
            18225: "RDP",
            18226: "RDP",
            18227: "RDP",
            18228: "RDP",
            18229: "RDP",
            18230: "RDP",
            18231: "RDP",
            18232: "RDP",
            18233: "RDP",
            18234: "RDP",
            18235: "RDP",
            18236: "RDP",
            18237: "RDP",
            18238: "RDP",
            18239: "RDP",
            18240: "RDP",
            18241: "RDP",
            18242: "RDP",
            18243: "RDP",
            18244: "RDP",
            18245: "RDP",
            18246: "RDP",
            18247: "RDP",
            18248: "RDP",
            18249: "RDP",
            18250: "RDP",
            18251: "RDP",
            18252: "RDP",
            18253: "RDP",
            18254: "RDP",
            18255: "RDP",
            18256: "RDP",
            18257: "RDP",
            18258: "RDP",
            18259: "RDP",
            18260: "RDP",
            18261: "RDP",
            18262: "RDP",
            18263: "RDP",
            18264: "RDP",
            18265: "RDP",
            18266: "RDP",
            18267: "RDP",
            18268: "RDP",
            18269: "RDP",
            18270: "RDP",
            18271: "RDP",
            18272: "RDP",
            18273: "RDP",
            18274: "RDP",
            18275: "RDP",
            18276: "RDP",
            18277: "RDP",
            18278: "RDP",
            18279: "RDP",
            18280: "RDP",
            18281: "RDP",
            18282: "RDP",
            18283: "RDP",
            18284: "RDP",
            18285: "RDP",
            18286: "RDP",
            18287: "RDP",
            18288: "RDP",
            18289: "RDP",
            18290: "RDP",
            18291: "RDP",
            18292: "RDP",
            18293: "RDP",
            18294: "RDP",
            18295: "RDP",
            18296: "RDP",
            18297: "RDP",
            18298: "RDP",
            18299: "RDP",
            18300: "RDP",
            18301: "RDP",
            18302: "RDP",
            18303: "RDP",
            18304: "RDP",
            18305: "RDP",
            18306: "RDP",
            18307: "RDP",
            18308: "RDP",
            18309: "RDP",
            18310: "RDP",
            18311: "RDP",
            18312: "RDP",
            18313: "RDP",
            18314: "RDP",
            18315: "RDP",
            18316: "RDP",
            18317: "RDP",
            18318: "RDP",
            18319: "RDP",
            18320: "RDP",
            18321: "RDP",
            18322: "RDP",
            18323: "RDP",
            18324: "RDP",
            18325: "RDP",
            18326: "RDP",
            18327: "RDP",
            18328: "RDP",
            18329: "RDP",
            18330: "RDP",
            18331: "RDP",
            18332: "RDP",
            18333: "RDP",
            18334: "RDP",
            18335: "RDP",
            18336: "RDP",
            18337: "RDP",
            18338: "RDP",
            18339: "RDP",
            18340: "RDP",
            18341: "RDP",
            18342: "RDP",
            18343: "RDP",
            18344: "RDP",
            18345: "RDP",
            18346: "RDP",
            18347: "RDP",
            18348: "RDP",
            18349: "RDP",
            18350: "RDP",
            18351: "RDP",
            18352: "RDP",
            18353: "RDP",
            18354: "RDP",
            18355: "RDP",
            18356: "RDP",
            18357: "RDP",
            18358: "RDP",
            18359: "RDP",
            18360: "RDP",
            18361: "RDP",
            18362: "RDP",
            18363: "RDP",
            18364: "RDP",
            18365: "RDP",
            18366: "RDP",
            18367: "RDP",
            18368: "RDP",
            18369: "RDP",
            18370: "RDP",
            18371: "RDP",
            18372: "RDP",
            18373: "RDP",
            18374: "RDP",
            18375: "RDP",
            18376: "RDP",
            18377: "RDP",
            18378: "RDP",
            18379: "RDP",
            18380: "RDP",
            18381: "RDP",
            18382: "RDP",
            18383: "RDP",
            18384: "RDP",
            18385: "RDP",
            18386: "RDP",
            18387: "RDP",
            18388: "RDP",
            18389: "RDP",
            18390: "RDP",
            18391: "RDP",
            18392: "RDP",
            18393: "RDP",
            18394: "RDP",
            18395: "RDP",
            18396: "RDP",
            18397: "RDP",
            18398: "RDP",
            18399: "RDP",
            18400: "RDP"
        }
        return common_services.get(port, "unknown")
    
    def _detect_service_from_banner(self, port: int, banner: str) -> str:
        """Detect service from banner"""
        banner_lower = banner.lower()
        
        if 'ssh' in banner_lower:
            return "SSH"
        elif 'ftp' in banner_lower:
            return "FTP"
        elif 'http' in banner_lower or 'html' in banner_lower:
            return "HTTP"
        elif 'smtp' in banner_lower:
            return "SMTP"
        elif 'pop3' in banner_lower:
            return "POP3"
        elif 'imap' in banner_lower:
            return "IMAP"
        elif 'mysql' in banner_lower:
            return "MySQL"
        elif 'postgresql' in banner_lower or 'postgres' in banner_lower:
            return "PostgreSQL"
        elif 'redis' in banner_lower:
            return "Redis"
        elif 'mongodb' in banner_lower:
            return "MongoDB"
        
        return self._detect_service(port)
    
    async def scan_all_ports(self):
        """
        Scan all ports from start_port to end_port
        """
        self.scan_start_time = time.time()
        self.total_ports = self.end_port - self.start_port + 1
        
        print(f"\n🚀 Starting ALL ports scan on {self.site_domain}")
        print(f"   Ports: {self.start_port}-{self.end_port} ({self.total_ports} ports)")
        print(f"   Speed: {self.scan_speed}, Concurrent: {self.concurrent_scans}")
        print(f"   Press Ctrl+C to stop\n")
        
        # Adjust concurrency based on speed
        if self.scan_speed == 'slow':
            self.concurrent_scans = min(100, self.concurrent_scans)
        elif self.scan_speed == 'medium':
            self.concurrent_scans = min(500, self.concurrent_scans)
        elif self.scan_speed == 'fast':
            self.concurrent_scans = min(1000, self.concurrent_scans)
        elif self.scan_speed == 'insane':
            self.concurrent_scans = min(5000, self.concurrent_scans)
        
        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.concurrent_scans)
        
        async def scan_with_semaphore(port):
            async with semaphore:
                return await self.scan_port(port)
        
        # Create tasks for all ports
        tasks = []
        for port in range(self.start_port, self.end_port + 1):
            task = asyncio.create_task(scan_with_semaphore(port))
            tasks.append(task)
        
        # Process results as they complete
        open_ports_data = []
        
        for task in asyncio.as_completed(tasks):
            port, is_open, port_data = await task
            if is_open:
                open_ports_data.append(port_data)
                self._print_open_port(port_data)
        
        self.scan_end_time = time.time()
        self.open_ports = open_ports_data
        
        return open_ports_data
    
    def _print_open_port(self, port_data: Dict):
        """Pretty print open port info"""
        port = port_data['port']
        service = port_data['service']
        banner = port_data['banner']
        response_time = port_data['response_time']
        
        if banner:
            print(f"\n✅ Port {port}: OPEN → {service} [{response_time:.1f}ms]")
            print(f"   Banner: {banner}")
        else:
            print(f"\n✅ Port {port}: OPEN → {service} [{response_time:.1f}ms]")
    
    async def scan_common_ports(self):
        """
        Scan only common ports
        """
        self.scan_start_time = time.time()
        self.total_ports = len(self.common_ports)
        
        print(f"\n🚀 Starting common ports scan on {self.site_domain}")
        print(f"   Ports: {len(self.common_ports)} common ports")
        
        open_ports_data = []
        
        for port in self.common_ports:
            _, is_open, port_data = await self.scan_port(port)
            if is_open:
                open_ports_data.append(port_data)
                self._print_open_port(port_data)
        
        self.scan_end_time = time.time()
        self.open_ports = open_ports_data
        
        return open_ports_data
    
    async
