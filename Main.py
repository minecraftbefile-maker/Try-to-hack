# thm_tester.py
import os
import asyncio
import aiohttp
import socket
from datetime import datetime
from dotenv import load_dotenv
import subprocess
import sys
import ipaddress
from typing import List, Dict, Any
import argparse

# Load environment variables
load_dotenv()

class TryHackMeTester:
    """
    TryHackMe machine testing tool using environment variables
    """
    
    def __init__(self):
        # Load configuration from environment
        self.site_domain = os.getenv('SITE_DOMAIN')
        self.ports = [int(p.strip()) for p in os.getenv('PORTS', '80,443').split(',')]
        self.vpn_interface = os.getenv('THM_VPN_INTERFACE', 'tun0')
        self.timeout = int(os.getenv('REQUEST_TIMEOUT', '5'))
        self.max_concurrent = int(os.getenv('MAX_CONCURRENT', '10'))
        self.user_agent = os.getenv('USER_AGENT', 'Mozilla/5.0')
        self.verify_ssl = os.getenv('VERIFY_SSL', 'false').lower() == 'true'
        self.scan_depth = os.getenv('SCAN_DEPTH', 'normal')
        
        # Validate configuration
        self._validate_config()
        
        # Check VPN connection
        self._check_vpn()
        
        print(f"\n✅ Configuration loaded from .env")
        print(f"   Target: {self.site_domain}")
        print(f"   Ports: {self.ports}")
        print(f"   VPN: {self.vpn_interface}")
    
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
    
    async def scan_ports(self) -> List[int]:
        """Scan configured ports"""
        print(f"\n🔍 Scanning ports on {self.site_domain}...")
        print(f"   Ports to scan: {self.ports}")
        
        open_ports = []
        
        for port in self.ports:
            try:
                # Try TCP connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.site_domain, port))
                
                if result == 0:
                    print(f"  ✅ Port {port}: OPEN")
                    open_ports.append(port)
                    
                    # Quick service detection
                    service = self._detect_service(port)
                    if service:
                        print(f"     → Likely service: {service}")
                else:
                    print(f"  ❌ Port {port}: Closed")
                sock.close()
            except Exception as e:
                print(f"  ⚠️  Port {port}: Error - {e}")
        
        return open_ports
    
    def _detect_service(self, port: int) -> str:
        """Basic service detection"""
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            27017: "MongoDB",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        return common_services.get(port, "Unknown")
    
    async def test_web_ports(self, open_ports: List[int]):
        """Test web servers on open ports"""
        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 1337, 3000, 5000]]
        
        if not web_ports:
            print("\n❌ No web ports found")
            return
        
        print(f"\n🌐 Testing web servers...")
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for port in web_ports:
                task = self._test_web_port(session, port)
                tasks.append(task)
            
            await asyncio.gather(*tasks)
    
    async def _test_web_port(self, session, port: int):
        """Test individual web port"""
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{self.site_domain}:{port}"
        
        headers = {"User-Agent": self.user_agent}
        
        try:
            async with session.get(
                url, 
                headers=headers,
                timeout=self.timeout,
                ssl=False
            ) as response:
                print(f"\n📡 Testing {url}")
                print(f"   Status: {response.status}")
                
                # Get headers
                print("   Headers:")
                for key, value in response.headers.items():
                    if key.lower() in ['server', 'content-type', 'x-powered-by']:
                        print(f"     {key}: {value}")
                
                # Get page title if HTML
                if 'text/html' in response.headers.get('Content-Type', ''):
                    html = await response.text()
                    title = self._extract_title(html)
                    if title:
                        print(f"   Page title: {title}")
                    
                    # Check for flags
                    if 'flag{' in html.lower() or 'thm{' in html.lower():
                        print("   🔴 FLAG FOUND in page source!")
                
        except asyncio.TimeoutError:
            print(f"   ⚠️  {url}: Timeout")
        except Exception as e:
            print(f"   ⚠️  {url}: Error - {str(e)[:50]}")
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        try:
            start = html.lower().find('<title>')
            end = html.lower().find('</title>')
            if start != -1 and end != -1:
                return html[start+7:end].strip()
        except:
            pass
        return None
    
    async def directory_scan(self, port: int = 80):
        """Scan for common directories"""
        
        # Wordlists based on scan depth
        wordlists = {
            "light": ["admin", "login", "robots.txt", "flag.txt", "backup"],
            "normal": ["admin", "login", "dashboard", "flag", "secret", 
                      "hidden", "backup", "robots.txt", "sitemap.xml", 
                      "uploads", "images", "css", "js", "api", "v1"],
            "deep": ["admin", "login", "dashboard", "flag", "secret", 
                    "hidden", "backup", "robots.txt", "sitemap.xml", 
                    "uploads", "images", "css", "js", "api", "v1",
                    "v2", "test", "dev", "stage", "private", "internal",
                    "phpmyadmin", "adminer", "wp-admin", "administrator"]
        }
        
        wordlist = wordlists.get(self.scan_depth, wordlists["normal"])
        
        protocol = "https" if port == 443 else "http"
        base_url = f"{protocol}://{self.site_domain}:{port}"
        
        print(f"\n📁 Scanning directories on {base_url}")
        print(f"   Depth: {self.scan_depth} ({len(wordlist)} paths)")
        
        found = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for directory in wordlist:
                task = self._check_directory(session, base_url, directory, semaphore)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            found = [r for r in results if r]
        
        if found:
            print(f"\n✅ Found {len(found)} accessible paths:")
            for path in found:
                print(f"   → {base_url}/{path}")
        else:
            print("\n❌ No directories found")
        
        return found
    
    async def _check_directory(self, session, base_url: str, directory: str, semaphore):
        """Check if directory exists"""
        url = f"{base_url}/{directory}"
        headers = {"User-Agent": self.user_agent}
        
        async with semaphore:
            try:
                async with session.get(
                    url, 
                    headers=headers,
                    timeout=self.timeout,
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    if response.status in [200, 301, 302, 403]:
                        print(f"  ✅ Found: /{directory} ({response.status})")
                        return directory
                    elif response.status == 401:
                        print(f"  🔒 Auth required: /{directory}")
                        return directory
            except:
                pass
        return None
    
    async def run_full_scan(self):
        """Run complete scan"""
        print("\n" + "="*60)
        print(f"🚀 Starting TryHackMe Scan on {self.site_domain}")
        print("="*60)
        
        start_time = datetime.now()
        
        # Step 1: Port scan
        open_ports = await self.scan_ports()
        
        # Step 2: Web tests
        if open_ports:
            await self.test_web_ports(open_ports)
            
            # Step 3: Directory scan on web ports
            web_ports = [p for p in open_ports if p in [80, 443, 8080, 1337]]
            for port in web_ports[:2]:  # Limit to first 2 web ports
                await self.directory_scan(port)
        
        # Summary
        elapsed = datetime.now() - start_time
        print("\n" + "="*60)
        print(f"✅ Scan completed in {elapsed.total_seconds():.1f} seconds")
        print(f"   Open ports found: {len(open_ports)}")
        print("="*60)

def create_env_template():
    """Create template .env file"""
    template = """# TryHackMe Testing Configuration
# Get machine IP from your TryHackMe room
SITE_DOMAIN=10.10.123.45  # Replace with your machine IP

# Ports to scan (comma-separated)
PORTS=21,22,23,25,80,443,445,8080,1337,3306,3389,5432,8081,8443,27017

# VPN Settings
THM_VPN_INTERFACE=tun0

# Request Settings
REQUEST_TIMEOUT=5
MAX_CONCURRENT=10
VERIFY_SSL=false

# Scan Settings
SCAN_DEPTH=normal  # Options: light, normal, deep

# User Agent for web requests
USER_AGENT=Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
"""
    
    with open('.env.template', 'w') as f:
        f.write(template)
    print("✅ Created .env.template file")

async def main():
    parser = argparse.ArgumentParser(description="TryHackMe Machine Tester")
    parser.add_argument("--create-env", action="store_true", help="Create .env template")
    parser.add_argument("--scan", action="store_true", help="Run scan")
    args = parser.parse_args()
    
    if args.create_env:
        create_env_template()
        return
    
    # Run scan
    tester = TryHackMeTester()
    await tester.run_full_scan()

if __name__ == "__main__":
    asyncio.run(main())
