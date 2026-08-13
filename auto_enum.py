#!/usr/bin/env python3
"""
Auto Service Enumeration Tool - With Detailed Summary
--------------------------------
Dynamic network enumeration tool that scans IP ranges, detects open services,
and automatically runs relevant enumeration tools (finger, rpcinfo, showmount,
enum4linux, smbclient, ldapsearch, banner grabs, etc.) with live output.

Features:
- Automatically installs missing dependencies (sudo apt install)
- Saves live hosts to live_hosts.txt
- Per-host dynamic port scanning and enumeration
- Generates a detailed markdown summary report with full service details

Usage:
    python3 auto_enum.py 192.168.1.1
    python3 auto_enum.py 192.168.1.0/24
    python3 auto_enum.py -f targets.txt
"""

import subprocess
import os
import sys
import time
import re
import socket
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime
import argparse

# ============================================================
# COLOR CODES
# ============================================================
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# ============================================================
# MAIN ENUMERATOR CLASS
# ============================================================
class ServiceEnumerator:
    def __init__(self, target, output_dir=None):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = output_dir if output_dir else f"enum_results_{self.timestamp}"
        self.live_hosts = []
        self.interesting_ports = [
            21, 22, 23, 25, 53, 79, 80, 110, 111, 135, 139, 143,
            443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
            6379, 8000, 8080, 8443
        ]
        self.port_string = ','.join(map(str, self.interesting_ports))
        os.makedirs(self.base_dir, exist_ok=True)

        # Data storage for detailed summary
        self.host_data = {}

        # Check and install dependencies automatically
        self.check_dependencies()

    # ---------- Print Helpers ----------
    def print_header(self, text):
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{text}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'='*70}{Colors.RESET}")

    def print_sub(self, text):
        print(f"{Colors.CYAN}   {text}{Colors.RESET}")

    def print_ok(self, text):
        print(f"{Colors.GREEN}   ✅ {text}{Colors.RESET}")

    def print_info(self, text):
        print(f"{Colors.BLUE}   ℹ️  {text}{Colors.RESET}")

    def print_warn(self, text):
        print(f"{Colors.YELLOW}   ⚠️ {text}{Colors.RESET}")

    def print_err(self, text):
        print(f"{Colors.RED}   ❌ {text}{Colors.RESET}")

    # ============================================================
    # STEP 0: DEPENDENCY CHECK & AUTO INSTALL
    # ============================================================
    def check_dependencies(self):
        tool_package_map = {
            'nmap': 'nmap',
            'finger': 'finger',
            'rpcinfo': 'rpcbind',
            'showmount': 'nfs-common',
            'smbclient': 'smbclient',
            'enum4linux': 'enum4linux',
            'ldapsearch': 'ldap-utils',
            'curl': 'curl',
            'nc': 'netcat-openbsd'
        }

        missing = []
        for tool, pkg in tool_package_map.items():
            if shutil.which(tool) is None:
                missing.append(pkg)

        if missing:
            self.print_warn(f"Missing tools/packages: {', '.join(missing)}")
            self.print_info("Attempting to install missing dependencies via apt...")
            try:
                subprocess.run("sudo apt update -y", shell=True, check=False, timeout=60)
                install_cmd = f"sudo apt install -y {' '.join(missing)}"
                result = subprocess.run(install_cmd, shell=True, check=False, timeout=300)
                if result.returncode == 0:
                    self.print_ok("All missing dependencies installed successfully!")
                else:
                    self.print_err("Some packages failed to install.")
            except Exception as e:
                self.print_err(f"Installation failed: {e}")
                self.print_warn("Continuing with available tools.")
        else:
            self.print_ok("All required tools are already installed.")

    # ============================================================
    # STEP 1: DISCOVER LIVE HOSTS
    # ============================================================
    def discover_hosts(self):
        self.print_header(f"📡 DISCOVERING LIVE HOSTS IN {self.target}")

        if '/' not in self.target:
            try:
                socket.inet_aton(self.target)
                self.print_info(f"Single IP provided: {self.target}")
                self.live_hosts = [self.target]
                self._save_live_hosts()
                self._init_host_data()
                return
            except socket.error:
                try:
                    ip = socket.gethostbyname(self.target)
                    self.print_info(f"Resolved {self.target} -> {ip}")
                    self.live_hosts = [ip]
                    self._save_live_hosts()
                    self._init_host_data()
                    return
                except:
                    self.print_err("Could not resolve target. Exiting.")
                    sys.exit(1)

        cmd = f"nmap -sn {self.target} -oG - | grep 'Host:' | awk '{{print $2}}'"
        self.print_info(f"Running: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)

        if result.returncode != 0:
            self.print_err("Ping sweep failed. Trying fallback with fping...")
            cmd = f"fping -ag {self.target} 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                self.print_err("Fallback failed. No live hosts found.")
                sys.exit(1)

        ips = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        self.live_hosts = ips

        if not self.live_hosts:
            self.print_err("No live hosts found!")
            sys.exit(1)

        self.print_ok(f"Found {len(self.live_hosts)} live host(s):")
        for ip in self.live_hosts:
            print(f"   {Colors.BLUE}• {ip}{Colors.RESET}")

        self._save_live_hosts()
        self._init_host_data()

    def _save_live_hosts(self):
        live_file = f"{self.base_dir}/live_hosts.txt"
        with open(live_file, 'w') as f:
            for ip in self.live_hosts:
                f.write(f"{ip}\n")
        self.print_ok(f"Live hosts saved to: {live_file}")

    def _init_host_data(self):
        for ip in self.live_hosts:
            self.host_data[ip] = {
                'open_ports': {},      # port -> service info
                'services': {},        # port -> detailed parsed info
                'findings': []         # summary findings
            }

    # ============================================================
    # STEP 2: SCAN PORTS ON EACH HOST
    # ============================================================
    def scan_host_ports(self, ip):
        xml_file = f"{self.base_dir}/nmap_{ip.replace('.', '_')}.xml"
        if os.path.exists(xml_file) and os.path.getsize(xml_file) > 0:
            self.print_info(f"Using cached Nmap scan for {ip}")
            return xml_file

        cmd = f"nmap -p {self.port_string} -sS -sV --open -T4 -oX {xml_file} {ip}"
        self.print_info(f"Scanning ports on {ip}...")
        subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return xml_file

    def parse_nmap_xml(self, xml_file):
        open_ports = {}
        if not os.path.exists(xml_file):
            return open_ports
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                for ports in host.findall('ports'):
                    for port in ports.findall('port'):
                        port_id = port.get('portid')
                        if port_id is None:
                            continue
                        state = port.find('state')
                        if state is None or state.get('state') != 'open':
                            continue
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        product = service.get('product') if service is not None else ''
                        version = service.get('version') if service is not None else ''
                        if product or version:
                            service_name = f"{service_name} ({product} {version})"
                        open_ports[int(port_id)] = {'name': service_name}
            return open_ports
        except Exception as e:
            self.print_err(f"Failed to parse Nmap XML: {e}")
            return {}

    # ============================================================
    # STEP 3: ENUMERATE SERVICES PER PORT
    # ============================================================
    def enumerate_port(self, ip, port, service_info):
        self.print_sub(f"Enumerating port {port} ({service_info.get('name', 'unknown')})")

        # Store service info
        self.host_data[ip]['open_ports'][port] = service_info

        if port == 79:
            self._run_finger(ip)
        elif port == 111:
            self._run_rpcinfo(ip)
            self._run_showmount(ip)
        elif port in [139, 445]:
            self._run_enum4linux(ip)
            self._run_smbclient(ip)
        elif port == 389:
            self._run_ldapsearch(ip)
        elif port == 22:
            self._run_ssh_banner(ip)
        elif port == 21:
            self._run_ftp_banner(ip)
        elif port in [80, 443, 8080, 8443]:
            self._run_http_banner(ip, port)
        else:
            self._run_banner_grab(ip, port)

    # ============================================================
    # INDIVIDUAL ENUMERATION WITH DATA STORAGE
    # ============================================================
    def _run_command(self, cmd, out_file, timeout=30):
        full_cmd = f"{cmd} > {out_file} 2>&1"
        try:
            subprocess.run(full_cmd, shell=True, timeout=timeout, check=False)
            if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                return True
            else:
                if os.path.exists(out_file):
                    os.remove(out_file)
                return False
        except Exception:
            return False

    def _print_cmd_output(self, out_file, max_lines=5):
        if not os.path.exists(out_file):
            return
        with open(out_file, 'r') as f:
            lines = f.readlines()
            if lines:
                for line in lines[:max_lines]:
                    print(f"      {line.strip()}")

    def _add_finding(self, ip, finding):
        if ip in self.host_data:
            self.host_data[ip]['findings'].append(finding)

    # ---------- FINGER ----------
    def _run_finger(self, ip):
        base_name = f"{self.base_dir}/finger_{ip}"
        details = {}
        out_file = f"{base_name}_long.txt"
        if self._run_command(f"finger -l @{ip}", out_file):
            self.print_ok(f"finger -l output saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "finger -l: successful")
            with open(out_file, 'r') as f:
                details['long'] = f.read()
        else:
            self.print_warn("finger -l failed")
        out_file = f"{base_name}_short.txt"
        if self._run_command(f"finger -s @{ip}", out_file):
            self.print_ok(f"finger -s output saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "finger -s: successful")
            with open(out_file, 'r') as f:
                details['short'] = f.read()
        else:
            self.print_warn("finger -s failed")
        out_file = f"{base_name}_plan.txt"
        if self._run_command(f"finger -p @{ip}", out_file):
            self.print_ok(f"finger -p output saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "finger -p: successful")
            with open(out_file, 'r') as f:
                details['plan'] = f.read()
        else:
            self.print_warn("finger -p failed")
        if details:
            self.host_data[ip]['services'][79] = details

    # ---------- RPCINFO ----------
    def _run_rpcinfo(self, ip):
        base_name = f"{self.base_dir}/rpcinfo_{ip}"
        details = {}
        out_file = f"{base_name}_p.txt"
        if self._run_command(f"rpcinfo -p {ip}", out_file):
            self.print_ok(f"rpcinfo -p output saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "rpcinfo -p: successful")
            with open(out_file, 'r') as f:
                details['portmap'] = f.read()
        else:
            self.print_warn("rpcinfo -p failed")
        out_file = f"{base_name}_s.txt"
        if self._run_command(f"rpcinfo -s {ip}", out_file):
            self.print_ok(f"rpcinfo -s output saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "rpcinfo -s: successful")
            with open(out_file, 'r') as f:
                details['status'] = f.read()
        else:
            self.print_warn("rpcinfo -s failed")
        out_file = f"{base_name}_t.txt"
        if self._run_command(f"rpcinfo -t {ip} 100000", out_file):
            self.print_ok(f"rpcinfo -t (portmap) saved ({out_file})")
            self._print_cmd_output(out_file)
            with open(out_file, 'r') as f:
                details['tcp_test'] = f.read()
        if details:
            self.host_data[ip]['services'][111] = details

    # ---------- SHOWMOUNT ----------
    def _run_showmount(self, ip):
        base_name = f"{self.base_dir}/showmount_{ip}"
        details = {}
        out_file = f"{base_name}_e.txt"
        if self._run_command(f"showmount -e {ip}", out_file):
            self.print_ok(f"showmount -e output saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "showmount -e: successful")
            with open(out_file, 'r') as f:
                details['exports'] = f.read()
        else:
            self.print_warn("showmount -e failed")
        out_file = f"{base_name}_a.txt"
        if self._run_command(f"showmount -a {ip}", out_file):
            self.print_ok(f"showmount -a output saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "showmount -a: successful")
            with open(out_file, 'r') as f:
                details['clients'] = f.read()
        else:
            self.print_warn("showmount -a failed")
        out_file = f"{base_name}_d.txt"
        if self._run_command(f"showmount -d {ip}", out_file):
            self.print_ok(f"showmount -d output saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "showmount -d: successful")
            with open(out_file, 'r') as f:
                details['dirs'] = f.read()
        else:
            self.print_warn("showmount -d failed")
        if details:
            self.host_data[ip]['services'][2049] = details

    # ---------- ENUM4LINUX ----------
    def _run_enum4linux(self, ip):
        base_name = f"{self.base_dir}/enum4linux_{ip}"
        details = {}
        out_file = f"{base_name}_a.txt"
        self.print_info("Running enum4linux -a (full aggressive scan, may take time)...")
        if self._run_command(f"enum4linux -a {ip}", out_file, timeout=300):
            self.print_ok(f"enum4linux -a saved ({out_file})")
            self._add_finding(ip, "enum4linux -a: successful")
            with open(out_file, 'r') as f:
                details['aggressive'] = f.read()
            # Show quick summary in terminal
            with open(out_file, 'r') as f:
                content = f.read()
                users = re.findall(r"user:\s*\[(.*?)\]", content, re.IGNORECASE)
                shares = re.findall(r"Sharename\s+Type\s+Comment\s*\n(.*?)\n\n", content, re.DOTALL)
                if users:
                    print(f"      {Colors.GREEN}Found {len(users)} users: {', '.join(users[:5])}{Colors.RESET}")
                if shares:
                    print(f"      {Colors.GREEN}Found shares: {shares[:1]}{Colors.RESET}")
        else:
            self.print_warn("enum4linux -a failed, trying individual modules...")
            self._add_finding(ip, "enum4linux -a failed")
            out_file = f"{base_name}_U.txt"
            if self._run_command(f"enum4linux -U {ip}", out_file, timeout=120):
                self.print_ok(f"enum4linux -U (users) saved ({out_file})")
                self._add_finding(ip, "enum4linux -U: successful")
                with open(out_file, 'r') as f:
                    details['users'] = f.read()
            out_file = f"{base_name}_S.txt"
            if self._run_command(f"enum4linux -S {ip}", out_file, timeout=120):
                self.print_ok(f"enum4linux -S (shares) saved ({out_file})")
                self._add_finding(ip, "enum4linux -S: successful")
                with open(out_file, 'r') as f:
                    details['shares'] = f.read()
            out_file = f"{base_name}_G.txt"
            if self._run_command(f"enum4linux -G {ip}", out_file, timeout=120):
                self.print_ok(f"enum4linux -G (groups) saved ({out_file})")
                self._add_finding(ip, "enum4linux -G: successful")
                with open(out_file, 'r') as f:
                    details['groups'] = f.read()
        if details:
            self.host_data[ip]['services'][445] = details

    # ---------- SMBCLIENT ----------
    def _run_smbclient(self, ip):
        base_name = f"{self.base_dir}/smbclient_{ip}"
        details = {}
        out_file = f"{base_name}_list.txt"
        if self._run_command(f"smbclient -L //{ip} -N", out_file):
            self.print_ok(f"smbclient -L saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "smbclient -L: successful")
            with open(out_file, 'r') as f:
                details['list'] = f.read()
        else:
            self.print_warn("smbclient -L failed")
        out_file = f"{base_name}_ipc.txt"
        if self._run_command(f"smbclient //{ip}/IPC$ -N -c 'dir'", out_file):
            self.print_ok(f"smbclient null session (IPC$) saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "smbclient null session on IPC$: successful")
            with open(out_file, 'r') as f:
                details['ipc'] = f.read()
        else:
            self.print_warn("smbclient null session on IPC$ failed")
        if details:
            # Merge with enum4linux data if present
            if 445 in self.host_data[ip]['services']:
                self.host_data[ip]['services'][445]['smbclient'] = details
            else:
                self.host_data[ip]['services'][445] = {'smbclient': details}

    # ---------- LDAPSEARCH ----------
    def _run_ldapsearch(self, ip):
        base_name = f"{self.base_dir}/ldapsearch_{ip}"
        details = {}
        out_file = f"{base_name}_base.txt"
        if self._run_command(f"ldapsearch -x -H ldap://{ip} -b '' -s base namingContexts", out_file):
            self.print_ok(f"LDAP base DN info saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "LDAP base DN discovery: successful")
            with open(out_file, 'r') as f:
                details['base'] = f.read()
            # Extract base DN
            base_dn = None
            with open(out_file, 'r') as f:
                content = f.read()
                match = re.search(r"namingContexts:\s*(.*)", content)
                if match:
                    base_dn = match.group(1).strip()
            if base_dn:
                out_file = f"{base_name}_dump.txt"
                self.print_info(f"LDAP base DN found: {base_dn}. Dumping all entries...")
                if self._run_command(f"ldapsearch -x -H ldap://{ip} -b '{base_dn}' -s sub '(objectClass=*)'", out_file, timeout=60):
                    self.print_ok(f"LDAP full dump saved ({out_file})")
                    with open(out_file, 'r') as f:
                        details['dump'] = f.read()
                    # Show count
                    with open(out_file, 'r') as f:
                        lines = f.readlines()
                        dn_lines = [l for l in lines if l.startswith('dn:')]
                        print(f"      {Colors.GREEN}Found {len(dn_lines)} LDAP entries{Colors.RESET}")
                else:
                    self.print_warn("LDAP full dump failed")
            else:
                self.print_warn("Could not extract base DN")
        else:
            self.print_warn("LDAP base DN discovery failed")
        if details:
            self.host_data[ip]['services'][389] = details

    # ---------- SSH BANNER ----------
    def _run_ssh_banner(self, ip):
        out_file = f"{self.base_dir}/ssh_banner_{ip}.txt"
        if self._run_command(f"nc -nv {ip} 22 -w 5", out_file):
            self.print_ok(f"SSH banner saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "SSH banner grabbed")
            with open(out_file, 'r') as f:
                self.host_data[ip]['services'][22] = {'banner': f.read()}
        else:
            self.print_warn("SSH banner grab failed")

    # ---------- FTP BANNER ----------
    def _run_ftp_banner(self, ip):
        out_file = f"{self.base_dir}/ftp_banner_{ip}.txt"
        if self._run_command(f"nc -nv {ip} 21 -w 5", out_file):
            self.print_ok(f"FTP banner saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, "FTP banner grabbed")
            with open(out_file, 'r') as f:
                self.host_data[ip]['services'][21] = {'banner': f.read()}
        else:
            self.print_warn("FTP banner grab failed")

    # ---------- HTTP BANNER ----------
    def _run_http_banner(self, ip, port):
        base_name = f"{self.base_dir}/http_banner_{ip}_{port}"
        proto = 'https' if port in [443, 8443] else 'http'
        details = {}
        out_file = f"{base_name}_headers.txt"
        if self._run_command(f"curl -s -k -I -m 5 {proto}://{ip}:{port}", out_file):
            self.print_ok(f"HTTP headers saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, f"HTTP headers from port {port}: successful")
            with open(out_file, 'r') as f:
                details['headers'] = f.read()
        else:
            self.print_warn("HTTP headers grab failed")
        out_file = f"{base_name}_root.txt"
        if self._run_command(f"curl -s -k -m 5 {proto}://{ip}:{port} | head -10", out_file):
            self.print_ok(f"HTTP root page sample saved ({out_file})")
            self._print_cmd_output(out_file)
            with open(out_file, 'r') as f:
                details['root_sample'] = f.read()
        else:
            self.print_warn("HTTP root page fetch failed")
        out_file = f"{base_name}_robots.txt"
        if self._run_command(f"curl -s -k -m 5 {proto}://{ip}:{port}/robots.txt", out_file):
            if os.path.getsize(out_file) > 10:
                self.print_ok(f"robots.txt found! ({out_file})")
                self._print_cmd_output(out_file)
                self._add_finding(ip, f"robots.txt found on port {port}")
                with open(out_file, 'r') as f:
                    details['robots'] = f.read()
            else:
                os.remove(out_file)
                self.print_info("robots.txt not found or empty")
        if details:
            self.host_data[ip]['services'][port] = details

    # ---------- GENERIC BANNER ----------
    def _run_banner_grab(self, ip, port):
        out_file = f"{self.base_dir}/banner_{ip}_{port}.txt"
        if self._run_command(f"nc -nv {ip} {port} -w 5", out_file):
            self.print_ok(f"Banner saved ({out_file})")
            self._print_cmd_output(out_file)
            self._add_finding(ip, f"Banner grabbed from port {port}")
            with open(out_file, 'r') as f:
                self.host_data[ip]['services'][port] = {'banner': f.read()}
        else:
            self.print_warn("Banner grab failed")

    # ============================================================
    # SUMMARY REPORT GENERATION (DETAILED)
    # ============================================================
    def _generate_summary(self):
        """Generate a detailed markdown summary report with all service data."""
        summary_file = f"{self.base_dir}/SUMMARY.md"
        with open(summary_file, 'w') as f:
            f.write(f"# 🔍 Auto Service Enumeration Summary\n\n")
            f.write(f"**Target:** `{self.target}`\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Output Directory:** `{self.base_dir}`\n\n")
            f.write(f"## 📊 Overview\n\n")
            f.write(f"| Metric | Value |\n")
            f.write(f"|--------|-------|\n")
            f.write(f"| Live Hosts | {len(self.live_hosts)} |\n")
            total_ports = sum(len(data['open_ports']) for data in self.host_data.values())
            f.write(f"| Open Interesting Ports | {total_ports} |\n")
            total_findings = sum(len(data['findings']) for data in self.host_data.values())
            f.write(f"| Total Findings | {total_findings} |\n\n")

            f.write(f"## 🖥️  Host Details\n\n")
            for ip, data in self.host_data.items():
                f.write(f"### 🌐 {ip}\n\n")
                if data['open_ports']:
                    f.write(f"**Open Ports:**\n\n")
                    f.write(f"| Port | Service |\n")
                    f.write(f"|------|---------|\n")
                    for port, info in sorted(data['open_ports'].items()):
                        f.write(f"| {port} | {info.get('name', 'unknown')} |\n")
                    f.write(f"\n")
                else:
                    f.write(f"*No open interesting ports found.*\n\n")

                # Detailed service information (full content)
                if data['services']:
                    f.write(f"**Service Details:**\n\n")
                    for port, details in sorted(data['services'].items()):
                        f.write(f"#### Port {port}\n\n")
                        if port in [80, 443, 8080, 8443]:
                            if 'headers' in details:
                                f.write(f"**HTTP Headers:**\n```\n{details['headers']}\n```\n")
                            if 'root_sample' in details:
                                f.write(f"**Root Page Sample:**\n```\n{details['root_sample']}\n```\n")
                            if 'robots' in details:
                                f.write(f"**robots.txt:**\n```\n{details['robots']}\n```\n")
                        elif port in [139, 445]:
                            if 'aggressive' in details:
                                f.write(f"**SMB Enumeration (aggressive):**\n```\n{details['aggressive']}\n```\n")
                            if 'users' in details:
                                f.write(f"**Users:**\n```\n{details['users']}\n```\n")
                            if 'shares' in details:
                                f.write(f"**Shares:**\n```\n{details['shares']}\n```\n")
                            if 'groups' in details:
                                f.write(f"**Groups:**\n```\n{details['groups']}\n```\n")
                            if 'smbclient' in details:
                                if 'list' in details['smbclient']:
                                    f.write(f"**SMB Shares (smbclient):**\n```\n{details['smbclient']['list']}\n```\n")
                                if 'ipc' in details['smbclient']:
                                    f.write(f"**IPC$ Null Session:**\n```\n{details['smbclient']['ipc']}\n```\n")
                        elif port == 111:
                            if 'portmap' in details:
                                f.write(f"**RPC Programs (portmap):**\n```\n{details['portmap']}\n```\n")
                            if 'status' in details:
                                f.write(f"**RPC Status:**\n```\n{details['status']}\n```\n")
                            if 'tcp_test' in details:
                                f.write(f"**RPC TCP Test:**\n```\n{details['tcp_test']}\n```\n")
                        elif port == 2049:
                            if 'exports' in details:
                                f.write(f"**NFS Exports:**\n```\n{details['exports']}\n```\n")
                            if 'clients' in details:
                                f.write(f"**NFS Mounted Clients:**\n```\n{details['clients']}\n```\n")
                            if 'dirs' in details:
                                f.write(f"**NFS Exported Directories:**\n```\n{details['dirs']}\n```\n")
                        elif port == 389:
                            if 'base' in details:
                                f.write(f"**LDAP Base DN Info:**\n```\n{details['base']}\n```\n")
                            if 'dump' in details:
                                f.write(f"**LDAP Full Dump:**\n```\n{details['dump']}\n```\n")
                        elif port == 22:
                            if 'banner' in details:
                                f.write(f"**SSH Banner:**\n```\n{details['banner']}\n```\n")
                        elif port == 21:
                            if 'banner' in details:
                                f.write(f"**FTP Banner:**\n```\n{details['banner']}\n```\n")
                        else:
                            if 'banner' in details:
                                f.write(f"**Banner:**\n```\n{details['banner']}\n```\n")
                        f.write("\n")
                else:
                    f.write(f"*No detailed service data available.*\n\n")

                # Overall findings for this host
                if data['findings']:
                    f.write(f"**Findings Summary:**\n\n")
                    for finding in data['findings']:
                        f.write(f"- {finding}\n")
                    f.write(f"\n")
                f.write(f"---\n\n")

            # List generated files
            f.write(f"## 📁 Generated Files\n\n")
            files = os.listdir(self.base_dir)
            files.sort()
            f.write(f"| File | Size |\n")
            f.write(f"|------|------|\n")
            for file in files:
                if file == "SUMMARY.md":
                    continue
                size = os.path.getsize(os.path.join(self.base_dir, file))
                f.write(f"| {file} | {size} bytes |\n")
            f.write(f"\n---\n")
            f.write(f"*Report generated by Auto Service Enumeration Tool*\n")

        self.print_ok(f"Summary report generated: {summary_file}")

    # ============================================================
    # MAIN EXECUTION
    # ============================================================
    def run(self):
        self.print_header(f"🚀 AUTO SERVICE ENUMERATION STARTED")
        print(f"{Colors.CYAN}Target: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}Output Directory: {self.base_dir}{Colors.RESET}")

        # Step 1: Discover live hosts
        self.discover_hosts()

        # Step 2 & 3: For each host, scan ports and enumerate
        for idx, ip in enumerate(self.live_hosts, 1):
            self.print_header(f"📝 [{idx}/{len(self.live_hosts)}] SCANNING {ip}")

            xml_file = self.scan_host_ports(ip)
            open_ports = self.parse_nmap_xml(xml_file)

            if not open_ports:
                self.print_warn(f"No interesting open ports found on {ip}")
                continue

            self.print_ok(f"Found {len(open_ports)} open interesting ports:")
            for port, info in open_ports.items():
                print(f"   {Colors.BLUE}• Port {port}: {info['name']}{Colors.RESET}")

            for port, info in open_ports.items():
                self.enumerate_port(ip, port, info)

        # Generate detailed summary
        self._generate_summary()

        # Final Summary
        self.print_header("✅ ENUMERATION COMPLETE")
        print(f"{Colors.GREEN}All results saved in: {self.base_dir}{Colors.RESET}")
        print(f"{Colors.CYAN}Live hosts list: {self.base_dir}/live_hosts.txt{Colors.RESET}")
        print(f"{Colors.CYAN}Summary report: {self.base_dir}/SUMMARY.md{Colors.RESET}")
        print(f"{Colors.CYAN}Review individual files for detailed output.{Colors.RESET}")


# ============================================================
# COMMAND LINE INTERFACE
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Auto Service Enumeration Tool - Detailed Summary",
        epilog="Example: python3 auto_enum.py 192.168.1.0/24"
    )
    parser.add_argument("target", help="IP address, domain, or CIDR range (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="Output directory (default: enum_results_<timestamp>)")
    parser.add_argument("-f", "--file", help="File containing list of targets (one per line)")

    args = parser.parse_args()

    if args.file:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        for target in targets:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}=== Processing target: {target} ==={Colors.RESET}")
            enumerator = ServiceEnumerator(target, args.output)
            enumerator.run()
    else:
        enumerator = ServiceEnumerator(args.target, args.output)
        enumerator.run()

if __name__ == "__main__":
    main()