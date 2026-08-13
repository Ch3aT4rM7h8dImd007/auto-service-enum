# 🔧 AutoServiceEnum – Automated Network Service Enumeration with Detailed Reporting

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://)
[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen)]()
[![Nmap](https://img.shields.io/badge/Nmap-7.x-green)](https://nmap.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](http://makeapullrequest.com)

> **One‑command network service enumeration – automatically discovers live hosts, scans interesting ports, runs service‑specific tools (finger, rpcinfo, enum4linux, smbclient, ldapsearch, etc.), and compiles everything into a detailed Markdown summary.**

---

## 📖 What is AutoServiceEnum?

**AutoServiceEnum** is a Python‑based tool that automates the entire reconnaissance process for a target IP, domain, or CIDR range. It:

1. **Discovers live hosts** using `nmap -sn` (or `fping` fallback).
2. **Scans a curated list of interesting ports** (21, 22, 23, 25, 53, 79, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443) with service version detection (`-sV`).
3. **Runs targeted enumeration tools** based on open services:
   - **Port 79** – `finger` (long, short, plan)
   - **Port 111** – `rpcinfo -p`, `rpcinfo -s`, `rpcinfo -t` and `showmount -e/-a/-d`
   - **Ports 139/445** – `enum4linux -a` (full aggressive) and `smbclient` (null session checks)
   - **Port 389** – `ldapsearch` to discover base DN and dump all entries
   - **Port 22** – SSH banner grab via `nc`
   - **Port 21** – FTP banner grab
   - **Ports 80/443/8080/8443** – HTTP headers, root page sample, `robots.txt`
   - **Other ports** – generic banner grab using `nc`
4. **Saves all output** to timestamped directories, with one file per command.
5. **Automatically installs missing dependencies** (using `sudo apt install`) for tools like `nmap`, `finger`, `rpcbind`, `nfs-common`, `smbclient`, `enum4linux`, `ldap-utils`, `curl`, `netcat-openbsd`.
6. **Generates a comprehensive Markdown summary** (`SUMMARY.md`) that includes:
   - Overview statistics (live hosts, open ports, findings).
   - Per‑host open ports table.
   - Full outputs from all enumeration commands (grouped by service).
   - A findings summary for each host.
   - A list of all generated files.

**AutoServiceEnum** is ideal for **penetration testers**, **CTF players**, **bug bounty hunters**, and **system administrators** who need a quick, thorough, and well‑documented service enumeration on a network or host.

---

## ✨ Features at a Glance

| Feature | Description |
|---------|-------------|
| **Live Host Discovery** | Uses `nmap -sn` with fallback to `fping` to find responsive hosts in a CIDR range. |
| **Focused Port Scan** | Scans 25 interesting ports with service version detection (`-sV`). |
| **Service‑Specific Enumeration** | Automatically runs the most relevant tools for each open port. |
| **Auto‑Install Dependencies** | Checks for missing tools and installs them via `apt` (sudo required). |
| **Live Terminal Output** | Shows progress and key findings as they happen (coloured for readability). |
| **Modular Output** | Each enumeration command saves its output to a separate `.txt` file. |
| **Detailed Markdown Report** | Generates a `SUMMARY.md` with statistics, per‑host details, and full command outputs. |
| **Multi‑Target Support** | Can process a list of targets from a file (`-f`). |
| **Custom Output Directory** | Specify a custom directory with `-o`. |
| **Lightweight & Fast** | Uses standard tools and parallelisable (though runs sequentially for reliability). |

---

## 🛠️ Installation

### Prerequisites

- **Python 3.6+** (with standard library).
- **Nmap**, **finger**, **rpcbind**, **nfs-common**, **smbclient**, **enum4linux**, **ldap-utils**, **curl**, **netcat-openbsd** – the script will attempt to install them automatically if missing.
- **Root/sudo privileges** (for installing dependencies and for some scans).

### Step 1: Clone the repository

```bash
git clone [https://github.com/yourusername/auto-service-enum.git](https://github.com/yourusername/auto-service-enum.git)
cd auto-service-enum
```

### Step 2: Make the script executable

```bash
chmod +x auto_enum.py
```

### Step 3: Run with a target (the script will prompt for sudo if needed)

```bash
python3 auto_enum.py 192.168.1.0/24
```

If dependencies are missing, the script will attempt to install them automatically (requires sudo permission).

---

## 🚀 Usage

### Basic Usage

```bash
python3 auto_enum.py <target>
```

Where `<target>` can be:
- A single IP: `192.168.1.1`
- A domain: `example.com`
- A CIDR range: `192.168.1.0/24`

### Advanced Options

| Argument | Description |
|----------|-------------|
| `target` | IP, domain, or CIDR range (required unless `-f` is used). |
| `-o, --output` | Custom output directory (default: `enum_results_<timestamp>`). |
| `-f, --file` | File containing a list of targets (one per line). Each target will be processed sequentially. |

### Examples

```bash
# Scan a single IP
python3 auto_enum.py 192.168.1.10

# Scan a CIDR range
python3 auto_enum.py 192.168.1.0/24

# Use a custom output directory
python3 auto_enum.py 10.0.0.0/24 -o my_scan

# Process multiple targets from a file
python3 auto_enum.py -f targets.txt
```

---

## 🖥️ Example Terminal Output

```text
======================================================================
🚀 AUTO SERVICE ENUMERATION STARTED
======================================================================
Target: 192.168.1.0/24
Output Directory: enum_results_20260101_120000
   ✅ All required tools are already installed.

======================================================================
📡 DISCOVERING LIVE HOSTS IN 192.168.1.0/24
======================================================================
   ℹ️  Running: nmap -sn 192.168.1.0/24 -oG - | grep 'Host:' | awk '{print $2}'
   ✅ Found 3 live host(s):
      • 192.168.1.1
      • 192.168.1.10
      • 192.168.1.20
   ✅ Live hosts saved to: enum_results_20260101_120000/live_hosts.txt

======================================================================
📝 [1/3] SCANNING 192.168.1.1
======================================================================
   ℹ️  Scanning ports on 192.168.1.1...
   ✅ Found 5 open interesting ports:
      • Port 22: ssh (OpenSSH 7.4)
      • Port 80: http (Apache httpd 2.4.6)
      • Port 443: https (Apache httpd 2.4.6)
      • Port 139: netbios-ssn (Samba smbd 3.X)
      • Port 445: netbios-ssn (Samba smbd 3.X)

   Enumerating port 22 (ssh (OpenSSH 7.4))
   ✅ SSH banner saved (enum_results_.../ssh_banner_192.168.1.1.txt)
      SSH-2.0-OpenSSH_7.4

   Enumerating port 80 (http (Apache httpd 2.4.6))
   ✅ HTTP headers saved (enum_results_.../http_banner_192.168.1.1_80_headers.txt)
      HTTP/1.1 200 OK
      Server: Apache/2.4.6 (CentOS)
      ...
   ✅ HTTP root page sample saved (enum_results_.../http_banner_192.168.1.1_80_root.txt)
      <html>...</html>
   ℹ️  robots.txt not found or empty

   Enumerating port 443 (https (Apache httpd 2.4.6))
   ... (similar)

   Enumerating port 139 (netbios-ssn (Samba smbd 3.X))
   ℹ️  Running enum4linux -a (full aggressive scan, may take time)...
   ✅ enum4linux -a saved (enum_results_.../enum4linux_192.168.1.1_a.txt)
      Found 2 users: root, smith
      Found shares: public, IPC$
   ✅ smbclient -L saved (enum_results_.../smbclient_192.168.1.1_list.txt)
      Sharename       Type      Comment
      ---------       ----      -------
      public          Disk      Public Share
      IPC$            IPC       IPC Service

   Enumerating port 445 ... (similar to 139)

======================================================================
📝 [2/3] SCANNING 192.168.1.10
======================================================================
   ...
```

After completion, the script generates a detailed `SUMMARY.md` in the output directory.

---

## ⚙️ How It Works (Flow Diagram)

```text
┌────────────────────────────────────────────────────────────────────────┐
│                            START SCAN                                 │
│         Target provided: IP, domain, CIDR, or file list              │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              STEP 0: DEPENDENCY CHECK & AUTO-INSTALL                  │
│   - Check if required tools (nmap, finger, rpcinfo, etc.) exist.     │
│   - If missing, run `sudo apt install -y <packages>`.                │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              STEP 1: DISCOVER LIVE HOSTS                              │
│   - For CIDR ranges: run `nmap -sn` to ping sweep.                   │
│   - Fallback to `fping -ag` if nmap fails.                           │
│   - For single IP/domain: resolve and skip sweep.                    │
│   - Save IPs to `live_hosts.txt`.                                    │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              STEP 2: PER‑HOST PORT SCAN & ENUMERATION                │
│   For each live host:                                                │
│   ┌──────────────────────────────────────────────────────────────────┐ │
│   │ 2.1 Port Scan (nmap) – scan 25 interesting ports with -sV.    │ │
│   │     Save XML output. Parse to get open ports and service names.│ │
│   └──────────────────────────────────────────────────────────────────┘ │
│                                    │                                   │
│                                    ▼                                   │
│   ┌──────────────────────────────────────────────────────────────────┐ │
│   │ 2.2 For each open port, run the appropriate enumeration        │ │
│   │     tools (see table below).                                   │ │
│   │     - Each tool's output is saved to a separate .txt file.     │ │
│   │     - Key findings are printed live to the terminal.          │ │
│   │     - Data is stored in `self.host_data` for the summary.     │ │
│   └──────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              STEP 3: GENERATE DETAILED SUMMARY                        │
│   - Create `SUMMARY.md` in the output directory.                     │
│   - Write overview statistics (live hosts, open ports, findings).   │
│   - For each host:                                                  │
│        * Table of open ports.                                       │
│        * Full outputs of all enumeration commands (grouped by port).│
│        * Summary of findings (e.g., "users found", "shares found"). │
│   - List all generated files with sizes.                            │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       SCAN COMPLETE                                   │
│          All results saved; summary available.                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Port‑to‑Enumeration Mapping

| Port(s) | Tools Run |
|---------|-----------|
| **79** | `finger -l`, `finger -s`, `finger -p` (long, short, plan) |
| **111** | `rpcinfo -p`, `rpcinfo -s`, `rpcinfo -t 100000` (portmap test), `showmount -e`, `showmount -a`, `showmount -d` |
| **139, 445** | `enum4linux -a` (or `-U`, `-S`, `-G` if aggressive fails), `smbclient -L`, `smbclient` null session on `IPC$` |
| **389** | `ldapsearch` to get base DN, then full dump of all entries |
| **22** | `nc` banner grab |
| **21** | `nc` banner grab |
| **80, 443, 8080, 8443** | `curl -I` for headers, `curl` for root page sample, `curl` for `/robots.txt` |
| **Others** | `nc` banner grab |

---

## 📁 Output Structure

After a scan, a timestamped directory (or custom name) is created:

```text
enum_results_YYYYMMDD_HHMMSS/
├── live_hosts.txt                           # List of discovered IPs
├── SUMMARY.md                               # Comprehensive report
├── nmap_192_168_1_1.xml                     # Nmap XML for host 192.168.1.1
├── finger_192.168.1.1_long.txt             # finger -l output
├── finger_192.168.1.1_short.txt            # finger -s output
├── finger_192.168.1.1_plan.txt             # finger -p output
├── rpcinfo_192.168.1.1_p.txt               # rpcinfo -p
├── rpcinfo_192.168.1.1_s.txt               # rpcinfo -s
├── rpcinfo_192.168.1.1_t.txt               # rpcinfo -t
├── showmount_192.168.1.1_e.txt             # showmount -e
├── showmount_192.168.1.1_a.txt             # showmount -a
├── showmount_192.168.1.1_d.txt             # showmount -d
├── enum4linux_192.168.1.1_a.txt            # enum4linux -a
├── enum4linux_192.168.1.1_U.txt            # enum4linux -U (if -a failed)
├── smbclient_192.168.1.1_list.txt          # smbclient -L
├── smbclient_192.168.1.1_ipc.txt           # smbclient null session on IPC$
├── ldapsearch_192.168.1.1_base.txt         # ldapsearch base DN
├── ldapsearch_192.168.1.1_dump.txt         # full LDAP dump
├── ssh_banner_192.168.1.1.txt              # SSH banner
├── ftp_banner_192.168.1.1.txt              # FTP banner
├── http_banner_192.168.1.1_80_headers.txt  # HTTP headers (port 80)
├── http_banner_192.168.1.1_80_root.txt     # root page sample
├── http_banner_192.168.1.1_80_robots.txt   # robots.txt (if present)
├── banner_192.168.1.1_25.txt               # generic banner for other ports
└── ...                                    # files for other hosts
```

---

## ⚙️ Configuration

The script is highly customizable by editing the source code.

| Setting | Location | Description |
|---------|----------|-------------|
| **Interesting ports** | `self.interesting_ports` in `__init__` | Add/remove ports to scan. |
| **Service‑to‑tool mapping** | Inside `enumerate_port()` | Change which tools run for each port. |
| **Tool command lines** | Individual `_run_*` methods | Modify flags, timeouts, output formats. |
| **Timeout for long commands** | `timeout=300` in `_run_enum4linux` | Adjust for slower networks. |
| **Output directory** | `-o` command‑line argument | Set custom name. |

To add a new service enumeration (e.g., for port 3306 – MySQL), you would:
1. Add a new method `_run_mysql(ip)`.
2. In `enumerate_port()`, add an `elif port == 3306: self._run_mysql(ip)`.

---

## 🧪 Troubleshooting

| Issue | Solution |
|-------|----------|
| `sudo: command not found` | Run as root or ensure `sudo` is installed. |
| Permission denied when installing packages | The script needs `sudo` to install dependencies. Run with a user that has `sudo` rights. |
| `nmap` ping sweep finds no hosts | Try using a different ping method (e.g., `-Pn` to skip host discovery). You can edit the `discover_hosts()` method to use different flags. |
| `enum4linux` times out | Increase the timeout in `_run_enum4linux` or use individual modules (`-U`, `-S`, `-G`) which are faster. |
| No output from `finger` | The host may not run the finger daemon. This is normal. |
| LDAP dump fails | The base DN may not be accessible anonymously. Try with credentials if known. |
| HTTP root page sample truncated | The `head -10` limits the output to 10 lines; you can increase this. |
| The summary report is huge | The report includes full command outputs, which can be lengthy. To reduce size, you can modify the report generation to only show key findings (like count of users, shares). |
| Files are not saved | Ensure write permissions in the output directory. |

---

## 📦 Dependencies

### System Tools (auto‑installed if missing)
- `nmap`
- `finger`
- `rpcbind` (provides `rpcinfo`)
- `nfs-common` (provides `showmount`)
- `smbclient`
- `enum4linux`
- `ldap-utils` (provides `ldapsearch`)
- `curl`
- `netcat-openbsd` (provides `nc`)

### Python
Only standard library modules (`subprocess`, `os`, `sys`, `time`, `re`, `socket`, `shutil`, `xml.etree.ElementTree`, `datetime`, `argparse`).

---

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is intended for educational and authorised testing purposes only.
Use it only on systems you own or have explicit written permission to test. Unauthorised scanning and enumeration may violate laws and terms of service. The authors are not responsible for any misuse, damage, or legal consequences arising from the use of this software. Always comply with applicable laws and regulations.

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit them (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

### Contribution Ideas
- Add support for more services (MySQL, PostgreSQL, Redis, etc.).
- Implement parallel processing of hosts to speed up large scans.
- Generate HTML reports in addition to Markdown.
- Add CVE lookup for detected service versions.
- Allow custom script lists for enumeration.
- Improve error handling and retry logic.

Please ensure your code follows the existing style and includes appropriate comments. For major changes, open an issue first to discuss.

---

## 📚 Resources

- [Nmap Documentation](https://nmap.org/docs.html)
- [Enum4linux Guide](https://github.com/C246/enum4linux)
- [SMBClient Manual](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [Finger Protocol](https://datatracker.ietf.org/doc/html/rfc1288)
- [RPCMap (showmount)](https://linux.die.net/man/8/showmount)

---

## 📊 Badges

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://)
[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](http://makeapullrequest.com)

---

## 👨‍💻 Author

Your Name  
GitHub: [@yourusername](https://github.com/)  
Twitter: [@yourtwitter](https://twitter.com/)  

---

## 🙏 Acknowledgments

- **Nmap developers** – for the versatile port scanner.
- **Samba team** – for enum4linux and smbclient.
- **Open‑source community** – for the myriad of tools that make network enumeration possible.

---

## 📌 Final Notes

### Quick Start

```bash
# Clone and run
git clone [https://github.com/yourusername/auto-service-enum.git](https://github.com/yourusername/auto-service-enum.git)
cd auto-service-enum
chmod +x auto_enum.py
python3 auto_enum.py 192.168.1.0/24
```

### Pro Tips
- **Use `-o` to organise scans** by project.
- **Review `SUMMARY.md` first** – it contains the most important information.
- **Combine with other tools** – use the discovered shares or users for further exploitation.
- **Run as root for best results** (some tools require raw sockets).
- **Be patient** – `enum4linux -a` can take a few minutes per host.

Made with ❤️ for the Security Community

[![Security Community](https://img.shields.io/badge/security-community-blue)](https://)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](http://makeapullrequest.com)
