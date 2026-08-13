#!/usr/bin/env bash
# Setup script for Auto Service Enumeration Tool

set -e

echo -e "\n[+] Auto Service Enumeration Tool Setup\n"

# Update package lists
echo "[+] Updating package lists..."
sudo apt update -qq

# Install required system packages
echo "[+] Installing required tools (nmap, finger, rpcbind, nfs-common, smbclient, enum4linux, ldap-utils, curl, netcat-openbsd)..."
sudo apt install -y \
    nmap \
    finger \
    rpcbind \
    nfs-common \
    smbclient \
    enum4linux \
    ldap-utils \
    curl \
    netcat-openbsd \
    python3 \
    python3-pip

# Make the main script executable
if [ -f "auto_enum.py" ]; then
    chmod +x auto_enum.py
    echo "[+] Made auto_enum.py executable"
else
    echo "[!] auto_enum.py not found in current directory."
    echo "    Please rename your script to auto_enum.py or adjust the shebang."
fi

echo -e "\n[+] Setup complete! You can now run the enumerator:\n"
echo "    python3 auto_enum.py 192.168.1.0/24"
echo "    or"
echo "    ./auto_enum.py 192.168.1.0/24"
echo
echo "    To use a file with multiple targets:"
echo "    python3 auto_enum.py -f targets.txt"
