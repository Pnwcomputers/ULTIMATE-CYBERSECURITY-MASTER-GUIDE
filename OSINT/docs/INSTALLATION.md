# Installation Guide

## System Requirements

### Minimum Requirements
- **Operating System**: Tsurugi Linux, Kali Linux, Ubuntu 22.04+, Debian 12+, Parrot OS, or Arch/Manjaro
- **RAM**: 4 GB minimum, 8 GB recommended
- **Storage**: 5 GB free space for tools and case data
- **Network**: Internet connection for API calls and tool installation

### Recommended Requirements
- **RAM**: 8–16 GB for running multiple scans in parallel
- **Storage**: SSD for faster nmap/nuclei output writing
- **Network**: Broadband connection (10+ Mbps) for parallel API queries

---

## Quick Install (Debian/Ubuntu/Kali)

```bash
git clone https://github.com/PNW-Computers/osint.git
cd osint
sudo bash playbook/install_dependencies.sh
```

The installer auto-detects your distro and handles apt, dnf, or pacman accordingly.

---

## Manual Installation

### Step 1 — Core system packages

**Debian / Ubuntu / Kali / Tsurugi**
```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    golang-go git curl wget \
    nmap masscan whois dnsutils \
    jq hashdeep ssdeep wkhtmltopdf pandoc sqlite3 \
    libffi-dev libssl-dev build-essential
```

**Fedora / RHEL / CentOS**
```bash
sudo dnf install -y \
    python3 python3-pip golang \
    git curl wget nmap \
    whois bind-utils jq \
    wkhtmltopdf pandoc sqlite \
    libffi-devel openssl-devel gcc make
```

**Arch / Manjaro**
```bash
sudo pacman -Sy --noconfirm \
    python python-pip go \
    git curl wget nmap masscan \
    whois bind jq hashdeep ssdeep \
    wkhtmltopdf pandoc sqlite
```

### Step 2 — Python OSINT tools

```bash
pip3 install --break-system-packages \
    holehe h8mail maigret sherlock \
    waybackpy phonenumbers requests \
    beautifulsoup4 python-whois dnspython \
    shodan censys
```

### Step 3 — Go tools (ProjectDiscovery suite)

```bash
export GOPATH="${HOME}/go"
export PATH="${PATH}:${GOPATH}/bin"

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/assetfinder@latest
```

Add to `~/.bashrc`:
```bash
echo 'export GOPATH="${HOME}/go"' >> ~/.bashrc
echo 'export PATH="${PATH}:${GOPATH}/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Step 4 — PhoneInfoga

```bash
curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash
sudo mv phoneinfoga /usr/local/bin/
```

### Step 5 — theHarvester (from source)

```bash
git clone https://github.com/laramies/theHarvester.git ~/.config/osint-investigator/tools/theHarvester
pip3 install -r ~/.config/osint-investigator/tools/theHarvester/requirements/base.txt --break-system-packages
sudo ln -sf ~/.config/osint-investigator/tools/theHarvester/theHarvester.py /usr/local/bin/theHarvester
```

### Step 6 — Optional tools

**SpiderFoot**
```bash
git clone https://github.com/smicallef/spiderfoot.git ~/.config/osint-investigator/tools/spiderfoot
pip3 install -r ~/.config/osint-investigator/tools/spiderfoot/requirements.txt --break-system-packages
```

**Blackbird** (username OSINT)
```bash
git clone https://github.com/p1ngul1n0/blackbird.git ~/.config/osint-investigator/tools/blackbird
pip3 install -r ~/.config/osint-investigator/tools/blackbird/requirements.txt --break-system-packages
```

**ASN Lookup**
```bash
curl -s https://raw.githubusercontent.com/nitefood/asn/master/asn | sudo tee /usr/bin/asn > /dev/null
sudo chmod +x /usr/bin/asn
```

---

## Configure API Keys

```bash
mkdir -p ~/.config/osint-investigator
cp playbook/api_keys.conf ~/.config/osint-investigator/api_keys.conf
chmod 600 ~/.config/osint-investigator/api_keys.conf
nano ~/.config/osint-investigator/api_keys.conf
```

Or use the interactive config wizard:
```bash
./playbook/osint_investigator.sh --config
```

---

## Verify Installation

```bash
./playbook/osint_investigator.sh --status
```

This checks all tools and API key status in one pass.

---

## Update Nuclei Templates

```bash
nuclei -ut
```

Run this periodically to keep vulnerability templates current.
