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
bash playbook/install_dependencies.sh
```

Run the installer as your normal user; it refuses to run as root and may request only the specific administrative actions it needs. Review the script before use. It auto-detects supported package managers.

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
sudo pacman -Syu \
    python python-pip go \
    git curl wget nmap masscan \
    whois bind jq hashdeep ssdeep \
    wkhtmltopdf pandoc sqlite
```

### Step 2 — Python OSINT tools

Use an isolated virtual environment for Python command-line tools. This keeps
OS-managed Python packages intact and avoids bypassing the distribution's
externally-managed-environment protections. Create and activate one environment
in the current shell, then use it for the Python installs in the following steps;
reactivate it in each new shell.

```bash
python3 -m venv ~/.venvs/osint-tools
source ~/.venvs/osint-tools/bin/activate
python -m pip install --upgrade pip
python -m pip install \
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

Use the [official PhoneInfoga installation guide](https://github.com/sundowndev/phoneinfoga/blob/master/docs/getting-started/install.md)
and its [GitHub releases](https://github.com/sundowndev/phoneinfoga/releases). Select a
specific release and matching OS/architecture asset, verify it using the checksum
published for that release, and inspect the extracted binary/version before placing
it on your `PATH`. Avoid piping a moving `master`-branch script directly into a
shell. If you use the project's installer, download and inspect the script first,
then verify the release artifact against its published checksum.

### Step 5 — theHarvester (from source)

```bash
git clone https://github.com/laramies/theHarvester.git ~/.config/osint-investigator/tools/theHarvester
python -m pip install -r ~/.config/osint-investigator/tools/theHarvester/requirements/base.txt
sudo ln -sf ~/.config/osint-investigator/tools/theHarvester/theHarvester.py /usr/local/bin/theHarvester
```

### Step 6 — Optional tools

**SpiderFoot**
```bash
git clone https://github.com/smicallef/spiderfoot.git ~/.config/osint-investigator/tools/spiderfoot
python -m pip install -r ~/.config/osint-investigator/tools/spiderfoot/requirements.txt
```

**Blackbird** (username OSINT)
```bash
git clone https://github.com/p1ngul1n0/blackbird.git ~/.config/osint-investigator/tools/blackbird
python -m pip install -r ~/.config/osint-investigator/tools/blackbird/requirements.txt
```

**ASN Lookup**

The upstream project is [nitefood/asn](https://github.com/nitefood/asn). Follow its
documented installation process and inspect the source before use. Do not pipe a
moving branch directly into a privileged system path; verify a pinned release and
its published checksums or signatures when available.

---

## Configure API Keys

Use the script's interactive configuration command. It creates or updates the
private user config at `~/.config/osint-investigator/api_keys.conf` and applies
restrictive permissions.

```bash
./playbook/osint_investigator.sh --config
```

Do not store real API keys in the repository or edit a tracked configuration file.

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
