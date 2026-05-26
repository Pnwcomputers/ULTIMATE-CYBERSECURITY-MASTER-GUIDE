#!/usr/bin/env bash
# =============================================================================
#  PNWC ULTIMATE CYBERSECURITY MASTER GUIDE — Linux Tool Installer
#  github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE
# =============================================================================
#  Supports: Debian · Ubuntu · Kali · Parrot · BackBox (apt)
#            Arch · BlackArch · Manjaro  (pacman / blackarch repo)
#            Fedora · RHEL · CentOS · Rocky (dnf/yum)
# =============================================================================
#  Usage:
#    chmod +x pnwc_install_tools.sh
#    sudo ./pnwc_install_tools.sh [OPTIONS]
#
#  Options:
#    --all          Install every category (default)
#    --recon        Recon & OSINT only
#    --web          Web application tools only
#    --network      Network tools only
#    --exploit      Exploitation frameworks only
#    --password     Password & credential tools only
#    --wireless     Wireless tools only
#    --forensics    Forensics & RE tools only
#    --defense      IDS/IPS & monitoring tools only
#    --dev          Development dependencies only
#    --help         Show this help
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Globals ───────────────────────────────────────────────────────────────────
LOGFILE="/var/log/pnwc_install_$(date +%Y%m%d_%H%M%S).log"
INSTALL_DIR="/opt/pnwc-tools"
FAILED_TOOLS=()
SKIPPED_TOOLS=()

# ── Helper functions ──────────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
  ██████╗ ███╗   ██╗██╗    ██╗ ██████╗
  ██╔══██╗████╗  ██║██║    ██║██╔════╝
  ██████╔╝██╔██╗ ██║██║ █╗ ██║██║
  ██╔═══╝ ██║╚██╗██║██║███╗██║██║
  ██║     ██║ ╚████║╚███╔███╔╝╚██████╗
  ╚═╝     ╚═╝  ╚═══╝ ╚══╝╚══╝  ╚═════╝
  ULTIMATE CYBERSECURITY MASTER GUIDE
  Cross-Distro Tool Installer v2.0
EOF
    echo -e "${RESET}"
}

info()    { echo -e "${CYAN}[*]${RESET} $*" | tee -a "$LOGFILE"; }
ok()      { echo -e "${GREEN}[+]${RESET} $*" | tee -a "$LOGFILE"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOGFILE"; }
error()   { echo -e "${RED}[-]${RESET} $*" | tee -a "$LOGFILE"; }
section() { echo -e "\n${BOLD}${YELLOW}══ $* ══${RESET}\n" | tee -a "$LOGFILE"; }

usage() {
    echo -e "${BOLD}Usage:${RESET} sudo $0 [OPTIONS]"
    grep '^#    --' "$0" | sed 's/#/   /'
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# ── Distro detection ──────────────────────────────────────────────────────────
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        DISTRO_ID="${ID,,}"
        DISTRO_LIKE="${ID_LIKE,,:-}"
    else
        DISTRO_ID="unknown"
        DISTRO_LIKE=""
    fi

    # Normalise to a package-manager family
    if [[ "$DISTRO_ID" =~ ^(kali|parrot|ubuntu|debian|backbox|linuxmint|pop|elementary)$ ]] \
       || [[ "$DISTRO_LIKE" =~ debian|ubuntu ]]; then
        PKG_MGR="apt"
    elif [[ "$DISTRO_ID" =~ ^(arch|blackarch|manjaro|garuda|endeavouros)$ ]] \
         || [[ "$DISTRO_LIKE" =~ arch ]]; then
        PKG_MGR="pacman"
    elif [[ "$DISTRO_ID" =~ ^(fedora|rhel|centos|rocky|alma|ol)$ ]] \
         || [[ "$DISTRO_LIKE" =~ fedora|rhel ]]; then
        PKG_MGR="dnf"
    else
        warn "Unrecognised distro '$DISTRO_ID'. Attempting apt…"
        PKG_MGR="apt"
    fi

    info "Detected distro: ${BOLD}$DISTRO_ID${RESET} → package manager: ${BOLD}$PKG_MGR${RESET}"
}

# ── Package manager wrappers ──────────────────────────────────────────────────
pkg_update() {
    info "Updating package index…"
    case "$PKG_MGR" in
        apt)    apt-get update -qq ;;
        pacman) pacman -Sy --noconfirm ;;
        dnf)    dnf check-update -q || true ;;
    esac
}

# Install one or more packages, swallowing errors per-package
pkg_install() {
    for pkg in "$@"; do
        info "  Installing package: $pkg"
        case "$PKG_MGR" in
            apt)
                if apt-get install -y -qq "$pkg" >> "$LOGFILE" 2>&1; then
                    ok "  $pkg installed"
                else
                    warn "  $pkg not found in apt repos — skipping"
                    SKIPPED_TOOLS+=("$pkg")
                fi
                ;;
            pacman)
                if pacman -S --noconfirm --needed "$pkg" >> "$LOGFILE" 2>&1; then
                    ok "  $pkg installed"
                else
                    warn "  $pkg not found in pacman repos — skipping"
                    SKIPPED_TOOLS+=("$pkg")
                fi
                ;;
            dnf)
                if dnf install -y -q "$pkg" >> "$LOGFILE" 2>&1; then
                    ok "  $pkg installed"
                else
                    warn "  $pkg not found in dnf repos — skipping"
                    SKIPPED_TOOLS+=("$pkg")
                fi
                ;;
        esac
    done
}

# pip install — always user-safe, never fails the script
pip_install() {
    for pkg in "$@"; do
        info "  pip install: $pkg"
        if pip3 install --quiet "$pkg" >> "$LOGFILE" 2>&1; then
            ok "  $pkg (pip) installed"
        else
            warn "  pip failed for $pkg"
            FAILED_TOOLS+=("pip:$pkg")
        fi
    done
}

# go install — requires go in PATH
go_install() {
    local pkg="$1"
    if ! command -v go &>/dev/null; then
        warn "Go not in PATH — skipping $pkg"
        SKIPPED_TOOLS+=("go:$pkg")
        return
    fi
    info "  go install: $pkg"
    if GOPATH=/opt/go go install "$pkg" >> "$LOGFILE" 2>&1; then
        ok "  $pkg (go) installed"
    else
        warn "  go install failed for $pkg"
        FAILED_TOOLS+=("go:$pkg")
    fi
}

# git clone a tool into $INSTALL_DIR
git_clone_tool() {
    local name="$1"
    local url="$2"
    local target="$INSTALL_DIR/$name"
    if [[ -d "$target" ]]; then
        info "  $name already cloned — pulling latest"
        git -C "$target" pull -q >> "$LOGFILE" 2>&1 || true
    else
        info "  Cloning $name from $url"
        git clone --depth=1 -q "$url" "$target" >> "$LOGFILE" 2>&1 \
            && ok "  $name cloned to $target" \
            || { warn "  Failed to clone $name"; FAILED_TOOLS+=("git:$name"); }
    fi
}

# Create a symlink in /usr/local/bin for a python script
make_symlink() {
    local name="$1"
    local path="$2"
    if [[ -f "$path" ]]; then
        chmod +x "$path"
        ln -sf "$path" "/usr/local/bin/$name" && ok "  Symlink: /usr/local/bin/$name → $path"
    fi
}

# ── Setup BlackArch / Kali extra repos ───────────────────────────────────────
setup_extra_repos() {
    section "Extra Repository Setup"
    case "$PKG_MGR" in
        apt)
            # Kali rolling already has everything; for Ubuntu/Debian add Kali repo tools
            if [[ "$DISTRO_ID" != "kali" ]] && [[ "$DISTRO_ID" != "parrot" ]]; then
                warn "Non-Kali Debian-based system detected."
                warn "Some tools may be unavailable. Consider using Kali/Parrot for full coverage."
            fi
            ;;
        pacman)
            if ! grep -q '\[blackarch\]' /etc/pacman.conf 2>/dev/null; then
                info "Adding BlackArch repository…"
                curl -qO https://blackarch.org/strap.sh >> "$LOGFILE" 2>&1
                chmod +x strap.sh
                bash strap.sh >> "$LOGFILE" 2>&1 && ok "BlackArch repo added" \
                    || warn "BlackArch strap.sh failed — continuing without it"
                rm -f strap.sh
            else
                ok "BlackArch repo already configured"
            fi
            ;;
        dnf)
            # Enable EPEL for extra packages on RHEL-based
            dnf install -y -q epel-release >> "$LOGFILE" 2>&1 || true
            ok "EPEL repo enabled (if applicable)"
            ;;
    esac
}

# ── Directory setup ───────────────────────────────────────────────────────────
setup_dirs() {
    mkdir -p "$INSTALL_DIR"/{osint,wireless,exploit,forensics,wordlists,web}
    ok "Created tool directories under $INSTALL_DIR"
}

# =============================================================================
#  INSTALLATION CATEGORIES
# =============================================================================

# ── 1. Development dependencies ───────────────────────────────────────────────
install_dev() {
    section "Development Dependencies"
    case "$PKG_MGR" in
        apt)
            pkg_install \
                build-essential git curl wget python3 python3-pip python3-venv \
                python3-dev libssl-dev libffi-dev ruby ruby-dev gem golang \
                nodejs npm cargo rustup libpcap-dev libnet1-dev libnl-3-dev \
                libnl-genl-3-dev cmake automake autoconf libtool pkg-config \
                swig zlib1g-dev libusb-dev libusb-1.0-0-dev default-jre \
                default-jdk docker.io docker-compose jq vim tmux screen
            ;;
        pacman)
            pkg_install \
                base-devel git curl wget python python-pip python-virtualenv \
                ruby go nodejs npm rust cmake automake autoconf libtool \
                libpcap libnet libnl swig zlib libusb jre-openjdk \
                jdk-openjdk docker docker-compose jq vim tmux screen
            ;;
        dnf)
            pkg_install \
                "@Development Tools" git curl wget python3 python3-pip \
                python3-devel openssl-devel libffi-devel ruby ruby-devel \
                golang nodejs npm cargo cmake automake autoconf libtool \
                libpcap-devel libnl3-devel swig zlib-devel libusb-devel \
                java-17-openjdk docker docker-compose jq vim tmux screen
            ;;
    esac

    # Upgrade pip
    pip3 install --quiet --upgrade pip setuptools wheel >> "$LOGFILE" 2>&1
    ok "pip upgraded"

    # Go path
    mkdir -p /opt/go/{bin,pkg,src}
    export GOPATH=/opt/go
    export PATH="$PATH:/opt/go/bin"
    ok "GOPATH set to /opt/go"
}

# ── 2. Recon & OSINT ──────────────────────────────────────────────────────────
install_recon() {
    section "Reconnaissance & OSINT Tools"

    # Package manager
    case "$PKG_MGR" in
        apt)    pkg_install nmap masscan dnsutils whois traceroute netdiscover \
                            recon-ng theharvester amass maltego spiderfoot ;;
        pacman) pkg_install nmap masscan dnsutils whois traceroute netdiscover \
                            recon-ng theharvester amass ;;
        dnf)    pkg_install nmap masscan bind-utils whois traceroute netdiscover ;;
    esac

    # Python OSINT tools
    pip_install \
        theHarvester \
        shodan \
        censys \
        holehe \
        maigret \
        h8mail \
        "git+https://github.com/s0md3v/Photon.git" \
        osrframework \
        phoneinfoga \
        metagoofil

    # Sherlock
    git_clone_tool "sherlock" "https://github.com/sherlock-project/sherlock.git"
    make_symlink "sherlock" "$INSTALL_DIR/sherlock/sherlock/sherlock.py"

    # SpiderFoot (if not in packages)
    if ! command -v spiderfoot &>/dev/null; then
        git_clone_tool "spiderfoot" "https://github.com/smicallef/spiderfoot.git"
        pip3 install -q -r "$INSTALL_DIR/spiderfoot/requirements.txt" >> "$LOGFILE" 2>&1
        make_symlink "spiderfoot" "$INSTALL_DIR/spiderfoot/sf.py"
    fi

    # PhoneInfoga (Go binary)
    go_install "github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest"

    # Amass (Go)
    go_install "github.com/owasp-amass/amass/v4/...@master"

    # Subfinder (Go — ProjectDiscovery)
    go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

    # httpx (Go — ProjectDiscovery)
    go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"

    # dnsx (Go — ProjectDiscovery)
    go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

    # katana (Go — ProjectDiscovery web crawler)
    go_install "github.com/projectdiscovery/katana/cmd/katana@latest"

    # Recon-ng
    git_clone_tool "recon-ng" "https://github.com/lanmaster53/recon-ng.git"
    pip3 install -q -r "$INSTALL_DIR/recon-ng/REQUIREMENTS" >> "$LOGFILE" 2>&1
    make_symlink "recon-ng" "$INSTALL_DIR/recon-ng/recon-ng"

    ok "Recon & OSINT tools installed"
}

# ── 3. Network Tools ──────────────────────────────────────────────────────────
install_network() {
    section "Network Analysis & Attack Tools"

    case "$PKG_MGR" in
        apt)
            pkg_install \
                wireshark tshark tcpdump netcat-openbsd ncat socat \
                bettercap arpwatch net-tools iproute2 iputils-ping \
                nmap masscan p0f ettercap-text-only dsniff hping3 \
                yersinia macchanger proxychains4 sshuttle \
                openvpn wireguard tor torsocks
            ;;
        pacman)
            pkg_install \
                wireshark-qt tshark tcpdump openbsd-netcat ncat socat \
                bettercap arpwatch net-tools iproute2 iputils \
                nmap masscan p0f ettercap dsniff hping macchanger \
                proxychains-ng sshuttle openvpn wireguard-tools tor
            ;;
        dnf)
            pkg_install \
                wireshark tshark tcpdump ncat socat net-tools iproute \
                nmap masscan hping3 macchanger proxychains-ng openvpn tor
            ;;
    esac

    # Bettercap (Go)
    if ! command -v bettercap &>/dev/null; then
        go_install "github.com/bettercap/bettercap@latest"
    fi

    # Responder
    git_clone_tool "Responder" "https://github.com/lgandx/Responder.git"
    make_symlink "responder" "$INSTALL_DIR/Responder/Responder.py"

    # Impacket
    pip_install impacket

    # CrackMapExec / NetExec
    pip_install crackmapexec netexec

    # Evil-WinRM
    if command -v gem &>/dev/null; then
        gem install evil-winrm --quiet >> "$LOGFILE" 2>&1 && ok "evil-winrm installed" \
            || warn "evil-winrm gem install failed"
    fi

    ok "Network tools installed"
}

# ── 4. Web Application Security ───────────────────────────────────────────────
install_web() {
    section "Web Application Security Tools"

    case "$PKG_MGR" in
        apt)    pkg_install nikto sqlmap dirb dirbuster wfuzz zaproxy ;;
        pacman) pkg_install nikto sqlmap dirb wfuzz ;;
        dnf)    pkg_install nikto sqlmap ;;
    esac

    # Gobuster (Go)
    go_install "github.com/OJ/gobuster/v3@latest"

    # ffuf (Go)
    go_install "github.com/ffuf/ffuf/v2@latest"

    # Nuclei (Go — ProjectDiscovery)
    go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    # Update Nuclei templates
    if command -v nuclei &>/dev/null; then
        nuclei -update-templates -silent >> "$LOGFILE" 2>&1 && ok "Nuclei templates updated"
    fi

    # dalfox (XSS scanner — Go)
    go_install "github.com/hahwul/dalfox/v2@latest"

    # feroxbuster (Rust-based dir buster)
    if command -v cargo &>/dev/null; then
        cargo install feroxbuster --quiet >> "$LOGFILE" 2>&1 && ok "feroxbuster installed" \
            || warn "feroxbuster cargo install failed"
    fi

    # Python web tools
    pip_install \
        sqlmap \
        wfuzz \
        arjun \
        uro \
        "git+https://github.com/s0md3v/Arjun.git"

    # WhatWeb
    if command -v gem &>/dev/null; then
        gem install whatweb --quiet >> "$LOGFILE" 2>&1 && ok "whatweb installed" \
            || warn "whatweb gem install failed"
    fi

    # AutoRecon
    pip_install autorecon

    ok "Web application security tools installed"
}

# ── 5. Exploitation Frameworks ────────────────────────────────────────────────
install_exploit() {
    section "Exploitation Frameworks & Tools"

    case "$PKG_MGR" in
        apt)
            pkg_install metasploit-framework exploitdb \
                        python3-impacket python3-pwntools
            ;;
        pacman)
            pkg_install metasploit exploitdb python-pwntools ;;
        dnf)
            : # Metasploit not in default dnf repos
            ;;
    esac

    # Metasploit installer (universal fallback)
    if ! command -v msfconsole &>/dev/null; then
        info "Installing Metasploit Framework via rapid7 installer…"
        curl -qs https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
             -o /tmp/msfinstall >> "$LOGFILE" 2>&1
        chmod +x /tmp/msfinstall
        /tmp/msfinstall >> "$LOGFILE" 2>&1 && ok "Metasploit installed" \
            || warn "Metasploit install failed — install manually from https://metasploit.com"
    else
        ok "Metasploit already installed"
    fi

    # pwntools
    pip_install pwntools

    # Impacket (Python)
    pip_install impacket

    # PayloadsAllTheThings (reference repo)
    git_clone_tool "PayloadsAllTheThings" \
        "https://github.com/swisskyrepo/PayloadsAllTheThings.git"

    # SecLists (wordlists)
    if [[ ! -d /usr/share/seclists ]] && [[ ! -d "$INSTALL_DIR/SecLists" ]]; then
        git_clone_tool "SecLists" "https://github.com/danielmiessler/SecLists.git"
        ln -sf "$INSTALL_DIR/SecLists" /usr/share/seclists && ok "SecLists linked to /usr/share/seclists"
    else
        ok "SecLists already present"
    fi

    # PEASS-ng (LinPEAS / WinPEAS)
    git_clone_tool "PEASS-ng" "https://github.com/carlospolop/PEASS-ng.git"

    # BloodHound
    case "$PKG_MGR" in
        apt)    pkg_install bloodhound ;;
        pacman) pkg_install bloodhound ;;
        *) warn "BloodHound not auto-installed on this distro — download from https://github.com/BloodHoundAD/BloodHound/releases" ;;
    esac

    # Empire post-exploitation
    git_clone_tool "Empire" "https://github.com/BC-SECURITY/Empire.git"
    if [[ -f "$INSTALL_DIR/Empire/setup/install.sh" ]]; then
        bash "$INSTALL_DIR/Empire/setup/install.sh" >> "$LOGFILE" 2>&1 \
            && ok "Empire installed" || warn "Empire setup failed"
    fi

    # PowerSploit (reference)
    git_clone_tool "PowerSploit" "https://github.com/PowerShellMafia/PowerSploit.git"

    # Nishang (reference)
    git_clone_tool "Nishang" "https://github.com/samratashok/nishang.git"

    # ExploitDB searchsploit
    if ! command -v searchsploit &>/dev/null; then
        git_clone_tool "exploitdb" "https://github.com/offensive-security/exploitdb.git"
        make_symlink "searchsploit" "$INSTALL_DIR/exploitdb/searchsploit"
    fi

    ok "Exploitation frameworks installed"
}

# ── 6. Password & Credential Tools ───────────────────────────────────────────
install_password() {
    section "Password & Credential Tools"

    case "$PKG_MGR" in
        apt)    pkg_install john hydra hashcat medusa crunch \
                            wordlists cewl ;;
        pacman) pkg_install john hydra hashcat medusa crunch cewl ;;
        dnf)    pkg_install john hydra hashcat ;;
    esac

    # Rockyou wordlist
    if [[ ! -f /usr/share/wordlists/rockyou.txt ]] && \
       [[ ! -f /usr/share/wordlists/rockyou.txt.gz ]]; then
        info "Downloading rockyou.txt…"
        mkdir -p /usr/share/wordlists
        curl -qs -L \
            "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
            -o /usr/share/wordlists/rockyou.txt >> "$LOGFILE" 2>&1 \
            && ok "rockyou.txt downloaded" || warn "rockyou.txt download failed"
    else
        ok "rockyou.txt already present"
    fi

    # Mentalist (Go based wordlist generator)
    go_install "github.com/sc0tfree/mentalist@latest" || true

    # Sprayhound / kerbrute
    go_install "github.com/ropnop/kerbrute@latest"

    # Default credential scanner
    pip_install defaultcreds-cheat-sheet

    ok "Password & credential tools installed"
}

# ── 7. Wireless Tools ─────────────────────────────────────────────────────────
install_wireless() {
    section "Wireless & RF Tools"

    case "$PKG_MGR" in
        apt)
            pkg_install aircrack-ng kismet wifite reaver bully \
                        hostapd dnsmasq wireless-tools iw rfkill \
                        hackrf rtl-sdr gqrx gnuradio libhackrf-dev \
                        ubertooth mdk4
            ;;
        pacman)
            pkg_install aircrack-ng kismet wifite reaver hostapd \
                        dnsmasq wireless_tools iw rfkill hackrf \
                        rtl-sdr gqrx gnuradio ubertooth mdk4
            ;;
        dnf)
            pkg_install aircrack-ng kismet hostapd dnsmasq \
                        wireless-tools iw rfkill
            ;;
    esac

    # Wifite2
    git_clone_tool "wifite2" "https://github.com/derv82/wifite2.git"
    make_symlink "wifite2" "$INSTALL_DIR/wifite2/Wifite.py"

    # hcxtools / hcxdumptool (for PMKID attacks)
    if command -v apt &>/dev/null; then
        pkg_install hcxtools hcxdumptool
    else
        git_clone_tool "hcxtools" "https://github.com/ZerBea/hcxtools.git"
        cd "$INSTALL_DIR/hcxtools" && make -j"$(nproc)" install >> "$LOGFILE" 2>&1 || true
    fi

    # Bettercap (already in network, but re-confirm)
    command -v bettercap &>/dev/null && ok "bettercap available for wireless MITM" || true

    # gr-osmosdr (SDR GNU Radio)
    case "$PKG_MGR" in
        apt)    pkg_install gr-osmosdr ;;
        pacman) pkg_install gr-osmosdr ;;
        *) ;;
    esac

    ok "Wireless tools installed"
}

# ── 8. Forensics & Reverse Engineering ───────────────────────────────────────
install_forensics() {
    section "Forensics, Reverse Engineering & Analysis"

    case "$PKG_MGR" in
        apt)
            pkg_install autopsy sleuthkit volatility3 binwalk foremost \
                        strings file exiftool testdisk photorec \
                        radare2 gdb ltrace strace pwndbg \
                        hexedit xxd bless \
                        ghidra jadx apktool dex2jar \
                        yara scalpel
            ;;
        pacman)
            pkg_install autopsy sleuthkit volatility3 binwalk foremost \
                        exiftool testdisk radare2 gdb ltrace strace \
                        ghidra apktool yara
            ;;
        dnf)
            pkg_install sleuthkit binwalk foremost file exiftool \
                        radare2 gdb ltrace strace yara
            ;;
    esac

    # Volatility 3
    if ! command -v vol3 &>/dev/null && ! command -v volatility3 &>/dev/null; then
        git_clone_tool "volatility3" "https://github.com/volatilityfoundation/volatility3.git"
        pip3 install -q -r "$INSTALL_DIR/volatility3/requirements.txt" >> "$LOGFILE" 2>&1
        make_symlink "vol3" "$INSTALL_DIR/volatility3/vol.py"
    fi

    # Ghidra (if not installed via package manager)
    if ! command -v ghidra &>/dev/null && [[ ! -d /opt/ghidra ]]; then
        info "Downloading Ghidra…"
        GHIDRA_VER="11.1.2"
        GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_20240709.zip"
        curl -qs -L "$GHIDRA_URL" -o /tmp/ghidra.zip >> "$LOGFILE" 2>&1 \
            && unzip -q /tmp/ghidra.zip -d /opt/ >> "$LOGFILE" 2>&1 \
            && mv /opt/ghidra_${GHIDRA_VER}_PUBLIC /opt/ghidra 2>/dev/null || true \
            && ln -sf /opt/ghidra/ghidraRun /usr/local/bin/ghidra \
            && ok "Ghidra installed to /opt/ghidra" \
            || warn "Ghidra download failed — install manually from https://ghidra-sre.org"
        rm -f /tmp/ghidra.zip
    else
        ok "Ghidra already installed"
    fi

    # radare2 (from source if package old)
    if ! command -v r2 &>/dev/null; then
        git_clone_tool "radare2" "https://github.com/radareorg/radare2.git"
        bash "$INSTALL_DIR/radare2/sys/install.sh" >> "$LOGFILE" 2>&1 \
            && ok "radare2 built from source" || warn "radare2 build failed"
    fi

    # Python forensics
    pip_install \
        oletools \
        pefile \
        capstone \
        unicorn \
        ropper \
        pwntools \
        r2pipe

    # YARA rules
    git_clone_tool "yara-rules" "https://github.com/Yara-Rules/rules.git"

    ok "Forensics & RE tools installed"
}

# ── 9. Defense / Monitoring / IDS ─────────────────────────────────────────────
install_defense() {
    section "Defense, IDS/IPS & Monitoring Tools"

    case "$PKG_MGR" in
        apt)
            pkg_install snort suricata zeek ossec-hids fail2ban \
                        auditd aide rkhunter chkrootkit lynis \
                        clamav clamav-daemon ufw iptables-persistent \
                        logwatch logcheck rsyslog
            ;;
        pacman)
            pkg_install snort suricata zeek fail2ban \
                        audit aide rkhunter lynis \
                        clamav ufw iptables
            ;;
        dnf)
            pkg_install snort suricata fail2ban audit \
                        aide rkhunter lynis clamav clamav-update \
                        firewalld
            ;;
    esac

    # Wazuh agent (universal installer)
    if ! command -v wazuh-agent &>/dev/null; then
        info "Wazuh agent — see https://documentation.wazuh.com/current/installation-guide/ for your platform"
        warn "Wazuh requires a server endpoint — skipping automated install"
        SKIPPED_TOOLS+=("wazuh-agent")
    fi

    # Update ClamAV signatures
    if command -v freshclam &>/dev/null; then
        freshclam --quiet >> "$LOGFILE" 2>&1 && ok "ClamAV signatures updated" || true
    fi

    # Lynis
    if ! command -v lynis &>/dev/null; then
        git_clone_tool "lynis" "https://github.com/CISOfy/lynis.git"
        make_symlink "lynis" "$INSTALL_DIR/lynis/lynis"
    fi

    ok "Defense & monitoring tools installed"
}

# ── 10. Hardware / Embedded / RF ─────────────────────────────────────────────
install_hardware() {
    section "Hardware, Embedded & RF Tools"

    case "$PKG_MGR" in
        apt)
            pkg_install openocd flashrom binwalk avrdude \
                        python3-serial minicom picocom screen \
                        hackrf rtl-sdr librtlsdr-dev \
                        sdrpp gqrx gr-osmosdr \
                        bluetooth bluez bluez-tools \
                        libusb-dev libusb-1.0-0-dev
            ;;
        pacman)
            pkg_install openocd flashrom binwalk avrdude \
                        python-pyserial minicom picocom \
                        hackrf rtl-sdr bluez bluez-utils libusb
            ;;
        dnf)
            pkg_install openocd flashrom avrdude minicom \
                        bluez libusb-devel
            ;;
    esac

    # ChipWhisperer
    git_clone_tool "chipwhisperer" "https://github.com/newaetech/chipwhisperer.git"
    pip3 install -q -e "$INSTALL_DIR/chipwhisperer/" >> "$LOGFILE" 2>&1 \
        && ok "ChipWhisperer installed" || warn "ChipWhisperer install failed"

    # Bus Pirate scripts / pyserial tools
    pip_install pyserial bitstring

    # Scapy (packet crafting)
    pip_install scapy

    # Bluepy / Bleak for BLE
    pip_install bluepy bleak

    ok "Hardware & RF tools installed"
}

# ── 11. Wordlists & Resources ─────────────────────────────────────────────────
install_wordlists() {
    section "Wordlists & Reference Data"

    mkdir -p /usr/share/wordlists

    # RockYou (already handled in password section, but idempotent)
    [[ ! -f /usr/share/wordlists/rockyou.txt ]] && {
        curl -qs -L \
            "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
            -o /usr/share/wordlists/rockyou.txt >> "$LOGFILE" 2>&1 || true
    }

    # SecLists (large — already handled in exploit section)
    [[ ! -d /usr/share/seclists ]] && [[ ! -d "$INSTALL_DIR/SecLists" ]] && {
        git_clone_tool "SecLists" "https://github.com/danielmiessler/SecLists.git"
        ln -sf "$INSTALL_DIR/SecLists" /usr/share/seclists
    }

    # FuzzDB
    git_clone_tool "fuzzdb" "https://github.com/fuzzdb-project/fuzzdb.git"

    # Assetnote wordlists (small index subset)
    git_clone_tool "commonspeak2-wordlists" \
        "https://github.com/assetnote/commonspeak2-wordlists.git"

    ok "Wordlists installed"
}

# ── 12. PNWC Custom Scripts ───────────────────────────────────────────────────
install_pnwc_scripts() {
    section "PNWC Custom Scripts & Tools"

    # Clone the master guide itself
    git_clone_tool "ULTIMATE-CYBERSECURITY-MASTER-GUIDE" \
        "https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE.git"

    ok "PNWC master guide cloned to $INSTALL_DIR/ULTIMATE-CYBERSECURITY-MASTER-GUIDE"
    info "Playbooks: $INSTALL_DIR/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/PlayBooks/"
    info "Scripts:   $INSTALL_DIR/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/Scripts/"
    info "Checklists:$INSTALL_DIR/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/Checklists/"
}

# =============================================================================
#  FINAL REPORT
# =============================================================================
print_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${GREEN}  INSTALLATION COMPLETE — PNWC MASTER GUIDE TOOLS${RESET}"
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  Tool install dir: ${CYAN}$INSTALL_DIR${RESET}"
    echo -e "  Full log:         ${CYAN}$LOGFILE${RESET}"
    echo ""

    if [[ ${#FAILED_TOOLS[@]} -gt 0 ]]; then
        echo -e "${RED}  Failed installs (${#FAILED_TOOLS[@]}):${RESET}"
        for t in "${FAILED_TOOLS[@]}"; do
            echo -e "    ${RED}✗${RESET} $t"
        done
        echo ""
    fi

    if [[ ${#SKIPPED_TOOLS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}  Skipped / not in repos (${#SKIPPED_TOOLS[@]}):${RESET}"
        for t in "${SKIPPED_TOOLS[@]}"; do
            echo -e "    ${YELLOW}→${RESET} $t"
        done
        echo ""
    fi

    echo -e "${CYAN}  Quick starts:${RESET}"
    echo -e "    msfconsole                   # Metasploit Framework"
    echo -e "    nmap -sV -sC <target>        # Network scan"
    echo -e "    nuclei -u <target>           # Vuln scan"
    echo -e "    gobuster dir -u <url> -w ... # Web enumeration"
    echo -e "    aircrack-ng --help           # WiFi auditing"
    echo -e "    vol3 -f <dump> ...           # Memory forensics"
    echo -e "    lynis audit system           # Hardening audit"
    echo ""
    echo -e "${YELLOW}  ⚠  LEGAL: Only use these tools on systems you own${RESET}"
    echo -e "${YELLOW}     or have WRITTEN authorization to test.${RESET}"
    echo -e "${YELLOW}     Unauthorized access is a federal crime.${RESET}"
    echo ""
}

# =============================================================================
#  ENTRYPOINT
# =============================================================================
main() {
    # Parse args
    MODE="all"
    [[ $# -gt 0 ]] && MODE="${1//--/}"
    [[ "$MODE" == "help" ]] && usage

    banner
    check_root

    # Init log
    touch "$LOGFILE"
    info "Log file: $LOGFILE"
    info "Mode: $MODE"

    detect_distro
    setup_extra_repos
    setup_dirs

    pkg_update

    case "$MODE" in
        all)
            install_dev
            install_recon
            install_network
            install_web
            install_exploit
            install_password
            install_wireless
            install_forensics
            install_defense
            install_hardware
            install_wordlists
            install_pnwc_scripts
            ;;
        recon)     install_dev; install_recon ;;
        web)       install_dev; install_web ;;
        network)   install_dev; install_network ;;
        exploit)   install_dev; install_exploit ;;
        password)  install_dev; install_password ;;
        wireless)  install_dev; install_wireless ;;
        forensics) install_dev; install_forensics ;;
        defense)   install_dev; install_defense ;;
        dev)       install_dev ;;
        *)
            error "Unknown option: $MODE"
            usage
            ;;
    esac

    print_summary
}

main "$@"
