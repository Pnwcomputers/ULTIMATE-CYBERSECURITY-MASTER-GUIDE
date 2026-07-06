#!/bin/bash
#===============================================================================
#
#          FILE: install_dependencies.sh
#
#         USAGE: sudo ./install_dependencies.sh [--minimal|--full]
#
#   DESCRIPTION: Installs all dependencies for the OSINT Investigator Playbook
#
#        AUTHOR: PNW Computers (jon@pnwcomputers.com)
#       VERSION: 1.0
#
#===============================================================================

set -e

#-------------------------------------------------------------------------------
# COLORS
#-------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

#-------------------------------------------------------------------------------
# CHECKS
#-------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        warn "Some installations require root. Run with sudo for full installation."
    fi
}

check_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        info "Detected distribution: ${DISTRO}"
    else
        warn "Could not detect distribution"
        DISTRO="unknown"
    fi
}

#-------------------------------------------------------------------------------
# SYSTEM PACKAGES
#-------------------------------------------------------------------------------
install_system_packages() {
    info "Installing system packages..."
    
    case $DISTRO in
        ubuntu|debian|tsurugi|kali)
            apt update
            apt install -y \
                python3 python3-pip python3-venv python3-dev \
                golang-go \
                git curl wget \
                nmap masscan \
                whois dnsutils \
                jq \
                hashdeep ssdeep \
                wkhtmltopdf \
                pandoc \
                sqlite3 \
                libffi-dev libssl-dev \
                build-essential
            
            # Optional: screenshot tools
            apt install -y cutycapt 2>/dev/null || warn "cutycapt not available"
            apt install -y flameshot 2>/dev/null || warn "flameshot not available"
            ;;
        fedora|centos|rhel)
            dnf install -y \
                python3 python3-pip python3-devel \
                golang \
                git curl wget \
                nmap \
                whois bind-utils \
                jq \
                wkhtmltopdf \
                pandoc \
                sqlite \
                libffi-devel openssl-devel \
                gcc gcc-c++ make
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm \
                python python-pip \
                go \
                git curl wget \
                nmap masscan \
                whois bind \
                jq \
                hashdeep ssdeep \
                wkhtmltopdf \
                pandoc \
                sqlite
            ;;
        *)
            warn "Unknown distribution. Please install packages manually."
            ;;
    esac
    
    success "System packages installed"
}

#-------------------------------------------------------------------------------
# PYTHON TOOLS
#-------------------------------------------------------------------------------
install_python_tools() {
    info "Installing Python tools..."
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
    
    # Core OSINT tools
    pip3 install --break-system-packages \
        holehe \
        h8mail \
        maigret \
        sherlock-project \
        waybackpy \
        phonenumbers \
        requests \
        beautifulsoup4 \
        python-whois \
        dnspython \
        shodan \
        censys \
        2>/dev/null || \
    pip3 install \
        holehe \
        h8mail \
        maigret \
        sherlock-project \
        waybackpy \
        phonenumbers \
        requests \
        beautifulsoup4 \
        python-whois \
        dnspython \
        shodan \
        censys
    
    success "Python tools installed"
}

#-------------------------------------------------------------------------------
# GO TOOLS
#-------------------------------------------------------------------------------
install_go_tools() {
    info "Installing Go tools..."
    
    # Set up Go environment
    export GOPATH="${HOME}/go"
    export PATH="${PATH}:${GOPATH}/bin"
    
    # Add to shell config
    if ! grep -q 'GOPATH' ~/.bashrc 2>/dev/null; then
        echo 'export GOPATH="${HOME}/go"' >> ~/.bashrc
        echo 'export PATH="${PATH}:${GOPATH}/bin"' >> ~/.bashrc
    fi
    
    # ProjectDiscovery tools
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    
    # Other Go tools
    go install github.com/tomnomnom/waybackurls@latest
    go install github.com/tomnomnom/assetfinder@latest
    
    success "Go tools installed"
}

#-------------------------------------------------------------------------------
# SPECIALIZED TOOLS
#-------------------------------------------------------------------------------
install_phoneinfoga() {
    info "Installing PhoneInfoga..."
    
    curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash
    
    if [[ -f ./phoneinfoga ]]; then
        mv phoneinfoga /usr/local/bin/ 2>/dev/null || mv phoneinfoga "${HOME}/.local/bin/"
    fi
    
    success "PhoneInfoga installed"
}

install_asn_tool() {
    info "Installing ASN lookup tool..."
    
    curl -s https://raw.githubusercontent.com/nitefood/asn/master/asn | tee /usr/bin/asn > /dev/null
    chmod +x /usr/bin/asn
    
    success "ASN tool installed"
}

install_theharvester() {
    info "Installing theHarvester..."
    
    local tools_dir="${HOME}/.config/osint-investigator/tools"
    mkdir -p "$tools_dir"
    
    if [[ ! -d "${tools_dir}/theHarvester" ]]; then
        git clone https://github.com/laramies/theHarvester.git "${tools_dir}/theHarvester"
        pip3 install -r "${tools_dir}/theHarvester/requirements/base.txt" --break-system-packages 2>/dev/null || \
        pip3 install -r "${tools_dir}/theHarvester/requirements/base.txt"
    fi
    
    # Create symlink
    ln -sf "${tools_dir}/theHarvester/theHarvester.py" /usr/local/bin/theHarvester 2>/dev/null || true
    
    success "theHarvester installed"
}

install_spiderfoot() {
    info "Installing SpiderFoot..."
    
    local tools_dir="${HOME}/.config/osint-investigator/tools"
    mkdir -p "$tools_dir"
    
    if [[ ! -d "${tools_dir}/spiderfoot" ]]; then
        git clone https://github.com/smicallef/spiderfoot.git "${tools_dir}/spiderfoot"
        pip3 install -r "${tools_dir}/spiderfoot/requirements.txt" --break-system-packages 2>/dev/null || \
        pip3 install -r "${tools_dir}/spiderfoot/requirements.txt"
    fi
    
    success "SpiderFoot installed"
}

install_blackbird() {
    info "Installing Blackbird..."
    
    local tools_dir="${HOME}/.config/osint-investigator/tools"
    mkdir -p "$tools_dir"
    
    if [[ ! -d "${tools_dir}/blackbird" ]]; then
        git clone https://github.com/p1ngul1n0/blackbird.git "${tools_dir}/blackbird"
        pip3 install -r "${tools_dir}/blackbird/requirements.txt" --break-system-packages 2>/dev/null || \
        pip3 install -r "${tools_dir}/blackbird/requirements.txt"
    fi
    
    success "Blackbird installed"
}

install_archivebox() {
    info "Installing ArchiveBox..."
    
    pip3 install archivebox --break-system-packages 2>/dev/null || pip3 install archivebox
    
    success "ArchiveBox installed"
}

install_monolith() {
    info "Installing Monolith..."
    
    # Try cargo first
    if command -v cargo &>/dev/null; then
        cargo install monolith
    else
        # Download binary
        local version="v2.7.0"
        local arch="x86_64-unknown-linux-gnu"
        curl -sLO "https://github.com/Y2Z/monolith/releases/download/${version}/monolith-${version}-${arch}.tar.gz"
        tar -xzf "monolith-${version}-${arch}.tar.gz"
        mv monolith /usr/local/bin/ 2>/dev/null || mv monolith "${HOME}/.local/bin/"
        rm "monolith-${version}-${arch}.tar.gz"
    fi
    
    success "Monolith installed"
}

#-------------------------------------------------------------------------------
# NUCLEI TEMPLATES
#-------------------------------------------------------------------------------
install_nuclei_templates() {
    info "Updating Nuclei templates..."
    
    if command -v nuclei &>/dev/null; then
        nuclei -ut
    fi
    
    success "Nuclei templates updated"
}

#-------------------------------------------------------------------------------
# POST-INSTALL
#-------------------------------------------------------------------------------
post_install_setup() {
    info "Running post-installation setup..."
    
    # Create config directory
    mkdir -p "${HOME}/.config/osint-investigator"/{tools,logs}
    
    # Create local bin if needed
    mkdir -p "${HOME}/.local/bin"
    
    # Ensure PATH includes local bin
    if ! echo "$PATH" | grep -q "${HOME}/.local/bin"; then
        echo 'export PATH="${PATH}:${HOME}/.local/bin"' >> ~/.bashrc
    fi
    
    success "Post-installation setup complete"
}

verify_installation() {
    info "Verifying installation..."
    
    local tools=(
        "holehe"
        "h8mail"
        "maigret"
        "sherlock"
        "phoneinfoga"
        "subfinder"
        "httpx"
        "dnsx"
        "waybackurls"
        "nmap"
        "whois"
        "dig"
    )
    
    local missing=0
    
    echo ""
    echo "Installation Status:"
    echo "──────────────────────────────────────"
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool"
            ((missing++))
        fi
    done
    
    echo "──────────────────────────────────────"
    
    if [[ $missing -eq 0 ]]; then
        success "All tools installed successfully!"
    else
        warn "${missing} tools could not be verified. Check PATH or install manually."
    fi
}

#-------------------------------------------------------------------------------
# MAIN
#-------------------------------------------------------------------------------
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     OSINT Investigator Playbook - Dependency Installer        ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    
    check_root
    check_distro
    
    case "${1:-full}" in
        --minimal|-m)
            info "Installing minimal dependencies..."
            install_system_packages
            install_python_tools
            install_phoneinfoga
            install_asn_tool
            ;;
        --full|-f|*)
            info "Installing full dependencies..."
            install_system_packages
            install_python_tools
            install_go_tools
            install_phoneinfoga
            install_asn_tool
            install_theharvester
            install_spiderfoot
            install_blackbird
            install_archivebox
            install_monolith
            install_nuclei_templates
            ;;
    esac
    
    post_install_setup
    verify_installation
    
    echo ""
    success "Installation complete!"
    info "Please restart your terminal or run: source ~/.bashrc"
    echo ""
}

main "$@"
