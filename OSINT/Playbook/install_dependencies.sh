#!/usr/bin/env bash
#===============================================================================
#
#          FILE: install_dependencies.sh
#
#         USAGE: ./install_dependencies.sh [--minimal|--full] [--allow-unpinned] [--print-pins]
#
#   DESCRIPTION: Installs dependencies for the OSINT Investigator Playbook.
#
#   RUN AS A NORMAL USER. The script calls sudo only for distribution packages;
#   everything else is installed under your home directory:
#       ~/.local/share/osint-investigator/venvs/<tool>   isolated Python tools
#       ~/.local/bin                                      command links
#       ~/go/bin                                          Go tools
#
#   SUPPLY CHAIN: external sources are installed only from versions pinned in
#   Scripts/tool_pins.conf (see Scripts/PINNING.md). Downloaded binaries must
#   match a pinned SHA-256 and are verified BEFORE they are unpacked or run.
#   A missing pin skips that item and reports it. --allow-unpinned is a loud,
#   lab-only override for pip/go/git/cargo sources; it never applies to
#   downloaded binaries.
#
#        AUTHOR: Jon-Eric Pienkowski ~ PNW Computers (jon@pnwcomputers.com)
#       VERSION: 2.0
#
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_SCRIPTS_DIR="$(cd -- "${SCRIPT_DIR}/../../Scripts" 2>/dev/null && pwd || true)"

# This script sources and reads helper files, so refuse symlinks and anything
# writable by group/others.
trusted_file() {
    local f="$1" mode
    [[ -f "$f" && ! -L "$f" ]] || return 1
    mode=$(stat -c '%a' -- "$f") || return 1
    (( (8#$mode & 8#022) == 0 ))
}

#-------------------------------------------------------------------------------
# OUTPUT
#-------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
ok()      { success "$1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1" >&2; }

if [[ -z "$REPO_SCRIPTS_DIR" ]] || ! trusted_file "${REPO_SCRIPTS_DIR}/lib/safe_install.sh"; then
    error "Scripts/lib/safe_install.sh is missing, is a symlink, or is writable by others; refusing to continue."
    exit 1
fi
# shellcheck source=../../Scripts/lib/safe_install.sh
source "${REPO_SCRIPTS_DIR}/lib/safe_install.sh"

#-------------------------------------------------------------------------------
# GLOBALS
#-------------------------------------------------------------------------------
OSINT_HOME="${HOME}/.local/share/osint-investigator"
BIN_DIR="${HOME}/.local/bin"
TOOLS_DIR="${HOME}/.config/osint-investigator/tools"
PINS_FILE="${PNWC_PINS_FILE:-${REPO_SCRIPTS_DIR}/tool_pins.conf}"
LOGFILE="/dev/null"

# Read by lib/safe_install.sh (git checkouts, Go workspace, shared-venv interpreter).
# shellcheck disable=SC2034
PNWC_TOOLS_DIR="${TOOLS_DIR}"
PNWC_GOPATH="${HOME}/go"
# shellcheck disable=SC2034
PNWC_VENV_PYTHON="${OSINT_HOME}/venv/bin/python"

FAILED_TOOLS=()
SKIPPED_TOOLS=()
MANUAL_TOOLS=()
# shellcheck disable=SC2034  # appended to by lib/safe_install.sh
UNPINNED_USED=()
PRINT_PINS=0
DISTRO="unknown"
SUDO=(sudo)

usage() {
    cat <<'EOF'
Usage: ./install_dependencies.sh [OPTIONS]

  --minimal, -m      Core OSINT tools only
  --full, -f         Everything (default)
  --allow-unpinned   LAB ONLY: permit pip/go/git/cargo installs that have no pin
  --print-pins       After installing, print proposed pins for unpinned items
  --help, -h         Show this help

Run as a normal user (not root); sudo is used only for distribution packages.
EOF
    exit "${1:-0}"
}

#-------------------------------------------------------------------------------
# CHECKS
#-------------------------------------------------------------------------------
check_user() {
    if [[ $EUID -eq 0 ]]; then
        error "Do not run this installer as root or with sudo."
        error "Run it as your normal user; it calls sudo only for distribution packages."
        exit 1
    fi
    if ! command -v sudo &>/dev/null; then
        error "sudo is required to install distribution packages. Install it or install the packages manually."
        exit 1
    fi
}

check_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO="${ID:-unknown}"
        info "Detected distribution: ${DISTRO}"
    else
        warn "Could not detect distribution"
        DISTRO="unknown"
    fi
}

#-------------------------------------------------------------------------------
# SYSTEM PACKAGES (distribution package managers verify their own signatures)
#-------------------------------------------------------------------------------
install_system_packages() {
    info "Installing system packages..."

    case $DISTRO in
        ubuntu|debian|tsurugi|kali)
            "${SUDO[@]}" apt update
            "${SUDO[@]}" apt install -y \
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
            "${SUDO[@]}" apt install -y cutycapt 2>/dev/null || warn "cutycapt not available"
            "${SUDO[@]}" apt install -y flameshot 2>/dev/null || warn "flameshot not available"
            ;;
        fedora|centos|rhel)
            "${SUDO[@]}" dnf install -y \
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
            # Never run a bare "pacman -Sy": a partial upgrade can break the system.
            warn "Arch/Manjaro: complete a full upgrade (sudo pacman -Syu) before running this installer."
            "${SUDO[@]}" pacman -S --noconfirm --needed \
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
            MANUAL_TOOLS+=("system packages (unknown distribution)")
            ;;
    esac

    success "System package step finished"
}

#-------------------------------------------------------------------------------
# HELPERS
#-------------------------------------------------------------------------------
ensure_venv() {
    local dir="$1"
    [[ -x "${dir}/bin/python" ]] && return 0
    mkdir -p "$(dirname "$dir")"
    python3 -m venv "$dir" >> "$LOGFILE" 2>&1 || {
        error "Cannot create virtualenv at ${dir} (is the python3 venv package installed?)"
        return 1
    }
}

# venv_tool NAME PIP_PACKAGE EXECUTABLE...
#   One isolated virtualenv per CLI tool; executables are linked into ~/.local/bin.
venv_tool() {
    local name="$1" pkg="$2" exe dir
    shift 2
    resolve_pip "$pkg" || return 0
    dir="${OSINT_HOME}/venvs/${name}"
    if ! ensure_venv "$dir"; then
        FAILED_TOOLS+=("${name} (virtualenv)")
        return 0
    fi
    info "  ${name}: pip install ${PIP_SPEC} (isolated venv)"
    if ! "${dir}/bin/python" -m pip install --quiet "$PIP_SPEC" >> "$LOGFILE" 2>&1; then
        warn "  pip failed for ${pkg}"
        FAILED_TOOLS+=("pip:${pkg}")
        return 0
    fi
    for exe in "$@"; do
        if [[ -x "${dir}/bin/${exe}" ]]; then
            ln -sf "${dir}/bin/${exe}" "${BIN_DIR}/${exe}"
        else
            warn "  expected executable not found after install: ${exe}"
            FAILED_TOOLS+=("${name}: ${exe} (executable missing)")
        fi
    done
}

# write_wrapper OUT PYTHON ENTRYPOINT — a tiny launcher; paths are shell-quoted.
write_wrapper() {
    local out="$1" py="$2" entry="$3"
    printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$py" "$entry" > "$out"
    chmod 755 "$out"
}

# python_app_from_git NAME URL REQUIREMENTS_FILE ENTRYPOINT [WRAPPER_NAME]
#   Pinned checkout + its own venv + launcher in ~/.local/bin.
#   NOTE: the project's requirements file is installed as written; its
#   transitive dependencies are not hash-locked (tracked as a follow-up).
python_app_from_git() {
    local name="$1" url="$2" req="$3" entry="$4" wrapper="${5:-$1}"
    local checkout="${TOOLS_DIR}/${name}" dir="${OSINT_HOME}/venvs/${name}"

    git_clone_tool "$name" "$url"
    [[ -d "${checkout}/.git" ]] || return 0
    if [[ ! -f "${checkout}/${req}" || ! -f "${checkout}/${entry}" ]]; then
        warn "  ${name}: expected files not found in checkout"
        FAILED_TOOLS+=("${name} (checkout layout)")
        return 0
    fi
    if ! ensure_venv "$dir"; then
        FAILED_TOOLS+=("${name} (virtualenv)")
        return 0
    fi
    if "${dir}/bin/python" -m pip install --quiet -r "${checkout}/${req}" >> "$LOGFILE" 2>&1; then
        write_wrapper "${BIN_DIR}/${wrapper}" "${dir}/bin/python" "${checkout}/${entry}"
        ok "  ${name} installed"
    else
        warn "  ${name}: requirements install failed"
        FAILED_TOOLS+=("${name} (requirements)")
    fi
}

#-------------------------------------------------------------------------------
# PYTHON TOOLS
#-------------------------------------------------------------------------------
install_python_tools() {
    info "Installing Python tools (isolated virtualenvs, no system pip)..."

    # The Sherlock OSINT package is sherlock-project; its executable is sherlock.
    venv_tool holehe   holehe          holehe
    venv_tool h8mail   h8mail          h8mail
    venv_tool maigret  maigret         maigret
    venv_tool sherlock sherlock-project sherlock
    venv_tool shodan   shodan          shodan
    venv_tool censys   censys          censys

    # Library environment for scripts that import these modules.
    if ensure_venv "${OSINT_HOME}/venv"; then
        pip_install waybackpy phonenumbers requests beautifulsoup4 python-whois dnspython
    else
        FAILED_TOOLS+=("python libraries (virtualenv)")
    fi

    success "Python tool step finished"
}

# Flask for the optional web interface lives in its own venv; nothing is
# pip-installed at launch time.
install_web_dependencies() {
    venv_tool web flask flask
}

#-------------------------------------------------------------------------------
# GO TOOLS (versions come from pins; Go's checksum database verifies the code)
#-------------------------------------------------------------------------------
install_go_tools() {
    info "Installing Go tools..."

    if ! command -v go &>/dev/null; then
        warn "Go not found; skipping Go tools"
        SKIPPED_TOOLS+=("go tools (go not installed)")
        return 0
    fi

    export GOPATH="${PNWC_GOPATH}"
    export PATH="${PATH}:${GOPATH}/bin"

    # ProjectDiscovery tools
    go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder
    go_install github.com/projectdiscovery/httpx/cmd/httpx
    go_install github.com/projectdiscovery/dnsx/cmd/dnsx
    go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei
    go_install github.com/projectdiscovery/katana/cmd/katana

    # Other Go tools
    go_install github.com/tomnomnom/waybackurls
    go_install github.com/tomnomnom/assetfinder

    success "Go tool step finished"
}

#-------------------------------------------------------------------------------
# SPECIALIZED TOOLS
#-------------------------------------------------------------------------------
install_phoneinfoga() {
    info "Installing PhoneInfoga (verified release binary)..."
    if command -v phoneinfoga &>/dev/null; then
        ok "  phoneinfoga already installed"
        return 0
    fi
    release_prereqs phoneinfoga || return 0
    local asset_arch="x86_64"
    [[ "$REL_ARCH" == arm64 ]] && asset_arch="arm64"
    install_release_member phoneinfoga \
        "https://github.com/sundowndev/phoneinfoga/releases/download/${REL_VER}/phoneinfoga_Linux_${asset_arch}.tar.gz" \
        "$REL_ARCH" phoneinfoga "$BIN_DIR"
}

install_asn_tool() {
    info "Installing ASN lookup tool (content must match a pinned SHA-256)..."
    if command -v asn &>/dev/null; then
        ok "  asn already installed"
        return 0
    fi
    # dl:asn:commit is an upstream commit, so the URL (and therefore the hash) is immutable
    if ! release_prereqs asn any; then
        MANUAL_TOOLS+=("asn (pin dl:asn:commit and dl:asn:sha256:any, or install from https://github.com/nitefood/asn)")
        return 0
    fi
    local d
    safe_mktemp_dir d
    if fetch_pinned asn any "https://raw.githubusercontent.com/nitefood/asn/${REL_VER}/asn" "${d}/asn" \
       && install -m 0755 "${d}/asn" "${BIN_DIR}/asn"; then
        ok "  asn installed to ${BIN_DIR}/asn"
    else
        MANUAL_TOOLS+=("asn (pin dl:asn:sha256:any, or install from https://github.com/nitefood/asn)")
    fi
}

install_theharvester() {
    info "Installing theHarvester..."
    python_app_from_git theHarvester https://github.com/laramies/theHarvester.git \
        requirements/base.txt theHarvester.py theHarvester
}

install_spiderfoot() {
    info "Installing SpiderFoot..."
    python_app_from_git spiderfoot https://github.com/smicallef/spiderfoot.git \
        requirements.txt sf.py spiderfoot
}

install_blackbird() {
    info "Installing Blackbird..."
    python_app_from_git blackbird https://github.com/p1ngul1n0/blackbird.git \
        requirements.txt blackbird.py blackbird
}

install_archivebox() {
    info "Installing ArchiveBox..."
    venv_tool archivebox archivebox archivebox
}

install_monolith() {
    info "Installing Monolith..."
    if command -v monolith &>/dev/null; then
        ok "  monolith already installed"
        return 0
    fi

    if command -v cargo &>/dev/null; then
        local ver rc
        ver=$(pin_get "cargo:monolith") && rc=0 || rc=1
        if (( rc == 0 )); then
            if safe_is_version "$ver"; then
                cargo install --locked --root "${HOME}/.local" --version "$ver" monolith >> "$LOGFILE" 2>&1 \
                    && ok "  monolith installed (cargo ${ver})" \
                    || { warn "  cargo install monolith failed"; FAILED_TOOLS+=("cargo:monolith"); }
            else
                error "  invalid pin for cargo:monolith"; FAILED_TOOLS+=("cargo:monolith (invalid pin)")
            fi
        elif unpinned_ok "cargo:monolith"; then
            cargo install --locked --root "${HOME}/.local" monolith >> "$LOGFILE" 2>&1 \
                && ok "  monolith installed (cargo, UNPINNED)" \
                || { warn "  cargo install monolith failed"; FAILED_TOOLS+=("cargo:monolith"); }
        fi
        return 0
    fi

    # Upstream publishes no Linux tar.gz asset matching a stable name, so there is no
    # verified-download fallback; install via cargo (pinned, --locked) or by hand.
    MANUAL_TOOLS+=("monolith (install cargo, then re-run; or see https://github.com/Y2Z/monolith)")
}

#-------------------------------------------------------------------------------
# NUCLEI TEMPLATES
#-------------------------------------------------------------------------------
install_nuclei_templates() {
    info "Updating Nuclei templates..."

    if command -v nuclei &>/dev/null; then
        # Templates are fetched by nuclei itself from the network (not pinned here).
        nuclei -ut || warn "Nuclei template update failed"
    fi

    success "Nuclei template step finished"
}

#-------------------------------------------------------------------------------
# POST-INSTALL
#-------------------------------------------------------------------------------
post_install_setup() {
    info "Running post-installation setup..."

    mkdir -p "${HOME}/.config/osint-investigator"/{tools,logs}

    # Persist PATH entries once, with a marker so reruns do not duplicate them.
    if ! grep -q 'osint-investigator PATH' "${HOME}/.bashrc" 2>/dev/null; then
        {
            echo '# osint-investigator PATH'
            echo 'export PATH="${PATH}:${HOME}/.local/bin:${HOME}/go/bin"'
        } >> "${HOME}/.bashrc"
        info "Added ~/.local/bin and ~/go/bin to PATH in ~/.bashrc"
    fi

    success "Post-installation setup complete"
}

# verify_installation MODE — returns 0 only if every expected tool is present.
verify_installation() {
    local mode="$1" tool missing=0
    info "Verifying installation..."

    local tools=(holehe h8mail maigret sherlock phoneinfoga nmap whois dig)
    if [[ "$mode" == full ]]; then
        tools+=(subfinder httpx dnsx waybackurls)
    fi

    export PATH="${PATH}:${BIN_DIR}:${PNWC_GOPATH}/bin"

    echo ""
    echo "Installation Status:"
    echo "──────────────────────────────────────"
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool"
            missing=$((missing + 1))
        fi
    done
    echo "──────────────────────────────────────"

    if (( missing == 0 )); then
        success "All expected tools are present."
        return 0
    fi
    warn "${missing} expected tool(s) missing. Check the reasons below, then PATH or install manually."
    return 1
}

print_report() {
    local t
    if (( ${#FAILED_TOOLS[@]} > 0 )); then
        echo -e "${RED}Failed (${#FAILED_TOOLS[@]}):${NC}"
        for t in "${FAILED_TOOLS[@]}"; do echo -e "  ${RED}✗${NC} $t"; done
    fi
    if (( ${#SKIPPED_TOOLS[@]} > 0 )); then
        echo -e "${YELLOW}Skipped (${#SKIPPED_TOOLS[@]}) — usually a missing pin; see Scripts/PINNING.md:${NC}"
        for t in "${SKIPPED_TOOLS[@]}"; do echo -e "  ${YELLOW}→${NC} $t"; done
    fi
    if (( ${#MANUAL_TOOLS[@]} > 0 )); then
        echo -e "${BLUE}Manual setup needed (${#MANUAL_TOOLS[@]}):${NC}"
        for t in "${MANUAL_TOOLS[@]}"; do echo -e "  ${BLUE}ℹ${NC} $t"; done
    fi
}

#-------------------------------------------------------------------------------
# MAIN
#-------------------------------------------------------------------------------
main() {
    local mode="full" arg verified=0
    for arg in "$@"; do
        case "$arg" in
            --help|-h)        usage ;;
            --minimal|-m)     mode="minimal" ;;
            --full|-f)        mode="full" ;;
            --allow-unpinned) export PNWC_ALLOW_UNPINNED=1 ;;
            --print-pins)     PRINT_PINS=1 ;;
            *) error "Unknown argument: ${arg}"; usage 2 ;;
        esac
    done

    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     OSINT Investigator Playbook - Dependency Installer        ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    check_user
    check_distro

    if [[ -e "$PINS_FILE" ]] && ! trusted_file "$PINS_FILE"; then
        error "${PINS_FILE} is a symlink or writable by others; refusing to use it"
        exit 1
    fi
    [[ -e "$PINS_FILE" ]] || warn "No pins file at ${PINS_FILE}; every pin-dependent item will be skipped"
    if safe_allow_unpinned; then
        warn "LAB-ONLY MODE: unpinned pip/go/git/cargo sources are allowed. Do not use this on a production machine."
    fi

    mkdir -p "${OSINT_HOME}/venvs" "${OSINT_HOME}/logs" "${TOOLS_DIR}" "${BIN_DIR}"
    chmod 700 "${OSINT_HOME}" "${OSINT_HOME}/logs"
    LOGFILE="${OSINT_HOME}/logs/install_$(date +%Y%m%d_%H%M%S).log"
    ( umask 077; : > "$LOGFILE" )
    info "Log file: ${LOGFILE}"
    trap safe_cleanup EXIT

    case "$mode" in
        minimal)
            info "Installing minimal dependencies..."
            install_system_packages
            install_python_tools
            install_phoneinfoga
            install_asn_tool
            ;;
        full)
            info "Installing full dependencies..."
            install_system_packages
            install_python_tools
            install_web_dependencies
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
    verify_installation "$mode" && verified=1

    echo ""
    print_report
    (( PRINT_PINS )) && print_proposed_pins

    echo ""
    if (( verified == 1 && ${#FAILED_TOOLS[@]} == 0 )); then
        success "Installation finished with no failures."
        info "Open a new terminal or run: source ~/.bashrc"
        return 0
    fi
    error "Installation did NOT complete cleanly. Review the report above."
    return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
