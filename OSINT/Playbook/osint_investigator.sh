#!/bin/bash
#===============================================================================
#
#          FILE: osint_investigator.sh
#
#         USAGE: ./osint_investigator.sh [--install|--config|--help]
#
#   DESCRIPTION: Comprehensive OSINT Investigation Playbook for Scam/Fraud Cases
#                Generates professional abuse reports for IC3/Law Enforcement
#
#        AUTHOR: Jon-Eric Pienkowski ~ Pacific Northwest Computers (PNWC)
#       CONTACT: jon@pnwcomputers.com | (360) 624-7379
#       VERSION: 2.1
#       CREATED: 2024
#      PLATFORM: Tsurugi Linux / Ubuntu / Debian
#
#===============================================================================

set -o pipefail

#-------------------------------------------------------------------------------
# COMPANY / INVESTIGATOR BRANDING CONFIGURATION
#
# These are placeholder defaults. Put YOUR real values in a local, gitignored
# config and they will override the defaults below:
#     cp branding.conf.example ~/.config/osint-investigator/branding.conf
#     nano ~/.config/osint-investigator/branding.conf
# Do NOT hardcode personal or private contact details into this committed file.
#-------------------------------------------------------------------------------
export COMPANY_NAME="Your Company Name"
export COMPANY_SHORT="YOURORG"
export COMPANY_EMAIL="investigator@example.com"
export COMPANY_PHONE="(555) 000-0000"
export COMPANY_CELL=""
export COMPANY_WEBSITE="www.example.com"
export COMPANY_LINKTREE=""
export COMPANY_LOCATION="City, ST"
export INVESTIGATOR_NAME="Investigator Name"

# Override placeholders with local operator config if present (gitignored)
BRANDING_CONF="${BRANDING_CONF:-${HOME}/.config/osint-investigator/branding.conf}"
# shellcheck source=/dev/null
[[ -f "$BRANDING_CONF" ]] && source "$BRANDING_CONF"

#-------------------------------------------------------------------------------
# GLOBAL CONFIGURATION
#-------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_CONFIG="${CONFIG_DIR}/api_keys.conf"
CASE_BASE_DIR="${HOME}/OSINT_Cases"
LOG_DIR="${CONFIG_DIR}/logs"
TOOLS_DIR="${CONFIG_DIR}/tools"

sanitize_case_id() {
    echo "$1" | tr ' ' '_' | tr -cd '[:alnum:]_-'
}

set_case_id_from_input() {
    local raw="$1"
    local cleaned
    cleaned="$(sanitize_case_id "$raw")"

    if [[ -z "$cleaned" ]]; then
        error "Case ID cannot be empty after removing invalid characters."
        return 1
    fi

    CASE_ID="$cleaned"
    return 0
}

# Current case variables
CASE_ID=""
CASE_DIR=""
EVIDENCE_DIR=""
REPORTS_DIR=""
LOGS_DIR=""
RAW_DIR=""

# Investigation data (populated by functions throughout the script)
# shellcheck disable=SC2034
{
declare -A COLLECTED_DATA
declare -a EMAILS=()
declare -a PHONES=()
declare -a DOMAINS=()
declare -a IPS=()
declare -a IPV6S=()
declare -a USERNAMES=()
declare -a CRYPTO_ADDRESSES=()
declare -a URLS=()
declare -a SUBDOMAINS=()
declare -a OPEN_PORTS=()
declare -a NMAP_SERVICES=()
COMPANY_NAME_TARGET=""
CASE_NOTES=""
CASE_TYPE="Fraudulent Domain / Scam Infrastructure Investigation"

# Hosting/Infrastructure data
HOSTING_PROVIDER=""
HOSTING_ASN=""
HOSTING_ISP=""
HOSTING_REGISTRY=""
HOSTING_GEOLOCATION=""
HOSTING_COORDINATES=""
HOSTING_TIMEZONE=""
OS_FINGERPRINT=""
DEVICE_TYPE=""
OS_GUESS=""
NETWORK_DISTANCE=""
FIREWALL_STATUS=""
}

#-------------------------------------------------------------------------------
# COLOR DEFINITIONS
#-------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

#-------------------------------------------------------------------------------
# LOGGING & UI FUNCTIONS
#-------------------------------------------------------------------------------
LOG_FILE=""

init_logging() {
    mkdir -p "${LOG_DIR}"
    LOG_FILE="${LOG_DIR}/osint_$(date +%Y%m%d_%H%M%S).log"
}

log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" >> "${LOG_FILE}" 2>/dev/null; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >> "${LOG_FILE}" 2>/dev/null; }

print_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════════╗
║    ██████╗ ███╗   ██╗██╗    ██╗ ██████╗                                          ║
║    ██╔══██╗████╗  ██║██║    ██║██╔════╝     OSINT Investigator Playbook          ║
║    ██████╔╝██╔██╗ ██║██║ █╗ ██║██║          Pacific Northwest Computers          ║
║    ██╔═══╝ ██║╚██╗██║██║███╗██║██║          Vancouver, WA | Portland Metro       ║
║    ██║     ██║ ╚████║╚███╔███╔╝╚██████╗                                          ║
║    ╚═╝     ╚═╝  ╚═══╝ ╚══╝╚══╝  ╚═════╝     v2.1 - Scam Infrastructure Analysis  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  Evidence Collection | Abuse Reporting | IC3 Documentation | Law Enforcement    ║
╚══════════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_subsection() { echo -e "\n${BLUE}┌─── $1 ───${NC}"; }

info() { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

prompt() {
    local var_name="$1" prompt_text="$2" default="$3" value
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${YELLOW}[?]${NC} ${prompt_text} [${default}]: ")" value
        value="${value:-$default}"
    else
        read -rp "$(echo -e "${YELLOW}[?]${NC} ${prompt_text}: ")" value
    fi
    printf -v "$var_name" '%s' "$value"
}

prompt_array() {
    local array_name="$1" prompt_text="$2" input
    local -n _pa_ref="$array_name"
    echo -e "${YELLOW}[?]${NC} ${prompt_text}"
    echo -e "${DIM}    (Enter one per line, empty line when done)${NC}"
    _pa_ref=()
    while true; do
        read -rp "    → " input
        [[ -z "$input" ]] && break
        _pa_ref+=("$input")
    done
}

confirm() {
    local response
    read -rp "$(echo -e "${YELLOW}[?]${NC} $1 [y/N]: ")" response
    [[ "$response" =~ ^[Yy]$ ]]
}

press_enter() { echo ""; read -rp "$(echo -e "${DIM}Press Enter to continue...${NC}")"; }

check_tool() {
    command -v "$1" &>/dev/null
}

#-------------------------------------------------------------------------------
# CONFIGURATION
#-------------------------------------------------------------------------------
init_config() {
    mkdir -p "${CONFIG_DIR}" "${LOG_DIR}" "${TOOLS_DIR}"
    [[ ! -f "${API_CONFIG}" ]] && create_api_config
    # shellcheck source=/dev/null
    [[ -f "${API_CONFIG}" ]] && source "${API_CONFIG}"
}

create_api_config() {
    cat > "${API_CONFIG}" << 'APIEOF'
# OSINT Investigator API Configuration
# chmod 600 this file!

export SHODAN_API_KEY=""
export VIRUSTOTAL_API_KEY=""
export CENSYS_API_ID=""
export CENSYS_API_SECRET=""
export SECURITYTRAILS_API_KEY=""
export HAVEIBEENPWNED_API_KEY=""
export HUNTER_API_KEY=""
export INTELX_API_KEY=""
export WHOISXML_API_KEY=""
export VERIPHONE_API_KEY=""
export ABUSEIPDB_API_KEY=""
export ETHERSCAN_API_KEY=""
APIEOF
    chmod 600 "${API_CONFIG}"
}

configure_apis() {
    print_section "API Key Configuration"
    # shellcheck source=/dev/null
    source "${API_CONFIG}" 2>/dev/null
    
    local apis=(
        "SHODAN_API_KEY:Shodan"
        "VIRUSTOTAL_API_KEY:VirusTotal"
        "HAVEIBEENPWNED_API_KEY:HaveIBeenPwned"
        "SECURITYTRAILS_API_KEY:SecurityTrails"
        "ABUSEIPDB_API_KEY:AbuseIPDB"
        "WHOISXML_API_KEY:WhoisXML"
        "VERIPHONE_API_KEY:Veriphone"
    )
    
    for api_entry in "${apis[@]}"; do
        local var_name="${api_entry%%:*}"
        local description="${api_entry#*:}"
        local current_value="${!var_name}"
        
        if [[ -n "$current_value" ]]; then
            echo -e "${GREEN}●${NC} ${description}: ${current_value:0:4}...${current_value: -4}"
        else
            echo -e "${RED}○${NC} ${description}: Not configured"
        fi
        
        read -rp "  Enter new key (Enter to keep): " new_value
        [[ -n "$new_value" ]] && sed -i "s|^export ${var_name}=.*|export ${var_name}=\"${new_value}\"|" "${API_CONFIG}"
    done
    # shellcheck source=/dev/null
    source "${API_CONFIG}"
    success "API configuration saved"
}

show_api_status() {
    print_section "API Status"
    # shellcheck source=/dev/null
    [[ -f "${API_CONFIG}" ]] && source "${API_CONFIG}"

    local apis=(
        "SHODAN_API_KEY:Shodan"
        "VIRUSTOTAL_API_KEY:VirusTotal"
        "HAVEIBEENPWNED_API_KEY:HIBP"
    )

    for entry in "${apis[@]}"; do
        local var="${entry%%:*}"
        local name="${entry#*:}"
        local val="${!var}"
        [[ -n "$val" ]] && echo -e "  ${GREEN}●${NC} ${name}" || echo -e "  ${RED}○${NC} ${name}"
    done
}

show_tool_status() {
    print_section "Tool Status"
    local tools=("holehe" "h8mail" "maigret" "sherlock" "phoneinfoga" "subfinder" "httpx" "nmap" "whois")
    for tool in "${tools[@]}"; do
        command -v "$tool" &>/dev/null && echo -e "  ${GREEN}✓${NC} ${tool}" || echo -e "  ${RED}✗${NC} ${tool}"
    done
}

launch_web_interface() {
    local web_script="${SCRIPT_DIR}/web_interface.py"

    [[ ! -f "$web_script" ]] && { error "Web interface not found"; return 1; }

    python3 -c "import flask" 2>/dev/null || {
        warn "Installing Flask..."
        pip3 install flask --break-system-packages 2>/dev/null || pip3 install flask
    }

    info "Starting web interface at http://localhost:5000"
    info "Press Ctrl+C to stop"
    python3 "$web_script" --host 127.0.0.1 --port 5000
}

#-------------------------------------------------------------------------------
# CASE MANAGEMENT
#-------------------------------------------------------------------------------
create_new_case() {
    print_section "Create New Investigation Case"
    prompt CASE_ID "Enter Case ID" "$(date +%Y%m%d)-001"
    set_case_id_from_input "$CASE_ID" || return 1
    
    CASE_DIR="${CASE_BASE_DIR}/${CASE_ID}"
    
    if [[ -d "$CASE_DIR" ]]; then
        confirm "Case exists. Resume?" && { load_case "$CASE_ID"; return 0; }
        error "Choose a different ID."
        return 1
    fi
    
    EVIDENCE_DIR="${CASE_DIR}/evidence"
    REPORTS_DIR="${CASE_DIR}/reports"
    LOGS_DIR="${CASE_DIR}/logs"
    RAW_DIR="${CASE_DIR}/raw_data"
    
    mkdir -p "${EVIDENCE_DIR}"/{screenshots,archives,hashes}
    mkdir -p "${REPORTS_DIR}"/{final,abuse_reports}
    mkdir -p "${LOGS_DIR}"
    mkdir -p "${RAW_DIR}"/{email,domain,ip,phone,username,crypto,nmap}
    
    echo "{\"case_id\": \"${CASE_ID}\", \"created\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"investigator\": \"${INVESTIGATOR_NAME}\"}" > "${CASE_DIR}/case_info.json"
    
    cat > "${CASE_DIR}/evidence_log.md" << EOF
# Evidence Log - Case ${CASE_ID}

| Timestamp | Type | Description | SHA256 | Source |
|-----------|------|-------------|--------|--------|
EOF
    
    success "Created case: ${CASE_ID}"
    save_case_state
}

load_case() {
    set_case_id_from_input "$1" || return 1
    CASE_DIR="${CASE_BASE_DIR}/${CASE_ID}"
    EVIDENCE_DIR="${CASE_DIR}/evidence"
    REPORTS_DIR="${CASE_DIR}/reports"
    RAW_DIR="${CASE_DIR}/raw_data"
    
    [[ ! -d "$CASE_DIR" ]] && { error "Case not found"; return 1; }
    # shellcheck source=/dev/null
    [[ -f "${CASE_DIR}/.case_state" ]] && source "${CASE_DIR}/.case_state"
    success "Loaded case: ${CASE_ID}"
}

save_case_state() {
    [[ -z "$CASE_DIR" ]] && return
    cat > "${CASE_DIR}/.case_state" << EOF
CASE_ID="${CASE_ID}"
CASE_TYPE="${CASE_TYPE}"
EMAILS=(${EMAILS[*]@Q})
PHONES=(${PHONES[*]@Q})
DOMAINS=(${DOMAINS[*]@Q})
IPS=(${IPS[*]@Q})
IPV6S=(${IPV6S[*]@Q})
USERNAMES=(${USERNAMES[*]@Q})
CRYPTO_ADDRESSES=(${CRYPTO_ADDRESSES[*]@Q})
SUBDOMAINS=(${SUBDOMAINS[*]@Q})
COMPANY_NAME_TARGET="${COMPANY_NAME_TARGET}"
HOSTING_PROVIDER="${HOSTING_PROVIDER}"
HOSTING_ASN="${HOSTING_ASN}"
HOSTING_ISP="${HOSTING_ISP}"
HOSTING_REGISTRY="${HOSTING_REGISTRY}"
HOSTING_GEOLOCATION="${HOSTING_GEOLOCATION}"
HOSTING_COORDINATES="${HOSTING_COORDINATES}"
HOSTING_TIMEZONE="${HOSTING_TIMEZONE}"
EOF
}

list_cases() {
    print_section "Existing Cases"
    [[ ! -d "$CASE_BASE_DIR" ]] && { info "No cases found."; return; }
    
    printf "${WHITE}%-30s %-20s %s${NC}\n" "Case ID" "Created" "Status"
    echo "─────────────────────────────────────────────────────────────"
    
    for case_dir in "${CASE_BASE_DIR}"/*/; do
        [[ ! -d "$case_dir" ]] && continue
        local case_id; case_id=$(basename "$case_dir")
        local created; created=$(grep -oP '"created":\s*"\K[^"]+' "${case_dir}/case_info.json" 2>/dev/null | cut -d'T' -f1)
        local status; status=$(grep -oP '"status":\s*"\K[^"]+' "${case_dir}/case_info.json" 2>/dev/null)
        printf "%-30s %-20s %s\n" "$case_id" "${created:-Unknown}" "${status:-active}"
    done
}

select_case() {
    list_cases
    echo ""
    read -rp "Enter Case ID to load: " selected_case
    [[ -n "$selected_case" ]] && load_case "$selected_case"
}

#-------------------------------------------------------------------------------
# INVESTIGATION FUNCTIONS
#-------------------------------------------------------------------------------
investigate_email() {
    local email="$1"
    local output_dir="${RAW_DIR}/email"
    mkdir -p "$output_dir"
    
    print_subsection "Email Investigation: ${email}"
    
    local report_file; report_file="${output_dir}/${email//[@.]/_}_$(date +%Y%m%d_%H%M%S).md"

    {
        echo "# Email Investigation: ${email}"
        echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
        
        # Holehe
        if command -v holehe &>/dev/null; then
            echo "## Account Discovery (Holehe)"
            echo '```'
            holehe "$email" --only-used 2>/dev/null
            echo '```'
        fi
        
        # h8mail
        if command -v h8mail &>/dev/null; then
            echo "## Breach Data (h8mail)"
            echo '```'
            h8mail -t "$email" 2>/dev/null | head -50
            echo '```'
        fi
        
    } > "$report_file"
    
    success "Email report: ${report_file}"
}

investigate_phone() {
    local phone="$1"
    local output_dir="${RAW_DIR}/phone"
    mkdir -p "$output_dir"
    
    print_subsection "Phone Investigation: ${phone}"
    
    if command -v phoneinfoga &>/dev/null; then
        phoneinfoga scan -n "$phone" 2>/dev/null | tee "${output_dir}/${phone//[^0-9]/}_$(date +%Y%m%d_%H%M%S).txt"
    else
        warn "PhoneInfoga not installed"
    fi
}

investigate_domain() {
    local domain="$1"
    local output_dir="${RAW_DIR}/domain"
    mkdir -p "$output_dir"
    
    print_subsection "Domain Investigation: ${domain}"
    
    local report_file; report_file="${output_dir}/${domain//./_}_$(date +%Y%m%d_%H%M%S).md"

    {
        echo "# Domain Investigation: ${domain}"
        echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
        
        echo "## WHOIS"
        echo '```'
        whois "$domain" 2>/dev/null | head -80
        echo '```'
        
        echo "## DNS Records"
        echo '```'
        for rtype in A AAAA MX NS TXT; do
            echo "--- ${rtype} ---"
            dig +short "$domain" "$rtype" 2>/dev/null
        done
        echo '```'
        
        if command -v subfinder &>/dev/null; then
            echo "## Subdomains"
            echo '```'
            subfinder -d "$domain" -silent 2>/dev/null | head -30
            echo '```'
        fi
        
    } > "$report_file"
    
    success "Domain report: ${report_file}"
}

investigate_ip() {
    local ip="$1"
    local output_dir="${RAW_DIR}/ip"
    mkdir -p "$output_dir"
    
    print_subsection "IP Investigation: ${ip}"
    
    local report_file; report_file="${output_dir}/${ip//./_}_$(date +%Y%m%d_%H%M%S).md"

    {
        echo "# IP Investigation: ${ip}"
        echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
        
        echo "## WHOIS/Abuse Contact"
        echo '```'
        whois "$ip" 2>/dev/null | grep -iE "abuse|orgname|netname|country" | head -20
        echo '```'
        
        echo "## Geolocation"
        echo '```'
        curl -s "http://ip-api.com/json/${ip}" 2>/dev/null | python3 -m json.tool 2>/dev/null
        echo '```'
        
        echo "## Reverse DNS"
        echo '```'
        dig -x "$ip" +short 2>/dev/null
        echo '```'
        
    } > "$report_file"
    
    success "IP report: ${report_file}"
}

investigate_username() {
    local username="$1"
    local output_dir="${RAW_DIR}/username"
    mkdir -p "$output_dir"
    
    print_subsection "Username Investigation: ${username}"
    
    if command -v maigret &>/dev/null; then
        info "Running Maigret..."
        maigret "$username" -o "$output_dir" --pdf 2>/dev/null
    elif command -v sherlock &>/dev/null; then
        info "Running Sherlock..."
        sherlock "$username" --output "${output_dir}/${username}.txt" 2>/dev/null
    else
        warn "Neither Maigret nor Sherlock installed"
    fi
}

investigate_all() {
    [[ ${#EMAILS[@]} -gt 0 ]] && for e in "${EMAILS[@]}"; do investigate_email "$e"; done
    [[ ${#PHONES[@]} -gt 0 ]] && for p in "${PHONES[@]}"; do investigate_phone "$p"; done
    [[ ${#DOMAINS[@]} -gt 0 ]] && for d in "${DOMAINS[@]}"; do investigate_domain "$d"; done
    [[ ${#IPS[@]} -gt 0 ]] && for i in "${IPS[@]}"; do investigate_ip "$i"; done
    [[ ${#USERNAMES[@]} -gt 0 ]] && for u in "${USERNAMES[@]}"; do investigate_username "$u"; done
}

#-------------------------------------------------------------------------------
# MENUS
#-------------------------------------------------------------------------------
show_investigation_menu() {
    while true; do
        print_banner
        [[ -n "$CASE_ID" ]] && echo -e "  ${WHITE}Active Case:${NC} ${CYAN}${CASE_ID}${NC}"
        echo ""
        echo -e "  ${GREEN}[1]${NC}  📧 Email Investigation"
        echo -e "  ${GREEN}[2]${NC}  📱 Phone Investigation"
        echo -e "  ${GREEN}[3]${NC}  🌐 Domain Investigation"
        echo -e "  ${GREEN}[4]${NC}  🔢 IP Address Investigation"
        echo -e "  ${GREEN}[5]${NC}  👤 Username Investigation"
        echo ""
        echo -e "  ${CYAN}[A]${NC}  🚀 Run All Investigations"
        echo ""
        echo -e "  ${YELLOW}[0]${NC}  Back"
        echo ""
        
        read -rp "Select: " choice
        case $choice in
            1) [[ -n "$CASE_ID" ]] && { for e in "${EMAILS[@]}"; do investigate_email "$e"; done; } || warn "Load case first"; press_enter ;;
            2) [[ -n "$CASE_ID" ]] && { for p in "${PHONES[@]}"; do investigate_phone "$p"; done; } || warn "Load case first"; press_enter ;;
            3) [[ -n "$CASE_ID" ]] && { for d in "${DOMAINS[@]}"; do investigate_domain "$d"; done; } || warn "Load case first"; press_enter ;;
            4) [[ -n "$CASE_ID" ]] && { for i in "${IPS[@]}"; do investigate_ip "$i"; done; } || warn "Load case first"; press_enter ;;
            5) [[ -n "$CASE_ID" ]] && { for u in "${USERNAMES[@]}"; do investigate_username "$u"; done; } || warn "Load case first"; press_enter ;;
            [Aa]) [[ -n "$CASE_ID" ]] && investigate_all || warn "Load case first"; press_enter ;;
            0) return ;;
        esac
    done
}

show_reports_menu() {
    while true; do
        print_banner
        print_section "Reports & Abuse Reports"
        
        echo -e "  ${GREEN}[1]${NC}  📄 Generate Final Investigation Report"
        echo -e "  ${GREEN}[2]${NC}  📝 Generate Abuse Report (Domain Registrar)"
        echo -e "  ${GREEN}[3]${NC}  📝 Generate Abuse Report (Hosting Provider)"
        echo -e "  ${GREEN}[4]${NC}  📝 Generate Abuse Report (Email Provider)"
        echo -e "  ${GREEN}[5]${NC}  📝 Generate IC3 Worksheet"
        echo ""
        echo -e "  ${CYAN}[A]${NC}  🚀 Launch Abuse Report Generator"
        echo ""
        echo -e "  ${YELLOW}[0]${NC}  Back"
        echo ""
        
        read -rp "Select: " choice
        case $choice in
            [Aa])
                local abuse_script="${SCRIPT_DIR}/abuse_report_generator.sh"
                if [[ -x "$abuse_script" ]]; then
                    "$abuse_script"
                else
                    warn "Abuse report generator not found"
                fi
                press_enter
                ;;
            0) return ;;
            *) warn "Use [A] to launch abuse report generator"; press_enter ;;
        esac
    done
}

show_integration_menu() {
    local integration_script="${SCRIPT_DIR}/toolkit_integration.sh"
    # shellcheck source=/dev/null
    [[ -f "$integration_script" ]] && source "$integration_script"
    
    while true; do
        print_banner
        print_section "Integrated Tools (scripts/ folder)"
        
        echo -e "  ${GREEN}[1]${NC}  🔍 Run scammer_audit.sh"
        echo -e "  ${GREEN}[2]${NC}  📧 Run email_audit.sh"
        echo -e "  ${GREEN}[3]${NC}  📱 Run phone_audit.sh"
        echo -e "  ${GREEN}[4]${NC}  🌐 Run full_nmap_scan.sh"
        echo -e "  ${GREEN}[5]${NC}  🌿 Run theHarvester"
        echo ""
        echo -e "  ${GREEN}[S]${NC}  📊 Show Integration Status"
        echo -e "  ${GREEN}[C]${NC}  ⚙️  Configure Integration"
        echo -e "  ${GREEN}[D]${NC}  🔄 Auto-Detect Scripts"
        echo ""
        echo -e "  ${YELLOW}[0]${NC}  Back"
        echo ""
        
        read -rp "Select: " choice
        case $choice in
            1)
                if [[ -n "$CASE_ID" ]]; then
                    read -rp "Enter target (domain/IP): " target
                    if [[ -n "$target" ]]; then
                        mkdir -p "${RAW_DIR}/integrated"
                        run_scammer_audit "$target" "${RAW_DIR}/integrated" 2>/dev/null || \
                            warn "scammer_audit.sh not configured - run [D] to detect or [C] to configure"
                    fi
                else
                    warn "Load a case first"
                fi
                press_enter
                ;;
            2)
                if [[ -n "$CASE_ID" ]]; then
                    read -rp "Enter email address: " target
                    if [[ -n "$target" ]]; then
                        mkdir -p "${RAW_DIR}/integrated"
                        run_email_audit "$target" "${RAW_DIR}/integrated" 2>/dev/null || \
                            warn "email_audit.sh not configured - run [D] to detect or [C] to configure"
                    fi
                else
                    warn "Load a case first"
                fi
                press_enter
                ;;
            3)
                if [[ -n "$CASE_ID" ]]; then
                    read -rp "Enter phone number: " target
                    if [[ -n "$target" ]]; then
                        mkdir -p "${RAW_DIR}/integrated"
                        run_phone_audit "$target" "${RAW_DIR}/integrated" 2>/dev/null || \
                            warn "phone_audit.sh not configured - run [D] to detect or [C] to configure"
                    fi
                else
                    warn "Load a case first"
                fi
                press_enter
                ;;
            4)
                if [[ -n "$CASE_ID" ]]; then
                    read -rp "Enter target IP address: " target
                    if [[ -n "$target" ]]; then
                        mkdir -p "${RAW_DIR}/integrated"
                        run_full_nmap "$target" "${RAW_DIR}/integrated" 2>/dev/null || \
                            warn "full_nmap_scan.sh not configured - run [D] to detect or [C] to configure"
                    fi
                else
                    warn "Load a case first"
                fi
                press_enter
                ;;
            5)
                if [[ -n "$CASE_ID" ]]; then
                    read -rp "Enter domain: " target
                    if [[ -n "$target" ]]; then
                        mkdir -p "${RAW_DIR}/integrated"
                        run_theharvester "$target" "${RAW_DIR}/integrated" 2>/dev/null || \
                            warn "theHarvester not configured"
                    fi
                else
                    warn "Load a case first"
                fi
                press_enter
                ;;
            [Ss]) show_integration_status 2>/dev/null || warn "Integration module not loaded"; press_enter ;;
            [Cc]) configure_integration 2>/dev/null; press_enter ;;
            [Dd]) 
                detect_existing_scripts 2>/dev/null && save_integration_config 2>/dev/null
                press_enter 
                ;;
            0) return ;;
            *) warn "Invalid option"; press_enter ;;
        esac
    done
}

show_settings_menu() {
    while true; do
        print_banner
        print_section "Settings"
        
        echo -e "  ${GREEN}[1]${NC}  🔑 Configure API Keys"
        echo -e "  ${GREEN}[2]${NC}  📊 View API Status"
        echo -e "  ${GREEN}[3]${NC}  🔧 Check Tool Status"
        echo -e "  ${GREEN}[4]${NC}  📦 Install Dependencies"
        echo ""
        echo -e "  ${YELLOW}[0]${NC}  Back"
        echo ""
        
        read -rp "Select: " choice
        case $choice in
            1) configure_apis; press_enter ;;
            2) show_api_status; press_enter ;;
            3) show_tool_status; press_enter ;;
            4)
                local installer="${SCRIPT_DIR}/install_dependencies.sh"
                if [[ -x "$installer" ]]; then
                    sudo "$installer"
                else
                    warn "Installer not found"
                fi
                press_enter
                ;;
            0) return ;;
        esac
    done
}

show_main_menu() {
    while true; do
        print_banner
        
        [[ -n "$CASE_ID" ]] && {
            echo -e "  ${WHITE}Active Case:${NC} ${CYAN}${CASE_ID}${NC}"
            echo -e "  ${WHITE}Directory:${NC} ${DIM}${CASE_DIR}${NC}"
        }
        echo ""
        
        echo -e "  ${GREEN}[1]${NC}  📁 Create New Case"
        echo -e "  ${GREEN}[2]${NC}  📂 Load Existing Case"
        echo -e "  ${GREEN}[3]${NC}  📋 List Cases"
        echo ""
        echo -e "  ${GREEN}[4]${NC}  🔍 Investigation Menu"
        echo -e "  ${GREEN}[5]${NC}  📄 Reports & Abuse Reports"
        echo -e "  ${GREEN}[6]${NC}  🔗 Integrated Tools"
        echo -e "  ${GREEN}[7]${NC}  ⚙️  Settings"
        echo ""
        echo -e "  ${CYAN}[W]${NC}  🌐 Launch Web Interface"
        echo ""
        echo -e "  ${RED}[0]${NC}  Exit"
        echo ""
        
        read -rp "Select: " choice
        case $choice in
            1) create_new_case; press_enter ;;
            2) select_case; press_enter ;;
            3) list_cases; press_enter ;;
            4) show_investigation_menu ;;
            5) show_reports_menu ;;
            6) show_integration_menu ;;
            7) show_settings_menu ;;
            [Ww]) launch_web_interface; press_enter ;;
            0)
                [[ -n "$CASE_ID" ]] && { save_case_state; success "Case saved"; }
                info "Goodbye!"
                exit 0
                ;;
        esac
    done
}

#-------------------------------------------------------------------------------
# MAIN
#-------------------------------------------------------------------------------
main() {
    init_config
    
    case "${1:-}" in
        --install|-i) sudo "${SCRIPT_DIR}/install_dependencies.sh"; exit ;;
        --config|-c) configure_apis; exit ;;
        --status|-s) show_tool_status; show_api_status; exit ;;
        --web|-w) launch_web_interface; exit ;;
        --help|-h)
            echo "OSINT Investigator Playbook"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "  --install    Install dependencies"
            echo "  --config     Configure API keys"
            echo "  --status     Show tool/API status"
            echo "  --web        Launch web interface"
            echo "  --help       Show this help"
            exit 0
            ;;
    esac
    
    show_main_menu
}

main "$@"
