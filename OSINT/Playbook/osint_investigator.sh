#!/bin/bash
#===============================================================================
#
#          FILE: osint_investigator.sh
#
#         USAGE: ./osint_investigator.sh [--install|--config|--help]
#
#   DESCRIPTION: Comprehensive OSINT Investigation Playbook for Scam/Fraud Cases
#                Designed for victim investigation and abuse reporting workflows
#
#        AUTHOR: PNW Computers (jon@pnwcomputers.com)
#       VERSION: 2.0
#       CREATED: 2024
#      PLATFORM: Tsurugi Linux / Ubuntu / Debian
#
#   REQUIREMENTS: See install_dependencies.sh for full requirements
#
#===============================================================================

set -o pipefail

#-------------------------------------------------------------------------------
# GLOBAL CONFIGURATION
#-------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_CONFIG="${CONFIG_DIR}/api_keys.conf"
CASE_BASE_DIR="${HOME}/OSINT_Cases"
LOG_DIR="${CONFIG_DIR}/logs"
TOOLS_DIR="${CONFIG_DIR}/tools"

# Current case variables (set during runtime)
CASE_ID=""
CASE_DIR=""
EVIDENCE_DIR=""
REPORTS_DIR=""
LOGS_DIR=""
RAW_DIR=""

# Investigation data collection
declare -A INVESTIGATION_DATA
declare -a EMAILS=()
declare -a PHONES=()
declare -a DOMAINS=()
declare -a IPS=()
declare -a USERNAMES=()
declare -a CRYPTO_ADDRESSES=()
declare -a URLS=()
COMPANY_NAME=""
CASE_NOTES=""

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
# LOGGING FUNCTIONS
#-------------------------------------------------------------------------------
LOG_FILE=""

init_logging() {
    mkdir -p "${LOG_DIR}"
    LOG_FILE="${LOG_DIR}/osint_$(date +%Y%m%d_%H%M%S).log"
    exec 3>&1 4>&2
    exec 1> >(tee -a "${LOG_FILE}") 2>&1
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}" 2>/dev/null
}

log_info() { log "INFO" "$*"; }
log_warn() { log "WARN" "$*"; }
log_error() { log "ERROR" "$*"; }
log_debug() { log "DEBUG" "$*"; }

#-------------------------------------------------------------------------------
# UI HELPER FUNCTIONS
#-------------------------------------------------------------------------------
print_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║    ██████╗ ███████╗██╗███╗   ██╗████████╗    ██████╗ ██╗      █████╗ ██╗   ██╗   ║
║   ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔══██╗██║     ██╔══██╗╚██╗ ██╔╝   ║
║   ██║   ██║███████╗██║██╔██╗ ██║   ██║       ██████╔╝██║     ███████║ ╚████╔╝    ║
║   ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔═══╝ ██║     ██╔══██║  ╚██╔╝     ║
║   ╚██████╔╝███████║██║██║ ╚████║   ██║       ██║     ███████╗██║  ██║   ██║      ║
║    ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝      ║
║                                                                                  ║
║              I N V E S T I G A T O R   P L A Y B O O K   v 2 . 0                 ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  Scam & Fraud Investigation | Evidence Collection | Abuse Reporting | IC3 Ready  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_subsection() {
    echo ""
    echo -e "${BLUE}┌─── $1 ───${NC}"
}

info() { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
debug() { [[ "${DEBUG:-0}" == "1" ]] && echo -e "${DIM}[D] $1${NC}"; }

prompt() {
    local var_name="$1"
    local prompt_text="$2"
    local default="$3"
    local value
    
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${YELLOW}[?]${NC} ${prompt_text} [${default}]: ")" value
        value="${value:-$default}"
    else
        read -rp "$(echo -e "${YELLOW}[?]${NC} ${prompt_text}: ")" value
    fi
    
    eval "$var_name=\"$value\""
}

prompt_array() {
    local array_name="$1"
    local prompt_text="$2"
    local input
    
    echo -e "${YELLOW}[?]${NC} ${prompt_text}"
    echo -e "${DIM}    (Enter one per line, empty line when done)${NC}"
    
    eval "$array_name=()"
    while true; do
        read -rp "    → " input
        [[ -z "$input" ]] && break
        eval "$array_name+=(\"\$input\")"
    done
}

confirm() {
    local prompt_text="$1"
    local response
    read -rp "$(echo -e "${YELLOW}[?]${NC} ${prompt_text} [y/N]: ")" response
    [[ "$response" =~ ^[Yy]$ ]]
}

press_enter() {
    echo ""
    read -rp "$(echo -e "${DIM}Press Enter to continue...${NC}")"
}

spinner() {
    local pid=$1
    local message="$2"
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${BLUE}[%s]${NC} %s" "${spin:i++%${#spin}:1}" "$message"
        sleep 0.1
    done
    printf "\r"
}

#-------------------------------------------------------------------------------
# ERROR HANDLING
#-------------------------------------------------------------------------------
handle_error() {
    local exit_code=$?
    local line_no=$1
    error "Error on line ${line_no}: Exit code ${exit_code}"
    log_error "Script error on line ${line_no} with exit code ${exit_code}"
}

trap 'handle_error ${LINENO}' ERR

check_tool() {
    local tool="$1"
    local install_hint="$2"
    
    if ! command -v "$tool" &>/dev/null; then
        warn "Tool not found: ${tool}"
        [[ -n "$install_hint" ]] && echo -e "    ${DIM}Install: ${install_hint}${NC}"
        return 1
    fi
    return 0
}

require_tool() {
    local tool="$1"
    local install_hint="$2"
    
    if ! check_tool "$tool" "$install_hint"; then
        error "Required tool '${tool}' is not installed."
        if confirm "Would you like to try installing it now?"; then
            install_single_tool "$tool"
        else
            return 1
        fi
    fi
    return 0
}

#-------------------------------------------------------------------------------
# CONFIGURATION & API MANAGEMENT
#-------------------------------------------------------------------------------
init_config() {
    mkdir -p "${CONFIG_DIR}" "${LOG_DIR}" "${TOOLS_DIR}"
    
    if [[ ! -f "${API_CONFIG}" ]]; then
        create_api_config
    fi
    
    # Source API keys
    # shellcheck source=/dev/null
    [[ -f "${API_CONFIG}" ]] && source "${API_CONFIG}"
}

create_api_config() {
    cat > "${API_CONFIG}" << 'APIEOF'
#===============================================================================
# OSINT Investigator API Configuration
# 
# SECURITY: chmod 600 this file after editing!
# DO NOT commit to version control with real keys!
#===============================================================================

#--- Primary Intelligence APIs ---
export SHODAN_API_KEY=""
export VIRUSTOTAL_API_KEY=""
export CENSYS_API_ID=""
export CENSYS_API_SECRET=""
export SECURITYTRAILS_API_KEY=""

#--- Email & Breach APIs ---
export HAVEIBEENPWNED_API_KEY=""
export HUNTER_API_KEY=""
export EMAILREP_API_KEY=""
export INTELX_API_KEY=""

#--- Domain & DNS APIs ---
export WHOISXML_API_KEY=""
export DNSDUMPSTER_API_KEY=""
export URLSCAN_API_KEY=""

#--- Phone Verification ---
export NUMVERIFY_API_KEY=""
export VERIPHONE_API_KEY=""
export ABSTRACTAPI_KEY=""

#--- Social & Username ---
export SOCIAL_ANALYZER_API=""

#--- Cryptocurrency ---
export ETHERSCAN_API_KEY=""
export BLOCKCYPHER_API_KEY=""

#--- Project Discovery Cloud ---
export PDCP_API_KEY=""

#--- Abuse Reporting ---
export ABUSEIPDB_API_KEY=""
APIEOF
    
    chmod 600 "${API_CONFIG}"
    success "Created API config: ${API_CONFIG}"
}

configure_apis() {
    print_section "API Key Configuration"
    
    # shellcheck source=/dev/null
    source "${API_CONFIG}" 2>/dev/null
    
    echo "Configure API keys for enhanced investigation capabilities."
    echo "Leave blank to skip. Keys are saved to: ${API_CONFIG}"
    echo ""
    
    local apis=(
        "SHODAN_API_KEY:Shodan (IP/Port Intelligence)"
        "VIRUSTOTAL_API_KEY:VirusTotal (Malware/URL Analysis)"
        "HAVEIBEENPWNED_API_KEY:HaveIBeenPwned (Breach Data)"
        "HUNTER_API_KEY:Hunter.io (Email Discovery)"
        "SECURITYTRAILS_API_KEY:SecurityTrails (Domain Intel)"
        "CENSYS_API_ID:Censys API ID"
        "CENSYS_API_SECRET:Censys API Secret"
        "INTELX_API_KEY:Intelligence X (Deep Search)"
        "ABUSEIPDB_API_KEY:AbuseIPDB (IP Reputation)"
        "WHOISXML_API_KEY:WhoisXML (WHOIS Data)"
        "VERIPHONE_API_KEY:Veriphone (Phone Lookup)"
        "PDCP_API_KEY:ProjectDiscovery Cloud"
    )
    
    for api_entry in "${apis[@]}"; do
        local var_name="${api_entry%%:*}"
        local description="${api_entry#*:}"
        local current_value="${!var_name}"
        local masked=""
        
        if [[ -n "$current_value" ]]; then
            masked="${current_value:0:4}...${current_value: -4}"
            echo -e "${GREEN}●${NC} ${description}"
            echo -e "  Current: ${masked}"
        else
            echo -e "${RED}○${NC} ${description}"
        fi
        
        read -rp "  Enter new key (or press Enter to keep): " new_value
        
        if [[ -n "$new_value" ]]; then
            sed -i "s|^export ${var_name}=.*|export ${var_name}=\"${new_value}\"|" "${API_CONFIG}"
            success "Updated ${var_name}"
        fi
        echo ""
    done
    
    # Reload configuration
    # shellcheck source=/dev/null
    source "${API_CONFIG}"
    success "API configuration saved"
}

show_api_status() {
    print_section "API Key Status"
    
    # shellcheck source=/dev/null
    source "${API_CONFIG}" 2>/dev/null
    
    local apis=(
        "SHODAN_API_KEY:Shodan"
        "VIRUSTOTAL_API_KEY:VirusTotal"
        "HAVEIBEENPWNED_API_KEY:HaveIBeenPwned"
        "HUNTER_API_KEY:Hunter.io"
        "SECURITYTRAILS_API_KEY:SecurityTrails"
        "CENSYS_API_ID:Censys"
        "INTELX_API_KEY:Intelligence X"
        "ABUSEIPDB_API_KEY:AbuseIPDB"
        "WHOISXML_API_KEY:WhoisXML"
        "VERIPHONE_API_KEY:Veriphone"
        "PDCP_API_KEY:ProjectDiscovery"
    )
    
    echo -e "${WHITE}Legend: ${GREEN}●${NC} Configured  ${RED}○${NC} Not Set${NC}"
    echo ""
    
    for api_entry in "${apis[@]}"; do
        local var_name="${api_entry%%:*}"
        local description="${api_entry#*:}"
        local value="${!var_name}"
        
        if [[ -n "$value" ]]; then
            echo -e "  ${GREEN}●${NC} ${description}"
        else
            echo -e "  ${RED}○${NC} ${description}"
        fi
    done
}

#-------------------------------------------------------------------------------
# CASE MANAGEMENT
#-------------------------------------------------------------------------------
create_new_case() {
    print_section "Create New Investigation Case"
    
    prompt CASE_ID "Enter Case ID (e.g., 2024-001-SCAM)" "$(date +%Y-%m%d)-001"
    
    # Sanitize case ID
    CASE_ID=$(echo "$CASE_ID" | tr ' ' '_' | tr -cd '[:alnum:]_-')
    
    CASE_DIR="${CASE_BASE_DIR}/${CASE_ID}"
    
    if [[ -d "$CASE_DIR" ]]; then
        if confirm "Case directory exists. Resume this case?"; then
            load_case "$CASE_ID"
            return 0
        else
            error "Case already exists. Choose a different ID."
            return 1
        fi
    fi
    
    # Create case structure
    EVIDENCE_DIR="${CASE_DIR}/evidence"
    REPORTS_DIR="${CASE_DIR}/reports"
    LOGS_DIR="${CASE_DIR}/logs"
    RAW_DIR="${CASE_DIR}/raw_data"
    
    mkdir -p "${EVIDENCE_DIR}"/{screenshots,archives,files,hashes}
    mkdir -p "${REPORTS_DIR}"/{interim,final,abuse_reports}
    mkdir -p "${LOGS_DIR}"
    mkdir -p "${RAW_DIR}"/{email,domain,ip,phone,username,crypto,company}
    
    # Create case metadata
    cat > "${CASE_DIR}/case_info.json" << EOF
{
    "case_id": "${CASE_ID}",
    "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "investigator": "$(whoami)",
    "hostname": "$(hostname)",
    "status": "active"
}
EOF
    
    # Initialize evidence log
    cat > "${CASE_DIR}/evidence_log.md" << EOF
# Evidence Log - Case ${CASE_ID}

## Case Information
- **Case ID:** ${CASE_ID}
- **Created:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')
- **Investigator:** $(whoami)
- **System:** $(hostname)

---

## Evidence Collection Log

| Timestamp | Type | Description | Hash (SHA256) | Source |
|-----------|------|-------------|---------------|--------|

EOF
    
    success "Created case: ${CASE_ID}"
    info "Case directory: ${CASE_DIR}"
    
    # Save case state
    save_case_state
    
    return 0
}

load_case() {
    local case_id="$1"
    
    CASE_ID="$case_id"
    CASE_DIR="${CASE_BASE_DIR}/${CASE_ID}"
    EVIDENCE_DIR="${CASE_DIR}/evidence"
    REPORTS_DIR="${CASE_DIR}/reports"
    LOGS_DIR="${CASE_DIR}/logs"
    RAW_DIR="${CASE_DIR}/raw_data"
    
    if [[ ! -d "$CASE_DIR" ]]; then
        error "Case not found: ${CASE_ID}"
        return 1
    fi
    
    # Load saved state if exists
    if [[ -f "${CASE_DIR}/.case_state" ]]; then
        # shellcheck source=/dev/null
        source "${CASE_DIR}/.case_state"
        success "Loaded case state: ${CASE_ID}"
    fi
    
    return 0
}

save_case_state() {
    [[ -z "$CASE_DIR" ]] && return
    
    cat > "${CASE_DIR}/.case_state" << EOF
# Case state - auto-generated
CASE_ID="${CASE_ID}"
EMAILS=(${EMAILS[*]@Q})
PHONES=(${PHONES[*]@Q})
DOMAINS=(${DOMAINS[*]@Q})
IPS=(${IPS[*]@Q})
USERNAMES=(${USERNAMES[*]@Q})
CRYPTO_ADDRESSES=(${CRYPTO_ADDRESSES[*]@Q})
URLS=(${URLS[*]@Q})
COMPANY_NAME="${COMPANY_NAME}"
CASE_NOTES="${CASE_NOTES}"
EOF
}

list_cases() {
    print_section "Existing Cases"
    
    if [[ ! -d "$CASE_BASE_DIR" ]]; then
        info "No cases found."
        return
    fi
    
    echo -e "${WHITE}ID                          Created              Status${NC}"
    echo "─────────────────────────────────────────────────────────────"
    
    for case_dir in "${CASE_BASE_DIR}"/*/; do
        [[ ! -d "$case_dir" ]] && continue
        
        local case_id
        case_id=$(basename "$case_dir")
        local created="Unknown"
        local status="Unknown"
        
        if [[ -f "${case_dir}/case_info.json" ]]; then
            created=$(grep -oP '"created":\s*"\K[^"]+' "${case_dir}/case_info.json" 2>/dev/null | cut -d'T' -f1)
            status=$(grep -oP '"status":\s*"\K[^"]+' "${case_dir}/case_info.json" 2>/dev/null)
        fi
        
        printf "%-27s %-20s %s\n" "$case_id" "$created" "$status"
    done
}

select_case() {
    list_cases
    echo ""
    prompt selected_case "Enter Case ID to load"
    
    if [[ -n "$selected_case" ]]; then
        load_case "$selected_case"
    fi
}

#-------------------------------------------------------------------------------
# EVIDENCE COLLECTION HELPERS
#-------------------------------------------------------------------------------
log_evidence() {
    local type="$1"
    local description="$2"
    local file="$3"
    local source="$4"
    
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    local hash=""
    
    if [[ -f "$file" ]]; then
        hash=$(sha256sum "$file" | cut -d' ' -f1)
    fi
    
    echo "| ${timestamp} | ${type} | ${description} | ${hash:0:16}... | ${source} |" >> "${CASE_DIR}/evidence_log.md"
    log_info "Evidence logged: ${type} - ${description}"
}

archive_url() {
    local url="$1"
    local output_dir="${EVIDENCE_DIR}/archives"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local safe_name
    safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-50)
    
    info "Archiving: ${url}"
    
    # Method 1: Monolith (single HTML file)
    if check_tool "monolith"; then
        local monolith_file="${output_dir}/${safe_name}_${timestamp}.html"
        if monolith "$url" -o "$monolith_file" 2>/dev/null; then
            success "Archived with Monolith: ${monolith_file}"
            log_evidence "Archive" "Monolith capture of ${url}" "$monolith_file" "monolith"
        fi
    fi
    
    # Method 2: wget mirror
    local wget_dir="${output_dir}/${safe_name}_${timestamp}_mirror"
    if wget --mirror --convert-links --adjust-extension --page-requisites \
            --no-parent -P "$wget_dir" "$url" 2>/dev/null; then
        success "Mirrored with wget"
    fi
    
    # Method 3: Screenshot
    if check_tool "cutycapt"; then
        local screenshot="${EVIDENCE_DIR}/screenshots/${safe_name}_${timestamp}.png"
        cutycapt --url="$url" --out="$screenshot" 2>/dev/null
        [[ -f "$screenshot" ]] && log_evidence "Screenshot" "Page capture of ${url}" "$screenshot" "cutycapt"
    elif check_tool "wkhtmltoimage"; then
        local screenshot="${EVIDENCE_DIR}/screenshots/${safe_name}_${timestamp}.png"
        wkhtmltoimage "$url" "$screenshot" 2>/dev/null
        [[ -f "$screenshot" ]] && log_evidence "Screenshot" "Page capture of ${url}" "$screenshot" "wkhtmltoimage"
    fi
    
    # Method 4: Wayback Machine submission
    if check_tool "waybackpy"; then
        info "Submitting to Wayback Machine..."
        local wayback_url
        wayback_url=$(waybackpy --url "$url" --save 2>/dev/null)
        if [[ -n "$wayback_url" ]]; then
            success "Wayback: ${wayback_url}"
            echo "${url} -> ${wayback_url}" >> "${output_dir}/wayback_receipts.txt"
        fi
    fi
}

hash_evidence() {
    local file="$1"
    local hash_file="${EVIDENCE_DIR}/hashes/$(basename "$file").hash"
    
    {
        echo "File: ${file}"
        echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "MD5:    $(md5sum "$file" | cut -d' ' -f1)"
        echo "SHA1:   $(sha1sum "$file" | cut -d' ' -f1)"
        echo "SHA256: $(sha256sum "$file" | cut -d' ' -f1)"
    } > "$hash_file"
    
    success "Hash manifest: ${hash_file}"
}

#-------------------------------------------------------------------------------
# EMAIL INVESTIGATION MODULE
#-------------------------------------------------------------------------------
investigate_email() {
    local email="$1"
    local output_dir="${RAW_DIR}/email"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local safe_email
    safe_email=$(echo "$email" | tr '@.' '_')
    local report_file="${output_dir}/${safe_email}_${timestamp}.md"
    
    print_subsection "Email Investigation: ${email}"
    
    {
        echo "# Email Investigation Report"
        echo "## Target: ${email}"
        echo "## Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } > "$report_file"
    
    # 1. Holehe - Account Discovery
    if check_tool "holehe"; then
        info "Running Holehe (account discovery)..."
        echo "### Account Discovery (Holehe)" >> "$report_file"
        echo '```' >> "$report_file"
        holehe "$email" --only-used 2>/dev/null | tee -a "$report_file"
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    else
        warn "Holehe not installed - skipping account discovery"
    fi
    
    # 2. h8mail - Breach Search
    if check_tool "h8mail"; then
        info "Running h8mail (breach search)..."
        local breach_file="${output_dir}/${safe_email}_breaches.csv"
        h8mail -t "$email" -o "$breach_file" 2>/dev/null
        
        echo "### Breach Data (h8mail)" >> "$report_file"
        if [[ -f "$breach_file" ]]; then
            echo '```' >> "$report_file"
            cat "$breach_file" >> "$report_file"
            echo '```' >> "$report_file"
        fi
        echo "" >> "$report_file"
    fi
    
    # 3. HaveIBeenPwned API
    if [[ -n "${HAVEIBEENPWNED_API_KEY}" ]]; then
        info "Checking HaveIBeenPwned..."
        echo "### HaveIBeenPwned Results" >> "$report_file"
        
        local hibp_response
        hibp_response=$(curl -s --request GET \
            --url "https://haveibeenpwned.com/api/v3/breachedaccount/${email}" \
            --header "hibp-api-key: ${HAVEIBEENPWNED_API_KEY}" \
            --header "user-agent: OSINT-Investigator" \
            -w "\n%{http_code}")
        
        local http_code
        http_code=$(echo "$hibp_response" | tail -1)
        local body
        body=$(echo "$hibp_response" | head -n -1)
        
        if [[ "$http_code" == "200" ]]; then
            warn "Email found in breaches!"
            echo '```json' >> "$report_file"
            echo "$body" | python3 -m json.tool >> "$report_file" 2>/dev/null
            echo '```' >> "$report_file"
        elif [[ "$http_code" == "404" ]]; then
            success "Email not found in HIBP breaches"
            echo "No breaches found." >> "$report_file"
        else
            warn "HIBP returned: ${http_code}"
        fi
        echo "" >> "$report_file"
    fi
    
    # 4. Hunter.io - Email Verification
    if [[ -n "${HUNTER_API_KEY}" ]]; then
        info "Verifying with Hunter.io..."
        echo "### Hunter.io Verification" >> "$report_file"
        
        local hunter_response
        hunter_response=$(curl -s "https://api.hunter.io/v2/email-verifier?email=${email}&api_key=${HUNTER_API_KEY}")
        
        echo '```json' >> "$report_file"
        echo "$hunter_response" | python3 -m json.tool >> "$report_file" 2>/dev/null
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 5. Email header analysis hint
    echo "### Manual Checks Required" >> "$report_file"
    echo "- [ ] Analyze email headers if available" >> "$report_file"
    echo "- [ ] Check sender reputation" >> "$report_file"
    echo "- [ ] Verify SPF/DKIM/DMARC" >> "$report_file"
    echo "" >> "$report_file"
    
    success "Email report saved: ${report_file}"
    log_evidence "Email Report" "Investigation of ${email}" "$report_file" "osint_investigator"
}

investigate_all_emails() {
    print_section "Email Investigation"
    
    if [[ ${#EMAILS[@]} -eq 0 ]]; then
        warn "No email addresses configured for this case."
        prompt_array EMAILS "Enter email addresses to investigate"
        save_case_state
    fi
    
    for email in "${EMAILS[@]}"; do
        investigate_email "$email"
        echo ""
    done
}

#-------------------------------------------------------------------------------
# PHONE INVESTIGATION MODULE
#-------------------------------------------------------------------------------
investigate_phone() {
    local phone="$1"
    local output_dir="${RAW_DIR}/phone"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local safe_phone
    safe_phone=$(echo "$phone" | tr -cd '[:alnum:]')
    local report_file="${output_dir}/${safe_phone}_${timestamp}.md"
    
    print_subsection "Phone Investigation: ${phone}"
    
    {
        echo "# Phone Investigation Report"
        echo "## Target: ${phone}"
        echo "## Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } > "$report_file"
    
    # 1. PhoneInfoga
    if check_tool "phoneinfoga"; then
        info "Running PhoneInfoga..."
        echo "### PhoneInfoga Results" >> "$report_file"
        echo '```' >> "$report_file"
        phoneinfoga scan -n "$phone" 2>/dev/null | tee -a "$report_file"
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    else
        warn "PhoneInfoga not installed"
    fi
    
    # 2. Veriphone API
    if [[ -n "${VERIPHONE_API_KEY}" ]]; then
        info "Checking Veriphone..."
        echo "### Veriphone Results" >> "$report_file"
        
        local veriphone_response
        veriphone_response=$(curl -s "https://api.veriphone.io/v2/verify?phone=${phone}&key=${VERIPHONE_API_KEY}")
        
        echo '```json' >> "$report_file"
        echo "$veriphone_response" | python3 -m json.tool >> "$report_file" 2>/dev/null
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 3. Python phonenumbers library
    if python3 -c "import phonenumbers" 2>/dev/null; then
        info "Parsing with phonenumbers library..."
        echo "### Phone Number Analysis" >> "$report_file"
        echo '```' >> "$report_file"
        
        python3 << EOF >> "$report_file" 2>/dev/null
import phonenumbers
from phonenumbers import carrier, geocoder, timezone

try:
    pn = phonenumbers.parse("${phone}")
    print(f"Valid: {phonenumbers.is_valid_number(pn)}")
    print(f"Country: {geocoder.description_for_number(pn, 'en')}")
    print(f"Carrier: {carrier.name_for_number(pn, 'en')}")
    print(f"Type: {phonenumbers.number_type(pn)}")
    print(f"Timezone: {timezone.time_zones_for_number(pn)}")
    print(f"International: {phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
except Exception as e:
    print(f"Error: {e}")
EOF
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    success "Phone report saved: ${report_file}"
    log_evidence "Phone Report" "Investigation of ${phone}" "$report_file" "osint_investigator"
}

investigate_all_phones() {
    print_section "Phone Investigation"
    
    if [[ ${#PHONES[@]} -eq 0 ]]; then
        warn "No phone numbers configured for this case."
        prompt_array PHONES "Enter phone numbers to investigate (with country code)"
        save_case_state
    fi
    
    for phone in "${PHONES[@]}"; do
        investigate_phone "$phone"
        echo ""
    done
}

#-------------------------------------------------------------------------------
# DOMAIN INVESTIGATION MODULE
#-------------------------------------------------------------------------------
investigate_domain() {
    local domain="$1"
    local output_dir="${RAW_DIR}/domain"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local safe_domain
    safe_domain=$(echo "$domain" | tr '.' '_')
    local report_file="${output_dir}/${safe_domain}_${timestamp}.md"
    
    print_subsection "Domain Investigation: ${domain}"
    
    {
        echo "# Domain Investigation Report"
        echo "## Target: ${domain}"
        echo "## Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } > "$report_file"
    
    # 1. WHOIS
    info "Running WHOIS lookup..."
    echo "### WHOIS Information" >> "$report_file"
    echo '```' >> "$report_file"
    whois "$domain" 2>/dev/null | head -100 >> "$report_file"
    echo '```' >> "$report_file"
    echo "" >> "$report_file"
    
    # 2. DNS Records
    info "Gathering DNS records..."
    echo "### DNS Records" >> "$report_file"
    echo '```' >> "$report_file"
    
    for record_type in A AAAA MX NS TXT SOA CNAME; do
        echo "--- ${record_type} Records ---"
        dig +short "$domain" "$record_type" 2>/dev/null
        echo ""
    done >> "$report_file"
    
    echo '```' >> "$report_file"
    echo "" >> "$report_file"
    
    # 3. Subfinder - Subdomain Enumeration
    if check_tool "subfinder"; then
        info "Running Subfinder (subdomain enumeration)..."
        local subdomains_file="${output_dir}/${safe_domain}_subdomains.txt"
        subfinder -d "$domain" -silent -o "$subdomains_file" 2>/dev/null
        
        echo "### Subdomains Found" >> "$report_file"
        echo '```' >> "$report_file"
        head -50 "$subdomains_file" >> "$report_file" 2>/dev/null
        local sub_count
        sub_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo "0")
        echo "" >> "$report_file"
        echo "Total subdomains: ${sub_count}" >> "$report_file"
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 4. httpx - Technology Detection
    if check_tool "httpx" && [[ -f "${output_dir}/${safe_domain}_subdomains.txt" ]]; then
        info "Running httpx (technology detection)..."
        local tech_file="${output_dir}/${safe_domain}_tech.json"
        
        cat "${output_dir}/${safe_domain}_subdomains.txt" | \
            httpx -silent -td -server -title -asn -json -o "$tech_file" 2>/dev/null
        
        echo "### Technology Stack" >> "$report_file"
        echo '```json' >> "$report_file"
        head -20 "$tech_file" >> "$report_file" 2>/dev/null
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 5. theHarvester
    if check_tool "theHarvester"; then
        info "Running theHarvester..."
        local harvester_file="${output_dir}/${safe_domain}_harvester.html"
        theHarvester -d "$domain" -l 100 -b all -f "${harvester_file%.html}" 2>/dev/null
        
        if [[ -f "$harvester_file" ]]; then
            echo "### theHarvester Results" >> "$report_file"
            echo "Full report: ${harvester_file}" >> "$report_file"
            echo "" >> "$report_file"
        fi
    fi
    
    # 6. SecurityTrails API
    if [[ -n "${SECURITYTRAILS_API_KEY}" ]]; then
        info "Checking SecurityTrails..."
        echo "### SecurityTrails Data" >> "$report_file"
        
        local st_response
        st_response=$(curl -s --request GET \
            --url "https://api.securitytrails.com/v1/domain/${domain}" \
            --header "apikey: ${SECURITYTRAILS_API_KEY}")
        
        echo '```json' >> "$report_file"
        echo "$st_response" | python3 -m json.tool >> "$report_file" 2>/dev/null
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 7. Wayback URLs
    if check_tool "waybackurls"; then
        info "Fetching Wayback URLs..."
        local wayback_file="${output_dir}/${safe_domain}_wayback.txt"
        echo "$domain" | waybackurls > "$wayback_file" 2>/dev/null
        
        echo "### Historical URLs (Wayback)" >> "$report_file"
        echo '```' >> "$report_file"
        head -50 "$wayback_file" >> "$report_file" 2>/dev/null
        local wb_count
        wb_count=$(wc -l < "$wayback_file" 2>/dev/null || echo "0")
        echo "" >> "$report_file"
        echo "Total archived URLs: ${wb_count}" >> "$report_file"
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 8. Certificate Transparency
    info "Checking Certificate Transparency logs..."
    echo "### SSL Certificates (crt.sh)" >> "$report_file"
    echo '```' >> "$report_file"
    curl -s "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
        python3 -c "import sys,json; data=json.load(sys.stdin); [print(f\"{d.get('name_value','N/A')}: {d.get('issuer_name','N/A')[:50]}\") for d in data[:20]]" 2>/dev/null >> "$report_file"
    echo '```' >> "$report_file"
    echo "" >> "$report_file"
    
    # 9. Abuse Contact Identification
    info "Identifying hosting provider and abuse contacts..."
    echo "### Hosting & Abuse Contacts" >> "$report_file"
    
    local domain_ip
    domain_ip=$(dig +short "$domain" A | head -1)
    
    if [[ -n "$domain_ip" ]]; then
        echo "Primary IP: ${domain_ip}" >> "$report_file"
        echo "" >> "$report_file"
        
        if check_tool "asn"; then
            echo '```' >> "$report_file"
            asn "$domain_ip" 2>/dev/null | head -30 >> "$report_file"
            echo '```' >> "$report_file"
        else
            echo '```' >> "$report_file"
            whois "$domain_ip" 2>/dev/null | grep -iE "(abuse|orgname|netname|country)" | head -20 >> "$report_file"
            echo '```' >> "$report_file"
        fi
    fi
    echo "" >> "$report_file"
    
    success "Domain report saved: ${report_file}"
    log_evidence "Domain Report" "Investigation of ${domain}" "$report_file" "osint_investigator"
}

investigate_all_domains() {
    print_section "Domain Investigation"
    
    if [[ ${#DOMAINS[@]} -eq 0 ]]; then
        warn "No domains configured for this case."
        prompt_array DOMAINS "Enter domains to investigate"
        save_case_state
    fi
    
    for domain in "${DOMAINS[@]}"; do
        investigate_domain "$domain"
        echo ""
    done
}

#-------------------------------------------------------------------------------
# IP ADDRESS INVESTIGATION MODULE
#-------------------------------------------------------------------------------
investigate_ip() {
    local ip="$1"
    local output_dir="${RAW_DIR}/ip"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local safe_ip
    safe_ip=$(echo "$ip" | tr '.' '_')
    local report_file="${output_dir}/${safe_ip}_${timestamp}.md"
    
    print_subsection "IP Investigation: ${ip}"
    
    {
        echo "# IP Address Investigation Report"
        echo "## Target: ${ip}"
        echo "## Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } > "$report_file"
    
    # 1. ASN Tool - Primary abuse contact lookup
    if check_tool "asn"; then
        info "Running ASN lookup (abuse contacts)..."
        echo "### ASN & Abuse Contact Information" >> "$report_file"
        echo '```' >> "$report_file"
        asn "$ip" 2>/dev/null >> "$report_file"
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    else
        # Fallback to whois
        info "Running WHOIS lookup..."
        echo "### WHOIS Information" >> "$report_file"
        echo '```' >> "$report_file"
        whois "$ip" 2>/dev/null | grep -iE "(abuse|netname|orgname|country|descr|address)" | head -30 >> "$report_file"
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 2. Geolocation
    info "Fetching geolocation..."
    echo "### Geolocation" >> "$report_file"
    echo '```json' >> "$report_file"
    curl -s "http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query" 2>/dev/null | \
        python3 -m json.tool >> "$report_file" 2>/dev/null
    echo '```' >> "$report_file"
    echo "" >> "$report_file"
    
    # 3. Shodan
    if [[ -n "${SHODAN_API_KEY}" ]]; then
        info "Checking Shodan..."
        echo "### Shodan Intelligence" >> "$report_file"
        echo '```json' >> "$report_file"
        curl -s "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" 2>/dev/null | \
            python3 -m json.tool >> "$report_file" 2>/dev/null
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 4. AbuseIPDB
    if [[ -n "${ABUSEIPDB_API_KEY}" ]]; then
        info "Checking AbuseIPDB..."
        echo "### AbuseIPDB Reputation" >> "$report_file"
        echo '```json' >> "$report_file"
        curl -s --request GET \
            --url "https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose" \
            --header "Key: ${ABUSEIPDB_API_KEY}" \
            --header "Accept: application/json" 2>/dev/null | \
            python3 -m json.tool >> "$report_file" 2>/dev/null
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 5. VirusTotal
    if [[ -n "${VIRUSTOTAL_API_KEY}" ]]; then
        info "Checking VirusTotal..."
        echo "### VirusTotal Analysis" >> "$report_file"
        echo '```json' >> "$report_file"
        curl -s --request GET \
            --url "https://www.virustotal.com/api/v3/ip_addresses/${ip}" \
            --header "x-apikey: ${VIRUSTOTAL_API_KEY}" 2>/dev/null | \
            python3 -m json.tool >> "$report_file" 2>/dev/null
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 6. Censys
    if [[ -n "${CENSYS_API_ID}" ]] && [[ -n "${CENSYS_API_SECRET}" ]]; then
        info "Checking Censys..."
        echo "### Censys Host Data" >> "$report_file"
        echo '```json' >> "$report_file"
        curl -s --request GET \
            --url "https://search.censys.io/api/v2/hosts/${ip}" \
            --user "${CENSYS_API_ID}:${CENSYS_API_SECRET}" 2>/dev/null | \
            python3 -m json.tool >> "$report_file" 2>/dev/null
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 7. Port Scan (if nmap available)
    if check_tool "nmap"; then
        info "Running quick port scan..."
        echo "### Open Ports (Quick Scan)" >> "$report_file"
        echo '```' >> "$report_file"
        nmap -F -T4 --open "$ip" 2>/dev/null >> "$report_file"
        echo '```' >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # 8. Reverse DNS
    info "Checking reverse DNS..."
    echo "### Reverse DNS" >> "$report_file"
    echo '```' >> "$report_file"
    host "$ip" 2>/dev/null >> "$report_file"
    dig -x "$ip" +short 2>/dev/null >> "$report_file"
    echo '```' >> "$report_file"
    echo "" >> "$report_file"
    
    success "IP report saved: ${report_file}"
    log_evidence "IP Report" "Investigation of ${ip}" "$report_file" "osint_investigator"
}

investigate_all_ips() {
    print_section "IP Address Investigation"
    
    if [[ ${#IPS[@]} -eq 0 ]]; then
        warn "No IP addresses configured for this case."
        prompt_array IPS "Enter IP addresses to investigate"
        save_case_state
    fi
    
    for ip in "${IPS[@]}"; do
        investigate_ip "$ip"
        echo ""
    done
}

#-------------------------------------------------------------------------------
# USERNAME INVESTIGATION MODULE
#-------------------------------------------------------------------------------
investigate_username() {
    local username="$1"
    local output_dir="${RAW_DIR}/username"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="${output_dir}/${username}_${timestamp}.md"
    
    print_subsection "Username Investigation: ${username}"
    
    {
        echo "# Username Investigation Report"
        echo "## Target: ${username}"
        echo "## Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } > "$report_file"
    
    # 1. Maigret (2500+ sites)
    if check_tool "maigret"; then
        info "Running Maigret (2500+ sites)..."
        local maigret_dir="${output_dir}/${username}_maigret"
        mkdir -p "$maigret_dir"
        
        maigret "$username" --pdf --html -o "$maigret_dir" 2>/dev/null
        
        echo "### Maigret Results" >> "$report_file"
        echo "Full reports saved to: ${maigret_dir}" >> "$report_file"
        
        # Extract found accounts
        if [[ -f "${maigret_dir}/${username}.txt" ]]; then
            echo '```' >> "$report_file"
            head -100 "${maigret_dir}/${username}.txt" >> "$report_file"
            echo '```' >> "$report_file"
        fi
        echo "" >> "$report_file"
    fi
    
    # 2. Sherlock (400+ sites)
    if check_tool "sherlock"; then
        info "Running Sherlock..."
        local sherlock_file="${output_dir}/${username}_sherlock.csv"
        
        sherlock "$username" --csv --output "$sherlock_file" 2>/dev/null
        
        echo "### Sherlock Results" >> "$report_file"
        if [[ -f "$sherlock_file" ]]; then
            echo '```csv' >> "$report_file"
            cat "$sherlock_file" >> "$report_file"
            echo '```' >> "$report_file"
        fi
        echo "" >> "$report_file"
    fi
    
    # 3. Blackbird (if available)
    if [[ -f "${TOOLS_DIR}/blackbird/blackbird.py" ]]; then
        info "Running Blackbird..."
        python3 "${TOOLS_DIR}/blackbird/blackbird.py" -u "$username" 2>/dev/null | tee -a "$report_file"
    fi
    
    # 4. Manual search links
    echo "### Manual Verification Links" >> "$report_file"
    echo "" >> "$report_file"
    echo "- Twitter: https://twitter.com/${username}" >> "$report_file"
    echo "- Instagram: https://instagram.com/${username}" >> "$report_file"
    echo "- Facebook: https://facebook.com/${username}" >> "$report_file"
    echo "- LinkedIn: https://linkedin.com/in/${username}" >> "$report_file"
    echo "- GitHub: https://github.com/${username}" >> "$report_file"
    echo "- Reddit: https://reddit.com/user/${username}" >> "$report_file"
    echo "- TikTok: https://tiktok.com/@${username}" >> "$report_file"
    echo "- YouTube: https://youtube.com/@${username}" >> "$report_file"
    echo "- Telegram: https://t.me/${username}" >> "$report_file"
    echo "- Discord: Search in Discord servers" >> "$report_file"
    echo "" >> "$report_file"
    
    success "Username report saved: ${report_file}"
    log_evidence "Username Report" "Investigation of ${username}" "$report_file" "osint_investigator"
}

investigate_all_usernames() {
    print_section "Username Investigation"
    
    if [[ ${#USERNAMES[@]} -eq 0 ]]; then
        warn "No usernames configured for this case."
        prompt_array USERNAMES "Enter usernames to investigate"
        save_case_state
    fi
    
    for username in "${USERNAMES[@]}"; do
        investigate_username "$username"
        echo ""
    done
}

#-------------------------------------------------------------------------------
# CRYPTOCURRENCY INVESTIGATION MODULE
#-------------------------------------------------------------------------------
investigate_crypto() {
    local address="$1"
    local output_dir="${RAW_DIR}/crypto"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local safe_addr
    safe_addr=$(echo "$address" | cut -c1-20)
    local report_file="${output_dir}/${safe_addr}_${timestamp}.md"
    
    print_subsection "Cryptocurrency Investigation: ${address:0:20}..."
    
    {
        echo "# Cryptocurrency Address Investigation"
        echo "## Address: ${address}"
        echo "## Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
    } > "$report_file"
    
    # Detect address type
    local addr_type="unknown"
    if [[ "$address" =~ ^(1|3|bc1) ]]; then
        addr_type="bitcoin"
    elif [[ "$address" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
        addr_type="ethereum"
    elif [[ "$address" =~ ^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$ ]]; then
        addr_type="litecoin"
    fi
    
    echo "### Address Type: ${addr_type}" >> "$report_file"
    echo "" >> "$report_file"
    
    # 1. Check abuse databases
    info "Checking abuse databases..."
    echo "### Abuse Database Checks" >> "$report_file"
    
    # BitcoinAbuse
    echo "#### BitcoinAbuse.com" >> "$report_file"
    echo "Manual check: https://www.bitcoinabuse.com/reports/${address}" >> "$report_file"
    echo "" >> "$report_file"
    
    # Chainabuse
    echo "#### Chainabuse.com" >> "$report_file"
    echo "Manual check: https://www.chainabuse.com/address/${address}" >> "$report_file"
    echo "" >> "$report_file"
    
    # 2. Blockchain Explorer
    info "Fetching blockchain data..."
    echo "### Blockchain Data" >> "$report_file"
    
    case "$addr_type" in
        bitcoin)
            echo "#### Blockchain.com Explorer" >> "$report_file"
            echo '```json' >> "$report_file"
            curl -s "https://blockchain.info/rawaddr/${address}?limit=10" 2>/dev/null | \
                python3 -m json.tool >> "$report_file" 2>/dev/null || echo "Failed to fetch" >> "$report_file"
            echo '```' >> "$report_file"
            
            echo "" >> "$report_file"
            echo "#### OXT.me (Advanced Analysis)" >> "$report_file"
            echo "Manual check: https://oxt.me/address/${address}" >> "$report_file"
            ;;
        ethereum)
            if [[ -n "${ETHERSCAN_API_KEY}" ]]; then
                echo "#### Etherscan Data" >> "$report_file"
                echo '```json' >> "$report_file"
                curl -s "https://api.etherscan.io/api?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=desc&apikey=${ETHERSCAN_API_KEY}" 2>/dev/null | \
                    python3 -m json.tool >> "$report_file" 2>/dev/null
                echo '```' >> "$report_file"
            else
                echo "#### Etherscan" >> "$report_file"
                echo "Manual check: https://etherscan.io/address/${address}" >> "$report_file"
            fi
            ;;
    esac
    echo "" >> "$report_file"
    
    # 3. Transaction summary
    echo "### Investigation Notes" >> "$report_file"
    echo "- [ ] Check total received/sent amounts" >> "$report_file"
    echo "- [ ] Identify connected wallets" >> "$report_file"
    echo "- [ ] Check for exchange deposits" >> "$report_file"
    echo "- [ ] Document transaction timeline" >> "$report_file"
    echo "- [ ] Check CryptoScamDB: https://cryptoscamdb.org/search" >> "$report_file"
    echo "" >> "$report_file"
    
    success "Crypto report saved: ${report_file}"
    log_evidence "Crypto Report" "Investigation of ${address}" "$report_file" "osint_investigator"
}

investigate_all_crypto() {
    print_section "Cryptocurrency Investigation"
    
    if [[ ${#CRYPTO_ADDRESSES[@]} -eq 0 ]]; then
        warn "No cryptocurrency addresses configured for this case."
        prompt_array CRYPTO_ADDRESSES "Enter cryptocurrency addresses to investigate"
        save_case_state
    fi
    
    for address in "${CRYPTO_ADDRESSES[@]}"; do
        investigate_crypto "$address"
        echo ""
    done
}

#-------------------------------------------------------------------------------
# FULL INVESTIGATION (ALL-IN-ONE)
#-------------------------------------------------------------------------------
run_full_investigation() {
    print_section "Full Investigation - Data Collection"
    
    echo "Enter all available information. Press Enter to skip any field."
    echo ""
    
    # Collect all data
    prompt_array EMAILS "Email addresses"
    prompt_array PHONES "Phone numbers (with country code, e.g., +1234567890)"
    prompt_array DOMAINS "Domains (e.g., scam-site.com)"
    prompt_array IPS "IP addresses"
    prompt_array USERNAMES "Usernames/handles"
    prompt_array CRYPTO_ADDRESSES "Cryptocurrency addresses"
    prompt_array URLS "URLs to archive"
    prompt COMPANY_NAME "Company/Business name (if applicable)"
    
    echo ""
    info "Case notes (describe the scam/incident, press Ctrl+D when done):"
    CASE_NOTES=$(cat)
    
    # Save case notes
    echo "$CASE_NOTES" > "${CASE_DIR}/case_notes.txt"
    
    save_case_state
    
    print_section "Starting Full Investigation"
    
    local start_time
    start_time=$(date +%s)
    
    # Run all investigations
    [[ ${#EMAILS[@]} -gt 0 ]] && investigate_all_emails
    [[ ${#PHONES[@]} -gt 0 ]] && investigate_all_phones
    [[ ${#DOMAINS[@]} -gt 0 ]] && investigate_all_domains
    [[ ${#IPS[@]} -gt 0 ]] && investigate_all_ips
    [[ ${#USERNAMES[@]} -gt 0 ]] && investigate_all_usernames
    [[ ${#CRYPTO_ADDRESSES[@]} -gt 0 ]] && investigate_all_crypto
    
    # Archive URLs
    if [[ ${#URLS[@]} -gt 0 ]]; then
        print_section "Archiving URLs"
        for url in "${URLS[@]}"; do
            archive_url "$url"
        done
    fi
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    print_section "Investigation Complete"
    success "Duration: ${duration} seconds"
    success "Case directory: ${CASE_DIR}"
    
    if confirm "Generate final report now?"; then
        generate_final_report
    fi
}

#-------------------------------------------------------------------------------
# REPORT GENERATION
#-------------------------------------------------------------------------------
generate_final_report() {
    print_section "Generating Final Report"
    
    local report_file="${REPORTS_DIR}/final/INVESTIGATION_REPORT_${CASE_ID}.md"
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    
    {
        echo "# Investigation Report"
        echo ""
        echo "## Case Information"
        echo "| Field | Value |"
        echo "|-------|-------|"
        echo "| Case ID | ${CASE_ID} |"
        echo "| Generated | ${timestamp} |"
        echo "| Investigator | $(whoami) |"
        echo "| System | $(hostname) |"
        echo ""
        
        echo "## Executive Summary"
        echo ""
        echo "This report documents the OSINT investigation conducted for case ${CASE_ID}."
        echo ""
        
        if [[ -f "${CASE_DIR}/case_notes.txt" ]]; then
            echo "### Case Notes"
            echo '```'
            cat "${CASE_DIR}/case_notes.txt"
            echo '```'
            echo ""
        fi
        
        echo "## Investigation Targets"
        echo ""
        
        if [[ ${#EMAILS[@]} -gt 0 ]]; then
            echo "### Email Addresses"
            for e in "${EMAILS[@]}"; do echo "- ${e}"; done
            echo ""
        fi
        
        if [[ ${#PHONES[@]} -gt 0 ]]; then
            echo "### Phone Numbers"
            for p in "${PHONES[@]}"; do echo "- ${p}"; done
            echo ""
        fi
        
        if [[ ${#DOMAINS[@]} -gt 0 ]]; then
            echo "### Domains"
            for d in "${DOMAINS[@]}"; do echo "- ${d}"; done
            echo ""
        fi
        
        if [[ ${#IPS[@]} -gt 0 ]]; then
            echo "### IP Addresses"
            for i in "${IPS[@]}"; do echo "- ${i}"; done
            echo ""
        fi
        
        if [[ ${#USERNAMES[@]} -gt 0 ]]; then
            echo "### Usernames"
            for u in "${USERNAMES[@]}"; do echo "- ${u}"; done
            echo ""
        fi
        
        if [[ ${#CRYPTO_ADDRESSES[@]} -gt 0 ]]; then
            echo "### Cryptocurrency Addresses"
            for c in "${CRYPTO_ADDRESSES[@]}"; do echo "- ${c}"; done
            echo ""
        fi
        
        echo "## Detailed Findings"
        echo ""
        echo "See individual reports in the raw_data directory for detailed findings."
        echo ""
        
        # Include evidence log
        echo "## Evidence Log"
        echo ""
        if [[ -f "${CASE_DIR}/evidence_log.md" ]]; then
            tail -n +10 "${CASE_DIR}/evidence_log.md"
        fi
        echo ""
        
        echo "## File Inventory"
        echo ""
        echo "| File | Size | SHA256 |"
        echo "|------|------|--------|"
        
        find "${CASE_DIR}" -type f -name "*.md" -o -name "*.json" -o -name "*.txt" -o -name "*.csv" 2>/dev/null | \
        while read -r f; do
            local size
            size=$(stat -c%s "$f" 2>/dev/null || echo "N/A")
            local hash
            hash=$(sha256sum "$f" 2>/dev/null | cut -c1-16 || echo "N/A")
            echo "| $(basename "$f") | ${size} | ${hash}... |"
        done
        
        echo ""
        echo "## Abuse Reporting Contacts"
        echo ""
        echo "Based on the investigation, reports should be filed with:"
        echo ""
        echo "- [ ] Domain Registrar (see WHOIS data)"
        echo "- [ ] Hosting Provider (see IP investigation)"
        echo "- [ ] Email Provider (see email headers)"
        echo "- [ ] IC3 (ic3.gov) - FBI Internet Crime Complaint Center"
        echo "- [ ] FTC (reportfraud.ftc.gov)"
        echo "- [ ] Local Law Enforcement"
        echo ""
        
        echo "---"
        echo "*Report generated by OSINT Investigator Playbook v2.0*"
        echo "*PNW Computers - jon@pnwcomputers.com*"
        
    } > "$report_file"
    
    success "Final report generated: ${report_file}"
    
    # Generate hash manifest
    local manifest="${REPORTS_DIR}/final/REPORT_MANIFEST.txt"
    {
        echo "Report Manifest - ${CASE_ID}"
        echo "Generated: ${timestamp}"
        echo ""
        sha256sum "${report_file}"
    } > "$manifest"
    
    # Try to convert to PDF if pandoc available
    if check_tool "pandoc"; then
        local pdf_file="${report_file%.md}.pdf"
        pandoc "$report_file" -o "$pdf_file" --pdf-engine=xelatex 2>/dev/null && \
            success "PDF report: ${pdf_file}"
    fi
    
    log_evidence "Final Report" "Investigation report for ${CASE_ID}" "$report_file" "osint_investigator"
}

generate_abuse_report() {
    print_section "Generate Abuse Report Template"
    
    local template_file="${REPORTS_DIR}/abuse_reports/ABUSE_REPORT_${CASE_ID}.md"
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    
    {
        echo "# Abuse Report"
        echo ""
        echo "**Date:** ${timestamp}"
        echo "**Case Reference:** ${CASE_ID}"
        echo "**Reporter:** [Your Name/Organization]"
        echo "**Contact:** [Your Email]"
        echo ""
        echo "## Nature of Abuse"
        echo ""
        echo "[  ] Phishing"
        echo "[  ] Scam/Fraud"
        echo "[  ] Malware Distribution"
        echo "[  ] Spam"
        echo "[  ] Other: ___________"
        echo ""
        echo "## Incident Description"
        echo ""
        if [[ -f "${CASE_DIR}/case_notes.txt" ]]; then
            cat "${CASE_DIR}/case_notes.txt"
        else
            echo "[Describe the incident here]"
        fi
        echo ""
        echo "## Malicious Resources"
        echo ""
        
        if [[ ${#DOMAINS[@]} -gt 0 ]]; then
            echo "### Domains"
            for d in "${DOMAINS[@]}"; do echo "- ${d}"; done
            echo ""
        fi
        
        if [[ ${#IPS[@]} -gt 0 ]]; then
            echo "### IP Addresses"
            for i in "${IPS[@]}"; do echo "- ${i}"; done
            echo ""
        fi
        
        if [[ ${#EMAILS[@]} -gt 0 ]]; then
            echo "### Email Addresses"
            for e in "${EMAILS[@]}"; do echo "- ${e}"; done
            echo ""
        fi
        
        if [[ ${#URLS[@]} -gt 0 ]]; then
            echo "### Malicious URLs"
            for u in "${URLS[@]}"; do echo "- ${u}"; done
            echo ""
        fi
        
        echo "## Evidence"
        echo ""
        echo "Evidence files are attached/available upon request."
        echo "Evidence has been cryptographically hashed for integrity verification."
        echo ""
        echo "## Requested Action"
        echo ""
        echo "- Suspend/terminate the reported resources"
        echo "- Preserve logs for law enforcement"
        echo "- Provide any relevant subscriber information (via proper legal channels)"
        echo ""
        echo "## Contact for Follow-up"
        echo ""
        echo "[Your contact information]"
        echo ""
        
    } > "$template_file"
    
    success "Abuse report template: ${template_file}"
}

#-------------------------------------------------------------------------------
# DEPENDENCY INSTALLATION
#-------------------------------------------------------------------------------
install_single_tool() {
    local tool="$1"
    
    case "$tool" in
        holehe)
            pip3 install holehe
            ;;
        h8mail)
            pip3 install h8mail
            ;;
        maigret)
            pip3 install maigret
            ;;
        sherlock)
            pip3 install sherlock-project
            ;;
        phoneinfoga)
            curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash
            sudo mv phoneinfoga /usr/local/bin/ 2>/dev/null || mv phoneinfoga "${HOME}/.local/bin/"
            ;;
        subfinder)
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
            ;;
        httpx)
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
            ;;
        dnsx)
            go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
            ;;
        waybackurls)
            go install github.com/tomnomnom/waybackurls@latest
            ;;
        asn)
            curl -s https://raw.githubusercontent.com/nitefood/asn/master/asn | sudo tee /usr/bin/asn > /dev/null
            sudo chmod +x /usr/bin/asn
            ;;
        *)
            warn "Unknown tool: ${tool}"
            return 1
            ;;
    esac
}

run_dependency_installer() {
    print_section "Dependency Installation"
    
    info "This will install required tools. Some may require sudo."
    
    if ! confirm "Continue with installation?"; then
        return
    fi
    
    # System packages
    info "Installing system packages..."
    sudo apt update
    sudo apt install -y \
        python3 python3-pip python3-venv \
        nmap whois dnsutils curl wget \
        jq git golang-go \
        hashdeep ssdeep \
        cutycapt wkhtmltopdf pandoc \
        2>/dev/null
    
    # Python tools
    info "Installing Python tools..."
    pip3 install --upgrade pip
    pip3 install \
        holehe \
        h8mail \
        maigret \
        sherlock-project \
        waybackpy \
        phonenumbers \
        requests \
        2>/dev/null
    
    # Go tools
    if command -v go &>/dev/null; then
        info "Installing Go tools..."
        export PATH="${PATH}:${HOME}/go/bin"
        
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        go install github.com/tomnomnom/waybackurls@latest
    else
        warn "Go not installed - skipping Go tools"
    fi
    
    # PhoneInfoga
    info "Installing PhoneInfoga..."
    curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash
    sudo mv phoneinfoga /usr/local/bin/ 2>/dev/null || true
    
    # ASN tool
    info "Installing ASN lookup tool..."
    curl -s https://raw.githubusercontent.com/nitefood/asn/master/asn | sudo tee /usr/bin/asn > /dev/null
    sudo chmod +x /usr/bin/asn
    
    # theHarvester
    if [[ ! -d "${TOOLS_DIR}/theHarvester" ]]; then
        info "Installing theHarvester..."
        git clone https://github.com/laramies/theHarvester.git "${TOOLS_DIR}/theHarvester"
        pip3 install -r "${TOOLS_DIR}/theHarvester/requirements/base.txt"
    fi
    
    success "Installation complete!"
    info "You may need to add ~/go/bin to your PATH"
    echo 'export PATH="${PATH}:${HOME}/go/bin"' >> ~/.bashrc
}

show_tool_status() {
    print_section "Tool Installation Status"
    
    local tools=(
        "holehe:Email account discovery:pip3 install holehe"
        "h8mail:Breach search:pip3 install h8mail"
        "maigret:Username search (2500+ sites):pip3 install maigret"
        "sherlock:Username search (400+ sites):pip3 install sherlock-project"
        "phoneinfoga:Phone investigation:see docs"
        "subfinder:Subdomain enumeration:go install"
        "httpx:HTTP probing:go install"
        "dnsx:DNS toolkit:go install"
        "waybackurls:Wayback Machine URLs:go install"
        "theHarvester:Email/subdomain harvesting:apt/pip"
        "nmap:Port scanning:apt install nmap"
        "whois:WHOIS lookup:apt install whois"
        "dig:DNS lookup:apt install dnsutils"
        "asn:ASN/abuse lookup:custom install"
        "hashdeep:File hashing:apt install hashdeep"
        "pandoc:Report conversion:apt install pandoc"
    )
    
    echo -e "${WHITE}Tool                    Status      Install Command${NC}"
    echo "────────────────────────────────────────────────────────────────────"
    
    for tool_entry in "${tools[@]}"; do
        local tool="${tool_entry%%:*}"
        local rest="${tool_entry#*:}"
        local desc="${rest%%:*}"
        local install="${rest#*:}"
        
        if command -v "$tool" &>/dev/null; then
            printf "%-23s ${GREEN}✓ Found${NC}     %s\n" "$tool" "$desc"
        else
            printf "%-23s ${RED}✗ Missing${NC}   %s\n" "$tool" "$install"
        fi
    done
}

#-------------------------------------------------------------------------------
# MENUS
#-------------------------------------------------------------------------------
show_investigation_menu() {
    while true; do
        print_banner
        
        if [[ -n "$CASE_ID" ]]; then
            echo -e "  ${WHITE}Active Case:${NC} ${CYAN}${CASE_ID}${NC}"
        else
            echo -e "  ${YELLOW}No active case - create or load one first${NC}"
        fi
        echo ""
        
        echo -e "  ${GREEN}[1]${NC}  📧 Email Investigation"
        echo -e "  ${GREEN}[2]${NC}  📱 Phone Investigation"
        echo -e "  ${GREEN}[3]${NC}  🌐 Domain Investigation"
        echo -e "  ${GREEN}[4]${NC}  🔢 IP Address Investigation"
        echo -e "  ${GREEN}[5]${NC}  👤 Username Investigation"
        echo -e "  ${GREEN}[6]${NC}  💰 Cryptocurrency Investigation"
        echo -e "  ${GREEN}[7]${NC}  📸 Archive URLs"
        echo ""
        echo -e "  ${CYAN}[A]${NC}  🚀 Run Full Investigation (All-in-One)"
        echo ""
        echo -e "  ${YELLOW}[0]${NC}  Back to Main Menu"
        echo ""
        
        read -rp "Select option: " choice
        
        case $choice in
            1) [[ -n "$CASE_ID" ]] && investigate_all_emails || warn "Load a case first"; press_enter ;;
            2) [[ -n "$CASE_ID" ]] && investigate_all_phones || warn "Load a case first"; press_enter ;;
            3) [[ -n "$CASE_ID" ]] && investigate_all_domains || warn "Load a case first"; press_enter ;;
            4) [[ -n "$CASE_ID" ]] && investigate_all_ips || warn "Load a case first"; press_enter ;;
            5) [[ -n "$CASE_ID" ]] && investigate_all_usernames || warn "Load a case first"; press_enter ;;
            6) [[ -n "$CASE_ID" ]] && investigate_all_crypto || warn "Load a case first"; press_enter ;;
            7)
                if [[ -n "$CASE_ID" ]]; then
                    prompt_array URLS "Enter URLs to archive"
                    for url in "${URLS[@]}"; do archive_url "$url"; done
                else
                    warn "Load a case first"
                fi
                press_enter
                ;;
            [Aa])
                if [[ -n "$CASE_ID" ]]; then
                    run_full_investigation
                else
                    warn "Load a case first"
                fi
                press_enter
                ;;
            0) return ;;
            *) warn "Invalid option" ;;
        esac
    done
}

show_reports_menu() {
    while true; do
        print_banner
        print_section "Reports & Documentation"
        
        echo -e "  ${GREEN}[1]${NC}  📄 Generate Final Investigation Report"
        echo -e "  ${GREEN}[2]${NC}  📝 Generate Abuse Report Template"
        echo -e "  ${GREEN}[3]${NC}  📋 View Evidence Log"
        echo -e "  ${GREEN}[4]${NC}  📁 Open Case Directory"
        echo ""
        echo -e "  ${YELLOW}[0]${NC}  Back to Main Menu"
        echo ""
        
        read -rp "Select option: " choice
        
        case $choice in
            1) [[ -n "$CASE_ID" ]] && generate_final_report || warn "Load a case first"; press_enter ;;
            2) [[ -n "$CASE_ID" ]] && generate_abuse_report || warn "Load a case first"; press_enter ;;
            3)
                if [[ -n "$CASE_ID" ]] && [[ -f "${CASE_DIR}/evidence_log.md" ]]; then
                    cat "${CASE_DIR}/evidence_log.md"
                else
                    warn "No evidence log found"
                fi
                press_enter
                ;;
            4)
                if [[ -n "$CASE_DIR" ]]; then
                    xdg-open "$CASE_DIR" 2>/dev/null || echo "Case directory: $CASE_DIR"
                fi
                press_enter
                ;;
            0) return ;;
            *) warn "Invalid option" ;;
        esac
    done
}

show_settings_menu() {
    while true; do
        print_banner
        print_section "Settings & Configuration"
        
        echo -e "  ${GREEN}[1]${NC}  🔑 Configure API Keys"
        echo -e "  ${GREEN}[2]${NC}  📊 View API Status"
        echo -e "  ${GREEN}[3]${NC}  🔧 View Tool Status"
        echo -e "  ${GREEN}[4]${NC}  📦 Install Dependencies"
        echo ""
        echo -e "  ${YELLOW}[0]${NC}  Back to Main Menu"
        echo ""
        
        read -rp "Select option: " choice
        
        case $choice in
            1) configure_apis; press_enter ;;
            2) show_api_status; press_enter ;;
            3) show_tool_status; press_enter ;;
            4) run_dependency_installer; press_enter ;;
            0) return ;;
            *) warn "Invalid option" ;;
        esac
    done
}

show_main_menu() {
    while true; do
        print_banner
        
        if [[ -n "$CASE_ID" ]]; then
            echo -e "  ${WHITE}Active Case:${NC} ${CYAN}${CASE_ID}${NC}"
            echo -e "  ${WHITE}Case Directory:${NC} ${DIM}${CASE_DIR}${NC}"
        fi
        echo ""
        
        echo -e "  ${GREEN}[1]${NC}  📁 Create New Case"
        echo -e "  ${GREEN}[2]${NC}  📂 Load Existing Case"
        echo -e "  ${GREEN}[3]${NC}  📋 List All Cases"
        echo ""
        echo -e "  ${GREEN}[4]${NC}  🔍 Investigation Menu"
        echo -e "  ${GREEN}[5]${NC}  📄 Reports & Documentation"
        echo -e "  ${GREEN}[6]${NC}  ⚙️  Settings & Configuration"
        echo ""
        echo -e "  ${RED}[0]${NC}  Exit"
        echo ""
        
        read -rp "Select option: " choice
        
        case $choice in
            1) create_new_case; press_enter ;;
            2) select_case; press_enter ;;
            3) list_cases; press_enter ;;
            4) show_investigation_menu ;;
            5) show_reports_menu ;;
            6) show_settings_menu ;;
            0)
                if [[ -n "$CASE_ID" ]]; then
                    save_case_state
                    success "Case state saved"
                fi
                echo ""
                info "Goodbye!"
                exit 0
                ;;
            *) warn "Invalid option" ;;
        esac
    done
}

#-------------------------------------------------------------------------------
# MAIN
#-------------------------------------------------------------------------------
main() {
    # Initialize
    init_config
    
    # Handle command line arguments
    case "${1:-}" in
        --install|-i)
            run_dependency_installer
            exit 0
            ;;
        --config|-c)
            configure_apis
            exit 0
            ;;
        --status|-s)
            show_tool_status
            show_api_status
            exit 0
            ;;
        --help|-h)
            echo "OSINT Investigator Playbook v2.0"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --install, -i    Install dependencies"
            echo "  --config, -c     Configure API keys"
            echo "  --status, -s     Show tool and API status"
            echo "  --help, -h       Show this help"
            echo ""
            exit 0
            ;;
    esac
    
    # Initialize logging
    init_logging
    log_info "OSINT Investigator started"
    
    # Run main menu
    show_main_menu
}

# Run main
main "$@"
