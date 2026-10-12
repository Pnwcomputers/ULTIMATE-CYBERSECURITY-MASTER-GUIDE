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
#        AUTHOR: Pacific Northwest Computers (PNWC) ~ github.com/Pnwcomputers
#       CONTACT: see repo for current contact details
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

# A config file is shell code. Only load one that belongs to the current user,
# is not a symlink and is not group/world-writable.
trusted_conf() {
    local f="$1" owner mode
    [[ -f "$f" && ! -L "$f" ]] || return 1
    read -r owner mode < <(stat -c '%u %a' -- "$f" 2>/dev/null) || return 1
    [[ "$owner" == "$(id -u)" ]] || return 1
    (( (8#$mode & 8#022) == 0 ))
}

# Override placeholders with local operator config if present (gitignored)
BRANDING_CONF="${BRANDING_CONF:-${HOME}/.config/osint-investigator/branding.conf}"
if [[ -e "$BRANDING_CONF" ]]; then
    if trusted_conf "$BRANDING_CONF"; then
        # shellcheck source=/dev/null
        source "$BRANDING_CONF"
    else
        echo "Refusing to load $BRANDING_CONF: must be a regular file you own, not group/world-writable." >&2
    fi
fi
umask 077   # case data, evidence and logs are private by default

#-------------------------------------------------------------------------------
# GLOBAL CONFIGURATION
#-------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_CONFIG="${CONFIG_DIR}/api_keys.conf"
CASE_BASE_DIR="${HOME}/OSINT_Cases"
LOG_DIR="${CONFIG_DIR}/logs"
TOOLS_DIR="${CONFIG_DIR}/tools"
STATE_PY="${SCRIPT_DIR}/lib/case_state.py"
EVIDENCE_PY="${SCRIPT_DIR}/lib/collect_evidence.py"
# Flask lives in the isolated venv created by install_dependencies.sh (no runtime pip).
WEB_PYTHON="${OSINT_WEB_PYTHON:-${HOME}/.local/share/osint-investigator/venvs/web/bin/python}"

sanitize_case_id() {
    printf '%s' "$1" | tr ' ' '_' | tr -cd '[:alnum:]_-' | cut -c1-64
}

set_case_id_from_input() {
    local raw="$1"
    local cleaned
    cleaned="$(sanitize_case_id "$raw")"

    if [[ -z "$cleaned" ]]; then
        error "Case ID cannot be empty after removing invalid characters."
        return 1
    fi

    python3 -I "$STATE_PY" check-id "$cleaned" || {
        error "Case ID must be 1-64 letters, digits, '_' or '-'."
        return 1
    }
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
    load_api_config
}

load_api_config() {
    [[ -e "${API_CONFIG}" ]] || return 0
    if trusted_conf "${API_CONFIG}"; then
        # shellcheck source=/dev/null
        source "${API_CONFIG}"
    else
        warn "Not loading ${API_CONFIG}: it must be a regular file you own and not group/world-writable (chmod 600)."
        return 1
    fi
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
    load_api_config || return 1

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
        
        read -rsp "  Enter new key (Enter to keep; input hidden): " new_value
        echo ""
        if [[ -z "$new_value" ]]; then
            continue
        # The value is written into a shell file: allow only characters that
        # cannot terminate the quotes or trigger expansion.
        elif [[ ! "$new_value" =~ ^[A-Za-z0-9._~+/=:-]{8,256}$ ]]; then
            warn "  Rejected: keys must be 8-256 characters of letters, digits and . _ ~ + / = : -"
            continue
        fi
        sed -i "s|^export ${var_name}=.*|export ${var_name}=\"${new_value}\"|" "${API_CONFIG}"
    done
    load_api_config
    success "API configuration saved"
}

show_api_status() {
    print_section "API Status"
    load_api_config

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

    if [[ ! -x "$WEB_PYTHON" ]] || ! "$WEB_PYTHON" -c "import flask" 2>/dev/null; then
        error "Flask is not installed in the playbook's isolated environment."
        info "Run ${SCRIPT_DIR}/install_dependencies.sh (as your normal user) to set it up."
        return 1
    fi

    info "Starting web interface at http://localhost:5000"
    info "Press Ctrl+C to stop"
    "$WEB_PYTHON" "$web_script" --host 127.0.0.1 --port 5000
}

#-------------------------------------------------------------------------------
# CASE MANAGEMENT
#-------------------------------------------------------------------------------
create_new_case() {
    print_section "Create New Investigation Case"
    prompt CASE_ID "Enter Case ID" "$(date +%Y%m%d)-001"
    set_case_id_from_input "$CASE_ID" || return 1
    
    CASE_DIR="${CASE_BASE_DIR}/${CASE_ID}"

    if [[ -e "$CASE_DIR" || -L "$CASE_DIR" ]]; then
        confirm "Case exists. Resume?" && { load_case "$CASE_ID"; return $?; }
        error "Choose a different ID."
        CASE_DIR=""
        return 1
    fi
    mkdir -p "$CASE_BASE_DIR" || { error "Cannot create $CASE_BASE_DIR"; CASE_DIR=""; return 1; }
    mkdir -m 700 "$CASE_DIR" || { error "Cannot create case directory"; CASE_DIR=""; return 1; }

    EVIDENCE_DIR="${CASE_DIR}/evidence"
    REPORTS_DIR="${CASE_DIR}/reports"
    LOGS_DIR="${CASE_DIR}/logs"
    RAW_DIR="${CASE_DIR}/raw_data"
    
    mkdir -p "${EVIDENCE_DIR}"/{screenshots,archives,hashes}
    mkdir -p "${REPORTS_DIR}"/{final,abuse_reports}
    mkdir -p "${LOGS_DIR}"
    mkdir -p "${RAW_DIR}"/{email,domain,ip,phone,username,crypto,nmap}
    
    # json.dumps does the escaping, so a name containing quotes cannot break the file.
    python3 -I -c 'import json, sys, datetime
print(json.dumps({"case_id": sys.argv[1], "investigator": sys.argv[2],
                  "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
                 indent=2))' "$CASE_ID" "$INVESTIGATOR_NAME" > "${CASE_DIR}/case_info.json"

    cat > "${CASE_DIR}/evidence_log.md" << EOF
# Evidence Log - Case ${CASE_ID}

| Timestamp | Type | Description | SHA256 | Source |
|-----------|------|-------------|--------|--------|
EOF
    
    success "Created case: ${CASE_ID}"
    save_case_state
}

reset_case_data() {
    CASE_TYPE="Fraudulent Domain / Scam Infrastructure Investigation"
    COMPANY_NAME_TARGET=""
    HOSTING_PROVIDER=""; HOSTING_ASN=""; HOSTING_ISP=""; HOSTING_REGISTRY=""
    HOSTING_GEOLOCATION=""; HOSTING_COORDINATES=""; HOSTING_TIMEZONE=""
    EMAILS=(); PHONES=(); DOMAINS=(); IPS=(); IPV6S=(); USERNAMES=()
    CRYPTO_ADDRESSES=(); SUBDOMAINS=()
}

# Case state is JSON validated by lib/case_state.py; it is never sourced or eval'd.
load_case() {
    set_case_id_from_input "$1" || return 1
    local wanted="$CASE_ID"
    CASE_DIR="${CASE_BASE_DIR}/${CASE_ID}"
    EVIDENCE_DIR="${CASE_DIR}/evidence"
    REPORTS_DIR="${CASE_DIR}/reports"
    LOGS_DIR="${CASE_DIR}/logs"
    RAW_DIR="${CASE_DIR}/raw_data"

    [[ -d "$CASE_DIR" && ! -L "$CASE_DIR" ]] || { error "Case not found"; CASE_ID=""; CASE_DIR=""; return 1; }

    reset_case_data
    if [[ -e "${CASE_DIR}/.case_state.json" || -L "${CASE_DIR}/.case_state.json" ]]; then
        local tmp key value
        tmp="$(mktemp)" || return 1
        if ! python3 -I "$STATE_PY" load "$CASE_DIR" > "$tmp"; then
            rm -f -- "$tmp"
            error "Case state failed validation and was NOT loaded."
            reset_case_data; CASE_ID=""; CASE_DIR=""
            return 1
        fi
        while IFS= read -r -d '' key && IFS= read -r -d '' value; do
            case "$key" in
                CASE_ID)             CASE_ID="$value" ;;
                CASE_TYPE)           CASE_TYPE="$value" ;;
                COMPANY_NAME_TARGET) COMPANY_NAME_TARGET="$value" ;;
                HOSTING_PROVIDER)    HOSTING_PROVIDER="$value" ;;
                HOSTING_ASN)         HOSTING_ASN="$value" ;;
                HOSTING_ISP)         HOSTING_ISP="$value" ;;
                HOSTING_REGISTRY)    HOSTING_REGISTRY="$value" ;;
                HOSTING_GEOLOCATION) HOSTING_GEOLOCATION="$value" ;;
                HOSTING_COORDINATES) HOSTING_COORDINATES="$value" ;;
                HOSTING_TIMEZONE)    HOSTING_TIMEZONE="$value" ;;
                EMAILS)              EMAILS+=("$value") ;;
                PHONES)              PHONES+=("$value") ;;
                DOMAINS)             DOMAINS+=("$value") ;;
                IPS)                 IPS+=("$value") ;;
                IPV6S)               IPV6S+=("$value") ;;
                USERNAMES)           USERNAMES+=("$value") ;;
                CRYPTO_ADDRESSES)    CRYPTO_ADDRESSES+=("$value") ;;
                SUBDOMAINS)          SUBDOMAINS+=("$value") ;;
            esac
        done < "$tmp"
        rm -f -- "$tmp"
        if [[ "$CASE_ID" != "$wanted" ]]; then
            error "Case state belongs to '${CASE_ID}', not '${wanted}'; refusing to load."
            reset_case_data; CASE_ID=""; CASE_DIR=""
            return 1
        fi
    elif [[ -e "${CASE_DIR}/.case_state" ]]; then
        warn "Found a legacy shell-format .case_state. It is NOT executed or loaded;"
        warn "re-enter the indicators for this case (they will be saved as JSON)."
    fi
    success "Loaded case: ${CASE_ID}"
}

_emit_array() {
    local key="$1" v
    shift
    for v in "$@"; do printf '%s\0%s\0' "$key" "$v"; done
}

save_case_state() {
    [[ -z "$CASE_DIR" ]] && return 0
    {
        printf '%s\0%s\0' \
            CASE_ID "$CASE_ID" \
            CASE_TYPE "$CASE_TYPE" \
            COMPANY_NAME_TARGET "$COMPANY_NAME_TARGET" \
            HOSTING_PROVIDER "$HOSTING_PROVIDER" \
            HOSTING_ASN "$HOSTING_ASN" \
            HOSTING_ISP "$HOSTING_ISP" \
            HOSTING_REGISTRY "$HOSTING_REGISTRY" \
            HOSTING_GEOLOCATION "$HOSTING_GEOLOCATION" \
            HOSTING_COORDINATES "$HOSTING_COORDINATES" \
            HOSTING_TIMEZONE "$HOSTING_TIMEZONE"
        _emit_array EMAILS "${EMAILS[@]}"
        _emit_array PHONES "${PHONES[@]}"
        _emit_array DOMAINS "${DOMAINS[@]}"
        _emit_array IPS "${IPS[@]}"
        _emit_array IPV6S "${IPV6S[@]}"
        _emit_array USERNAMES "${USERNAMES[@]}"
        _emit_array CRYPTO_ADDRESSES "${CRYPTO_ADDRESSES[@]}"
        _emit_array SUBDOMAINS "${SUBDOMAINS[@]}"
    } | python3 -I "$STATE_PY" save "$CASE_DIR" || {
        error "Case state was NOT saved (see message above)."
        return 1
    }
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
#-------------------------------------------------------------------------------
# EVIDENCE COLLECTION
#
# Every external command runs through lib/collect_evidence.py, which keeps the
# COMPLETE stdout and stderr, the exit code, UTC timestamps and SHA-256 hashes,
# and marks a run "partial" (non-zero exit, timeout, size cap) or "not_run"
# (tool missing). Nothing is truncated or silenced in the stored evidence;
# only the on-screen preview is shortened.
#-------------------------------------------------------------------------------
safe_name() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-80; }

# collect LABEL BASE -- CMD [ARGS...]
# Prints a short preview, returns 0 complete / 3 partial / 4 not run / other failure.
collect() {
    local label="$1" base="$2" rc=0
    shift 2
    [[ "${1:-}" == "--" ]] && shift
    if [[ -z "$CASE_DIR" ]]; then error "No active case"; return 1; fi
    python3 -I "$EVIDENCE_PY" --out "$base" --label "$label" \
        --log "${CASE_DIR}/evidence_log.md" --timeout "${COLLECT_TIMEOUT:-300}" -- "$@" || rc=$?
    case $rc in
        0) ;;
        3) warn "PARTIAL evidence for '${label}' (non-zero exit, timeout or size cap) - see ${base}.meta.json" ;;
        4) warn "NOT RUN: '${label}' could not be started - see ${base}.meta.json" ;;
        *) error "Evidence collection for '${label}' failed (rc=${rc})" ;;
    esac
    if [[ -s "${base}.stdout" ]]; then
        head -n 15 -- "${base}.stdout" | sed 's/\x1b/?/g'
        [[ $(wc -l < "${base}.stdout") -gt 15 ]] && echo -e "${DIM}  ... full output: ${base}.stdout${NC}"
    fi
    return "$rc"
}

# run_step REPORT LABEL BASE -- CMD...   (collect + one line in the human report)
run_step() {
    local report="$1" label="$2" base="$3" rc=0 status sha
    shift 3
    collect "$label" "$base" "$@" || rc=$?
    case $rc in 0) status="complete" ;; 3) status="PARTIAL" ;; 4) status="NOT RUN" ;; *) status="FAILED" ;; esac
    sha="n/a"
    [[ -f "${base}.stdout" ]] && sha="$(sha256sum -- "${base}.stdout" | cut -d' ' -f1)"
    printf -- '- **%s**: %s (stdout sha256 `%s`)\n  - files: `%s.stdout`, `%s.stderr`, `%s.meta.json`\n' \
        "$label" "$status" "$sha" "$(basename "$base")" "$(basename "$base")" "$(basename "$base")" >> "$report"
    return "$rc"
}

new_report() {  # new_report DIR TITLE STEM -> prints path
    local report="$1/$3.md"
    { printf '# %s\n' "$2"; printf 'Generated: %s\n\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"; } > "$report"
    printf '%s' "$report"
}

investigate_email() {
    local email="$1" output_dir="${RAW_DIR}/email" stem report
    mkdir -p "$output_dir"
    print_subsection "Email Investigation: ${email}"
    stem="$(safe_name "$email")_$(date -u +%Y%m%dT%H%M%S%N)"
    report="$(new_report "$output_dir" "Email Investigation: ${email}" "$stem")"

    if check_tool holehe; then
        run_step "$report" "holehe" "${output_dir}/${stem}.holehe" -- holehe "$email" --only-used
    else echo "- holehe: skipped (not installed)" >> "$report"; fi
    if check_tool h8mail; then
        run_step "$report" "h8mail" "${output_dir}/${stem}.h8mail" -- h8mail -t "$email"
    else echo "- h8mail: skipped (not installed)" >> "$report"; fi
    success "Email report: ${report}"
}

investigate_phone() {
    local phone="$1" output_dir="${RAW_DIR}/phone" stem report
    mkdir -p "$output_dir"
    print_subsection "Phone Investigation: ${phone}"
    stem="$(safe_name "${phone//[^0-9+]/}")_$(date -u +%Y%m%dT%H%M%S%N)"
    report="$(new_report "$output_dir" "Phone Investigation" "$stem")"
    if check_tool phoneinfoga; then
        run_step "$report" "phoneinfoga" "${output_dir}/${stem}.phoneinfoga" -- phoneinfoga scan -n "$phone"
    else
        echo "- phoneinfoga: skipped (not installed)" >> "$report"
        warn "PhoneInfoga not installed"
    fi
    success "Phone report: ${report}"
}

investigate_domain() {
    local domain="$1" output_dir="${RAW_DIR}/domain" stem report rtype
    mkdir -p "$output_dir"
    print_subsection "Domain Investigation: ${domain}"
    stem="$(safe_name "$domain")_$(date -u +%Y%m%dT%H%M%S%N)"
    report="$(new_report "$output_dir" "Domain Investigation: ${domain}" "$stem")"

    run_step "$report" "whois" "${output_dir}/${stem}.whois" -- whois "$domain"
    for rtype in A AAAA MX NS TXT; do
        run_step "$report" "dig ${rtype}" "${output_dir}/${stem}.dig-${rtype}" -- dig +noall +answer "$domain" "$rtype"
    done
    if check_tool subfinder; then
        run_step "$report" "subfinder" "${output_dir}/${stem}.subfinder" -- subfinder -d "$domain" -silent
    else echo "- subfinder: skipped (not installed)" >> "$report"; fi
    success "Domain report: ${report}"
}

investigate_ip() {
    local ip="$1" output_dir="${RAW_DIR}/ip" stem report
    mkdir -p "$output_dir"
    print_subsection "IP Investigation: ${ip}"
    stem="$(safe_name "$ip")_$(date -u +%Y%m%dT%H%M%S%N)"
    report="$(new_report "$output_dir" "IP Investigation: ${ip}" "$stem")"

    run_step "$report" "whois" "${output_dir}/${stem}.whois" -- whois "$ip"
    # ip-api.com's free endpoint is HTTP only: the queried IP is sent in cleartext.
    run_step "$report" "geolocation (ip-api.com)" "${output_dir}/${stem}.geo" -- \
        curl -sS --fail --max-time 30 -- "http://ip-api.com/json/${ip}"
    run_step "$report" "reverse DNS" "${output_dir}/${stem}.rdns" -- dig -x "$ip" +short
    success "IP report: ${report}"
}

investigate_username() {
    local username="$1" output_dir="${RAW_DIR}/username" stem report
    mkdir -p "$output_dir"
    print_subsection "Username Investigation: ${username}"
    stem="$(safe_name "$username")_$(date -u +%Y%m%dT%H%M%S%N)"
    report="$(new_report "$output_dir" "Username Investigation" "$stem")"

    if check_tool maigret; then
        info "Running Maigret..."
        run_step "$report" "maigret" "${output_dir}/${stem}.maigret" -- \
            maigret "$username" -o "${output_dir}/${stem}.maigret-out" --pdf
    elif check_tool sherlock; then
        info "Running Sherlock..."
        run_step "$report" "sherlock" "${output_dir}/${stem}.sherlock" -- \
            sherlock "$username" --output "${output_dir}/${stem}.sherlock.txt"
    else
        echo "- username tools: skipped (neither maigret nor sherlock installed)" >> "$report"
        warn "Neither Maigret nor Sherlock installed"
    fi
    success "Username report: ${report}"
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
                        run_scammer_audit "$target" "${RAW_DIR}/integrated" || \
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
                        run_email_audit "$target" "${RAW_DIR}/integrated" || \
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
                        run_phone_audit "$target" "${RAW_DIR}/integrated" || \
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
                        run_full_nmap "$target" "${RAW_DIR}/integrated" || \
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
                        run_theharvester "$target" "${RAW_DIR}/integrated" || \
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
                    "$installer"
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
        --install|-i) "${SCRIPT_DIR}/install_dependencies.sh"; exit $? ;;
        --config|-c) configure_apis; exit ;;
        --status|-s) show_tool_status; show_api_status; exit ;;
        --web|-w) launch_web_interface; exit ;;
        --help|-h)
            echo "OSINT Investigator Playbook"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "  --install    Install dependencies (run as your normal user, not root)"
            echo "  --config     Configure API keys"
            echo "  --status     Show tool/API status"
            echo "  --web        Launch web interface"
            echo "  --help       Show this help"
            exit 0
            ;;
    esac
    
    show_main_menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
