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
#        AUTHOR: Jon Pienkowski (PNWC)
#       VERSION: 2.1
#      PLATFORM: Tsurugi Linux / Ubuntu / Debian
#
#===============================================================================

set -o pipefail

#-------------------------------------------------------------------------------
# BRANDING & INVESTIGATOR CONFIGURATION
#-------------------------------------------------------------------------------
# Modify these variables to reflect your organization
COMPANY_NAME="Digital Forensic Services"
COMPANY_SHORT="DFS"
COMPANY_EMAIL="investigations@yourdomain.com"
COMPANY_PHONE="(000) 000-0000"
COMPANY_WEBSITE="www.yourdomain.com"
COMPANY_LOCATION="City, State | Region"
INVESTIGATOR_NAME="Lead Investigator"

#-------------------------------------------------------------------------------
# GLOBAL CONFIGURATION
#-------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_CONFIG="${CONFIG_DIR}/api_keys.conf"
CASE_BASE_DIR="${HOME}/OSINT_Cases"
LOG_DIR="${CONFIG_DIR}/logs"
TOOLS_DIR="${CONFIG_DIR}/tools"

# Case Variables Initialization
CASE_ID=""
CASE_DIR=""
EVIDENCE_DIR=""
REPORTS_DIR=""
LOGS_DIR=""
RAW_DIR=""

# Investigation Data Arrays
declare -A COLLECTED_DATA
declare -a EMAILS=()
declare -a PHONES=()
declare -a DOMAINS=()
declare -a IPS=()
declare -a IPV6S=()
declare -a USERNAMES=()
declare -a CRYPTO_ADDRESSES=()

# Target/Infrastructure Metadata
COMPANY_NAME_TARGET=""
CASE_NOTES=""
CASE_TYPE="Fraudulent Domain / Scam Infrastructure Investigation"
HOSTING_PROVIDER=""
HOSTING_ASN=""

#-------------------------------------------------------------------------------
# UI & COLOR DEFINITIONS
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
# CORE UTILITY FUNCTIONS
#-------------------------------------------------------------------------------
init_logging() {
    mkdir -p "${LOG_DIR}"
    LOG_FILE="${LOG_DIR}/osint_$(date +%Y%m%d_%H%M%S).log"
}

print_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗██╗███╗   ██╗████████╗                                          ║
║ ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝      OSINT Investigator Playbook         ║
║ ██║   ██║███████╗██║██╔██╗ ██║   ██║         Framework v2.1                      ║
║ ██║   ██║╚════██║██║██║╚██╗██║   ██║         Case Evidence Collection            ║
║ ╚██████╔╝███████║██║██║ ╚████║   ██║                                             ║
║  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝         Investigation & Reporting           ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  Domain Analysis | Account Discovery | Infrastructure Tracking | Case Management  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

success() { echo -e "${GREEN}[✓]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

prompt() {
    local var_name="$1" prompt_text="$2" default="$3" value
    read -rp "$(echo -e "${YELLOW}[?]${NC} ${prompt_text} [${default}]: ")" value
    value="${value:-$default}"
    eval "$var_name=\"$value\""
}

#-------------------------------------------------------------------------------
# CONFIGURATION MANAGEMENT
#-------------------------------------------------------------------------------
init_config() {
    mkdir -p "${CONFIG_DIR}" "${LOG_DIR}" "${TOOLS_DIR}"
    if [[ ! -f "${API_CONFIG}" ]]; then
        cat > "${API_CONFIG}" << 'APIEOF'
# OSINT API KEYS
export SHODAN_API_KEY=""
export VIRUSTOTAL_API_KEY=""
export HIBP_API_KEY=""
export ABUSEIPDB_API_KEY=""
export WHOISXML_API_KEY=""
APIEOF
        chmod 600 "${API_CONFIG}"
    fi
    source "${API_CONFIG}"
}

#-------------------------------------------------------------------------------
# CASE MANAGEMENT
#-------------------------------------------------------------------------------
create_new_case() {
    print_section "Initialize New Investigation"
    prompt CASE_ID "Enter Case Reference ID" "$(date +%Y-%m%d)-001"
    CASE_DIR="${CASE_BASE_DIR}/${CASE_ID}"
    
    if [[ -d "$CASE_DIR" ]]; then
        error "Case directory already exists."
        return 1
    fi
    
    RAW_DIR="${CASE_DIR}/raw_data"
    mkdir -p "${CASE_DIR}"/{evidence,reports,logs,raw_data}
    mkdir -p "${RAW_DIR}"/{email,domain,ip,phone,username}
    
    echo "{\"case_id\": \"${CASE_ID}\", \"created\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"investigator\": \"${INVESTIGATOR_NAME}\"}" > "${CASE_DIR}/case_info.json"
    success "Environment ready: ${CASE_DIR}"
}

#-------------------------------------------------------------------------------
# INVESTIGATION MODULES
#-------------------------------------------------------------------------------
investigate_domain() {
    local domain="$1"
    local out="${RAW_DIR}/domain/${domain//./_}.md"
    print_section "Target Analysis: ${domain}"
    
    {
        echo "# Domain Analysis: ${domain}"
        echo "## DNS Records"
        dig +short "$domain" ANY
        echo "## WHOIS Data"
        whois "$domain" | head -n 50
    } > "$out"
    success "Results saved to ${out}"
}

#-------------------------------------------------------------------------------
# MAIN MENU
#-------------------------------------------------------------------------------
show_main_menu() {
    while true; do
        print_banner
        [[ -n "$CASE_ID" ]] && echo -e "  ${WHITE}Active Case:${NC} ${CYAN}${CASE_ID}${NC}"
        echo -e "
  ${GREEN}[1]${NC}  📁 Create New Case
  ${GREEN}[2]${NC}  📂 Load Existing Case
  ${GREEN}[3]${NC}  🔍 Investigation Menu
  ${GREEN}[4]${NC}  ⚙️  Settings
  ${RED}[0]${NC}  Exit
        "
        read -rp "Select Option: " choice
        case $choice in
            1) create_new_case ;;
            2) info "Case loading logic goes here" ;;
            3) [[ -n "$CASE_ID" ]] && info "Launch Investigation Menu" || error "Please create/load a case first." ;;
            4) info "Open Settings" ;;
            0) exit 0 ;;
        esac
        read -rp "Press Enter to continue..."
    done
}

main() {
    init_config
    show_main_menu
}

main "$@"
