#!/bin/bash
#===============================================================================
#
#          FILE: toolkit_integration.sh
#
#         USAGE: Source this file or run standalone
#
#   DESCRIPTION: Integration module connecting OSINT Investigator with existing
#                toolkit scripts (scammer_audit.sh, email_audit.sh, phone_audit.sh,
#                full_nmap_scan.sh, victim_osint_toolkit.sh)
#
#        AUTHOR: Jon-Eric Pienkowski ~ PNW Computers (jon@pnwcomputers.com)
#       VERSION: 1.1
#
#===============================================================================

#-------------------------------------------------------------------------------
# CONFIGURATION
#-------------------------------------------------------------------------------
INTEGRATION_CONFIG="${HOME}/.config/osint-investigator/integration.conf"
CASE_BASE_DIR="${HOME}/OSINT_Cases"

# Default paths - will be auto-detected or configured
EXISTING_TOOLKIT_DIR=""
SCRIPTS_SUBDIR="scripts"  # Scripts subdirectory in the playbook
SCAMMER_AUDIT_SCRIPT=""
EMAIL_AUDIT_SCRIPT=""
PHONE_AUDIT_SCRIPT=""
FULL_NMAP_SCRIPT=""
VICTIM_TOOLKIT_SCRIPT=""
THEHARVESTER_PATH=""
THREAT_FEED_SCRIPT=""
CRYPTO_AUDIT_SCRIPT=""
DOMAIN_MONITOR_SCRIPT=""
USERNAME_AUDIT_SCRIPT=""
SSL_CERT_SCRIPT=""
CASE_REPORT_SCRIPT=""
WHOIS_BULK_SCRIPT=""
METADATA_STRIP_SCRIPT=""
SCREENSHOT_SCRIPT=""

#-------------------------------------------------------------------------------
# COLORS
#-------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

resolve_case_dir() {
    local input="$1"
    local base_dir
    base_dir=$(cd "$CASE_BASE_DIR" 2>/dev/null && pwd)

    if [[ -z "$input" || -z "$base_dir" ]]; then
        return 1
    fi

    local candidate
    if [[ "$input" == /* ]]; then
        candidate="$input"
    else
        candidate="${CASE_BASE_DIR}/${input}"
    fi

    candidate=$(cd "$candidate" 2>/dev/null && pwd) || return 1

    if [[ "$candidate" == "$base_dir" || "$candidate" == "$base_dir"/* ]]; then
        printf '%s\n' "$candidate"
        return 0
    fi

    return 1
}

#-------------------------------------------------------------------------------
# AUTO-DETECTION
#-------------------------------------------------------------------------------
detect_existing_scripts() {
    info "Auto-detecting existing OSINT scripts..."
    
    # Get the directory where this script is located
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Primary location: scripts/ subdirectory in the playbook folder
    local playbook_scripts_dir="${script_dir}/${SCRIPTS_SUBDIR}"
    
    # Search paths in order of priority
    local search_paths=(
        "${playbook_scripts_dir}"
        "${script_dir}"
        "${HOME}/osint/playbook/scripts"
        "${HOME}/osint/scripts"
        "${HOME}/osint"
        "${HOME}/Scripts"
        "${HOME}/scripts"
        "${HOME}/tools"
        "/opt/osint"
    )
    
    # Search for scammer_audit.sh
    for path in "${search_paths[@]}"; do
        if [[ -f "${path}/scammer_audit.sh" ]]; then
            SCAMMER_AUDIT_SCRIPT="${path}/scammer_audit.sh"
            [[ -z "$EXISTING_TOOLKIT_DIR" ]] && EXISTING_TOOLKIT_DIR="${path}"
            success "Found scammer_audit.sh: ${SCAMMER_AUDIT_SCRIPT}"
            break
        fi
    done
    
    # Search for email_audit.sh
    for path in "${search_paths[@]}"; do
        if [[ -f "${path}/email_audit.sh" ]]; then
            EMAIL_AUDIT_SCRIPT="${path}/email_audit.sh"
            success "Found email_audit.sh: ${EMAIL_AUDIT_SCRIPT}"
            break
        fi
    done
    
    # Search for phone_audit.sh
    for path in "${search_paths[@]}"; do
        if [[ -f "${path}/phone_audit.sh" ]]; then
            PHONE_AUDIT_SCRIPT="${path}/phone_audit.sh"
            success "Found phone_audit.sh: ${PHONE_AUDIT_SCRIPT}"
            break
        fi
    done
    
    # Search for full_nmap_scan.sh
    for path in "${search_paths[@]}"; do
        if [[ -f "${path}/full_nmap_scan.sh" ]]; then
            FULL_NMAP_SCRIPT="${path}/full_nmap_scan.sh"
            success "Found full_nmap_scan.sh: ${FULL_NMAP_SCRIPT}"
            break
        fi
    done
    
    # Search for victim_osint_toolkit.sh
    for path in "${search_paths[@]}"; do
        if [[ -f "${path}/victim_osint_toolkit.sh" ]]; then
            VICTIM_TOOLKIT_SCRIPT="${path}/victim_osint_toolkit.sh"
            success "Found victim_osint_toolkit.sh: ${VICTIM_TOOLKIT_SCRIPT}"
            break
        fi
    done

    # Search for new supplemental scripts
    local new_scripts=(
        "threat_feed_check.sh:THREAT_FEED_SCRIPT"
        "crypto_audit.sh:CRYPTO_AUDIT_SCRIPT"
        "domain_monitor.sh:DOMAIN_MONITOR_SCRIPT"
        "username_audit.sh:USERNAME_AUDIT_SCRIPT"
        "ssl_cert_audit.sh:SSL_CERT_SCRIPT"
        "case_report_generator.sh:CASE_REPORT_SCRIPT"
        "whois_bulk.sh:WHOIS_BULK_SCRIPT"
        "metadata_stripper.sh:METADATA_STRIP_SCRIPT"
        "screenshot_archive.sh:SCREENSHOT_SCRIPT"
    )
    for entry in "${new_scripts[@]}"; do
        local sname="${entry%%:*}"
        local svar="${entry#*:}"
        for path in "${search_paths[@]}"; do
            if [[ -f "${path}/${sname}" ]]; then
                printf -v "$svar" '%s' "${path}/${sname}"
                success "Found ${sname}: ${path}/${sname}"
                break
            fi
        done
    done

    # Search for theHarvester
    if command -v theHarvester &>/dev/null; then
        THEHARVESTER_PATH=$(command -v theHarvester)
        success "Found theHarvester: ${THEHARVESTER_PATH}"
    elif [[ -f "${HOME}/.config/osint-investigator/tools/theHarvester/theHarvester.py" ]]; then
        THEHARVESTER_PATH="${HOME}/.config/osint-investigator/tools/theHarvester/theHarvester.py"
        success "Found theHarvester: ${THEHARVESTER_PATH}"
    fi
    
    # Summary
    echo ""
    local found=0
    [[ -n "$SCAMMER_AUDIT_SCRIPT" ]] && ((found++))
    [[ -n "$EMAIL_AUDIT_SCRIPT" ]] && ((found++))
    [[ -n "$PHONE_AUDIT_SCRIPT" ]] && ((found++))
    [[ -n "$FULL_NMAP_SCRIPT" ]] && ((found++))
    [[ -n "$THEHARVESTER_PATH" ]] && ((found++))
    [[ -n "$THREAT_FEED_SCRIPT" ]] && ((found++))
    [[ -n "$CRYPTO_AUDIT_SCRIPT" ]] && ((found++))
    [[ -n "$DOMAIN_MONITOR_SCRIPT" ]] && ((found++))
    [[ -n "$USERNAME_AUDIT_SCRIPT" ]] && ((found++))
    [[ -n "$SSL_CERT_SCRIPT" ]] && ((found++))
    [[ -n "$CASE_REPORT_SCRIPT" ]] && ((found++))
    [[ -n "$WHOIS_BULK_SCRIPT" ]] && ((found++))
    [[ -n "$METADATA_STRIP_SCRIPT" ]] && ((found++))
    [[ -n "$SCREENSHOT_SCRIPT" ]] && ((found++))
    
    if [[ $found -gt 0 ]]; then
        success "Found ${found} integrated tool(s)"
    else
        warn "No scripts found. Place scripts in: ${playbook_scripts_dir}/"
    fi
}

#-------------------------------------------------------------------------------
# CONFIGURATION
#-------------------------------------------------------------------------------
load_integration_config() {
    mkdir -p "$(dirname "$INTEGRATION_CONFIG")"
    
    if [[ -f "$INTEGRATION_CONFIG" ]]; then
        # shellcheck source=/dev/null
        source "$INTEGRATION_CONFIG"
        return 0
    fi
    
    # Auto-detect if no config exists
    detect_existing_scripts
    save_integration_config
}

save_integration_config() {
    mkdir -p "$(dirname "$INTEGRATION_CONFIG")"
    cat > "$INTEGRATION_CONFIG" << EOF
# OSINT Integration Configuration
# Auto-generated - modify paths as needed

EXISTING_TOOLKIT_DIR="${EXISTING_TOOLKIT_DIR}"
SCRIPTS_SUBDIR="${SCRIPTS_SUBDIR}"
SCAMMER_AUDIT_SCRIPT="${SCAMMER_AUDIT_SCRIPT}"
EMAIL_AUDIT_SCRIPT="${EMAIL_AUDIT_SCRIPT}"
PHONE_AUDIT_SCRIPT="${PHONE_AUDIT_SCRIPT}"
FULL_NMAP_SCRIPT="${FULL_NMAP_SCRIPT}"
VICTIM_TOOLKIT_SCRIPT="${VICTIM_TOOLKIT_SCRIPT}"
THEHARVESTER_PATH="${THEHARVESTER_PATH}"
THREAT_FEED_SCRIPT="${THREAT_FEED_SCRIPT}"
CRYPTO_AUDIT_SCRIPT="${CRYPTO_AUDIT_SCRIPT}"
DOMAIN_MONITOR_SCRIPT="${DOMAIN_MONITOR_SCRIPT}"
USERNAME_AUDIT_SCRIPT="${USERNAME_AUDIT_SCRIPT}"
SSL_CERT_SCRIPT="${SSL_CERT_SCRIPT}"
CASE_REPORT_SCRIPT="${CASE_REPORT_SCRIPT}"
WHOIS_BULK_SCRIPT="${WHOIS_BULK_SCRIPT}"
METADATA_STRIP_SCRIPT="${METADATA_STRIP_SCRIPT}"
SCREENSHOT_SCRIPT="${SCREENSHOT_SCRIPT}"
EOF
    success "Integration config saved: ${INTEGRATION_CONFIG}"
}

configure_integration() {
    echo ""
    echo -e "${CYAN}═══ Configure Toolkit Integration ═══${NC}"
    echo ""
    echo "Enter paths to existing scripts (leave blank to skip):"
    echo ""
    
    read -rp "Scripts directory [${EXISTING_TOOLKIT_DIR}]: " input
    EXISTING_TOOLKIT_DIR="${input:-$EXISTING_TOOLKIT_DIR}"
    
    read -rp "scammer_audit.sh path [${SCAMMER_AUDIT_SCRIPT}]: " input
    SCAMMER_AUDIT_SCRIPT="${input:-$SCAMMER_AUDIT_SCRIPT}"
    
    read -rp "email_audit.sh path [${EMAIL_AUDIT_SCRIPT}]: " input
    EMAIL_AUDIT_SCRIPT="${input:-$EMAIL_AUDIT_SCRIPT}"
    
    read -rp "phone_audit.sh path [${PHONE_AUDIT_SCRIPT}]: " input
    PHONE_AUDIT_SCRIPT="${input:-$PHONE_AUDIT_SCRIPT}"
    
    read -rp "full_nmap_scan.sh path [${FULL_NMAP_SCRIPT}]: " input
    FULL_NMAP_SCRIPT="${input:-$FULL_NMAP_SCRIPT}"
    
    read -rp "victim_osint_toolkit.sh path [${VICTIM_TOOLKIT_SCRIPT}]: " input
    VICTIM_TOOLKIT_SCRIPT="${input:-$VICTIM_TOOLKIT_SCRIPT}"
    
    read -rp "theHarvester path [${THEHARVESTER_PATH}]: " input
    THEHARVESTER_PATH="${input:-$THEHARVESTER_PATH}"
    
    save_integration_config
}

show_integration_status() {
    echo ""
    echo -e "${CYAN}═══ Integration Status ═══${NC}"
    echo ""
    
    echo -e "${BLUE}Scripts Directory:${NC}"
    if [[ -d "$EXISTING_TOOLKIT_DIR" ]]; then
        echo -e "  ${GREEN}✓${NC} ${EXISTING_TOOLKIT_DIR}"
    else
        echo -e "  ${RED}✗${NC} Not configured"
    fi
    
    echo ""
    echo -e "${BLUE}Available Scripts:${NC}"
    
    local scripts=(
        "scammer_audit.sh:${SCAMMER_AUDIT_SCRIPT}"
        "email_audit.sh:${EMAIL_AUDIT_SCRIPT}"
        "phone_audit.sh:${PHONE_AUDIT_SCRIPT}"
        "full_nmap_scan.sh:${FULL_NMAP_SCRIPT}"
        "victim_osint_toolkit.sh:${VICTIM_TOOLKIT_SCRIPT}"
        "theHarvester:${THEHARVESTER_PATH}"
        "threat_feed_check.sh:${THREAT_FEED_SCRIPT}"
        "crypto_audit.sh:${CRYPTO_AUDIT_SCRIPT}"
        "domain_monitor.sh:${DOMAIN_MONITOR_SCRIPT}"
        "username_audit.sh:${USERNAME_AUDIT_SCRIPT}"
        "ssl_cert_audit.sh:${SSL_CERT_SCRIPT}"
        "case_report_generator.sh:${CASE_REPORT_SCRIPT}"
        "whois_bulk.sh:${WHOIS_BULK_SCRIPT}"
        "metadata_stripper.sh:${METADATA_STRIP_SCRIPT}"
        "screenshot_archive.sh:${SCREENSHOT_SCRIPT}"
    )
    
    for entry in "${scripts[@]}"; do
        local name="${entry%%:*}"
        local path="${entry#*:}"
        
        if [[ -n "$path" ]] && [[ -f "$path" || -x "$path" ]]; then
            echo -e "  ${GREEN}✓${NC} ${name}: ${path}"
        elif [[ -n "$path" ]]; then
            echo -e "  ${YELLOW}?${NC} ${name}: ${path} (not found)"
        else
            echo -e "  ${RED}✗${NC} ${name}: Not configured"
        fi
    done
    
    echo ""
    echo -e "${BLUE}Config File:${NC}"
    if [[ -f "$INTEGRATION_CONFIG" ]]; then
        echo -e "  ${GREEN}✓${NC} ${INTEGRATION_CONFIG}"
    else
        echo -e "  ${YELLOW}!${NC} Not created yet (run --detect)"
    fi
}

#-------------------------------------------------------------------------------
# TOOL WRAPPERS
#-------------------------------------------------------------------------------

# Run scammer_audit.sh and capture output
run_scammer_audit() {
    local target="$1"
    local output_dir="$2"

    if [[ ! -x "$SCAMMER_AUDIT_SCRIPT" ]]; then
        error "scammer_audit.sh not found or not executable: ${SCAMMER_AUDIT_SCRIPT}"
        return 1
    fi

    info "Running scammer_audit.sh on: ${target}"

    # Select the correct flag based on target type
    local flag="-d"
    if [[ "$target" == *"@"* ]]; then
        flag="-e"
    elif [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        flag="-i"
    elif [[ "$target" =~ ^[0-9a-fA-F:]+$ ]]; then
        flag="-i"  # IPv6
    fi

    mkdir -p "$output_dir"
    local output_file; output_file="${output_dir}/scammer_audit_$(date +%Y%m%d_%H%M%S).txt"

    if "$SCAMMER_AUDIT_SCRIPT" "$flag" "$target" 2>&1 | tee "$output_file"; then
        success "Scammer audit complete: ${output_file}"
        return 0
    else
        error "Scammer audit failed"
        return 1
    fi
}

# Run email_audit.sh and capture output
run_email_audit() {
    local email="$1"
    local output_dir="$2"

    if [[ ! -x "$EMAIL_AUDIT_SCRIPT" ]]; then
        error "email_audit.sh not found or not executable: ${EMAIL_AUDIT_SCRIPT}"
        return 1
    fi

    info "Running email_audit.sh on: ${email}"

    mkdir -p "$output_dir"
    local output_file; output_file="${output_dir}/email_audit_$(date +%Y%m%d_%H%M%S).txt"

    if "$EMAIL_AUDIT_SCRIPT" -e "$email" 2>&1 | tee "$output_file"; then
        success "Email audit complete: ${output_file}"
        return 0
    else
        error "Email audit failed"
        return 1
    fi
}

# Run phone_audit.sh and capture output
run_phone_audit() {
    local phone="$1"
    local output_dir="$2"

    if [[ ! -x "$PHONE_AUDIT_SCRIPT" ]]; then
        error "phone_audit.sh not found or not executable: ${PHONE_AUDIT_SCRIPT}"
        return 1
    fi

    info "Running phone_audit.sh on: ${phone}"

    mkdir -p "$output_dir"
    local output_file; output_file="${output_dir}/phone_audit_$(date +%Y%m%d_%H%M%S).txt"

    if "$PHONE_AUDIT_SCRIPT" -p "$phone" 2>&1 | tee "$output_file"; then
        success "Phone audit complete: ${output_file}"
        return 0
    else
        error "Phone audit failed"
        return 1
    fi
}

# Run full_nmap_scan.sh for comprehensive network scanning
run_full_nmap() {
    local target="$1"
    local output_dir="$2"
    
    if [[ ! -x "$FULL_NMAP_SCRIPT" ]]; then
        error "full_nmap_scan.sh not found or not executable: ${FULL_NMAP_SCRIPT}"
        return 1
    fi
    
    info "Running full_nmap_scan.sh on: ${target}"
    
    mkdir -p "$output_dir"
    local output_file; output_file="${output_dir}/nmap_full_$(echo "$target" | tr './' '_')_$(date +%Y%m%d_%H%M%S).txt"
    
    # full_nmap_scan.sh takes IP as positional argument
    if "$FULL_NMAP_SCRIPT" "$target" 2>&1 | tee "$output_file"; then
        success "Full nmap scan complete: ${output_file}"
        return 0
    else
        error "Full nmap scan failed"
        return 1
    fi
}

# Run theHarvester for domain reconnaissance
run_theharvester() {
    local domain="$1"
    local output_dir="$2"
    local limit="${3:-500}"
    
    if [[ ! -x "$THEHARVESTER_PATH" ]] && [[ ! -f "$THEHARVESTER_PATH" ]]; then
        error "theHarvester not found"
        return 1
    fi
    
    info "Running theHarvester on: ${domain}"
    
    mkdir -p "$output_dir"
    local output_base; output_base="${output_dir}/harvester_$(echo "$domain" | tr '.' '_')_$(date +%Y%m%d_%H%M%S)"
    
    if [[ "$THEHARVESTER_PATH" == *.py ]]; then
        python3 "$THEHARVESTER_PATH" -d "$domain" -l "$limit" -b all -f "$output_base" 2>&1
    else
        "$THEHARVESTER_PATH" -d "$domain" -l "$limit" -b all -f "$output_base" 2>&1
    fi
    
    if [[ -f "${output_base}.html" ]] || [[ -f "${output_base}.xml" ]]; then
        success "theHarvester complete: ${output_base}.*"
        return 0
    else
        warn "theHarvester completed but output files not found"
        return 1
    fi
}

# Launch victim_osint_toolkit.sh
launch_victim_toolkit() {
    if [[ ! -x "$VICTIM_TOOLKIT_SCRIPT" ]]; then
        error "victim_osint_toolkit.sh not found or not executable"
        return 1
    fi

    info "Launching victim_osint_toolkit.sh..."
    "$VICTIM_TOOLKIT_SCRIPT"
}

# Check an IOC against all threat intelligence feeds
run_threat_feed_check() {
    local ioc="$1"
    local output_dir="$2"

    if [[ ! -x "$THREAT_FEED_SCRIPT" ]]; then
        error "threat_feed_check.sh not found or not executable: ${THREAT_FEED_SCRIPT}"
        return 1
    fi

    info "Running threat feed check on: ${ioc}"
    mkdir -p "$output_dir"
    local out_subdir; out_subdir="${output_dir}/threat_feed_$(echo "$ioc" | tr './:' '_')_$(date +%Y%m%d_%H%M%S)"
    "$THREAT_FEED_SCRIPT" -i "$ioc" -o "$out_subdir" 2>&1
    success "Threat feed check complete: ${out_subdir}"
}

# Investigate cryptocurrency wallet addresses
run_crypto_audit() {
    local address="$1"
    local output_dir="$2"

    if [[ ! -x "$CRYPTO_AUDIT_SCRIPT" ]]; then
        error "crypto_audit.sh not found or not executable: ${CRYPTO_AUDIT_SCRIPT}"
        return 1
    fi

    info "Running crypto audit on: ${address}"
    mkdir -p "$output_dir"
    local out_subdir; out_subdir="${output_dir}/crypto_$(echo "$address" | tr '/' '_')_$(date +%Y%m%d_%H%M%S)"
    "$CRYPTO_AUDIT_SCRIPT" -a "$address" -o "$out_subdir" 2>&1
    success "Crypto audit complete: ${out_subdir}"
}

# Initialize domain monitoring baseline
run_domain_monitor_init() {
    local domain="$1"

    if [[ ! -x "$DOMAIN_MONITOR_SCRIPT" ]]; then
        warn "domain_monitor.sh not found — skipping monitor init for ${domain}"
        return 0
    fi

    info "Initializing domain monitor baseline for: ${domain}"
    "$DOMAIN_MONITOR_SCRIPT" --init "$domain" 2>&1
    success "Domain monitor baseline set for: ${domain}"
}

# Run username OSINT investigation
run_username_audit() {
    local username="$1"
    local output_dir="$2"

    if [[ ! -x "$USERNAME_AUDIT_SCRIPT" ]]; then
        error "username_audit.sh not found or not executable: ${USERNAME_AUDIT_SCRIPT}"
        return 1
    fi

    info "Running username audit on: ${username}"
    mkdir -p "$output_dir"
    local out_subdir; out_subdir="${output_dir}/username_${username}_$(date +%Y%m%d_%H%M%S)"
    "$USERNAME_AUDIT_SCRIPT" -u "$username" -o "$out_subdir" 2>&1
    success "Username audit complete: ${out_subdir}"
}

# Run SSL certificate deep-dive on a domain
run_ssl_cert_audit() {
    local domain="$1"
    local output_dir="$2"

    if [[ ! -x "$SSL_CERT_SCRIPT" ]]; then
        error "ssl_cert_audit.sh not found or not executable: ${SSL_CERT_SCRIPT}"
        return 1
    fi

    info "Running SSL cert audit on: ${domain}"
    mkdir -p "$output_dir"
    local out_subdir; out_subdir="${output_dir}/ssl_$(echo "$domain" | tr './' '_')_$(date +%Y%m%d_%H%M%S)"
    "$SSL_CERT_SCRIPT" -d "$domain" -o "$out_subdir" 2>&1
    success "SSL cert audit complete: ${out_subdir}"
}

# Generate a consolidated case report
run_case_report() {
    local case_id="$1"
    local pdf="${2:-false}"

    if [[ ! -x "$CASE_REPORT_SCRIPT" ]]; then
        error "case_report_generator.sh not found or not executable: ${CASE_REPORT_SCRIPT}"
        return 1
    fi

    info "Generating case report for: ${case_id}"
    if [[ "$pdf" == "true" ]]; then
        "$CASE_REPORT_SCRIPT" -c "$case_id" --pdf 2>&1
    else
        "$CASE_REPORT_SCRIPT" -c "$case_id" 2>&1
    fi
    success "Case report generated for: ${case_id}"
}

# Bulk WHOIS lookup on a list of domains
run_whois_bulk() {
    local domain_list="$1"
    local output_dir="$2"

    if [[ ! -x "$WHOIS_BULK_SCRIPT" ]]; then
        error "whois_bulk.sh not found or not executable: ${WHOIS_BULK_SCRIPT}"
        return 1
    fi

    info "Running bulk WHOIS on list: ${domain_list}"
    mkdir -p "$output_dir"
    "$WHOIS_BULK_SCRIPT" -f "$domain_list" -o "$output_dir" 2>&1
    success "Bulk WHOIS complete: ${output_dir}"
}

# Strip metadata from evidence files before sharing
run_metadata_strip() {
    local target="$1"
    local output_dir="$2"

    if [[ ! -x "$METADATA_STRIP_SCRIPT" ]]; then
        error "metadata_stripper.sh not found or not executable: ${METADATA_STRIP_SCRIPT}"
        return 1
    fi

    info "Stripping metadata from: ${target}"
    mkdir -p "$output_dir"
    if [[ -d "$target" ]]; then
        "$METADATA_STRIP_SCRIPT" -d "$target" -o "$output_dir" 2>&1
    else
        "$METADATA_STRIP_SCRIPT" -f "$target" -o "$output_dir" 2>&1
    fi
    success "Metadata strip complete: ${output_dir}"
}

# Capture and archive screenshots of web evidence
run_screenshot_archive() {
    local url="$1"
    local output_dir="$2"

    if [[ ! -x "$SCREENSHOT_SCRIPT" ]]; then
        error "screenshot_archive.sh not found or not executable: ${SCREENSHOT_SCRIPT}"
        return 1
    fi

    info "Archiving screenshot of: ${url}"
    mkdir -p "$output_dir"
    "$SCREENSHOT_SCRIPT" -u "$url" -o "$output_dir" 2>&1
    success "Screenshot archived: ${output_dir}"
}

#-------------------------------------------------------------------------------
# INTEGRATED INVESTIGATION
#-------------------------------------------------------------------------------

# Run comprehensive investigation using all available tools
run_integrated_investigation() {
    local case_dir
    case_dir=$(resolve_case_dir "$1") || {
        error "Case directory not found or outside ${CASE_BASE_DIR}: $1"
        return 1
    }
    
    # Load case state — validate before sourcing to prevent shell injection
    if [[ -f "${case_dir}/.case_state" ]]; then
        if grep -Pq '\$\(|`|;\s*eval|;\s*source' "${case_dir}/.case_state" 2>/dev/null; then
            error ".case_state contains unsafe content (command substitution or eval), refusing to load"
            return 1
        fi
        # shellcheck source=/dev/null
        source "${case_dir}/.case_state"
    else
        error "No case state found in: ${case_dir}"
        return 1
    fi
    
    local output_dir="${case_dir}/raw_data/integrated"
    mkdir -p "$output_dir"
    
    echo ""
    echo -e "${CYAN}═══ Integrated Investigation ═══${NC}"
    echo ""
    
    # Process domains with scammer_audit if available
    if [[ -x "$SCAMMER_AUDIT_SCRIPT" ]] && [[ ${#DOMAINS[@]} -gt 0 ]]; then
        echo ""
        info "Running scammer audits on domains..."
        for domain in "${DOMAINS[@]}"; do
            run_scammer_audit "$domain" "$output_dir"
        done
    fi
    
    # Process IPs with scammer_audit if available
    if [[ -x "$SCAMMER_AUDIT_SCRIPT" ]] && [[ ${#IPS[@]} -gt 0 ]]; then
        echo ""
        info "Running scammer audits on IPs..."
        for ip in "${IPS[@]}"; do
            run_scammer_audit "$ip" "$output_dir"
        done
    fi
    
    # Run full nmap scan on IPs if available
    if [[ -x "$FULL_NMAP_SCRIPT" ]] && [[ ${#IPS[@]} -gt 0 ]]; then
        echo ""
        info "Running full nmap scans..."
        for ip in "${IPS[@]}"; do
            run_full_nmap "$ip" "$output_dir"
        done
    fi
    
    # Process emails with email_audit if available
    if [[ -x "$EMAIL_AUDIT_SCRIPT" ]] && [[ ${#EMAILS[@]} -gt 0 ]]; then
        echo ""
        info "Running email audits..."
        for email in "${EMAILS[@]}"; do
            run_email_audit "$email" "$output_dir"
        done
    fi
    
    # Process phones with phone_audit if available
    if [[ -x "$PHONE_AUDIT_SCRIPT" ]] && [[ ${#PHONES[@]} -gt 0 ]]; then
        echo ""
        info "Running phone audits..."
        for phone in "${PHONES[@]}"; do
            run_phone_audit "$phone" "$output_dir"
        done
    fi
    
    # Run theHarvester on domains
    if [[ -n "$THEHARVESTER_PATH" ]] && [[ ${#DOMAINS[@]} -gt 0 ]]; then
        echo ""
        info "Running theHarvester..."
        for domain in "${DOMAINS[@]}"; do
            run_theharvester "$domain" "$output_dir"
        done
    fi

    # SSL cert audit on domains
    if [[ -x "$SSL_CERT_SCRIPT" ]] && [[ ${#DOMAINS[@]} -gt 0 ]]; then
        echo ""
        info "Running SSL cert audits on domains..."
        for domain in "${DOMAINS[@]}"; do
            run_ssl_cert_audit "$domain" "$output_dir"
        done
    fi

    # Threat feed checks on IPs and domains
    if [[ -x "$THREAT_FEED_SCRIPT" ]]; then
        echo ""
        info "Running threat feed checks..."
        for ip in "${IPS[@]}"; do
            run_threat_feed_check "$ip" "$output_dir"
        done
        for domain in "${DOMAINS[@]}"; do
            run_threat_feed_check "$domain" "$output_dir"
        done
    fi

    # Crypto audit on wallet addresses
    if [[ -x "$CRYPTO_AUDIT_SCRIPT" ]] && [[ ${#CRYPTO_ADDRESSES[@]} -gt 0 ]]; then
        echo ""
        info "Running crypto audits on wallet addresses..."
        for addr in "${CRYPTO_ADDRESSES[@]}"; do
            run_crypto_audit "$addr" "$output_dir"
        done
    fi

    # Username audits
    if [[ -x "$USERNAME_AUDIT_SCRIPT" ]] && [[ ${#USERNAMES[@]} -gt 0 ]]; then
        echo ""
        info "Running username audits..."
        for username in "${USERNAMES[@]}"; do
            run_username_audit "$username" "$output_dir"
        done
    fi

    # Initialize domain monitoring baselines (non-blocking)
    if [[ -x "$DOMAIN_MONITOR_SCRIPT" ]] && [[ ${#DOMAINS[@]} -gt 0 ]]; then
        echo ""
        info "Setting up domain monitor baselines..."
        for domain in "${DOMAINS[@]}"; do
            run_domain_monitor_init "$domain"
        done
    fi

    echo ""
    success "Integrated investigation complete"
    info "Results saved in: ${output_dir}"
}

#-------------------------------------------------------------------------------
# MERGE RESULTS
#-------------------------------------------------------------------------------

# Merge results from all tools into unified report
merge_investigation_results() {
    local case_dir="$1"
    local output_file="${case_dir}/reports/final/INTEGRATED_FINDINGS.md"
    
    mkdir -p "$(dirname "$output_file")"
    
    {
        echo "# Integrated Investigation Findings"
        echo ""
        echo "**Generated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "**Case:** ${CASE_ID:-Unknown}"
        echo ""
        echo "---"
        echo ""
        
        # Include scammer audit results
        if ls "${case_dir}/raw_data/integrated/scammer_audit_"*.txt 1>/dev/null 2>&1; then
            echo "## Scammer Audit Results"
            echo ""
            for f in "${case_dir}/raw_data/integrated/scammer_audit_"*.txt; do
                echo "### $(basename "$f")"
                echo '```'
                head -100 "$f"
                echo '```'
                echo ""
            done
        fi
        
        # Include email audit results
        if ls "${case_dir}/raw_data/integrated/email_audit_"*.txt 1>/dev/null 2>&1; then
            echo "## Email Audit Results"
            echo ""
            for f in "${case_dir}/raw_data/integrated/email_audit_"*.txt; do
                echo "### $(basename "$f")"
                echo '```'
                head -100 "$f"
                echo '```'
                echo ""
            done
        fi
        
        # Include phone audit results
        if ls "${case_dir}/raw_data/integrated/phone_audit_"*.txt 1>/dev/null 2>&1; then
            echo "## Phone Audit Results"
            echo ""
            for f in "${case_dir}/raw_data/integrated/phone_audit_"*.txt; do
                echo "### $(basename "$f")"
                echo '```'
                head -100 "$f"
                echo '```'
                echo ""
            done
        fi
        
        # Include nmap results
        if ls "${case_dir}/raw_data/integrated/nmap_full_"*.txt 1>/dev/null 2>&1; then
            echo "## Full Nmap Scan Results"
            echo ""
            for f in "${case_dir}/raw_data/integrated/nmap_full_"*.txt; do
                echo "### $(basename "$f")"
                echo '```'
                head -100 "$f"
                echo '```'
                echo ""
            done
        fi
        
        # Include theHarvester results
        if ls "${case_dir}/raw_data/integrated/harvester_"*.xml 1>/dev/null 2>&1; then
            echo "## theHarvester Results"
            echo ""
            echo "See XML/HTML reports in raw_data/integrated/"
            echo ""
        fi
        
        echo "---"
        echo ""
        echo "*Report generated by OSINT Investigator Toolkit Integration*"
        
    } > "$output_file"
    
    success "Integrated findings: ${output_file}"
}

#-------------------------------------------------------------------------------
# MAIN
#-------------------------------------------------------------------------------
main() {
    case "${1:-}" in
        --detect|-d)
            detect_existing_scripts
            save_integration_config
            ;;
        --config|-c)
            load_integration_config
            configure_integration
            ;;
        --status|-s)
            load_integration_config
            show_integration_status
            ;;
        --help|-h)
            echo "OSINT Toolkit Integration Module"
            echo ""
            echo "Usage: source $0 (to load functions)"
            echo "       $0 --detect    Auto-detect scripts in scripts/ folder"
            echo "       $0 --config    Configure integration paths"
            echo "       $0 --status    Show integration status"
            echo ""
            echo "Expected folder structure:"
            echo "  playbook/"
            echo "  ├── scripts/"
            echo "  │   ├── scammer_audit.sh"
            echo "  │   ├── email_audit.sh"
            echo "  │   ├── phone_audit.sh"
            echo "  │   ├── full_nmap_scan.sh"
            echo "  │   ├── threat_feed_check.sh"
            echo "  │   ├── crypto_audit.sh"
            echo "  │   ├── domain_monitor.sh"
            echo "  │   ├── username_audit.sh"
            echo "  │   ├── ssl_cert_audit.sh"
            echo "  │   ├── case_report_generator.sh"
            echo "  │   ├── whois_bulk.sh"
            echo "  │   ├── metadata_stripper.sh"
            echo "  │   └── screenshot_archive.sh"
            echo "  ├── osint_investigator.sh"
            echo "  └── toolkit_integration.sh"
            echo ""
            ;;
        *)
            # When sourced, just load config
            load_integration_config
            ;;
    esac
}

# Only run main if not being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
