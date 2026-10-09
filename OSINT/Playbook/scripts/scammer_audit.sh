#!/bin/bash

#############################################
#  SCAMMER OSINT INVESTIGATION SCRIPT v3.1
#  Jon-Eric Pienkowski ~ PNW Computers (PNWC)
#  
#  Usage: ./scammer_audit.sh -d <domain>
#         ./scammer_audit.sh -i <ip1,ip2,ip3>
#         ./scammer_audit.sh -d <domain> -i <ip1,ip2>
#         ./scammer_audit.sh -f <file_with_ips>
#         ./scammer_audit.sh -e <email>
#
#  theHarvester handles: Shodan, VirusTotal, Hunter, SecurityTrails,
#                        WhoisXML, ZoomEye, Censys, FullHunt, IntelX
#
#  This script adds: CriminalIP, HaveIBeenPwned, LeakLookup, Netlas,
#                    ipinfo.io, ip-api.com, Nmap, Nuclei, Dirsearch
#
#  Dependencies:
#    sudo apt install whatweb nuclei dirsearch jq nmap curl netcat-openbsd
#    sudo docker pull rustscan/rustscan:2.1.1
#############################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

#############################################
# API KEYS (APIs NOT used by theHarvester)
#############################################
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_CONFIG="${CONFIG_DIR}/api_keys.conf"

# API keys are loaded from the config file or environment. Support both the
# short variable names used by this script and the exported names documented in
# `playbook/api_keys.conf`.
CRIMINALIP_KEY="${CRIMINALIP_KEY:-${CRIMINALIP_API_KEY:-}}"
HIBP_KEY="${HIBP_KEY:-${HAVEIBEENPWNED_API_KEY:-}}"
LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-}}"
NETLAS_KEY="${NETLAS_KEY:-${NETLAS_API_KEY:-}}"
PROJECTDISCOVERY_KEY="${PROJECTDISCOVERY_KEY:-${PDCP_API_KEY:-}}"
URLSCAN_KEY="${URLSCAN_KEY:-${URLSCAN_API_KEY:-}}"
DNSDUMPSTER_KEY="${DNSDUMPSTER_KEY:-${DNSDUMPSTER_API_KEY:-}}"
ZOOMEYE_KEY="${ZOOMEYE_KEY:-${ZOOMEYE_API_KEY:-}}"
FULLHUNT_KEY="${FULLHUNT_KEY:-${FULLHUNT_API_KEY:-}}"

load_api_keys() {
    if [ -f "$API_CONFIG" ]; then
        # shellcheck disable=SC1090
        source "$API_CONFIG"

        CRIMINALIP_KEY="${CRIMINALIP_KEY:-${CRIMINALIP_API_KEY:-${criminalip_api_key:-}}}"
        HIBP_KEY="${HIBP_KEY:-${HAVEIBEENPWNED_API_KEY:-${hibp_key:-${haveibeenpwned_api_key:-}}}}"
        LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-${leaklookup_api_key:-}}}"
        NETLAS_KEY="${NETLAS_KEY:-${NETLAS_API_KEY:-${netlas_api_key:-}}}"
        PROJECTDISCOVERY_KEY="${PROJECTDISCOVERY_KEY:-${PDCP_API_KEY:-${pdcp_api_key:-}}}"
        URLSCAN_KEY="${URLSCAN_KEY:-${URLSCAN_API_KEY:-}}"
        DNSDUMPSTER_KEY="${DNSDUMPSTER_KEY:-${DNSDUMPSTER_API_KEY:-}}"
        ZOOMEYE_KEY="${ZOOMEYE_KEY:-${ZOOMEYE_API_KEY:-}}"
        FULLHUNT_KEY="${FULLHUNT_KEY:-${FULLHUNT_API_KEY:-}}"
    else
        echo -e "${YELLOW}[!] API config not found at $API_CONFIG. Set keys via environment variables.${NC}" >&2
    fi
}

#############################################
# Variables
#############################################
DOMAIN=""
IPS=()
IP_FILE=""
EMAIL=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SKIP_AGGRESSIVE=false
SKIP_NUCLEI=false
SKIP_DIRSEARCH=false
QUICK_MODE=false
PARALLEL_MODE=false
MAX_PARALLEL=3

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║           SCAMMER OSINT INVESTIGATION SCRIPT v3.1                  ║"
    echo "║                 Pacific Northwest Computers                        ║"
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║  theHarvester: Shodan, VirusTotal, Hunter, SecurityTrails,         ║"
    echo "║                WhoisXML, ZoomEye, Censys, FullHunt, IntelX         ║"
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║  Additional:   CriminalIP, HIBP, LeakLookup, Netlas, Nmap,         ║"
    echo "║                Nuclei, Dirsearch, WhatWeb, RustScan                ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Usage
usage() {
    echo "Usage: $0 -d <domain> [-i <ip1,ip2,ip3>] [options]"
    echo "       $0 -i <ip1,ip2,ip3> [options]"
    echo "       $0 -e <email> [options]"
    echo "       $0 -f <file_with_ips> [options]"
    echo ""
    echo "Options:"
    echo "  -d    Target domain (e.g., example-scam-domain.tld)"
    echo "  -i    Target IP address(es), comma-separated"
    echo "  -e    Target email address for breach lookups"
    echo "  -f    File containing IPs (one per line)"
    echo "  -s    Skip aggressive nmap scan (no sudo prompt)"
    echo "  -n    Skip Nuclei vulnerability scan"
    echo "  -D    Skip Dirsearch directory enumeration"
    echo "  -q    Quick mode (skip slow scans)"
    echo "  -p    Parallel mode (scan multiple IPs simultaneously)"
    echo "  -h    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -d example-scam-domain.tld"
    echo "  $0 -d example-scam-domain.tld -e scammer@domain.com"
    echo "  $0 -i 192.0.2.1,198.51.100.1"
    echo "  $0 -d example-scam-domain.tld -p    # Parallel scanning"
    echo "  $0 -d example-scam-domain.tld -q    # Quick mode"
    exit 1
}

# Check dependencies
check_dependencies() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    
    MISSING=()
    command -v nmap &> /dev/null || MISSING+=("nmap")
    command -v curl &> /dev/null || MISSING+=("curl")
    command -v jq &> /dev/null || MISSING+=("jq")
    
    OPTIONAL_MISSING=()
    command -v theHarvester &> /dev/null || OPTIONAL_MISSING+=("theHarvester")
    command -v whatweb &> /dev/null || OPTIONAL_MISSING+=("whatweb")
    command -v nuclei &> /dev/null || OPTIONAL_MISSING+=("nuclei")
    command -v dirsearch &> /dev/null || OPTIONAL_MISSING+=("dirsearch")
    command -v nc &> /dev/null || OPTIONAL_MISSING+=("netcat-openbsd")
    
    if command -v docker &> /dev/null; then
        docker image inspect rustscan/rustscan:2.1.1 &> /dev/null || OPTIONAL_MISSING+=("rustscan")
    else
        OPTIONAL_MISSING+=("docker+rustscan")
    fi
    
    if [ ${#MISSING[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required: ${MISSING[*]}${NC}"
        echo -e "${RED}[!] Install: sudo apt install ${MISSING[*]}${NC}"
        exit 1
    fi
    
    if [ ${#OPTIONAL_MISSING[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Missing optional: ${OPTIONAL_MISSING[*]}${NC}"
    else
        echo -e "${GREEN}[+] All dependencies found!${NC}"
    fi
    echo ""
}

# Parse arguments
while getopts "d:i:e:f:snDqph" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        i) IFS=',' read -ra IPS <<< "$OPTARG" ;;
        e) EMAIL="$OPTARG" ;;
        f) IP_FILE="$OPTARG" ;;
        s) SKIP_AGGRESSIVE=true ;;
        n) SKIP_NUCLEI=true ;;
        D) SKIP_DIRSEARCH=true ;;
        q) QUICK_MODE=true; SKIP_NUCLEI=true; SKIP_DIRSEARCH=true ;;
        p) PARALLEL_MODE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Load IPs from file
if [ -n "$IP_FILE" ]; then
    if [ -f "$IP_FILE" ]; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            IPS+=("$line")
        done < "$IP_FILE"
    else
        echo -e "${RED}[!] Error: File $IP_FILE not found${NC}"
        exit 1
    fi
fi

# Validate input
if [ -z "$DOMAIN" ] && [ ${#IPS[@]} -eq 0 ] && [ -z "$EMAIL" ]; then
    echo -e "${RED}[!] Error: Provide domain (-d), IP(s) (-i), email (-e), or file (-f)${NC}"
    usage
fi

# Create output directory
if [ -n "$DOMAIN" ]; then
    OUTPUT_DIR="scammer_audit_${DOMAIN}_${TIMESTAMP}"
elif [ -n "$EMAIL" ]; then
    EMAIL_SAFE=$(echo "$EMAIL" | tr '@.' '_')
    OUTPUT_DIR="scammer_audit_${EMAIL_SAFE}_${TIMESTAMP}"
else
    OUTPUT_DIR="scammer_audit_${IPS[0]}_${TIMESTAMP}"
fi
mkdir -p "$OUTPUT_DIR"/{ips,domain,email}

LOG_FILE="$OUTPUT_DIR/audit_log.txt"

# Logging
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

section() {
    log ""
    log "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    log "${YELLOW}  $1${NC}"
    log "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    log ""
}

ip_section() {
    log ""
    log "${CYAN}───────────────────────────────────────────────────────────────${NC}"
    log "${GREEN}  IP: $1${NC}"
    log "${CYAN}───────────────────────────────────────────────────────────────${NC}"
}

pretty_json() {
    jq '.' 2>/dev/null || cat
}

# Start
print_banner
check_dependencies
load_api_keys

log "Investigation started: $(date)"
log "Output directory: $OUTPUT_DIR"
[ -n "$DOMAIN" ] && log "Target Domain: $DOMAIN"
[ -n "$EMAIL" ] && log "Target Email: $EMAIL"
log "Target IPs: ${IPS[*]:-Will extract from theHarvester}"
log "Quick Mode: $QUICK_MODE | Parallel Mode: $PARALLEL_MODE"
log ""


#############################################
# API FUNCTIONS (Not covered by theHarvester)
#############################################

# CriminalIP - IP threat intelligence
query_criminalip() {
    local IP="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Querying CriminalIP...${NC}"
    curl -s "https://api.criminalip.io/v1/ip/data?ip=$IP" \
        -H "x-api-key: $CRIMINALIP_KEY" | pretty_json > "$OUTPUT" 2>&1
    
    # Check for malicious score
    if command -v jq &> /dev/null && [ -s "$OUTPUT" ]; then
        SCORE=$(jq -r '(.data.score.inbound // .data.score // .score // empty)' "$OUTPUT" 2>/dev/null)
        if [ -n "$SCORE" ] && [ "$SCORE" != "null" ]; then
            log "${YELLOW}    [!] CriminalIP Score: $SCORE${NC}"
        fi
    fi
    log "${GREEN}    [+] CriminalIP complete${NC}"
}

# HaveIBeenPwned - Breach check for emails
query_hibp() {
    local EMAIL="$1"
    local OUTPUT="$2"
    log "${GREEN}[*] Checking HaveIBeenPwned for breaches...${NC}"
    local HTTP_CODE
    HTTP_CODE=$(curl -s -w "%{http_code}" -o "$OUTPUT" \
        "https://haveibeenpwned.com/api/v3/breachedaccount/$EMAIL" \
        -H "hibp-api-key: $HIBP_KEY" \
        -H "user-agent: PNWC-Scammer-Audit")

    if [ "$HTTP_CODE" = "200" ] && [ -s "$OUTPUT" ]; then
        BREACH_COUNT=$(jq '. | length' "$OUTPUT" 2>/dev/null || echo "0")
        if [ "$BREACH_COUNT" -gt 0 ] 2>/dev/null; then
            log "${RED}    [!] BREACHED! Found in $BREACH_COUNT breach(es)!${NC}"
            jq -r '.[].Name' "$OUTPUT" 2>/dev/null | while read -r breach; do
                log "${RED}        - $breach${NC}"
            done
        fi
    elif [ "$HTTP_CODE" = "404" ]; then
        log "${GREEN}    [+] No breaches found${NC}"
    else
        log "${YELLOW}    [!] HIBP API error (HTTP $HTTP_CODE)${NC}"
    fi
}

# HaveIBeenPwned - Pastes check
query_hibp_pastes() {
    local EMAIL="$1"
    local OUTPUT="$2"
    log "${GREEN}[*] Checking HaveIBeenPwned for pastes...${NC}"
    local HTTP_CODE_PASTES
    HTTP_CODE_PASTES=$(curl -s -w "%{http_code}" -o "$OUTPUT" \
        "https://haveibeenpwned.com/api/v3/pasteaccount/$EMAIL" \
        -H "hibp-api-key: $HIBP_KEY" \
        -H "user-agent: PNWC-Scammer-Audit")

    if [ "$HTTP_CODE_PASTES" = "200" ] && [ -s "$OUTPUT" ]; then
        PASTE_COUNT=$(jq '. | length' "$OUTPUT" 2>/dev/null || echo "0")
        if [ "$PASTE_COUNT" -gt 0 ] 2>/dev/null; then
            log "${RED}    [!] Found in $PASTE_COUNT paste(s)!${NC}"
        fi
    elif [ "$HTTP_CODE_PASTES" = "404" ]; then
        log "${GREEN}    [+] No pastes found${NC}"
    else
        log "${YELLOW}    [!] HIBP pastes API error (HTTP $HTTP_CODE_PASTES)${NC}"
    fi
}

# LeakLookup - Credential leak search
query_leaklookup() {
    local QUERY="$1"
    local TYPE="$2"  # email_address, username, ip_address, domain, password, hash
    local OUTPUT="$3"
    log "${GREEN}[*] Querying LeakLookup ($TYPE)...${NC}"
    curl -s "https://leak-lookup.com/api/search" \
        -d "key=$LEAKLOOKUP_KEY&type=$TYPE&query=$QUERY" | pretty_json > "$OUTPUT" 2>&1
    
    if [ -s "$OUTPUT" ]; then
        ERROR=$(jq -r '.error // "none"' "$OUTPUT" 2>/dev/null)
        if [ "$ERROR" = "none" ] || [ "$ERROR" = "null" ]; then
            FOUND=$(jq -r '.message // "unknown"' "$OUTPUT" 2>/dev/null)
            if [ "$FOUND" != "Not found" ] && [ "$FOUND" != "unknown" ]; then
                log "${RED}    [!] LeakLookup: Data found!${NC}"
            else
                log "${GREEN}    [+] LeakLookup: No leaks found${NC}"
            fi
        fi
    fi
}

# Netlas - Internet scan data
query_netlas() {
    local IP="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Querying Netlas...${NC}"
    curl -s "https://app.netlas.io/api/hosts/$IP/" \
        -H "X-API-Key: $NETLAS_KEY" | pretty_json > "$OUTPUT" 2>&1
    log "${GREEN}    [+] Netlas complete${NC}"
}

# ipinfo.io - Geolocation
query_ipinfo() {
    local IP="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Querying ipinfo.io...${NC}"
    curl -s "https://ipinfo.io/$IP" | pretty_json > "$OUTPUT" 2>&1
    log "${GREEN}    [+] ipinfo.io complete${NC}"
}

# ip-api.com - Geolocation & ISP
query_ipapi() {
    local IP="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Querying ip-api.com...${NC}"
    curl -s "http://ip-api.com/json/$IP?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query" \
        | pretty_json > "$OUTPUT" 2>&1
    
    # Check for proxy/hosting flags
    if command -v jq &> /dev/null; then
        IS_PROXY=$(jq -r '.proxy // false' "$OUTPUT" 2>/dev/null)
        IS_HOSTING=$(jq -r '.hosting // false' "$OUTPUT" 2>/dev/null)
        if [ "$IS_PROXY" = "true" ]; then
            log "${YELLOW}    [!] IP flagged as PROXY${NC}"
        fi
        if [ "$IS_HOSTING" = "true" ]; then
            log "${YELLOW}    [!] IP flagged as HOSTING/DATACENTER${NC}"
        fi
    fi
    log "${GREEN}    [+] ip-api.com complete${NC}"
}

# URLScan.io - search existing domain/IP scans
query_urlscan() {
    local TARGET="$1"
    local OUTPUT="$2"
    local TYPE="$3"  # domain or ip

    if [ -z "$URLSCAN_KEY" ]; then
        log "${YELLOW}    [!] URLSCAN_API_KEY not set; using unauthenticated (rate-limited)${NC}"
    fi

    local QUERY
    case "$TYPE" in
        ip)     QUERY="ip:${TARGET}" ;;
        domain) QUERY="domain:${TARGET}" ;;
        *)      QUERY="${TARGET}" ;;
    esac

    log "${GREEN}    [*] Querying URLScan.io...${NC}"
    local ENCODED_QUERY
    ENCODED_QUERY=$(OSINT_QUERY="${QUERY}" python3 -c "import os,urllib.parse; print(urllib.parse.quote(os.environ['OSINT_QUERY']))" 2>/dev/null || printf '%s' "$QUERY" | sed 's/:/%3A/g;s/ /+/g')

    local -a CURL_ARGS=(-s -H "Content-Type: application/json")
    [ -n "$URLSCAN_KEY" ] && CURL_ARGS+=(-H "API-Key: ${URLSCAN_KEY}")

    curl "${CURL_ARGS[@]}" \
        "https://urlscan.io/api/v1/search/?q=${ENCODED_QUERY}&size=10" \
        | pretty_json > "$OUTPUT" 2>&1

    if command -v jq &>/dev/null; then
        local TOTAL
        TOTAL=$(jq -r '.total // 0' "$OUTPUT" 2>/dev/null)
        log "${GREEN}    [+] URLScan.io: ${TOTAL} existing scan(s) for ${TARGET}${NC}"
    else
        log "${GREEN}    [+] URLScan.io complete${NC}"
    fi
}

# DNSDumpster - DNS records and subdomain discovery
query_dnsdumpster() {
    local DOMAIN="$1"
    local OUTPUT="$2"

    if [ -z "$DNSDUMPSTER_KEY" ]; then
        log "${YELLOW}    [!] DNSDUMPSTER_API_KEY not set; skipping DNSDumpster${NC}"
        return
    fi

    log "${GREEN}    [*] Querying DNSDumpster...${NC}"
    curl -s \
        -H "Authorization: Bearer ${DNSDUMPSTER_KEY}" \
        "https://api.dnsdumpster.com/domain/${DOMAIN}" \
        | pretty_json > "$OUTPUT" 2>&1
    log "${GREEN}    [+] DNSDumpster complete${NC}"
}

# ZoomEye - Cyberspace search engine
query_zoomeye() {
    local TARGET="$1"
    local OUTPUT="$2"
    local TYPE="$3"  # ip or domain

    if [ -z "$ZOOMEYE_KEY" ]; then
        log "${YELLOW}    [!] ZOOMEYE_API_KEY not set; skipping ZoomEye${NC}"
        return
    fi

    local QUERY
    case "$TYPE" in
        ip)     QUERY="ip:${TARGET}" ;;
        domain) QUERY="hostname:${TARGET}" ;;
        *)      QUERY="${TARGET}" ;;
    esac

    log "${GREEN}    [*] Querying ZoomEye...${NC}"
    local ENCODED_QUERY
    ENCODED_QUERY=$(OSINT_QUERY="${QUERY}" python3 -c "import os,urllib.parse; print(urllib.parse.quote(os.environ['OSINT_QUERY']))" 2>/dev/null || printf '%s' "$QUERY" | sed 's/:/%3A/g;s/ /+/g')

    curl -s \
        -H "API-KEY: ${ZOOMEYE_KEY}" \
        "https://api.zoomeye.org/host/search?query=${ENCODED_QUERY}&page=1" \
        | pretty_json > "$OUTPUT" 2>&1
    log "${GREEN}    [+] ZoomEye complete${NC}"
}

# FullHunt - attack surface and subdomain discovery
query_fullhunt() {
    local DOMAIN="$1"
    local OUTPUT="$2"

    if [ -z "$FULLHUNT_KEY" ]; then
        log "${YELLOW}    [!] FULLHUNT_API_KEY not set; skipping FullHunt${NC}"
        return
    fi

    log "${GREEN}    [*] Querying FullHunt...${NC}"
    curl -s \
        -H "X-API-KEY: ${FULLHUNT_KEY}" \
        "https://fullhunt.io/api/v1/domain/${DOMAIN}/subdomains" \
        | pretty_json > "$OUTPUT" 2>&1

    if command -v jq &>/dev/null; then
        local SUB_COUNT
        SUB_COUNT=$(jq -r '.hosts | length // 0' "$OUTPUT" 2>/dev/null)
        log "${GREEN}    [+] FullHunt: found ${SUB_COUNT} subdomains for ${DOMAIN}${NC}"
    else
        log "${GREEN}    [+] FullHunt complete${NC}"
    fi
}


#############################################
# Nuclei Scan
#############################################
run_nuclei() {
    local TARGET="$1"
    local OUTPUT_FILE="$2"
    
    if [ "$SKIP_NUCLEI" = true ]; then
        log "${YELLOW}[!] Nuclei skipped${NC}"
        return
    fi
    
    if command -v nuclei &> /dev/null; then
        log "${GREEN}[*] Running Nuclei vulnerability scan...${NC}"
        log "${YELLOW}    (This may take a while...)${NC}"
        
        # Update templates silently
        nuclei -ut -silent 2>/dev/null

        # Run nuclei
        nuclei -u "$TARGET" -severity low,medium,high,critical -silent -o "$OUTPUT_FILE" 2>&1

        if [ -s "$OUTPUT_FILE" ]; then
            VULN_COUNT=$(wc -l < "$OUTPUT_FILE")
            log "${RED}[!] Found $VULN_COUNT vulnerability/ies! Check: $OUTPUT_FILE${NC}"
            head -10 "$OUTPUT_FILE" | tee -a "$LOG_FILE"
            [ "$VULN_COUNT" -gt 10 ] && log "${YELLOW}    ... and $(($VULN_COUNT - 10)) more${NC}"
        else
            log "${GREEN}[+] No vulnerabilities detected${NC}"
        fi
    else
        log "${YELLOW}[!] Nuclei not installed${NC}"
    fi
}


#############################################
# Dirsearch
#############################################
run_dirsearch() {
    local TARGET="$1"
    local OUTPUT_FILE="$2"
    
    if [ "$SKIP_DIRSEARCH" = true ]; then
        log "${YELLOW}[!] Dirsearch skipped${NC}"
        return
    fi
    
    if command -v dirsearch &> /dev/null; then
        log "${GREEN}[*] Running Dirsearch directory enumeration...${NC}"
        log "${YELLOW}    (This may take a while...)${NC}"
        
        dirsearch -u "$TARGET" -e php,html,js,txt,asp,aspx,jsp,bak,old,zip -q --format plain -o "$OUTPUT_FILE" 2>&1
        
        if [ -s "$OUTPUT_FILE" ]; then
            FOUND_COUNT=$(wc -l < "$OUTPUT_FILE")
            log "${GREEN}[+] Dirsearch found $FOUND_COUNT paths${NC}"
        else
            log "${GREEN}[+] Dirsearch complete - no interesting paths found${NC}"
        fi
    else
        log "${YELLOW}[!] Dirsearch not installed${NC}"
    fi
}


#############################################
# RustScan
#############################################
run_rustscan() {
    local IP="$1"
    local OUTPUT="$2"
    
    if command -v docker &> /dev/null && docker image inspect rustscan/rustscan:2.1.1 &> /dev/null; then
        log "${GREEN}[*] Running RustScan (fast port discovery)...${NC}"
        timeout 120 docker run --rm rustscan/rustscan:2.1.1 -a "$IP" --ulimit 5000 -b 1500 -- -sV 2>&1 | tee "$OUTPUT"
        log "${GREEN}[+] RustScan complete${NC}"
        return 0
    else
        log "${YELLOW}[!] RustScan not available${NC}"
        return 1
    fi
}


#############################################
# SCAN SINGLE IP
#############################################
scan_ip() {
    local IP="$1"
    local IP_SAFE; IP_SAFE=$(echo "$IP" | tr ':' '_')
    local IP_DIR="$OUTPUT_DIR/ips/$IP_SAFE"
    mkdir -p "$IP_DIR"
    
    ip_section "$IP"
    
    #-----------------------------------------
    # IP Intelligence (NOT in theHarvester)
    #-----------------------------------------
    log "${GREEN}[*] Running IP Intelligence...${NC}"
    
    query_ipinfo "$IP" "$IP_DIR/ipinfo.json"
    query_ipapi "$IP" "$IP_DIR/ipapi.json"
    
    # WHOIS
    if [[ ! "$IP" =~ ":" ]]; then
        log "${GREEN}    [*] Running WHOIS...${NC}"
        whois -h whois.arin.net "$IP" > "$IP_DIR/whois_arin.txt" 2>&1
        log "${GREEN}    [+] WHOIS complete${NC}"
    fi
    
    #-----------------------------------------
    # Additional APIs (NOT in theHarvester)
    #-----------------------------------------
    query_criminalip "$IP" "$IP_DIR/criminalip.json"
    sleep 1

    query_netlas "$IP" "$IP_DIR/netlas.json"
    query_urlscan "$IP" "$IP_DIR/urlscan.json" "ip"
    query_zoomeye "$IP" "$IP_DIR/zoomeye.json" "ip"
    sleep 1
    
    query_leaklookup "$IP" "ip_address" "$IP_DIR/leaklookup.json"
    
    #-----------------------------------------
    # RustScan (Fast Port Discovery)
    #-----------------------------------------
    run_rustscan "$IP" "$IP_DIR/rustscan.txt"
    
    #-----------------------------------------
    # Nmap Scans
    #-----------------------------------------
    log "${GREEN}[*] Running Nmap scans...${NC}"
    
    # Basic Scan
    nmap -sV -sC --host-timeout 300s "$IP" -oN "$IP_DIR/nmap_basic.txt" -oX "$IP_DIR/nmap_basic.xml" > /dev/null 2>&1
    log "${GREEN}    [+] Basic scan done${NC}"

    # Full port scan (skip in quick mode)
    if [ "$QUICK_MODE" = false ]; then
        log "${GREEN}    [*] Running full port scan (this takes a while)...${NC}"
        nmap -p- -T4 --host-timeout 600s "$IP" -oN "$IP_DIR/nmap_fullport.txt" > /dev/null 2>&1
        log "${GREEN}    [+] Full port scan done${NC}"
    fi
    
    # DNS NSID
    nmap --script dns-nsid "$IP" -oN "$IP_DIR/nmap_dns.txt" > /dev/null 2>&1
    log "${GREEN}    [+] DNS scan done${NC}"
    
    # Extra ports
    nmap -Pn -sV -p 443,8080,8443,3389,22,21,25,3306,5432,27017,6379 "$IP" -oN "$IP_DIR/nmap_extra.txt" > /dev/null 2>&1
    log "${GREEN}    [+] Extra ports scan done${NC}"
    
    # Vuln scripts
    log "${GREEN}    [*] Running Nmap vuln scripts...${NC}"
    nmap --script vuln "$IP" -oN "$IP_DIR/nmap_vuln.txt" > /dev/null 2>&1
    log "${GREEN}    [+] Vuln scan done${NC}"
    
    #-----------------------------------------
    # Banner Grab
    #-----------------------------------------
    log "${GREEN}[*] Grabbing banners...${NC}"
    echo '' | timeout 5 nc -v "$IP" 80 > "$IP_DIR/banner_80.txt" 2>&1
    echo '' | timeout 5 nc -v "$IP" 443 > "$IP_DIR/banner_443.txt" 2>&1
    echo '' | timeout 5 nc -v "$IP" 22 > "$IP_DIR/banner_22.txt" 2>&1
    log "${GREEN}    [+] Banner grab complete${NC}"
    
    #-----------------------------------------
    # Web Recon (if ports open)
    #-----------------------------------------
    PORT80_OPEN=0
    PORT443_OPEN=0
    if [ -f "$IP_DIR/nmap_basic.txt" ]; then
        PORT80_OPEN=$(grep -c "80/tcp.*open" "$IP_DIR/nmap_basic.txt" 2>/dev/null) || PORT80_OPEN=0
        PORT443_OPEN=$(grep -c "443/tcp.*open" "$IP_DIR/nmap_basic.txt" 2>/dev/null) || PORT443_OPEN=0
    fi
    
    if [ "$PORT80_OPEN" -gt 0 ] 2>/dev/null || [ "$PORT443_OPEN" -gt 0 ] 2>/dev/null; then
        log "${GREEN}[*] Web ports detected - running web recon...${NC}"
        
        if [ "$PORT443_OPEN" -gt 0 ]; then
            WEB_TARGET="https://$IP"
        else
            WEB_TARGET="http://$IP"
        fi
        
        # WhatWeb
        if command -v whatweb &> /dev/null; then
            log "${GREEN}    [*] Running WhatWeb...${NC}"
            whatweb "$WEB_TARGET" --log-json="$IP_DIR/whatweb.json" > "$IP_DIR/whatweb.txt" 2>&1
            log "${GREEN}    [+] WhatWeb complete${NC}"
        fi
        
        # Nuclei
        run_nuclei "$WEB_TARGET" "$IP_DIR/nuclei_results.txt"
        
        # Dirsearch
        run_dirsearch "$WEB_TARGET" "$IP_DIR/dirsearch_results.txt"
    else
        log "${YELLOW}[!] No web ports (80/443) detected, skipping web recon${NC}"
    fi
    
    #-----------------------------------------
    # Generate IP Summary
    #-----------------------------------------
    log "${GREEN}[*] Generating IP summary...${NC}"
    
    # Handle empty JSON files gracefully
    IPINFO_ORG="Unknown"
    IPINFO_CITY="Unknown"
    IPINFO_COUNTRY="Unknown"
    IPAPI_ISP="Unknown"
    IPAPI_AS="Unknown"
    IS_PROXY="Unknown"
    IS_HOSTING="Unknown"
    
    if [ -s "$IP_DIR/ipinfo.json" ]; then
        IPINFO_ORG=$(jq -r '.org // "Unknown"' "$IP_DIR/ipinfo.json" 2>/dev/null) || IPINFO_ORG="Unknown"
        IPINFO_CITY=$(jq -r '.city // "Unknown"' "$IP_DIR/ipinfo.json" 2>/dev/null) || IPINFO_CITY="Unknown"
        IPINFO_COUNTRY=$(jq -r '.country // "Unknown"' "$IP_DIR/ipinfo.json" 2>/dev/null) || IPINFO_COUNTRY="Unknown"
        [ -z "$IPINFO_ORG" ] && IPINFO_ORG="Unknown"
        [ -z "$IPINFO_CITY" ] && IPINFO_CITY="Unknown"
        [ -z "$IPINFO_COUNTRY" ] && IPINFO_COUNTRY="Unknown"
    fi
    
    if [ -s "$IP_DIR/ipapi.json" ]; then
        IPAPI_ISP=$(jq -r '.isp // "Unknown"' "$IP_DIR/ipapi.json" 2>/dev/null) || IPAPI_ISP="Unknown"
        IPAPI_AS=$(jq -r '.as // "Unknown"' "$IP_DIR/ipapi.json" 2>/dev/null) || IPAPI_AS="Unknown"
        IS_PROXY=$(jq -r '.proxy // "Unknown"' "$IP_DIR/ipapi.json" 2>/dev/null) || IS_PROXY="Unknown"
        IS_HOSTING=$(jq -r '.hosting // "Unknown"' "$IP_DIR/ipapi.json" 2>/dev/null) || IS_HOSTING="Unknown"
        [ -z "$IPAPI_ISP" ] && IPAPI_ISP="Unknown"
        [ -z "$IPAPI_AS" ] && IPAPI_AS="Unknown"
        [ -z "$IS_PROXY" ] && IS_PROXY="Unknown"
        [ -z "$IS_HOSTING" ] && IS_HOSTING="Unknown"
    fi
    
    cat << EOF > "$IP_DIR/SUMMARY.txt"
╔═══════════════════════════════════════════════════════════════════════════╗
║                    IP INVESTIGATION SUMMARY                               ║
╚═══════════════════════════════════════════════════════════════════════════╝

Target IP: $IP
Scanned: $(date)

═══════════════════════════════════════════════════════════════════════════
QUICK FACTS
═══════════════════════════════════════════════════════════════════════════
Organization: $IPINFO_ORG
ISP: $IPAPI_ISP
AS: $IPAPI_AS
Location: $IPINFO_CITY, $IPINFO_COUNTRY
Is Proxy: $IS_PROXY
Is Hosting/Datacenter: $IS_HOSTING

═══════════════════════════════════════════════════════════════════════════
IPINFO.IO
═══════════════════════════════════════════════════════════════════════════
$(cat "$IP_DIR/ipinfo.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
IP-API.COM
═══════════════════════════════════════════════════════════════════════════
$(cat "$IP_DIR/ipapi.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
CRIMINALIP
═══════════════════════════════════════════════════════════════════════════
$(cat "$IP_DIR/criminalip.json" 2>/dev/null | head -50)

═══════════════════════════════════════════════════════════════════════════
NMAP BASIC SCAN
═══════════════════════════════════════════════════════════════════════════
$(cat "$IP_DIR/nmap_basic.txt" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
NMAP VULNERABILITY SCAN
═══════════════════════════════════════════════════════════════════════════
$(cat "$IP_DIR/nmap_vuln.txt" 2>/dev/null | head -100)

EOF

    # Add nuclei results if they exist
    if [ -s "$IP_DIR/nuclei_results.txt" ]; then
        cat << EOF >> "$IP_DIR/SUMMARY.txt"
═══════════════════════════════════════════════════════════════════════════
NUCLEI VULNERABILITIES
═══════════════════════════════════════════════════════════════════════════
$(cat "$IP_DIR/nuclei_results.txt" 2>/dev/null)

EOF
    fi

    cat << EOF >> "$IP_DIR/SUMMARY.txt"
═══════════════════════════════════════════════════════════════════════════
FILES GENERATED
═══════════════════════════════════════════════════════════════════════════
$(ls -la "$IP_DIR"/)
EOF
    
    log "${GREEN}[+] IP $IP scan complete${NC}"
}


#############################################
# 1) theHarvester - Domain OSINT
#############################################
if [ -n "$DOMAIN" ]; then
    section "1) theHarvester - Domain Reconnaissance"
    
    if command -v theHarvester &> /dev/null; then
        log "${GREEN}[*] Running theHarvester on $DOMAIN...${NC}"
        log "${CYAN}    APIs: hunter, shodan, virustotal, whoisxml, zoomeye, censys, fullhunt, intelx, securityTrails${NC}"
        
        theHarvester -d "$DOMAIN" -b hunter,shodan,virustotal,whoisxml,zoomeye,censys,fullhunt,intelx,securityTrails 2>&1 | tee "$OUTPUT_DIR/1_theharvester.txt"
        
        # Extract IPs if none provided
        if [ ${#IPS[@]} -eq 0 ]; then
            log "${GREEN}[*] Extracting IPs from theHarvester results...${NC}"
            
            # Extract IPv4
            IPV4_LIST=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTPUT_DIR/1_theharvester.txt" | sort -u)
            
            # Extract IPv6
            IPV6_LIST=$(grep -oE '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}' "$OUTPUT_DIR/1_theharvester.txt" | sort -u)
            
            while IFS= read -r ip; do
                [ -n "$ip" ] && IPS+=("$ip")
            done <<< "$IPV4_LIST"
            
            while IFS= read -r ip; do
                [ -n "$ip" ] && IPS+=("$ip")
            done <<< "$IPV6_LIST"
            
            if [ ${#IPS[@]} -gt 0 ]; then
                log "${GREEN}[+] Extracted ${#IPS[@]} IP(s):${NC}"
                printf '%s\n' "${IPS[@]}" | tee -a "$LOG_FILE"
            else
                log "${YELLOW}[!] No IPs found from theHarvester${NC}"
            fi
        fi
        
        log "${GREEN}[+] theHarvester complete${NC}"
    else
        log "${RED}[!] theHarvester not installed - this is required for domain recon${NC}"
        log "${YELLOW}[!] Install: sudo apt install theharvester${NC}"
    fi
fi


#############################################
# 2) Additional Domain APIs (Not in theHarvester)
#############################################
if [ -n "$DOMAIN" ]; then
    section "2) Additional Domain Intelligence"
    
    # LeakLookup for domain
    query_leaklookup "$DOMAIN" "domain" "$OUTPUT_DIR/domain/leaklookup.json"

    # URLScan.io — search existing scans
    query_urlscan "$DOMAIN" "$OUTPUT_DIR/domain/urlscan.json" "domain"

    # DNSDumpster — DNS records and subdomain discovery
    query_dnsdumpster "$DOMAIN" "$OUTPUT_DIR/domain/dnsdumpster.json"

    # ZoomEye — cyberspace search
    query_zoomeye "$DOMAIN" "$OUTPUT_DIR/domain/zoomeye.json" "domain"

    # FullHunt — attack surface and subdomains
    query_fullhunt "$DOMAIN" "$OUTPUT_DIR/domain/fullhunt.json"

    # WhatWeb
    if command -v whatweb &> /dev/null; then
        log "${GREEN}[*] Running WhatWeb on domain...${NC}"
        whatweb "http://$DOMAIN" --log-json="$OUTPUT_DIR/domain/whatweb_http.json" > "$OUTPUT_DIR/domain/whatweb_http.txt" 2>&1
        whatweb "https://$DOMAIN" --log-json="$OUTPUT_DIR/domain/whatweb_https.json" > "$OUTPUT_DIR/domain/whatweb_https.txt" 2>&1
        log "${GREEN}[+] WhatWeb complete${NC}"
    fi

    # Nuclei on domain
    run_nuclei "https://$DOMAIN" "$OUTPUT_DIR/domain/nuclei_results.txt"

    # Dirsearch on domain
    run_dirsearch "https://$DOMAIN" "$OUTPUT_DIR/domain/dirsearch_results.txt"
fi


#############################################
# 3) Email Investigation
#############################################
if [ -n "$EMAIL" ]; then
    section "3) Email Investigation"
    
    log "${GREEN}[*] Investigating email: $EMAIL${NC}"
    
    # HaveIBeenPwned - Breaches
    query_hibp "$EMAIL" "$OUTPUT_DIR/email/hibp_breaches.json"
    sleep 2  # HIBP rate limiting
    
    # HaveIBeenPwned - Pastes
    query_hibp_pastes "$EMAIL" "$OUTPUT_DIR/email/hibp_pastes.json"
    sleep 1
    
    # LeakLookup
    query_leaklookup "$EMAIL" "email_address" "$OUTPUT_DIR/email/leaklookup.json"
    
    # Generate email summary
    cat << EOF > "$OUTPUT_DIR/email/SUMMARY.txt"
╔═══════════════════════════════════════════════════════════════════════════╗
║                    EMAIL INVESTIGATION SUMMARY                            ║
╚═══════════════════════════════════════════════════════════════════════════╝

Target Email: $EMAIL
Investigated: $(date)

═══════════════════════════════════════════════════════════════════════════
HAVEIBEENPWNED - BREACHES
═══════════════════════════════════════════════════════════════════════════
$(cat "$OUTPUT_DIR/email/hibp_breaches.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
HAVEIBEENPWNED - PASTES
═══════════════════════════════════════════════════════════════════════════
$(cat "$OUTPUT_DIR/email/hibp_pastes.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
LEAKLOOKUP
═══════════════════════════════════════════════════════════════════════════
$(cat "$OUTPUT_DIR/email/leaklookup.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
FILES GENERATED
═══════════════════════════════════════════════════════════════════════════
$(ls -la "$OUTPUT_DIR/email/"/)
EOF

    log "${GREEN}[+] Email investigation complete${NC}"
fi


#############################################
# 4) Scan All IPs
#############################################
if [ ${#IPS[@]} -gt 0 ]; then
    section "4) Scanning ${#IPS[@]} IP Address(es)"
    
    if [ "$PARALLEL_MODE" = true ]; then
        log "${YELLOW}[*] Running in PARALLEL mode (max $MAX_PARALLEL simultaneous)${NC}"
        
        job_count=0
        for IP in "${IPS[@]}"; do
            scan_ip "$IP" &
            job_count=$((job_count + 1))
            
            if [ $job_count -ge $MAX_PARALLEL ]; then
                # wait -n requires bash 4.3+, use wait for compatibility
                wait -n 2>/dev/null || wait
                job_count=$((job_count - 1))
            fi
        done
        wait
    else
        IP_COUNT=0
        for IP in "${IPS[@]}"; do
            IP_COUNT=$((IP_COUNT + 1))
            log ""
            log "${YELLOW}[*] Scanning IP $IP_COUNT of ${#IPS[@]}: $IP${NC}"
            scan_ip "$IP"
        done
    fi
fi


#############################################
# 5) Aggressive Scans (Optional)
#############################################
if [ "$SKIP_AGGRESSIVE" = false ] && [ ${#IPS[@]} -gt 0 ]; then
    section "5) Aggressive Scans (Optional)"
    
    log "${YELLOW}[?] Run aggressive nmap on all IPs? (requires sudo) [y/N]${NC}"
    read -t 15 -n 1 RUN_AGGRESSIVE
    echo ""
    
    if [[ "$RUN_AGGRESSIVE" =~ ^[Yy]$ ]]; then
        for IP in "${IPS[@]}"; do
            IP_SAFE=$(echo "$IP" | tr ':' '_')
            log "${GREEN}[*] Aggressive scan on $IP...${NC}"
            sudo nmap -A -T4 "$IP" -oN "$OUTPUT_DIR/ips/$IP_SAFE/nmap_aggressive.txt" 2>&1
            log "${GREEN}[+] Aggressive scan complete for $IP${NC}"
        done
    else
        log "${YELLOW}[!] Skipping aggressive scans${NC}"
    fi
fi


#############################################
# 6) Generate Master Summary
#############################################
section "6) Generating Master Summary Report"

SUMMARY_FILE="$OUTPUT_DIR/MASTER_SUMMARY.txt"

cat << EOF > "$SUMMARY_FILE"
╔═══════════════════════════════════════════════════════════════════════════╗
║              SCAMMER INVESTIGATION MASTER REPORT v3.1                     ║
║                    Pacific Northwest Computers                            ║
╚═══════════════════════════════════════════════════════════════════════════╝

Report Generated: $(date)
Investigation ID: $TIMESTAMP

═══════════════════════════════════════════════════════════════════════════
TARGET INFORMATION
═══════════════════════════════════════════════════════════════════════════
EOF

[ -n "$DOMAIN" ] && echo "Domain: $DOMAIN" >> "$SUMMARY_FILE"
[ -n "$EMAIL" ] && echo "Email: $EMAIL" >> "$SUMMARY_FILE"
echo "Total IPs Scanned: ${#IPS[@]}" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "IP Addresses:" >> "$SUMMARY_FILE"
for IP in "${IPS[@]}"; do
    echo "  - $IP" >> "$SUMMARY_FILE"
done

cat << EOF >> "$SUMMARY_FILE"

═══════════════════════════════════════════════════════════════════════════
TOOLS & APIs USED
═══════════════════════════════════════════════════════════════════════════
theHarvester APIs (domain recon):
  - Shodan, VirusTotal, Hunter.io, SecurityTrails
  - WhoisXML, ZoomEye, Censys, FullHunt, IntelX

Additional APIs (this script):
  - CriminalIP      (IP threat intelligence)
  - HaveIBeenPwned  (Breach & paste data)
  - LeakLookup      (Credential leak search)
  - Netlas          (Internet scan data)
  - ipinfo.io       (IP geolocation)
  - ip-api.com      (IP intelligence + proxy detection)

Scanning Tools:
  - Nmap            (Port scanning, service detection, vuln scripts)
  - RustScan        (Fast port discovery)
  - WhatWeb         (Web technology fingerprinting)
  - Nuclei          (Vulnerability scanning)
  - Dirsearch       (Directory enumeration)

EOF

# Add theHarvester results summary
if [ -f "$OUTPUT_DIR/1_theharvester.txt" ]; then
    cat << EOF >> "$SUMMARY_FILE"
═══════════════════════════════════════════════════════════════════════════
THEHARVESTER RESULTS
═══════════════════════════════════════════════════════════════════════════
$(cat "$OUTPUT_DIR/1_theharvester.txt" 2>/dev/null)

EOF
fi

# Add each IP's summary
for IP in "${IPS[@]}"; do
    IP_SAFE=$(echo "$IP" | tr ':' '_')
    if [ -f "$OUTPUT_DIR/ips/$IP_SAFE/SUMMARY.txt" ]; then
        echo "" >> "$SUMMARY_FILE"
        cat "$OUTPUT_DIR/ips/$IP_SAFE/SUMMARY.txt" >> "$SUMMARY_FILE"
    fi
done

# Add email summary
if [ -f "$OUTPUT_DIR/email/SUMMARY.txt" ]; then
    echo "" >> "$SUMMARY_FILE"
    cat "$OUTPUT_DIR/email/SUMMARY.txt" >> "$SUMMARY_FILE"
fi

cat << EOF >> "$SUMMARY_FILE"

═══════════════════════════════════════════════════════════════════════════
RECOMMENDED REPORTING ACTIONS
═══════════════════════════════════════════════════════════════════════════
1. Hosting Provider Abuse Team (check ipinfo.io for provider)
   - Hostinger: abuse@hostinger.com
   - DigitalOcean: abuse@digitalocean.com
   - AWS: abuse@amazonaws.com

2. Regional IP Registry:
   - ARIN (North America): abuse@arin.net
   - LACNIC (Latin America): abuse@lacnic.net
   - RIPE (Europe): abuse@ripe.net

3. Law Enforcement:
   - FBI IC3: ic3.gov
   - FTC: reportfraud.ftc.gov

4. Platform Reporting:
   - Google Safe Browsing: safebrowsing.google.com/safebrowsing/report_phish/
   - AbuseIPDB: abuseipdb.com

5. Domain Registrar (check WHOIS for registrar abuse contact)

═══════════════════════════════════════════════════════════════════════════
OUTPUT DIRECTORY STRUCTURE
═══════════════════════════════════════════════════════════════════════════
$OUTPUT_DIR/
├── MASTER_SUMMARY.txt          (This report)
├── audit_log.txt               (Full execution log)
├── 1_theharvester.txt          (theHarvester results)
├── domain/                     (Domain-level scans)
│   ├── leaklookup.json
│   ├── whatweb_*.txt/json
│   ├── nuclei_results.txt
│   └── dirsearch_results.txt
├── email/                      (Email investigation)
│   ├── SUMMARY.txt
│   ├── hibp_breaches.json
│   ├── hibp_pastes.json
│   └── leaklookup.json
└── ips/                        (Per-IP results)
EOF

for IP in "${IPS[@]}"; do
    IP_SAFE=$(echo "$IP" | tr ':' '_')
    cat << EOF >> "$SUMMARY_FILE"
    └── $IP_SAFE/
        ├── SUMMARY.txt
        ├── ipinfo.json
        ├── ipapi.json
        ├── criminalip.json
        ├── netlas.json
        ├── leaklookup.json
        ├── whois_arin.txt
        ├── nmap_*.txt
        ├── rustscan.txt
        ├── whatweb.txt/json
        ├── nuclei_results.txt
        └── dirsearch_results.txt
EOF
done

cat << EOF >> "$SUMMARY_FILE"

═══════════════════════════════════════════════════════════════════════════
                              END OF REPORT
═══════════════════════════════════════════════════════════════════════════
EOF

log "${GREEN}[+] Master summary: $SUMMARY_FILE${NC}"


#############################################
# Complete
#############################################
section "Investigation Complete!"

log "All results saved to: ${GREEN}$OUTPUT_DIR/${NC}"
log ""
log "Quick commands:"
log "  ${CYAN}cat $OUTPUT_DIR/MASTER_SUMMARY.txt${NC}"
log "  ${CYAN}ls -la $OUTPUT_DIR/ips/${NC}"
log ""
log "IPs scanned: ${#IPS[@]}"
for IP in "${IPS[@]}"; do
    IP_SAFE=$(echo "$IP" | tr ':' '_')
    log "  - $IP -> $OUTPUT_DIR/ips/$IP_SAFE/"
done
log ""
log "${GREEN}Investigation completed: $(date)${NC}"
