#!/bin/bash

#############################################
#  SCAMMER OSINT INVESTIGATION SCRIPT v3.1
#  Template Version
#  
#  Usage: ./scammer_audit.sh -d <domain>
#         ./scammer_audit.sh -i <ip1,ip2,ip3>
#         ./scammer_audit.sh -d <domain> -i <ip1,ip2>
#         ./scammer_audit.sh -f <file_with_ips>
#         ./scammer_audit.sh -e <email>
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
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

#############################################
# BRANDING CONFIGURATION
#############################################
ORG_NAME="OSINT Investigation Services"
ORG_TAG="INVESTIGATOR"

#############################################
# API KEYS (APIs NOT used by theHarvester)
#############################################
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_CONFIG="${CONFIG_DIR}/api_keys.conf"

# API keys are loaded from the config file or environment.
CRIMINALIP_KEY="${CRIMINALIP_KEY:-${CRIMINALIP_API_KEY:-}}"
HIBP_KEY="${HIBP_KEY:-${HAVEIBEENPWNED_API_KEY:-}}"
LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-}}"
NETLAS_KEY="${NETLAS_KEY:-${NETLAS_API_KEY:-}}"
PROJECTDISCOVERY_KEY="${PROJECTDISCOVERY_KEY:-${PDCP_API_KEY:-}}"

load_api_keys() {
    if [ -f "$API_CONFIG" ]; then
        # shellcheck disable=SC1090
        source "$API_CONFIG"

        CRIMINALIP_KEY="${CRIMINALIP_KEY:-${CRIMINALIP_API_KEY:-${criminalip_api_key:-}}}"
        HIBP_KEY="${HIBP_KEY:-${HAVEIBEENPWNED_API_KEY:-${hibp_key:-${haveibeenpwned_api_key:-}}}}"
        LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-${leaklookup_api_key:-}}}"
        NETLAS_KEY="${NETLAS_KEY:-${NETLAS_API_KEY:-${netlas_api_key:-}}}"
        PROJECTDISCOVERY_KEY="${PROJECTDISCOVERY_KEY:-${PDCP_API_KEY:-${pdcp_api_key:-}}}"
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
    echo "║                [ORGANIZATION/TOOL NAME HERE]                       ║"
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║  theHarvester: Shodan, VirusTotal, Hunter, SecurityTrails,         ║"
    echo "║                 WhoisXML, ZoomEye, Censys, FullHunt, IntelX        ║"
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║  Additional:    CriminalIP, HIBP, LeakLookup, Netlas, Nmap,        ║"
    echo "║                 Nuclei, Dirsearch, WhatWeb, RustScan               ║"
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
    echo "  -d    Target domain"
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

query_criminalip() {
    local IP="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Querying CriminalIP...${NC}"
    curl -s "https://api.criminalip.io/v1/ip/data?ip=$IP" \
        -H "x-api-key: $CRIMINALIP_KEY" | pretty_json > "$OUTPUT" 2>&1
    
    if command -v jq &> /dev/null && [ -s "$OUTPUT" ]; then
        SCORE=$(jq -r '.score // empty' "$OUTPUT" 2>/dev/null)
        if [ -n "$SCORE" ] && [ "$SCORE" != "null" ]; then
            log "${YELLOW}    [!] CriminalIP Score: $SCORE${NC}"
        fi
    fi
}

query_hibp() {
    local EMAIL="$1"
    local OUTPUT="$2"
    log "${GREEN}[*] Checking HaveIBeenPwned for breaches...${NC}"
    curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$EMAIL" \
        -H "hibp-api-key: $HIBP_KEY" \
        -H "user-agent: ${ORG_TAG}-Framework" | pretty_json > "$OUTPUT" 2>&1
    
    if [ -s "$OUTPUT" ] && ! grep -q "error" "$OUTPUT" && ! grep -q "404" "$OUTPUT"; then
        BREACH_COUNT=$(jq '. | length' "$OUTPUT" 2>/dev/null || echo "0")
        if [ "$BREACH_COUNT" -gt 0 ] 2>/dev/null; then
            log "${RED}    [!] BREACHED! Found in $BREACH_COUNT breach(es)!${NC}"
            jq -r '.[].Name' "$OUTPUT" 2>/dev/null | while read breach; do
                log "${RED}        - $breach${NC}"
            done
        fi
    else
        log "${GREEN}    [+] No breaches found${NC}"
    fi
}

query_hibp_pastes() {
    local EMAIL="$1"
    local OUTPUT="$2"
    log "${GREEN}[*] Checking HaveIBeenPwned for pastes...${NC}"
    curl -s "https://haveibeenpwned.com/api/v3/pasteaccount/$EMAIL" \
        -H "hibp-api-key: $HIBP_KEY" \
        -H "user-agent: ${ORG_TAG}-Framework" | pretty_json > "$OUTPUT" 2>&1
}

query_leaklookup() {
    local QUERY="$1"
    local TYPE="$2"
    local OUTPUT="$3"
    log "${GREEN}[*] Querying LeakLookup ($TYPE)...${NC}"
    curl -s "https://leak-lookup.com/api/search" \
        -d "key=$LEAKLOOKUP_KEY&type=$TYPE&query=$QUERY" | pretty_json > "$OUTPUT" 2>&1
}

query_netlas() {
    local IP="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Querying Netlas...${NC}"
    curl -s "https://app.netlas.io/api/hosts/$IP/" \
        -H "X-API-Key: $NETLAS_KEY" | pretty_json > "$OUTPUT" 2>&1
}

query_ipinfo() {
    local IP="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Querying ipinfo.io...${NC}"
    curl -s "https://ipinfo.io/$IP" | pretty_json > "$OUTPUT" 2>&1
}

query_ipapi() {
    local IP="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Querying ip-api.com...${NC}"
    curl -s "http://ip-api.com/json/$IP?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query" \
        | pretty_json > "$OUTPUT" 2>&1
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
        nuclei -update-templates -silent 2>/dev/null
        nuclei -u "$TARGET" -severity low,medium,high,critical -silent -o "$OUTPUT_FILE" 2>&1
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
        dirsearch -u "$TARGET" -e php,html,js,txt,asp,aspx,jsp,bak,old,zip -q --format plain -o "$OUTPUT_FILE" 2>&1
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
        return 0
    else
        return 1
    fi
}

#############################################
# SCAN SINGLE IP
#############################################
scan_ip() {
    local IP="$1"
    local IP_SAFE=$(echo "$IP" | tr ':' '_')
    local IP_DIR="$OUTPUT_DIR/ips/$IP_SAFE"
    mkdir -p "$IP_DIR"
    
    ip_section "$IP"
    
    query_ipinfo "$IP" "$IP_DIR/ipinfo.json"
    query_ipapi "$IP" "$IP_DIR/ipapi.json"
    
    if [[ ! "$IP" =~ ":" ]]; then
        whois -h whois.arin.net "$IP" > "$IP_DIR/whois_arin.txt" 2>&1
    fi
    
    query_criminalip "$IP" "$IP_DIR/criminalip.json"
    query_netlas "$IP" "$IP_DIR/netlas.json"
    query_leaklookup "$IP" "ip_address" "$IP_DIR/leaklookup.json"
    
    run_rustscan "$IP" "$IP_DIR/rustscan.txt"
    
    log "${GREEN}[*] Running Nmap scans...${NC}"
    nmap -sV -sC "$IP" -oN "$IP_DIR/nmap_basic.txt" -oX "$IP_DIR/nmap_basic.xml" > /dev/null 2>&1
    
    if [ "$QUICK_MODE" = false ]; then
        nmap -p- -T4 "$IP" -oN "$IP_DIR/nmap_fullport.txt" > /dev/null 2>&1
    fi
    
    nmap --script dns-nsid "$IP" -oN "$IP_DIR/nmap_dns.txt" > /dev/null 2>&1
    nmap --script vuln "$IP" -oN "$IP_DIR/nmap_vuln.txt" > /dev/null 2>&1
    
    # Banner Grab
    timeout 5 bash -c "echo '' | nc -v $IP 80" > "$IP_DIR/banner_80.txt" 2>&1
    
    # Web Recon
    PORT80_OPEN=$(grep -c "80/tcp.*open" "$IP_DIR/nmap_basic.txt" 2>/dev/null || echo 0)
    if [ "$PORT80_OPEN" -gt 0 ]; then
        WEB_TARGET="http://$IP"
        [ command -v whatweb &> /dev/null ] && whatweb "$WEB_TARGET" --log-json="$IP_DIR/whatweb.json" > "$IP_DIR/whatweb.txt" 2>&1
        run_nuclei "$WEB_TARGET" "$IP_DIR/nuclei_results.txt"
        run_dirsearch "$WEB_TARGET" "$IP_DIR/dirsearch_results.txt"
    fi
    
    log "${GREEN}[+] IP $IP scan complete${NC}"
}

#############################################
# 1) theHarvester - Domain OSINT
#############################################
if [ -n "$DOMAIN" ]; then
    section "1) theHarvester - Domain Reconnaissance"
    if command -v theHarvester &> /dev/null; then
        theHarvester -d "$DOMAIN" -b hunter,shodan,virustotal,whoisxml,zoomeye,censys,fullhunt,intelx,securityTrails 2>&1 | tee "$OUTPUT_DIR/1_theharvester.txt"
        
        if [ ${#IPS[@]} -eq 0 ]; then
            IPV4_LIST=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTPUT_DIR/1_theharvester.txt" | sort -u)
            while IFS= read -r ip; do [ -n "$ip" ] && IPS+=("$ip"); done <<< "$IPV4_LIST"
        fi
    fi
fi

#############################################
# 2) Additional Domain Intelligence
#############################################
if [ -n "$DOMAIN" ]; then
    section "2) Additional Domain Intelligence"
    query_leaklookup "$DOMAIN" "domain" "$OUTPUT_DIR/domain/leaklookup.json"
    [ command -v whatweb &> /dev/null ] && whatweb "http://$DOMAIN" --log-json="$OUTPUT_DIR/domain/whatweb_http.json" > "$OUTPUT_DIR/domain/whatweb_http.txt" 2>&1
    run_nuclei "https://$DOMAIN" "$OUTPUT_DIR/domain/nuclei_results.txt"
fi

#############################################
# 3) Email Investigation
#############################################
if [ -n "$EMAIL" ]; then
    section "3) Email Investigation"
    query_hibp "$EMAIL" "$OUTPUT_DIR/email/hibp_breaches.json"
    sleep 2
    query_hibp_pastes "$EMAIL" "$OUTPUT_DIR/email/hibp_pastes.json"
    query_leaklookup "$EMAIL" "email_address" "$OUTPUT_DIR/email/leaklookup.json"
fi

#############################################
# 4) Scan All IPs
#############################################
if [ ${#IPS[@]} -gt 0 ]; then
    section "4) Scanning ${#IPS[@]} IP Address(es)"
    if [ "$PARALLEL_MODE" = true ]; then
        job_count=0
        for IP in "${IPS[@]}"; do
            scan_ip "$IP" &
            job_count=$((job_count + 1))
            if [ $job_count -ge $MAX_PARALLEL ]; then
                wait -n 2>/dev/null || wait
                job_count=$((job_count - 1))
            fi
        done
        wait
    else
        for IP in "${IPS[@]}"; do
            scan_ip "$IP"
        done
    fi
fi

#############################################
# 6) Generate Master Summary
#############################################
section "6) Generating Master Summary Report"
SUMMARY_FILE="$OUTPUT_DIR/MASTER_SUMMARY.txt"

cat << EOF > "$SUMMARY_FILE"
╔═══════════════════════════════════════════════════════════════════════════╗
║               SCAMMER INVESTIGATION MASTER REPORT v3.1                    ║
║                       [ORGANIZATION NAME]                                 ║
╚═══════════════════════════════════════════════════════════════════════════╝
Report Generated: $(date)
EOF

log "${GREEN}[+] Master summary: $SUMMARY_FILE${NC}"
section "Investigation Complete!"
