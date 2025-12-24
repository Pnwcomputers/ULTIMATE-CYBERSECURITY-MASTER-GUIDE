#!/bin/bash

#############################################
#  EMAIL OSINT INVESTIGATION SCRIPT v1.0
#  Template Version
#  
#  Usage: ./email_audit.sh -e <email>
#         ./email_audit.sh -e <email1,email2,email3>
#         ./email_audit.sh -f <file_with_emails>
#
#  Dependencies:
#    sudo apt install jq curl
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
ORG_NAME="OSINT Framework"
ORG_TAG="INVESTIGATION-TOOL"

#############################################
# API CONFIGURATION
#############################################
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_CONFIG="${CONFIG_DIR}/api_keys.conf"

# API keys are loaded from the config file or environment.
HIBP_KEY="${HIBP_KEY:-${HAVEIBEENPWNED_API_KEY:-}}"
HUNTER_KEY="${HUNTER_KEY:-${HUNTER_API_KEY:-}}"
LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-}}"
INTELX_KEY="${INTELX_KEY:-${INTELX_API_KEY:-}}"

load_api_keys() {
    if [ -f "$API_CONFIG" ]; then
        # shellcheck disable=SC1090
        source "$API_CONFIG"
        HIBP_KEY="${HIBP_KEY:-${HAVEIBEENPWNED_API_KEY:-${hibp_key:-${haveibeenpwned_api_key:-}}}}"
        HUNTER_KEY="${HUNTER_KEY:-${HUNTER_API_KEY:-${hunter_key:-${hunter_api_key:-}}}}"
        LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-${leaklookup_key:-${leaklookup_api_key:-}}}}"
        INTELX_KEY="${INTELX_KEY:-${INTELX_API_KEY:-${intelx_key:-${intelx_api_key:-}}}}"
    else
        echo -e "${YELLOW}[!] API config not found at $API_CONFIG. Set keys via environment variables.${NC}"
    fi
}

#############################################
# Variables
#############################################
EMAILS=()
EMAIL_FILE=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
QUICK_MODE=false
PARALLEL_MODE=false
MAX_PARALLEL=3

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║              EMAIL OSINT INVESTIGATION SCRIPT v1.0                 ║"
    echo "║                 [ORGANIZATION/RESOURCES NAME]                      ║"
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║  APIs: HaveIBeenPwned | Hunter.io | EmailRep | LeakLookup          ║"
    echo "║         IntelX | Gravatar | Social Media Checks                    ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Usage
usage() {
    echo "Usage: $0 -e <email> [options]"
    echo "       $0 -e <email1,email2,email3> [options]"
    echo "       $0 -f <file_with_emails> [options]"
    echo ""
    echo "Options:"
    echo "  -e    Target email address(es), comma-separated"
    echo "  -f    File containing emails (one per line)"
    echo "  -q    Quick mode (skip slow lookups)"
    echo "  -p    Parallel mode (investigate multiple emails simultaneously)"
    echo "  -h    Show this help message"
    echo ""
    exit 1
}

# Check dependencies
check_dependencies() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    
    MISSING=()
    command -v curl &> /dev/null || MISSING+=("curl")
    command -v jq &> /dev/null || MISSING+=("jq")
    command -v md5sum &> /dev/null || MISSING+=("coreutils")
    
    if [ ${#MISSING[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required: ${MISSING[*]}${NC}"
        echo -e "${RED}[!] Install: sudo apt install ${MISSING[*]}${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] All dependencies found!${NC}"
    echo ""
}

# Parse arguments
while getopts "e:f:qph" opt; do
    case $opt in
        e) IFS=',' read -ra EMAILS <<< "$OPTARG" ;;
        f) EMAIL_FILE="$OPTARG" ;;
        q) QUICK_MODE=true ;;
        p) PARALLEL_MODE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Load emails from file
if [ -n "$EMAIL_FILE" ]; then
    if [ -f "$EMAIL_FILE" ]; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            if [[ "$line" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
                EMAILS+=("$line")
            else
                echo -e "${YELLOW}[!] Skipping invalid email: $line${NC}"
            fi
        done < "$EMAIL_FILE"
    else
        echo -e "${RED}[!] Error: File $EMAIL_FILE not found${NC}"
        exit 1
    fi
fi

# Validate input
if [ ${#EMAILS[@]} -eq 0 ]; then
    echo -e "${RED}[!] Error: Provide email(s) (-e) or file (-f)${NC}"
    usage
fi

# Create output directory
EMAIL_SAFE=$(echo "${EMAILS[0]}" | tr '@.' '_')
OUTPUT_DIR="email_audit_${EMAIL_SAFE}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

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

email_section() {
    log ""
    log "${CYAN}───────────────────────────────────────────────────────────────${NC}"
    log "${GREEN}  Email: $1${NC}"
    log "${CYAN}───────────────────────────────────────────────────────────────${NC}"
}

pretty_json() {
    jq '.' 2>/dev/null || cat
}

# Start
print_banner
check_dependencies

log "Investigation started: $(date)"
log "Output directory: $OUTPUT_DIR"
log "Target Emails: ${EMAILS[*]}"
log "Quick Mode: $QUICK_MODE | Parallel Mode: $PARALLEL_MODE"
log ""

#############################################
# API FUNCTIONS
#############################################

load_api_keys

require_api_key() {
    local KEY_NAME="$1"
    local DISPLAY_NAME="$2"
    local VALUE="${!KEY_NAME}"

    if [ -z "$VALUE" ]; then
        log "${YELLOW}[!] Missing API key for ${DISPLAY_NAME}. Skip this lookup or set ${KEY_NAME}.${NC}"
        return 1
    fi

    return 0
}

get_domain() {
    echo "$1" | cut -d'@' -f2
}

get_username() {
    echo "$1" | cut -d'@' -f1
}

# HaveIBeenPwned - Breach check
query_hibp_breaches() {
    local EMAIL="$1"
    local OUTPUT="$2"

    if ! require_api_key "HIBP_KEY" "HaveIBeenPwned"; then
        return
    fi

    log "${GREEN}    [*] Checking HaveIBeenPwned for breaches...${NC}"
    
    HTTP_CODE=$(curl -s -w "%{http_code}" -o "$OUTPUT" \
        "https://haveibeenpwned.com/api/v3/breachedaccount/$EMAIL?truncateResponse=false" \
        -H "hibp-api-key: $HIBP_KEY" \
        -H "user-agent: ${ORG_TAG}-Framework")
    
    if [ "$HTTP_CODE" = "200" ] && [ -s "$OUTPUT" ]; then
        BREACH_COUNT=$(jq '. | length' "$OUTPUT" 2>/dev/null || echo "0")
        log "${RED}    [!] BREACHED! Found in $BREACH_COUNT breach(es)!${NC}"
        
        jq -r '.[] | "        - \(.Name) (\(.BreachDate))"' "$OUTPUT" 2>/dev/null | head -10 | while read line; do
            log "${RED}$line${NC}"
        done
        
        TOTAL=$(jq '. | length' "$OUTPUT" 2>/dev/null)
        if [ "$TOTAL" -gt 10 ] 2>/dev/null; then
            log "${RED}        ... and $((TOTAL - 10)) more${NC}"
        fi
    elif [ "$HTTP_CODE" = "404" ]; then
        log "${GREEN}    [+] No breaches found${NC}"
        echo '{"status": "clean", "breaches": []}' > "$OUTPUT"
    else
        log "${YELLOW}    [!] HIBP API error (HTTP $HTTP_CODE)${NC}"
    fi
}

# HaveIBeenPwned - Pastes check
query_hibp_pastes() {
    local EMAIL="$1"
    local OUTPUT="$2"

    if ! require_api_key "HIBP_KEY" "HaveIBeenPwned"; then
        return
    fi

    log "${GREEN}    [*] Checking HaveIBeenPwned for pastes...${NC}"
    
    HTTP_CODE=$(curl -s -w "%{http_code}" -o "$OUTPUT" \
        "https://haveibeenpwned.com/api/v3/pasteaccount/$EMAIL" \
        -H "hibp-api-key: $HIBP_KEY" \
        -H "user-agent: ${ORG_TAG}-Framework")
    
    if [ "$HTTP_CODE" = "200" ] && [ -s "$OUTPUT" ]; then
        PASTE_COUNT=$(jq '. | length' "$OUTPUT" 2>/dev/null || echo "0")
        log "${RED}    [!] Found in $PASTE_COUNT paste(s)!${NC}"
    elif [ "$HTTP_CODE" = "404" ]; then
        log "${GREEN}    [+] No pastes found${NC}"
        echo '{"status": "clean", "pastes": []}' > "$OUTPUT"
    else
        log "${YELLOW}    [!] HIBP Pastes API error (HTTP $HTTP_CODE)${NC}"
    fi
}

# Hunter.io - Email verification
query_hunter_verify() {
    local EMAIL="$1"
    local OUTPUT="$2"

    if ! require_api_key "HUNTER_KEY" "Hunter.io"; then
        return
    fi

    log "${GREEN}    [*] Verifying email with Hunter.io...${NC}"
    
    curl -s "https://api.hunter.io/v2/email-verifier?email=$EMAIL&api_key=$HUNTER_KEY" \
        | pretty_json > "$OUTPUT" 2>&1
    
    if [ -s "$OUTPUT" ]; then
        STATUS=$(jq -r '.data.status // "unknown"' "$OUTPUT" 2>/dev/null)
        SCORE=$(jq -r '.data.score // "unknown"' "$OUTPUT" 2>/dev/null)
        DELIVERABLE=$(jq -r '.data.result // "unknown"' "$OUTPUT" 2>/dev/null)
        
        if [ "$STATUS" != "unknown" ] && [ "$STATUS" != "null" ]; then
            log "${GREEN}    [+] Hunter.io: Status=$STATUS, Score=$SCORE, Deliverable=$DELIVERABLE${NC}"
        fi
    fi
}

# Hunter.io - Find related emails from domain
query_hunter_domain() {
    local DOMAIN="$1"
    local OUTPUT="$2"

    if ! require_api_key "HUNTER_KEY" "Hunter.io"; then
        return
    fi

    log "${GREEN}    [*] Searching Hunter.io for related emails on $DOMAIN...${NC}"
    
    curl -s "https://api.hunter.io/v2/domain-search?domain=$DOMAIN&api_key=$HUNTER_KEY" \
        | pretty_json > "$OUTPUT" 2>&1
    
    if [ -s "$OUTPUT" ]; then
        EMAIL_COUNT=$(jq -r '.meta.results // 0' "$OUTPUT" 2>/dev/null)
        if [ "$EMAIL_COUNT" -gt 0 ] 2>/dev/null; then
            log "${GREEN}    [+] Found $EMAIL_COUNT related email(s) on domain${NC}"
        fi
    fi
}

# EmailRep.io - Email reputation
query_emailrep() {
    local EMAIL="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Checking EmailRep.io reputation...${NC}"
    
    curl -s "https://emailrep.io/$EMAIL" \
        -H "User-Agent: ${ORG_TAG}-Framework" \
        | pretty_json > "$OUTPUT" 2>&1
    
    if [ -s "$OUTPUT" ]; then
        REPUTATION=$(jq -r '.reputation // "unknown"' "$OUTPUT" 2>/dev/null)
        SUSPICIOUS=$(jq -r '.suspicious // "unknown"' "$OUTPUT" 2>/dev/null)
        MALICIOUS=$(jq -r '.details.malicious_activity // false' "$OUTPUT" 2>/dev/null)
        SPAM=$(jq -r '.details.spam // false' "$OUTPUT" 2>/dev/null)
        
        if [ "$REPUTATION" != "unknown" ] && [ "$REPUTATION" != "null" ]; then
            log "${GREEN}    [+] EmailRep: Reputation=$REPUTATION, Suspicious=$SUSPICIOUS${NC}"
            
            if [ "$MALICIOUS" = "true" ]; then
                log "${RED}    [!] EmailRep: MALICIOUS ACTIVITY DETECTED${NC}"
            fi
            if [ "$SPAM" = "true" ]; then
                log "${YELLOW}    [!] EmailRep: Flagged as SPAM${NC}"
            fi
        fi
    fi
}

# LeakLookup - Credential leak search
query_leaklookup() {
    local EMAIL="$1"
    local OUTPUT="$2"

    if ! require_api_key "LEAKLOOKUP_KEY" "LeakLookup"; then
        return
    fi

    log "${GREEN}    [*] Checking LeakLookup for credential leaks...${NC}"
    
    curl -s "https://leak-lookup.com/api/search" \
        -d "key=$LEAKLOOKUP_KEY&type=email_address&query=$EMAIL" \
        | pretty_json > "$OUTPUT" 2>&1
    
    if [ -s "$OUTPUT" ]; then
        ERROR=$(jq -r '.error // "none"' "$OUTPUT" 2>/dev/null)
        if [ "$ERROR" = "false" ] || [ "$ERROR" = "none" ]; then
            MESSAGE=$(jq -r '.message // ""' "$OUTPUT" 2>/dev/null)
            if [ "$MESSAGE" != "Not found" ] && [ -n "$MESSAGE" ]; then
                log "${RED}    [!] LeakLookup: Credentials found in leaks!${NC}"
            else
                log "${GREEN}    [+] LeakLookup: No credential leaks found${NC}"
            fi
        fi
    fi
}

# IntelX - Intelligence search
query_intelx() {
    local EMAIL="$1"
    local OUTPUT="$2"

    if ! require_api_key "INTELX_KEY" "IntelX"; then
        return
    fi

    log "${GREEN}    [*] Searching IntelX...${NC}"
    
    SEARCH_RESPONSE=$(curl -s "https://2.intelx.io/phonebook/search" \
        -H "x-key: $INTELX_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"term\":\"$EMAIL\",\"maxresults\":100,\"media\":0,\"target\":1}")
    
    SEARCH_ID=$(echo "$SEARCH_RESPONSE" | jq -r '.id // empty' 2>/dev/null)
    
    if [ -n "$SEARCH_ID" ]; then
        sleep 2
        curl -s "https://2.intelx.io/phonebook/search/result?id=$SEARCH_ID" \
            -H "x-key: $INTELX_KEY" | pretty_json > "$OUTPUT" 2>&1
        
        if [ -s "$OUTPUT" ]; then
            RESULT_COUNT=$(jq -r '.selectors | length // 0' "$OUTPUT" 2>/dev/null)
            if [ "$RESULT_COUNT" -gt 0 ] 2>/dev/null; then
                log "${YELLOW}    [!] IntelX: Found $RESULT_COUNT related record(s)${NC}"
            else
                log "${GREEN}    [+] IntelX: No additional records found${NC}"
            fi
        fi
    else
        log "${YELLOW}    [!] IntelX search failed${NC}"
        echo '{"error": "search failed"}' > "$OUTPUT"
    fi
}

# Gravatar check
query_gravatar() {
    local EMAIL="$1"
    local OUTPUT_DIR="$2"
    log "${GREEN}    [*] Checking Gravatar...${NC}"
    
    EMAIL_LOWER=$(echo -n "$EMAIL" | tr '[:upper:]' '[:lower:]')
    HASH=$(echo -n "$EMAIL_LOWER" | md5sum | cut -d' ' -f1)
    
    GRAVATAR_URL="https://www.gravatar.com/avatar/$HASH?d=404"
    PROFILE_URL="https://www.gravatar.com/$HASH.json"
    
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$GRAVATAR_URL")
    
    if [ "$HTTP_CODE" = "200" ]; then
        log "${GREEN}    [+] Gravatar avatar found!${NC}"
        curl -s "$GRAVATAR_URL" -o "$OUTPUT_DIR/gravatar_avatar.jpg" 2>/dev/null
        echo "{\"has_avatar\": true, \"avatar_url\": \"$GRAVATAR_URL\", \"hash\": \"$HASH\"}" > "$OUTPUT_DIR/gravatar.json"
        
        curl -s "$PROFILE_URL" | pretty_json > "$OUTPUT_DIR/gravatar_profile.json" 2>&1
        
        if [ -s "$OUTPUT_DIR/gravatar_profile.json" ]; then
            DISPLAY_NAME=$(jq -r '.entry[0].displayName // empty' "$OUTPUT_DIR/gravatar_profile.json" 2>/dev/null)
            if [ -n "$DISPLAY_NAME" ]; then
                log "${GREEN}    [+] Gravatar display name: $DISPLAY_NAME${NC}"
            fi
        fi
    else
        log "${GREEN}    [+] No Gravatar found${NC}"
        echo "{\"has_avatar\": false, \"hash\": \"$HASH\"}" > "$OUTPUT_DIR/gravatar.json"
    fi
}

# Check common social media
check_social_media() {
    local EMAIL="$1"
    local USERNAME=$(get_username "$EMAIL")
    local OUTPUT="$2"
    
    log "${GREEN}    [*] Checking social media presence...${NC}"
    
    FOUND_SERVICES=()
    
    # GitHub
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://api.github.com/users/$USERNAME")
    if [ "$HTTP_CODE" = "200" ]; then
        FOUND_SERVICES+=("GitHub")
        log "${GREEN}        [+] GitHub: https://github.com/$USERNAME${NC}"
    fi
    
    # Twitter/X
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -L "https://twitter.com/$USERNAME")
    if [ "$HTTP_CODE" = "200" ]; then
        FOUND_SERVICES+=("Twitter")
        log "${GREEN}        [+] Twitter: https://twitter.com/$USERNAME (verify manually)${NC}"
    fi
    
    # Instagram
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -L "https://www.instagram.com/$USERNAME/")
    if [ "$HTTP_CODE" = "200" ]; then
        FOUND_SERVICES+=("Instagram")
        log "${GREEN}        [+] Instagram: https://instagram.com/$USERNAME (verify manually)${NC}"
    fi
    
    # Reddit
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://www.reddit.com/user/$USERNAME/about.json")
    if [ "$HTTP_CODE" = "200" ]; then
        FOUND_SERVICES+=("Reddit")
        log "${GREEN}        [+] Reddit: https://reddit.com/user/$USERNAME${NC}"
    fi
    
    echo "{\"username\": \"$USERNAME\", \"services_found\": [$(printf '"%s",' "${FOUND_SERVICES[@]}" | sed 's/,$//')]}" > "$OUTPUT"
}

check_domain_dns() {
    local DOMAIN="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Checking domain DNS records...${NC}"
    {
        echo "=== MX Records ==="
        dig +short MX "$DOMAIN" 2>/dev/null || echo "No MX records"
        echo ""
        echo "=== SPF Record ==="
        dig +short TXT "$DOMAIN" 2>/dev/null | grep -i spf || echo "No SPF record"
        echo ""
        echo "=== DMARC Record ==="
        dig +short TXT "_dmarc.$DOMAIN" 2>/dev/null || echo "No DMARC record"
        echo ""
        echo "=== A Record ==="
        dig +short A "$DOMAIN" 2>/dev/null || echo "No A record"
    } > "$OUTPUT" 2>&1
}

check_domain_whois() {
    local DOMAIN="$1"
    local OUTPUT="$2"
    log "${GREEN}    [*] Running WHOIS on domain...${NC}"
    if command -v whois &> /dev/null; then
        whois "$DOMAIN" > "$OUTPUT" 2>&1
    else
        log "${YELLOW}    [!] whois not installed${NC}"
        echo "whois not installed" > "$OUTPUT"
    fi
}

#############################################
# INVESTIGATE SINGLE EMAIL
#############################################
investigate_email() {
    local EMAIL="$1"
    local EMAIL_SAFE=$(echo "$EMAIL" | tr '@.' '_')
    local EMAIL_DIR="$OUTPUT_DIR/$EMAIL_SAFE"
    mkdir -p "$EMAIL_DIR"
    
    email_section "$EMAIL"
    
    local DOMAIN=$(get_domain "$EMAIL")
    local USERNAME=$(get_username "$EMAIL")
    
    query_hibp_breaches "$EMAIL" "$EMAIL_DIR/hibp_breaches.json"
    sleep 2
    query_hibp_pastes "$EMAIL" "$EMAIL_DIR/hibp_pastes.json"
    sleep 1
    query_leaklookup "$EMAIL" "$EMAIL_DIR/leaklookup.json"
    sleep 1
    query_hunter_verify "$EMAIL" "$EMAIL_DIR/hunter_verify.json"
    sleep 1
    query_emailrep "$EMAIL" "$EMAIL_DIR/emailrep.json"
    sleep 1
    
    if [ "$QUICK_MODE" = false ]; then
        query_intelx "$EMAIL" "$EMAIL_DIR/intelx.json"
        sleep 1
        query_hunter_domain "$DOMAIN" "$EMAIL_DIR/hunter_domain.json"
        sleep 1
    fi
    
    query_gravatar "$EMAIL" "$EMAIL_DIR"
    sleep 1
    check_social_media "$EMAIL" "$EMAIL_DIR/social_media.json"
    check_domain_dns "$DOMAIN" "$EMAIL_DIR/domain_dns.txt"
    
    if [ "$QUICK_MODE" = false ]; then
        check_domain_whois "$DOMAIN" "$EMAIL_DIR/domain_whois.txt"
    fi
    
    # Generate Email Summary
    HIBP_BREACH_COUNT=$(jq '. | if type == "array" then length else 0 end' "$EMAIL_DIR/hibp_breaches.json" 2>/dev/null || echo 0)
    HIBP_PASTE_COUNT=$(jq '. | if type == "array" then length else 0 end' "$EMAIL_DIR/hibp_pastes.json" 2>/dev/null || echo 0)
    EMAILREP_REPUTATION=$(jq -r '.reputation // "Unknown"' "$EMAIL_DIR/emailrep.json" 2>/dev/null)
    HUNTER_STATUS=$(jq -r '.data.status // "Unknown"' "$EMAIL_DIR/hunter_verify.json" 2>/dev/null)
    HAS_GRAVATAR=$([ -f "$EMAIL_DIR/gravatar_avatar.jpg" ] && echo "Yes" || echo "No")

    cat << EOF > "$EMAIL_DIR/SUMMARY.txt"
╔═══════════════════════════════════════════════════════════════════════════╗
║                    EMAIL INVESTIGATION SUMMARY                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
Target: $EMAIL
Investigated: $(date)

Breaches: $HIBP_BREACH_COUNT | Pastes: $HIBP_PASTE_COUNT
Reputation: $EMAILREP_REPUTATION | Hunter Status: $HUNTER_STATUS | Gravatar: $HAS_GRAVATAR
EOF

    log "${GREEN}[+] Email $EMAIL investigation complete${NC}"
}

#############################################
# MAIN EXECUTION
#############################################
section "Email Investigation"

if [ "$PARALLEL_MODE" = true ] && [ ${#EMAILS[@]} -gt 1 ]; then
    log "${YELLOW}[*] Running in PARALLEL mode${NC}"
    job_count=0
    for EMAIL in "${EMAILS[@]}"; do
        investigate_email "$EMAIL" &
        job_count=$((job_count + 1))
        if [ $job_count -ge $MAX_PARALLEL ]; then
            wait -n 2>/dev/null || wait
            job_count=$((job_count - 1))
        fi
    done
    wait
else
    for EMAIL in "${EMAILS[@]}"; do
        investigate_email "$EMAIL"
    done
fi

#############################################
# Generate Master Summary Report
#############################################
section "Generating Master Summary Report"
SUMMARY_FILE="$OUTPUT_DIR/MASTER_SUMMARY.txt"

cat << EOF > "$SUMMARY_FILE"
╔═══════════════════════════════════════════════════════════════════════════╗
║                EMAIL INVESTIGATION MASTER REPORT v1.0                     ║
║                       [ORGANIZATION NAME]                                 ║
╚═══════════════════════════════════════════════════════════════════════════╝
Report Generated: $(date)
Total Emails: ${#EMAILS[@]}
EOF

for EMAIL in "${EMAILS[@]}"; do
    EMAIL_SAFE=$(echo "$EMAIL" | tr '@.' '_')
    [ -f "$OUTPUT_DIR/$EMAIL_SAFE/SUMMARY.txt" ] && cat "$OUTPUT_DIR/$EMAIL_SAFE/SUMMARY.txt" >> "$SUMMARY_FILE"
done

log "${GREEN}[+] Master summary: $SUMMARY_FILE${NC}"
section "Investigation Complete!"
