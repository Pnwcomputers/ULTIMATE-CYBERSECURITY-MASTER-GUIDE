#!/bin/bash

#############################################
#  EMAIL OSINT INVESTIGATION SCRIPT v1.0
#  Jon-Eric Pienkowski ~ PNW Computers
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
NC='\033[0m' # No Color

#############################################
# API CONFIGURATION
#############################################
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_CONFIG="${CONFIG_DIR}/api_keys.conf"

# API keys are loaded from the config file or environment.
# Support both the short variable names used by this script and the
# exported names documented in `playbook/api_keys.conf`.
HIBP_KEY="${HIBP_KEY:-${HAVEIBEENPWNED_API_KEY:-}}"
HUNTER_KEY="${HUNTER_KEY:-${HUNTER_API_KEY:-}}"
LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-}}"
INTELX_KEY="${INTELX_KEY:-${INTELX_API_KEY:-}}"
ABSTRACTAPI_EMAIL_KEY="${ABSTRACTAPI_EMAIL_KEY:-}"

load_api_keys() {
    if [ -f "$API_CONFIG" ]; then
        # shellcheck disable=SC1090
        source "$API_CONFIG"
        HIBP_KEY="${HIBP_KEY:-${HAVEIBEENPWNED_API_KEY:-${hibp_key:-${haveibeenpwned_api_key:-}}}}"
        HUNTER_KEY="${HUNTER_KEY:-${HUNTER_API_KEY:-${hunter_key:-${hunter_api_key:-}}}}"
        LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-${leaklookup_key:-${leaklookup_api_key:-}}}}"
        INTELX_KEY="${INTELX_KEY:-${INTELX_API_KEY:-${intelx_key:-${intelx_api_key:-}}}}"
        ABSTRACTAPI_EMAIL_KEY="${ABSTRACTAPI_EMAIL_KEY:-}"
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
    echo "║             EMAIL OSINT INVESTIGATION SCRIPT v1.0                  ║"
    echo "║                 Pacific Northwest Computers                        ║"
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║  APIs: HaveIBeenPwned | Hunter.io | EmailRep | LeakLookup          ║"
    echo "║        IntelX | Gravatar | Social Media Checks                     ║"
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
    echo "Examples:"
    echo "  $0 -e scammer@example.com"
    echo "  $0 -e email1@test.com,email2@test.com"
    echo "  $0 -f email_list.txt"
    echo "  $0 -e scammer@example.com -q"
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
            # Basic email validation
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

# Extract domain from email
get_domain() {
    echo "$1" | cut -d'@' -f2
}

# Extract username from email
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
        -H "user-agent: PNWC-Email-Audit")
    
    if [ "$HTTP_CODE" = "200" ] && [ -s "$OUTPUT" ]; then
        BREACH_COUNT=$(jq '. | length' "$OUTPUT" 2>/dev/null || echo "0")
        log "${RED}    [!] BREACHED! Found in $BREACH_COUNT breach(es)!${NC}"
        
        # List breach names and dates
        jq -r '.[] | "        - \(.Name) (\(.BreachDate))"' "$OUTPUT" 2>/dev/null | head -10 | while read -r line; do
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
        -H "user-agent: PNWC-Email-Audit")
    
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

# AbstractAPI - Email validation
query_abstractapi_email() {
    local EMAIL="$1"
    local OUTPUT="$2"

    if [ -z "$ABSTRACTAPI_EMAIL_KEY" ]; then
        log "${YELLOW}    [!] ABSTRACTAPI_EMAIL_KEY not set, skipping AbstractAPI email check${NC}"
        return
    fi

    log "${GREEN}    [*] Validating email with AbstractAPI...${NC}"
    local HTTP_CODE
    HTTP_CODE=$(curl -s -w "%{http_code}" -o "$OUTPUT" \
        "https://emailvalidation.abstractapi.com/v1/?api_key=${ABSTRACTAPI_EMAIL_KEY}&email=${EMAIL}")

    if [ "$HTTP_CODE" = "200" ] && [ -s "$OUTPUT" ]; then
        local deliverability is_valid_format is_disposable is_free
        deliverability=$(jq -r '.deliverability // "UNKNOWN"' "$OUTPUT" 2>/dev/null)
        is_valid_format=$(jq -r '.is_valid_format.value // false' "$OUTPUT" 2>/dev/null)
        is_disposable=$(jq -r '.is_disposable_email.value // false' "$OUTPUT" 2>/dev/null)
        is_free=$(jq -r '.is_free_email.value // false' "$OUTPUT" 2>/dev/null)
        log "${GREEN}    [+] AbstractAPI: deliverability=${deliverability}, valid_format=${is_valid_format}, disposable=${is_disposable}, free=${is_free}${NC}"
        if [ "$is_disposable" = "true" ]; then
            log "${RED}    [!] AbstractAPI: DISPOSABLE EMAIL ADDRESS${NC}"
        fi
    else
        log "${YELLOW}    [!] AbstractAPI email API error (HTTP $HTTP_CODE)${NC}"
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
        -H "User-Agent: PNWC-Email-Audit" \
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
    
    # Start search
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
    
    # MD5 hash of lowercase email
    EMAIL_LOWER=$(echo -n "$EMAIL" | tr '[:upper:]' '[:lower:]')
    HASH=$(echo -n "$EMAIL_LOWER" | md5sum | cut -d' ' -f1)
    
    GRAVATAR_URL="https://www.gravatar.com/avatar/$HASH?d=404"
    PROFILE_URL="https://www.gravatar.com/$HASH.json"
    
    # Check if avatar exists
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$GRAVATAR_URL")
    
    if [ "$HTTP_CODE" = "200" ]; then
        log "${GREEN}    [+] Gravatar avatar found!${NC}"
        curl -s "$GRAVATAR_URL" -o "$OUTPUT_DIR/gravatar_avatar.jpg" 2>/dev/null
        echo "{\"has_avatar\": true, \"avatar_url\": \"$GRAVATAR_URL\", \"hash\": \"$HASH\"}" > "$OUTPUT_DIR/gravatar.json"
        
        # Try to get profile
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

# Check common social media / services
check_social_media() {
    local EMAIL="$1"
    local USERNAME; USERNAME=$(get_username "$EMAIL")
    local OUTPUT="$2"
    
    log "${GREEN}    [*] Checking social media presence...${NC}"
    
    FOUND_SERVICES=()
    
    # Check various services (HEAD requests to avoid loading full pages)
    # These check if username exists, not necessarily linked to email
    
    # GitHub
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://api.github.com/users/$USERNAME")
    if [ "$HTTP_CODE" = "200" ]; then
        FOUND_SERVICES+=("GitHub")
        log "${GREEN}        [+] GitHub: https://github.com/$USERNAME${NC}"
    fi
    
    # Twitter/X and Instagram always return 200 for bot traffic (redirect to login),
    # so HTTP checks produce false positives — use maigret/sherlock for these instead.
    # Leaving URL hints for manual follow-up.
    log "${YELLOW}        [~] Twitter/X: manually check https://twitter.com/$USERNAME${NC}"
    log "${YELLOW}        [~] Instagram: manually check https://instagram.com/$USERNAME${NC}"
    
    # Reddit
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://www.reddit.com/user/$USERNAME/about.json")
    if [ "$HTTP_CODE" = "200" ]; then
        FOUND_SERVICES+=("Reddit")
        log "${GREEN}        [+] Reddit: https://reddit.com/user/$USERNAME${NC}"
    fi
    
    # Create JSON output
    echo "{\"username\": \"$USERNAME\", \"services_found\": [$(printf '"%s",' "${FOUND_SERVICES[@]}" | sed 's/,$//')]}" > "$OUTPUT"
    
    if [ ${#FOUND_SERVICES[@]} -eq 0 ]; then
        log "${GREEN}    [+] No social media accounts found for username${NC}"
    fi
}

# DNS lookup for email domain
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
    
    log "${GREEN}    [+] DNS check complete${NC}"
}

# WHOIS for domain
check_domain_whois() {
    local DOMAIN="$1"
    local OUTPUT="$2"
    
    log "${GREEN}    [*] Running WHOIS on domain...${NC}"
    
    if command -v whois &> /dev/null; then
        whois "$DOMAIN" > "$OUTPUT" 2>&1
        log "${GREEN}    [+] WHOIS complete${NC}"
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
    local EMAIL_SAFE; EMAIL_SAFE=$(echo "$EMAIL" | tr '@.' '_')
    local EMAIL_DIR="$OUTPUT_DIR/$EMAIL_SAFE"
    mkdir -p "$EMAIL_DIR"

    email_section "$EMAIL"

    local DOMAIN; DOMAIN=$(get_domain "$EMAIL")
    local USERNAME; USERNAME=$(get_username "$EMAIL")
    
    log "${GREEN}[*] Domain: $DOMAIN | Username: $USERNAME${NC}"
    
    #-----------------------------------------
    # Breach & Leak Checks
    #-----------------------------------------
    log "${GREEN}[*] Running breach and leak checks...${NC}"
    
    query_hibp_breaches "$EMAIL" "$EMAIL_DIR/hibp_breaches.json"
    sleep 2  # HIBP rate limiting
    
    query_hibp_pastes "$EMAIL" "$EMAIL_DIR/hibp_pastes.json"
    sleep 1
    
    query_leaklookup "$EMAIL" "$EMAIL_DIR/leaklookup.json"
    sleep 1
    
    #-----------------------------------------
    # Email Verification & Reputation
    #-----------------------------------------
    log "${GREEN}[*] Checking email verification and reputation...${NC}"
    
    query_hunter_verify "$EMAIL" "$EMAIL_DIR/hunter_verify.json"
    sleep 1

    query_abstractapi_email "$EMAIL" "$EMAIL_DIR/abstractapi_email.json"
    sleep 1

    query_emailrep "$EMAIL" "$EMAIL_DIR/emailrep.json"
    sleep 1
    
    #-----------------------------------------
    # Intelligence Searches
    #-----------------------------------------
    if [ "$QUICK_MODE" = false ]; then
        log "${GREEN}[*] Running intelligence searches...${NC}"
        
        query_intelx "$EMAIL" "$EMAIL_DIR/intelx.json"
        sleep 1
        
        query_hunter_domain "$DOMAIN" "$EMAIL_DIR/hunter_domain.json"
        sleep 1
    fi
    
    #-----------------------------------------
    # Profile Discovery
    #-----------------------------------------
    log "${GREEN}[*] Searching for associated profiles...${NC}"
    
    query_gravatar "$EMAIL" "$EMAIL_DIR"
    sleep 1
    
    check_social_media "$EMAIL" "$EMAIL_DIR/social_media.json"
    
    #-----------------------------------------
    # Domain Checks
    #-----------------------------------------
    log "${GREEN}[*] Checking email domain...${NC}"
    
    check_domain_dns "$DOMAIN" "$EMAIL_DIR/domain_dns.txt"
    
    if [ "$QUICK_MODE" = false ]; then
        check_domain_whois "$DOMAIN" "$EMAIL_DIR/domain_whois.txt"
    fi
    
    #-----------------------------------------
    # Generate Email Summary
    #-----------------------------------------
    log "${GREEN}[*] Generating email summary...${NC}"
    
    # Extract key findings
    HIBP_BREACH_COUNT=0
    HIBP_PASTE_COUNT=0
    EMAILREP_REPUTATION="Unknown"
    HUNTER_STATUS="Unknown"
    HAS_GRAVATAR="No"
    
    if [ -s "$EMAIL_DIR/hibp_breaches.json" ]; then
        HIBP_BREACH_COUNT=$(jq '. | if type == "array" then length else 0 end' "$EMAIL_DIR/hibp_breaches.json" 2>/dev/null) || HIBP_BREACH_COUNT=0
    fi
    
    if [ -s "$EMAIL_DIR/hibp_pastes.json" ]; then
        HIBP_PASTE_COUNT=$(jq '. | if type == "array" then length else 0 end' "$EMAIL_DIR/hibp_pastes.json" 2>/dev/null) || HIBP_PASTE_COUNT=0
    fi
    
    if [ -s "$EMAIL_DIR/emailrep.json" ]; then
        EMAILREP_REPUTATION=$(jq -r '.reputation // "Unknown"' "$EMAIL_DIR/emailrep.json" 2>/dev/null)
        [ -z "$EMAILREP_REPUTATION" ] && EMAILREP_REPUTATION="Unknown"
    fi
    
    if [ -s "$EMAIL_DIR/hunter_verify.json" ]; then
        HUNTER_STATUS=$(jq -r '.data.status // "Unknown"' "$EMAIL_DIR/hunter_verify.json" 2>/dev/null)
        [ -z "$HUNTER_STATUS" ] && HUNTER_STATUS="Unknown"
    fi
    
    if [ -s "$EMAIL_DIR/gravatar.json" ]; then
        HAS_GRAV=$(jq -r '.has_avatar // false' "$EMAIL_DIR/gravatar.json" 2>/dev/null)
        [ "$HAS_GRAV" = "true" ] && HAS_GRAVATAR="Yes"
    fi
    
    cat << EOF > "$EMAIL_DIR/SUMMARY.txt"
╔═══════════════════════════════════════════════════════════════════════════╗
║                    EMAIL INVESTIGATION SUMMARY                            ║
╚═══════════════════════════════════════════════════════════════════════════╝

Target Email: $EMAIL
Domain: $DOMAIN
Username: $USERNAME
Investigated: $(date)

═══════════════════════════════════════════════════════════════════════════
QUICK FINDINGS
═══════════════════════════════════════════════════════════════════════════
Data Breaches: $HIBP_BREACH_COUNT
Paste Dumps: $HIBP_PASTE_COUNT
Email Reputation: $EMAILREP_REPUTATION
Hunter.io Status: $HUNTER_STATUS
Has Gravatar: $HAS_GRAVATAR

═══════════════════════════════════════════════════════════════════════════
HAVEIBEENPWNED - BREACHES
═══════════════════════════════════════════════════════════════════════════
$(cat "$EMAIL_DIR/hibp_breaches.json" 2>/dev/null | jq '.' 2>/dev/null || cat "$EMAIL_DIR/hibp_breaches.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
HAVEIBEENPWNED - PASTES
═══════════════════════════════════════════════════════════════════════════
$(cat "$EMAIL_DIR/hibp_pastes.json" 2>/dev/null | jq '.' 2>/dev/null || cat "$EMAIL_DIR/hibp_pastes.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
EMAILREP.IO
═══════════════════════════════════════════════════════════════════════════
$(cat "$EMAIL_DIR/emailrep.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
HUNTER.IO VERIFICATION
═══════════════════════════════════════════════════════════════════════════
$(cat "$EMAIL_DIR/hunter_verify.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
SOCIAL MEDIA / USERNAME CHECK
═══════════════════════════════════════════════════════════════════════════
$(cat "$EMAIL_DIR/social_media.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
GRAVATAR
═══════════════════════════════════════════════════════════════════════════
$(cat "$EMAIL_DIR/gravatar.json" 2>/dev/null)
$([ -f "$EMAIL_DIR/gravatar_profile.json" ] && echo "" && cat "$EMAIL_DIR/gravatar_profile.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
DOMAIN DNS RECORDS
═══════════════════════════════════════════════════════════════════════════
$(cat "$EMAIL_DIR/domain_dns.txt" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
FILES GENERATED
═══════════════════════════════════════════════════════════════════════════
$(ls -la "$EMAIL_DIR"/)

EOF

    log "${GREEN}[+] Email $EMAIL investigation complete${NC}"
}


#############################################
# MAIN EXECUTION
#############################################
section "Email Investigation"

if [ "$PARALLEL_MODE" = true ] && [ ${#EMAILS[@]} -gt 1 ]; then
    log "${YELLOW}[*] Running in PARALLEL mode (max $MAX_PARALLEL simultaneous)${NC}"
    
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
    EMAIL_COUNT=0
    for EMAIL in "${EMAILS[@]}"; do
        EMAIL_COUNT=$((EMAIL_COUNT + 1))
        log ""
        log "${YELLOW}[*] Investigating email $EMAIL_COUNT of ${#EMAILS[@]}: $EMAIL${NC}"
        investigate_email "$EMAIL"
    done
fi


#############################################
# Generate Master Summary
#############################################
section "Generating Master Summary Report"

SUMMARY_FILE="$OUTPUT_DIR/MASTER_SUMMARY.txt"

cat << EOF > "$SUMMARY_FILE"
╔═══════════════════════════════════════════════════════════════════════════╗
║                EMAIL INVESTIGATION MASTER REPORT v1.0                     ║
║                    Pacific Northwest Computers                            ║
╚═══════════════════════════════════════════════════════════════════════════╝

Report Generated: $(date)
Investigation ID: $TIMESTAMP
Total Emails Investigated: ${#EMAILS[@]}

═══════════════════════════════════════════════════════════════════════════
EMAILS INVESTIGATED
═══════════════════════════════════════════════════════════════════════════
EOF

for EMAIL in "${EMAILS[@]}"; do
    echo "  - $EMAIL" >> "$SUMMARY_FILE"
done

cat << EOF >> "$SUMMARY_FILE"

═══════════════════════════════════════════════════════════════════════════
APIs & SOURCES QUERIED
═══════════════════════════════════════════════════════════════════════════
- HaveIBeenPwned     (Breach & paste data)
- Hunter.io          (Email verification & domain search)
- EmailRep.io        (Email reputation scoring)
- LeakLookup         (Credential leak search)
- IntelX             (Intelligence search)
- Gravatar           (Avatar & profile lookup)
- Social Media       (Username availability check)
- DNS Records        (MX, SPF, DMARC, A records)
- WHOIS              (Domain registration)

EOF

# Add each email's summary
for EMAIL in "${EMAILS[@]}"; do
    EMAIL_SAFE=$(echo "$EMAIL" | tr '@.' '_')
    if [ -f "$OUTPUT_DIR/$EMAIL_SAFE/SUMMARY.txt" ]; then
        echo "" >> "$SUMMARY_FILE"
        cat "$OUTPUT_DIR/$EMAIL_SAFE/SUMMARY.txt" >> "$SUMMARY_FILE"
    fi
done

cat << EOF >> "$SUMMARY_FILE"

═══════════════════════════════════════════════════════════════════════════
RECOMMENDED ACTIONS
═══════════════════════════════════════════════════════════════════════════
1. If breaches found - Check for password reuse across services
2. If malicious - Report to email provider abuse team
3. If spam/scam - Report to FTC (reportfraud.ftc.gov)
4. If phishing - Report to Anti-Phishing Working Group (reportphishing@apwg.org)
5. Block email in spam filters if malicious

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
log ""
log "Emails investigated: ${#EMAILS[@]}"
for EMAIL in "${EMAILS[@]}"; do
    EMAIL_SAFE=$(echo "$EMAIL" | tr '@.' '_')
    log "  - $EMAIL -> $OUTPUT_DIR/$EMAIL_SAFE/"
done
log ""
log "${GREEN}Investigation completed: $(date)${NC}"
