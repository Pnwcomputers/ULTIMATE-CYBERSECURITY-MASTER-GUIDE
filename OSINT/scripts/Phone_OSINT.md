#!/bin/bash

#############################################
#  PHONE NUMBER OSINT INVESTIGATION SCRIPT v1.0
#  Jon-Eric Pienkowkski ~ Pacific Northwest Computers (PNWC)
#  
#  Usage: ./phone_audit.sh -p <phone_number>
#         ./phone_audit.sh -p <phone1,phone2,phone3>
#         ./phone_audit.sh -f <file_with_phones>
#
#  Phone format: Include country code (e.g., +1234567890 or 1234567890)
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
# API KEYS
#############################################
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_CONFIG="${CONFIG_DIR}/api_keys.conf"

# API keys are loaded from the config file or environment. Support both the
# short variable names used by this script and the exported names documented in
# `playbook/api_keys.conf`.
NUMVERIFY_KEY="${NUMVERIFY_KEY:-${NUMVERIFY_API_KEY:-}}"
VERIPHONE_KEY="${VERIPHONE_KEY:-${VERIPHONE_API_KEY:-}}"
ABSTRACTAPI_KEY="${ABSTRACTAPI_KEY:-${abstractapi_key:-}}"
INTELX_KEY="${INTELX_KEY:-${INTELX_API_KEY:-}}"
LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-}}"

# Truecaller (requires special access)
# TRUECALLER_KEY=""

load_api_keys() {
    if [ -f "$API_CONFIG" ]; then
        # shellcheck disable=SC1090
        source "$API_CONFIG"

        NUMVERIFY_KEY="${NUMVERIFY_KEY:-${NUMVERIFY_API_KEY:-${numverify_api_key:-}}}"
        VERIPHONE_KEY="${VERIPHONE_KEY:-${VERIPHONE_API_KEY:-${veriphone_api_key:-}}}"
        ABSTRACTAPI_KEY="${ABSTRACTAPI_KEY:-${abstractapi_key:-}}"
        INTELX_KEY="${INTELX_KEY:-${INTELX_API_KEY:-${intelx_api_key:-}}}"
        LEAKLOOKUP_KEY="${LEAKLOOKUP_KEY:-${LEAKLOOKUP_API_KEY:-${leaklookup_api_key:-}}}"
    else
        echo -e "${YELLOW}[!] API config not found at $API_CONFIG. Set keys via environment variables.${NC}" >&2
    fi
}

#############################################
# Variables
#############################################
PHONES=()
PHONE_FILE=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
QUICK_MODE=false
PARALLEL_MODE=false
MAX_PARALLEL=3

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║          PHONE NUMBER OSINT INVESTIGATION SCRIPT v1.0              ║"
    echo "║                 Pacific Northwest Computers                        ║"
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║  APIs: NumVerify | Veriphone | IntelX | LeakLookup                 ║"
    echo "║        Carrier Lookup | Phone Format Validation                    ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Usage
usage() {
    echo "Usage: $0 -p <phone_number> [options]"
    echo "       $0 -p <phone1,phone2,phone3> [options]"
    echo "       $0 -f <file_with_phones> [options]"
    echo ""
    echo "Options:"
    echo "  -p    Target phone number(s), comma-separated"
    echo "        Format: Include country code (e.g., +19835551234 or 19835551234)"
    echo "  -f    File containing phone numbers (one per line)"
    echo "  -q    Quick mode (skip slow lookups)"
    echo "  -P    Parallel mode (investigate multiple numbers simultaneously)"
    echo "  -h    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -p +19835551234"
    echo "  $0 -p 19835551234,19835555678"
    echo "  $0 -f phone_list.txt"
    echo "  $0 -p +19835551234 -q"
    exit 1
}

# Check dependencies
check_dependencies() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    
    MISSING=()
    command -v curl &> /dev/null || MISSING+=("curl")
    command -v jq &> /dev/null || MISSING+=("jq")
    
    if [ ${#MISSING[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required: ${MISSING[*]}${NC}"
        echo -e "${RED}[!] Install: sudo apt install ${MISSING[*]}${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] All dependencies found!${NC}"
    echo ""
}

# Normalize phone number (remove special chars, ensure format)
normalize_phone() {
    local PHONE="$1"
    # Remove +, -, (, ), spaces
    echo "$PHONE" | tr -d '+−()-. ' | sed 's/^00//'
}

# Extract country code (basic - assumes US +1 if 10 digits)
get_country_code() {
    local PHONE="$1"
    local NORMALIZED=$(normalize_phone "$PHONE")
    local LEN=${#NORMALIZED}
    
    if [ "$LEN" -eq 10 ]; then
        echo "1"  # Assume US
    elif [ "$LEN" -eq 11 ] && [[ "$NORMALIZED" == 1* ]]; then
        echo "1"  # US with country code
    elif [ "$LEN" -gt 10 ]; then
        # Try to extract country code (first 1-3 digits)
        echo "${NORMALIZED:0:$((LEN-10))}"
    else
        echo "unknown"
    fi
}

# Get national number (without country code)
get_national_number() {
    local PHONE="$1"
    local NORMALIZED=$(normalize_phone "$PHONE")
    local LEN=${#NORMALIZED}
    
    if [ "$LEN" -eq 10 ]; then
        echo "$NORMALIZED"
    elif [ "$LEN" -eq 11 ] && [[ "$NORMALIZED" == 1* ]]; then
        echo "${NORMALIZED:1}"
    elif [ "$LEN" -gt 10 ]; then
        echo "${NORMALIZED: -10}"
    else
        echo "$NORMALIZED"
    fi
}

# Format phone for display
format_phone() {
    local PHONE="$1"
    local NORMALIZED=$(normalize_phone "$PHONE")
    local NATIONAL=$(get_national_number "$PHONE")
    local COUNTRY=$(get_country_code "$PHONE")
    
    if [ ${#NATIONAL} -eq 10 ]; then
        echo "+$COUNTRY (${NATIONAL:0:3}) ${NATIONAL:3:3}-${NATIONAL:6:4}"
    else
        echo "+$COUNTRY $NATIONAL"
    fi
}

# Parse arguments
while getopts "p:f:qPh" opt; do
    case $opt in
        p) IFS=',' read -ra PHONES <<< "$OPTARG" ;;
        f) PHONE_FILE="$OPTARG" ;;
        q) QUICK_MODE=true ;;
        P) PARALLEL_MODE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Load phones from file
if [ -n "$PHONE_FILE" ]; then
    if [ -f "$PHONE_FILE" ]; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            PHONES+=("$line")
        done < "$PHONE_FILE"
    else
        echo -e "${RED}[!] Error: File $PHONE_FILE not found${NC}"
        exit 1
    fi
fi

# Validate input
if [ ${#PHONES[@]} -eq 0 ]; then
    echo -e "${RED}[!] Error: Provide phone number(s) (-p) or file (-f)${NC}"
    usage
fi

# Create output directory
PHONE_SAFE=$(normalize_phone "${PHONES[0]}")
OUTPUT_DIR="phone_audit_${PHONE_SAFE}_${TIMESTAMP}"
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

phone_section() {
    log ""
    log "${CYAN}───────────────────────────────────────────────────────────────${NC}"
    log "${GREEN}  Phone: $1${NC}"
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
log "Target Phones: ${PHONES[*]}"
log "Quick Mode: $QUICK_MODE | Parallel Mode: $PARALLEL_MODE"
log ""


#############################################
# API FUNCTIONS
#############################################

# NumVerify - Phone validation and carrier lookup
query_numverify() {
    local PHONE="$1"
    local OUTPUT="$2"
    local NORMALIZED=$(normalize_phone "$PHONE")
    
    log "${GREEN}    [*] Checking NumVerify...${NC}"
    
    if [ -z "$NUMVERIFY_KEY" ]; then
        log "${YELLOW}    [!] NumVerify API key not configured${NC}"
        echo '{"error": "API key not configured"}' > "$OUTPUT"
        return
    fi
    
    curl -s "http://apilayer.net/api/validate?access_key=$NUMVERIFY_KEY&number=$NORMALIZED" \
        | pretty_json > "$OUTPUT" 2>&1
    
    if [ -s "$OUTPUT" ]; then
        VALID=$(jq -r '.valid // false' "$OUTPUT" 2>/dev/null)
        CARRIER=$(jq -r '.carrier // "Unknown"' "$OUTPUT" 2>/dev/null)
        LINE_TYPE=$(jq -r '.line_type // "Unknown"' "$OUTPUT" 2>/dev/null)
        LOCATION=$(jq -r '.location // "Unknown"' "$OUTPUT" 2>/dev/null)
        
        if [ "$VALID" = "true" ]; then
            log "${GREEN}    [+] Valid number: Carrier=$CARRIER, Type=$LINE_TYPE, Location=$LOCATION${NC}"
        else
            log "${YELLOW}    [!] Number validation: Invalid or unknown${NC}"
        fi
    fi
}

# Veriphone - Phone validation
query_veriphone() {
    local PHONE="$1"
    local OUTPUT="$2"
    local NORMALIZED=$(normalize_phone "$PHONE")
    
    log "${GREEN}    [*] Checking Veriphone...${NC}"
    
    if [ -z "$VERIPHONE_KEY" ]; then
        # Veriphone has a free tier without key (limited)
        curl -s "https://api.veriphone.io/v2/verify?phone=$NORMALIZED" \
            | pretty_json > "$OUTPUT" 2>&1
    else
        curl -s "https://api.veriphone.io/v2/verify?phone=$NORMALIZED&key=$VERIPHONE_KEY" \
            | pretty_json > "$OUTPUT" 2>&1
    fi
    
    if [ -s "$OUTPUT" ]; then
        VALID=$(jq -r '.phone_valid // false' "$OUTPUT" 2>/dev/null)
        CARRIER=$(jq -r '.carrier // "Unknown"' "$OUTPUT" 2>/dev/null)
        PHONE_TYPE=$(jq -r '.phone_type // "Unknown"' "$OUTPUT" 2>/dev/null)
        COUNTRY=$(jq -r '.country // "Unknown"' "$OUTPUT" 2>/dev/null)
        
        if [ "$VALID" = "true" ]; then
            log "${GREEN}    [+] Veriphone: Valid, Carrier=$CARRIER, Type=$PHONE_TYPE, Country=$COUNTRY${NC}"
        elif [ "$VALID" != "false" ]; then
            log "${YELLOW}    [!] Veriphone: Could not validate${NC}"
        else
            log "${YELLOW}    [!] Veriphone: Invalid number${NC}"
        fi
    fi
}

# AbstractAPI Phone Validation
query_abstractapi() {
    local PHONE="$1"
    local OUTPUT="$2"
    local NORMALIZED=$(normalize_phone "$PHONE")
    
    log "${GREEN}    [*] Checking AbstractAPI...${NC}"
    
    if [ -z "$ABSTRACTAPI_KEY" ]; then
        log "${YELLOW}    [!] AbstractAPI key not configured${NC}"
        echo '{"error": "API key not configured"}' > "$OUTPUT"
        return
    fi
    
    curl -s "https://phonevalidation.abstractapi.com/v1/?api_key=$ABSTRACTAPI_KEY&phone=$NORMALIZED" \
        | pretty_json > "$OUTPUT" 2>&1
    
    if [ -s "$OUTPUT" ]; then
        VALID=$(jq -r '.valid // false' "$OUTPUT" 2>/dev/null)
        CARRIER=$(jq -r '.carrier // "Unknown"' "$OUTPUT" 2>/dev/null)
        TYPE=$(jq -r '.type // "Unknown"' "$OUTPUT" 2>/dev/null)
        
        if [ "$VALID" = "true" ]; then
            log "${GREEN}    [+] AbstractAPI: Valid, Carrier=$CARRIER, Type=$TYPE${NC}"
        fi
    fi
}

# IntelX - Intelligence search
query_intelx() {
    local PHONE="$1"
    local OUTPUT="$2"
    
    log "${GREEN}    [*] Searching IntelX...${NC}"
    
    # Format phone for search (try multiple formats)
    local NORMALIZED=$(normalize_phone "$PHONE")
    
    # Start search
    SEARCH_RESPONSE=$(curl -s "https://2.intelx.io/phonebook/search" \
        -H "x-key: $INTELX_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"term\":\"$NORMALIZED\",\"maxresults\":100,\"media\":0,\"target\":2}")
    
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
                log "${GREEN}    [+] IntelX: No records found${NC}"
            fi
        fi
    else
        log "${YELLOW}    [!] IntelX search failed${NC}"
        echo '{"error": "search failed"}' > "$OUTPUT"
    fi
}

# LeakLookup - Check if phone appears in leaks
query_leaklookup() {
    local PHONE="$1"
    local OUTPUT="$2"
    local NORMALIZED=$(normalize_phone "$PHONE")
    
    log "${GREEN}    [*] Checking LeakLookup...${NC}"
    
    curl -s "https://leak-lookup.com/api/search" \
        -d "key=$LEAKLOOKUP_KEY&type=phone&query=$NORMALIZED" \
        | pretty_json > "$OUTPUT" 2>&1
    
    if [ -s "$OUTPUT" ]; then
        ERROR=$(jq -r '.error // "none"' "$OUTPUT" 2>/dev/null)
        if [ "$ERROR" = "false" ] || [ "$ERROR" = "none" ]; then
            MESSAGE=$(jq -r '.message // ""' "$OUTPUT" 2>/dev/null)
            if [ "$MESSAGE" != "Not found" ] && [ -n "$MESSAGE" ]; then
                log "${RED}    [!] LeakLookup: Phone found in data leaks!${NC}"
            else
                log "${GREEN}    [+] LeakLookup: No leaks found${NC}"
            fi
        fi
    fi
}

# Phone number type detection (basic)
detect_phone_type() {
    local PHONE="$1"
    local OUTPUT="$2"
    local NATIONAL=$(get_national_number "$PHONE")
    
    log "${GREEN}    [*] Analyzing phone number format...${NC}"
    
    # US/Canada area code lookup (basic)
    local AREA_CODE="${NATIONAL:0:3}"
    local EXCHANGE="${NATIONAL:3:3}"
    
    # Known VoIP/Virtual prefixes (incomplete list)
    VOIP_PREFIXES=("456" "500" "521" "522" "523" "524" "525" "526" "527" "528" "529" "533" "544" "566" "577" "588")
    
    # Toll-free prefixes
    TOLLFREE_PREFIXES=("800" "833" "844" "855" "866" "877" "888")
    
    # Premium rate
    PREMIUM_PREFIXES=("900" "976")
    
    PHONE_TYPE="Unknown"
    PHONE_NOTES=""
    
    # Check toll-free
    for prefix in "${TOLLFREE_PREFIXES[@]}"; do
        if [ "$AREA_CODE" = "$prefix" ]; then
            PHONE_TYPE="Toll-Free"
            PHONE_NOTES="Toll-free numbers are often used by businesses but also by scammers"
            break
        fi
    done
    
    # Check premium
    for prefix in "${PREMIUM_PREFIXES[@]}"; do
        if [ "$AREA_CODE" = "$prefix" ]; then
            PHONE_TYPE="Premium Rate"
            PHONE_NOTES="WARNING: Premium rate numbers charge high fees. Often used in scams."
            break
        fi
    done
    
    # Check VoIP indicators
    for prefix in "${VOIP_PREFIXES[@]}"; do
        if [ "$AREA_CODE" = "$prefix" ]; then
            PHONE_TYPE="Likely VoIP/Virtual"
            PHONE_NOTES="VoIP numbers are easy to obtain anonymously"
            break
        fi
    done
    
    # 983 area code (mentioned in scam case)
    if [ "$AREA_CODE" = "983" ]; then
        PHONE_TYPE="VoIP/Virtual Number"
        PHONE_NOTES="983 is a newer area code often associated with VoIP services. Common in scam operations."
    fi
    
    # Output findings
    cat << EOF > "$OUTPUT"
{
    "phone": "$PHONE",
    "normalized": "$(normalize_phone "$PHONE")",
    "area_code": "$AREA_CODE",
    "exchange": "$EXCHANGE",
    "detected_type": "$PHONE_TYPE",
    "notes": "$PHONE_NOTES"
}
EOF

    if [ "$PHONE_TYPE" != "Unknown" ]; then
        log "${YELLOW}    [!] Type detected: $PHONE_TYPE${NC}"
        [ -n "$PHONE_NOTES" ] && log "${YELLOW}    [!] Note: $PHONE_NOTES${NC}"
    else
        log "${GREEN}    [+] Standard landline/mobile format${NC}"
    fi
}

# Area code lookup (US/Canada)
lookup_area_code() {
    local PHONE="$1"
    local OUTPUT="$2"
    local NATIONAL=$(get_national_number "$PHONE")
    local AREA_CODE="${NATIONAL:0:3}"
    
    log "${GREEN}    [*] Looking up area code $AREA_CODE...${NC}"
    
    # Query free area code API
    curl -s "https://www.randomphonenumbers.com/api/area-code/$AREA_CODE" \
        | pretty_json > "$OUTPUT" 2>&1 || true
    
    # Also try npa-nxx database (if available)
    # Fallback: use static lookup for common codes
    
    case "$AREA_CODE" in
        983) LOCATION="Eastern North Carolina (VoIP overlay)" ;;
        212) LOCATION="New York City, NY" ;;
        213) LOCATION="Los Angeles, CA" ;;
        312) LOCATION="Chicago, IL" ;;
        415) LOCATION="San Francisco, CA" ;;
        206) LOCATION="Seattle, WA" ;;
        305) LOCATION="Miami, FL" ;;
        404) LOCATION="Atlanta, GA" ;;
        713) LOCATION="Houston, TX" ;;
        972) LOCATION="Dallas, TX" ;;
        800|833|844|855|866|877|888) LOCATION="Toll-Free (Nationwide)" ;;
        900|976) LOCATION="Premium Rate" ;;
        *) LOCATION="Unknown - check carrier lookup" ;;
    esac
    
    log "${GREEN}    [+] Area Code $AREA_CODE: $LOCATION${NC}"
    
    # Append to output
    echo "{\"area_code\": \"$AREA_CODE\", \"location\": \"$LOCATION\"}" >> "$OUTPUT"
}

# Check spam databases (free sources)
check_spam_databases() {
    local PHONE="$1"
    local OUTPUT="$2"
    local NORMALIZED=$(normalize_phone "$PHONE")
    
    log "${GREEN}    [*] Checking spam databases...${NC}"
    
    SPAM_REPORTS=()
    
    # Note: Most spam lookup sites require scraping or paid API
    # These are placeholder checks - implement based on available APIs
    
    # Check if there's a website with reports (basic check)
    # In practice, you'd scrape sites like:
    # - 800notes.com
    # - whocallsme.com
    # - shouldianswer.com
    # - nomorobo.com
    
    # For now, create a placeholder
    cat << EOF > "$OUTPUT"
{
    "phone": "$NORMALIZED",
    "spam_check_note": "Manual verification recommended on spam databases",
    "recommended_sites": [
        "https://800notes.com/Phone.aspx/$NORMALIZED",
        "https://www.whocallsme.com/Phone-Number.aspx/$AREA_CODE/$EXCHANGE/$LINE",
        "https://www.shouldianswer.com/phone-number/$NORMALIZED",
        "https://www.nomorobo.com/lookup/${NORMALIZED:0:3}-${NORMALIZED:3:3}-${NORMALIZED:6:4}"
    ]
}
EOF

    log "${GREEN}    [+] Spam database links generated (manual check recommended)${NC}"
}

# Search social media by phone (limited)
search_social_by_phone() {
    local PHONE="$1"
    local OUTPUT="$2"
    local NORMALIZED=$(normalize_phone "$PHONE")
    
    log "${GREEN}    [*] Searching for social media associations...${NC}"
    
    # Note: Direct phone lookup on social media usually requires:
    # - Facebook Graph API (restricted)
    # - Paid people-search APIs
    # - Manual searching
    
    # Generate search URLs for manual investigation
    cat << EOF > "$OUTPUT"
{
    "phone": "$NORMALIZED",
    "manual_search_urls": {
        "google": "https://www.google.com/search?q=\"$NORMALIZED\"",
        "google_formatted": "https://www.google.com/search?q=\"$(format_phone "$PHONE")\"",
        "facebook": "https://www.facebook.com/search/top?q=$NORMALIZED",
        "linkedin": "https://www.linkedin.com/search/results/all/?keywords=$NORMALIZED",
        "twitter": "https://twitter.com/search?q=$NORMALIZED",
        "instagram": "https://www.google.com/search?q=site:instagram.com+\"$NORMALIZED\""
    },
    "note": "Social media phone lookup requires manual verification"
}
EOF

    log "${GREEN}    [+] Social media search URLs generated${NC}"
}

# Reverse phone lookup (using free services)
reverse_phone_lookup() {
    local PHONE="$1"
    local OUTPUT="$2"
    local NORMALIZED=$(normalize_phone "$PHONE")
    
    log "${GREEN}    [*] Attempting reverse phone lookup...${NC}"
    
    # Generate links to free reverse lookup services
    cat << EOF > "$OUTPUT"
{
    "phone": "$NORMALIZED",
    "reverse_lookup_urls": {
        "whitepages": "https://www.whitepages.com/phone/1-${NORMALIZED:0:3}-${NORMALIZED:3:3}-${NORMALIZED:6:4}",
        "truepeoplesearch": "https://www.truepeoplesearch.com/results?phoneno=$NORMALIZED",
        "fastpeoplesearch": "https://www.fastpeoplesearch.com/${NORMALIZED:0:3}-${NORMALIZED:3:3}-${NORMALIZED:6:4}",
        "spydialer": "https://www.spydialer.com/results.aspx?phone=$NORMALIZED",
        "zlookup": "https://www.zlookup.com/reverse-phone-lookup/$NORMALIZED",
        "calleridtest": "https://www.calleridtest.com/look-up-phone-number.php?number=$NORMALIZED"
    },
    "note": "Free reverse lookups have limited data. Paid services like BeenVerified or Intelius provide more details."
}
EOF

    log "${GREEN}    [+] Reverse lookup URLs generated${NC}"
}


#############################################
# INVESTIGATE SINGLE PHONE NUMBER
#############################################
investigate_phone() {
    local PHONE="$1"
    local PHONE_SAFE=$(normalize_phone "$PHONE")
    local PHONE_DIR="$OUTPUT_DIR/$PHONE_SAFE"
    mkdir -p "$PHONE_DIR"
    
    phone_section "$(format_phone "$PHONE")"
    
    local NORMALIZED=$(normalize_phone "$PHONE")
    local COUNTRY_CODE=$(get_country_code "$PHONE")
    local NATIONAL=$(get_national_number "$PHONE")
    local AREA_CODE="${NATIONAL:0:3}"
    
    log "${GREEN}[*] Normalized: $NORMALIZED | Country: +$COUNTRY_CODE | Area Code: $AREA_CODE${NC}"
    
    #-----------------------------------------
    # Phone Format Analysis
    #-----------------------------------------
    log "${GREEN}[*] Analyzing phone number...${NC}"
    
    detect_phone_type "$PHONE" "$PHONE_DIR/phone_type.json"
    lookup_area_code "$PHONE" "$PHONE_DIR/area_code.json"
    
    #-----------------------------------------
    # Phone Validation APIs
    #-----------------------------------------
    log "${GREEN}[*] Running phone validation...${NC}"
    
    query_numverify "$PHONE" "$PHONE_DIR/numverify.json"
    sleep 1
    
    query_veriphone "$PHONE" "$PHONE_DIR/veriphone.json"
    sleep 1
    
    if [ -n "$ABSTRACTAPI_KEY" ]; then
        query_abstractapi "$PHONE" "$PHONE_DIR/abstractapi.json"
        sleep 1
    fi
    
    #-----------------------------------------
    # Leak & Intelligence Checks
    #-----------------------------------------
    log "${GREEN}[*] Checking leaks and intelligence sources...${NC}"
    
    query_leaklookup "$PHONE" "$PHONE_DIR/leaklookup.json"
    sleep 1
    
    if [ "$QUICK_MODE" = false ]; then
        query_intelx "$PHONE" "$PHONE_DIR/intelx.json"
        sleep 1
    fi
    
    #-----------------------------------------
    # Spam & Reputation
    #-----------------------------------------
    log "${GREEN}[*] Checking spam databases...${NC}"
    
    check_spam_databases "$PHONE" "$PHONE_DIR/spam_databases.json"
    
    #-----------------------------------------
    # Reverse Lookup & Social Media
    #-----------------------------------------
    if [ "$QUICK_MODE" = false ]; then
        log "${GREEN}[*] Generating lookup URLs...${NC}"
        
        reverse_phone_lookup "$PHONE" "$PHONE_DIR/reverse_lookup.json"
        search_social_by_phone "$PHONE" "$PHONE_DIR/social_search.json"
    fi
    
    #-----------------------------------------
    # Generate Phone Summary
    #-----------------------------------------
    log "${GREEN}[*] Generating phone summary...${NC}"
    
    # Extract key findings
    PHONE_TYPE="Unknown"
    CARRIER="Unknown"
    LOCATION="Unknown"
    VALID="Unknown"
    LEAK_FOUND="No"
    
    if [ -s "$PHONE_DIR/phone_type.json" ]; then
        PHONE_TYPE=$(jq -r '.detected_type // "Unknown"' "$PHONE_DIR/phone_type.json" 2>/dev/null)
        [ -z "$PHONE_TYPE" ] && PHONE_TYPE="Unknown"
    fi
    
    if [ -s "$PHONE_DIR/veriphone.json" ]; then
        CARRIER=$(jq -r '.carrier // "Unknown"' "$PHONE_DIR/veriphone.json" 2>/dev/null)
        VALID=$(jq -r '.phone_valid // "Unknown"' "$PHONE_DIR/veriphone.json" 2>/dev/null)
        [ -z "$CARRIER" ] && CARRIER="Unknown"
    fi
    
    if [ -s "$PHONE_DIR/numverify.json" ]; then
        NV_CARRIER=$(jq -r '.carrier // ""' "$PHONE_DIR/numverify.json" 2>/dev/null)
        NV_LOCATION=$(jq -r '.location // ""' "$PHONE_DIR/numverify.json" 2>/dev/null)
        [ -n "$NV_CARRIER" ] && [ "$NV_CARRIER" != "null" ] && CARRIER="$NV_CARRIER"
        [ -n "$NV_LOCATION" ] && [ "$NV_LOCATION" != "null" ] && LOCATION="$NV_LOCATION"
    fi
    
    if [ -s "$PHONE_DIR/leaklookup.json" ]; then
        LL_MSG=$(jq -r '.message // "Not found"' "$PHONE_DIR/leaklookup.json" 2>/dev/null)
        if [ "$LL_MSG" != "Not found" ] && [ -n "$LL_MSG" ]; then
            LEAK_FOUND="Yes"
        fi
    fi
    
    cat << EOF > "$PHONE_DIR/SUMMARY.txt"
╔═══════════════════════════════════════════════════════════════════════════╗
║                   PHONE NUMBER INVESTIGATION SUMMARY                      ║
╚═══════════════════════════════════════════════════════════════════════════╝

Phone Number: $(format_phone "$PHONE")
Normalized: $NORMALIZED
Country Code: +$COUNTRY_CODE
Area Code: $AREA_CODE
Investigated: $(date)

═══════════════════════════════════════════════════════════════════════════
QUICK FINDINGS
═══════════════════════════════════════════════════════════════════════════
Phone Type: $PHONE_TYPE
Carrier: $CARRIER
Location: $LOCATION
Valid Number: $VALID
Found in Leaks: $LEAK_FOUND

═══════════════════════════════════════════════════════════════════════════
PHONE TYPE ANALYSIS
═══════════════════════════════════════════════════════════════════════════
$(cat "$PHONE_DIR/phone_type.json" 2>/dev/null | jq '.' 2>/dev/null || cat "$PHONE_DIR/phone_type.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
VERIPHONE VALIDATION
═══════════════════════════════════════════════════════════════════════════
$(cat "$PHONE_DIR/veriphone.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
NUMVERIFY VALIDATION
═══════════════════════════════════════════════════════════════════════════
$(cat "$PHONE_DIR/numverify.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
LEAKLOOKUP
═══════════════════════════════════════════════════════════════════════════
$(cat "$PHONE_DIR/leaklookup.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
SPAM DATABASE LINKS
═══════════════════════════════════════════════════════════════════════════
$(cat "$PHONE_DIR/spam_databases.json" 2>/dev/null | jq -r '.recommended_sites[]' 2>/dev/null || cat "$PHONE_DIR/spam_databases.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
REVERSE LOOKUP URLS (Manual Check)
═══════════════════════════════════════════════════════════════════════════
$(cat "$PHONE_DIR/reverse_lookup.json" 2>/dev/null | jq -r '.reverse_lookup_urls | to_entries[] | "\(.key): \(.value)"' 2>/dev/null || echo "Not generated (use without -q flag)")

═══════════════════════════════════════════════════════════════════════════
SOCIAL MEDIA SEARCH URLS
═══════════════════════════════════════════════════════════════════════════
$(cat "$PHONE_DIR/social_search.json" 2>/dev/null | jq -r '.manual_search_urls | to_entries[] | "\(.key): \(.value)"' 2>/dev/null || echo "Not generated (use without -q flag)")

═══════════════════════════════════════════════════════════════════════════
NOTES
═══════════════════════════════════════════════════════════════════════════
$(jq -r '.notes // ""' "$PHONE_DIR/phone_type.json" 2>/dev/null)

═══════════════════════════════════════════════════════════════════════════
FILES GENERATED
═══════════════════════════════════════════════════════════════════════════
$(ls -la "$PHONE_DIR"/)

EOF

    log "${GREEN}[+] Phone $PHONE investigation complete${NC}"
}


#############################################
# MAIN EXECUTION
#############################################
section "Phone Number Investigation"

if [ "$PARALLEL_MODE" = true ] && [ ${#PHONES[@]} -gt 1 ]; then
    log "${YELLOW}[*] Running in PARALLEL mode (max $MAX_PARALLEL simultaneous)${NC}"
    
    job_count=0
    for PHONE in "${PHONES[@]}"; do
        investigate_phone "$PHONE" &
        job_count=$((job_count + 1))
        
        if [ $job_count -ge $MAX_PARALLEL ]; then
            wait -n 2>/dev/null || wait
            job_count=$((job_count - 1))
        fi
    done
    wait
else
    PHONE_COUNT=0
    for PHONE in "${PHONES[@]}"; do
        PHONE_COUNT=$((PHONE_COUNT + 1))
        log ""
        log "${YELLOW}[*] Investigating phone $PHONE_COUNT of ${#PHONES[@]}: $(format_phone "$PHONE")${NC}"
        investigate_phone "$PHONE"
    done
fi


#############################################
# Generate Master Summary
#############################################
section "Generating Master Summary Report"

SUMMARY_FILE="$OUTPUT_DIR/MASTER_SUMMARY.txt"

cat << EOF > "$SUMMARY_FILE"
╔═══════════════════════════════════════════════════════════════════════════╗
║             PHONE NUMBER INVESTIGATION MASTER REPORT v1.0                 ║
║                    Pacific Northwest Computers                            ║
╚═══════════════════════════════════════════════════════════════════════════╝

Report Generated: $(date)
Investigation ID: $TIMESTAMP
Total Phone Numbers Investigated: ${#PHONES[@]}

═══════════════════════════════════════════════════════════════════════════
PHONE NUMBERS INVESTIGATED
═══════════════════════════════════════════════════════════════════════════
EOF

for PHONE in "${PHONES[@]}"; do
    echo "  - $(format_phone "$PHONE")" >> "$SUMMARY_FILE"
done

cat << EOF >> "$SUMMARY_FILE"

═══════════════════════════════════════════════════════════════════════════
APIs & SOURCES QUERIED
═══════════════════════════════════════════════════════════════════════════
- NumVerify          (Phone validation & carrier lookup)
- Veriphone          (Phone validation)
- AbstractAPI        (Phone validation - if configured)
- LeakLookup         (Data leak search)
- IntelX             (Intelligence search)
- Area Code Database (Location lookup)
- Spam Databases     (Manual verification links)
- Reverse Lookup     (People search links)
- Social Media       (Search URL generation)

═══════════════════════════════════════════════════════════════════════════
PHONE TYPE INDICATORS
═══════════════════════════════════════════════════════════════════════════
- VoIP/Virtual: Often anonymous, easy to obtain, common in scams
- Toll-Free (800, etc.): Business numbers, but also used by scammers
- Premium (900, 976): WARNING - Charges apply, often scams
- Mobile: Standard cell phone
- Landline: Traditional phone line

EOF

# Add each phone's summary
for PHONE in "${PHONES[@]}"; do
    PHONE_SAFE=$(normalize_phone "$PHONE")
    if [ -f "$OUTPUT_DIR/$PHONE_SAFE/SUMMARY.txt" ]; then
        echo "" >> "$SUMMARY_FILE"
        cat "$OUTPUT_DIR/$PHONE_SAFE/SUMMARY.txt" >> "$SUMMARY_FILE"
    fi
done

cat << EOF >> "$SUMMARY_FILE"

═══════════════════════════════════════════════════════════════════════════
RECOMMENDED ACTIONS
═══════════════════════════════════════════════════════════════════════════
1. If VoIP/Virtual - Higher suspicion, commonly used in fraud
2. If found in leaks - Associated with compromised accounts
3. Check spam databases manually using provided URLs
4. Use reverse lookup to find potential owner information
5. Report scam numbers to:
   - FTC: reportfraud.ftc.gov
   - FCC: fcc.gov/consumers/guides/stop-unwanted-robocalls-and-texts
   - Carrier: Forward spam texts to 7726 (SPAM)

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
log "Phone numbers investigated: ${#PHONES[@]}"
for PHONE in "${PHONES[@]}"; do
    PHONE_SAFE=$(normalize_phone "$PHONE")
    log "  - $(format_phone "$PHONE") -> $OUTPUT_DIR/$PHONE_SAFE/"
done
log ""
log "${GREEN}Investigation completed: $(date)${NC}"
