#!/usr/bin/env bash
# FILE:        whois_bulk.sh
# USAGE:       whois_bulk.sh -f <domain_list_file> [-o output_dir] [-d <delay_seconds>] [--diff <previous_csv>]
#              whois_bulk.sh -D example.com,scam.net,fraud.org [-o output_dir]
# DESCRIPTION: Batch WHOIS lookup for a list of domains with rate limiting, structured
#              output extraction, diff detection vs previous run, and suspicious-pattern flagging.
# AUTHOR:      Jon-Eric Pienkowski ~ Pacific Northwest Computers (PNWC)
# CONTACT:     jon@pnwcomputers.com
# VERSION:     1.0.0
# CREATED:     2024
# PLATFORM:    Tsurugi Linux / Ubuntu / Debian

set -o pipefail

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
OUTPUT_DIR="./whois_results_$(date +%Y%m%d_%H%M%S)"
LOG_FILE=""
CSV_FILE=""
DELAY=3
DOMAIN_FILE=""
DOMAIN_LIST=""
DIFF_CSV=""

# Known bulletproof / abuse-tolerant registrars (partial match, lowercase)
BULLETPROOF_REGISTRARS=(
    "namecheap"
    "internet.bs"
    "reg.ru"
    "beget"
    "pananames"
    "epik"
    "njalla"
    "openprovider"
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

section() {
    log "\n${CYAN}══════════════════════════════════════════════════════════${NC}"
    log "${CYAN}  $1${NC}"
    log "${CYAN}══════════════════════════════════════════════════════════${NC}"
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
${CYAN}${SCRIPT_NAME}${NC} — Batch WHOIS Lookup Tool (PNWC OSINT)

${YELLOW}USAGE:${NC}
  $SCRIPT_NAME -f <domain_list_file> [-o output_dir] [-s <delay_secs>] [--diff <previous_csv>]
  $SCRIPT_NAME -D example.com,scam.net [-o output_dir] [-s <delay_secs>]

${YELLOW}OPTIONS:${NC}
  -f <file>          File containing one domain per line
  -D <domains>       Comma-separated list of domains
  -o <dir>           Output directory (default: whois_results_<timestamp>)
  -s <seconds>       Delay between lookups in seconds (default: 3)
  --diff <csv>       Previous run CSV to diff against
  -h                 Show this help

${YELLOW}OUTPUT:${NC}
  <output_dir>/raw/<domain>.txt     Raw WHOIS text
  <output_dir>/results.csv          Extracted fields CSV
  <output_dir>/whois_bulk.log       Run log
  <output_dir>/suspicious.txt       Flagged domains
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
check_deps() {
    local missing=0
    for cmd in whois awk grep sed date; do
        if ! command -v "$cmd" &>/dev/null; then
            log "${RED}[MISSING]${NC} Required tool not found: ${cmd}"
            missing=1
        fi
    done
    [[ "$missing" -eq 1 ]] && { log "${RED}[FATAL]${NC} Install missing dependencies and retry."; exit 1; }
}

# ---------------------------------------------------------------------------
# Extract a single field from raw WHOIS text
# ---------------------------------------------------------------------------
extract_field() {
    local raw_file="$1"
    local pattern="$2"
    local value
    value=$(grep -i "^${pattern}" "$raw_file" | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r\n')
    echo "$value"
}

extract_field_multi() {
    local raw_file="$1"
    local pattern="$2"
    local value
    value=$(grep -i "^${pattern}" "$raw_file" | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | paste -sd '|' -)
    echo "$value"
}

# ---------------------------------------------------------------------------
# Escape a string for CSV
# ---------------------------------------------------------------------------
csv_escape() {
    local val="$1"
    # Wrap in quotes if it contains commas, quotes, or newlines
    if [[ "$val" == *','* || "$val" == *'"'* || "$val" == *$'\n'* ]]; then
        val="${val//\"/\"\"}"
        val="\"${val}\""
    fi
    echo "$val"
}

# ---------------------------------------------------------------------------
# Flag suspicious patterns
# ---------------------------------------------------------------------------
flag_suspicious() {
    local domain="$1"
    local created="$2"
    local expires="$3"
    local org="$4"
    local registrar="$5"
    local status="$6"
    local flags=()

    local today_epoch
    today_epoch=$(date +%s)

    # New domain: created < 30 days ago
    if [[ -n "$created" && "$created" != "N/A" ]]; then
        local created_clean
        created_clean=$(echo "$created" | sed 's/T.*//' | sed 's/Z$//')
        local created_epoch
        created_epoch=$(date -d "$created_clean" +%s 2>/dev/null || echo 0)
        if [[ "$created_epoch" -gt 0 ]]; then
            local age_days=$(( (today_epoch - created_epoch) / 86400 ))
            if [[ "$age_days" -lt 30 ]]; then
                flags+=("NEW_DOMAIN(${age_days}d old)")
            fi
        fi
    fi

    # Expires < 30 days away
    if [[ -n "$expires" && "$expires" != "N/A" ]]; then
        local expires_clean
        expires_clean=$(echo "$expires" | sed 's/T.*//' | sed 's/Z$//')
        local expires_epoch
        expires_epoch=$(date -d "$expires_clean" +%s 2>/dev/null || echo 0)
        if [[ "$expires_epoch" -gt 0 ]]; then
            local days_until=$(( (expires_epoch - today_epoch) / 86400 ))
            if [[ "$days_until" -lt 30 && "$days_until" -gt 0 ]]; then
                flags+=("EXPIRING_SOON(${days_until}d)")
            fi
        fi
    fi

    # Privacy-protected registrant
    local privacy_terms=("privacy" "protect" "whoisguard" "redacted" "not disclosed" "withheld" "data protected")
    local org_lower
    org_lower=$(echo "$org" | tr '[:upper:]' '[:lower:]')
    for term in "${privacy_terms[@]}"; do
        if [[ "$org_lower" == *"$term"* ]]; then
            flags+=("PRIVACY_PROTECTED")
            break
        fi
    done

    # Known bulletproof registrar
    local registrar_lower
    registrar_lower=$(echo "$registrar" | tr '[:upper:]' '[:lower:]')
    for bp in "${BULLETPROOF_REGISTRARS[@]}"; do
        if [[ "$registrar_lower" == *"$bp"* ]]; then
            flags+=("BULLETPROOF_REGISTRAR(${bp})")
            break
        fi
    done

    if [[ "${#flags[@]}" -gt 0 ]]; then
        local flag_str
        flag_str=$(IFS=';'; echo "${flags[*]}")
        log "${RED}[SUSPICIOUS]${NC} ${domain}: ${flag_str}"
        echo "${domain}: ${flag_str}" >> "${OUTPUT_DIR}/suspicious.txt"
    fi
}

# ---------------------------------------------------------------------------
# Perform WHOIS lookup and extract fields
# ---------------------------------------------------------------------------
lookup_domain() {
    local domain="$1"
    local raw_dir="${OUTPUT_DIR}/raw"
    local raw_file="${raw_dir}/${domain}.txt"

    log "\n${BLUE}[WHOIS]${NC} Querying: ${domain}"

    whois "$domain" > "$raw_file" 2>&1
    local rc=$?
    if [[ "$rc" -ne 0 ]]; then
        log "${RED}[ERROR]${NC} whois failed for ${domain} (exit ${rc})"
        return 1
    fi

    # Extract fields
    local registrar; registrar=$(extract_field "$raw_file" "Registrar")
    local abuse_email; abuse_email=$(extract_field "$raw_file" "Registrar Abuse Contact Email")
    local created; created=$(extract_field "$raw_file" "Creation Date")
    [[ -z "$created" ]] && created=$(extract_field "$raw_file" "Created On")
    [[ -z "$created" ]] && created=$(extract_field "$raw_file" "created")
    local expires; expires=$(extract_field "$raw_file" "Registry Expiry Date")
    [[ -z "$expires" ]] && expires=$(extract_field "$raw_file" "Registrar Registration Expiration Date")
    [[ -z "$expires" ]] && expires=$(extract_field "$raw_file" "Expiry date")
    local updated; updated=$(extract_field "$raw_file" "Updated Date")
    [[ -z "$updated" ]] && updated=$(extract_field "$raw_file" "Last updated")
    local nameservers; nameservers=$(extract_field_multi "$raw_file" "Name Server")
    local org; org=$(extract_field "$raw_file" "Registrant Organization")
    [[ -z "$org" ]] && org=$(extract_field "$raw_file" "Registrant Org")
    [[ -z "$org" ]] && org=$(extract_field "$raw_file" "org")
    local country; country=$(extract_field "$raw_file" "Registrant Country")
    local status; status=$(extract_field_multi "$raw_file" "Domain Status")

    # Normalize empty fields
    [[ -z "$registrar" ]]     && registrar="N/A"
    [[ -z "$abuse_email" ]]   && abuse_email="N/A"
    [[ -z "$created" ]]       && created="N/A"
    [[ -z "$expires" ]]       && expires="N/A"
    [[ -z "$updated" ]]       && updated="N/A"
    [[ -z "$nameservers" ]]   && nameservers="N/A"
    [[ -z "$org" ]]           && org="N/A"
    [[ -z "$country" ]]       && country="N/A"
    [[ -z "$status" ]]        && status="N/A"

    log "  ${GREEN}Registrar:${NC}    ${registrar}"
    log "  ${GREEN}Abuse Email:${NC}  ${abuse_email}"
    log "  ${GREEN}Created:${NC}      ${created}"
    log "  ${GREEN}Expires:${NC}      ${expires}"
    log "  ${GREEN}Updated:${NC}      ${updated}"
    log "  ${GREEN}Name Servers:${NC} ${nameservers}"
    log "  ${GREEN}Org:${NC}          ${org}"
    log "  ${GREEN}Country:${NC}      ${country}"
    log "  ${GREEN}Status:${NC}       ${status}"

    # Write CSV row
    local row
    row="$(csv_escape "$domain"),$(csv_escape "$registrar"),$(csv_escape "$abuse_email"),$(csv_escape "$created"),$(csv_escape "$expires"),$(csv_escape "$updated"),$(csv_escape "$nameservers"),$(csv_escape "$org"),$(csv_escape "$country"),$(csv_escape "$status")"
    echo "$row" >> "$CSV_FILE"

    # Flag suspicious patterns
    flag_suspicious "$domain" "$created" "$expires" "$org" "$registrar" "$status"
}

# ---------------------------------------------------------------------------
# Diff two CSV files
# ---------------------------------------------------------------------------
run_diff() {
    local prev_csv="$1"

    if [[ ! -f "$prev_csv" ]]; then
        log "${RED}[ERROR]${NC} Previous CSV not found: ${prev_csv}"
        return 1
    fi

    section "DIFF vs Previous Run"
    log "Comparing: ${prev_csv} → ${CSV_FILE}\n"

    local diff_file="${OUTPUT_DIR}/diff.txt"
    : > "$diff_file"

    # Build associative array from previous CSV (domain → full row)
    declare -A prev_rows
    while IFS= read -r line; do
        local prev_domain
        prev_domain=$(echo "$line" | cut -d',' -f1 | tr -d '"')
        prev_rows["$prev_domain"]="$line"
    done < <(tail -n +2 "$prev_csv")

    # Compare current CSV against previous
    while IFS= read -r line; do
        local domain
        domain=$(echo "$line" | cut -d',' -f1 | tr -d '"')
        if [[ -v "prev_rows[$domain]" ]]; then
            if [[ "${prev_rows[$domain]}" != "$line" ]]; then
                log "${YELLOW}[CHANGED]${NC} ${domain}"
                echo "CHANGED: ${domain}" >> "$diff_file"
                echo "  PREV: ${prev_rows[$domain]}" >> "$diff_file"
                echo "  CURR: ${line}" >> "$diff_file"
            fi
        else
            log "${GREEN}[NEW]${NC} ${domain} (not in previous run)"
            echo "NEW: ${domain}" >> "$diff_file"
        fi
    done < <(tail -n +2 "$CSV_FILE")

    # Domains in previous but not in current
    while IFS= read -r line; do
        local domain
        domain=$(echo "$line" | cut -d',' -f1 | tr -d '"')
        if ! grep -q "^$(csv_escape "$domain")," "$CSV_FILE" 2>/dev/null; then
            log "${RED}[REMOVED]${NC} ${domain} (in previous run, not in current)"
            echo "REMOVED: ${domain}" >> "$diff_file"
        fi
    done < <(tail -n +2 "$prev_csv")

    log "\nDiff saved: ${diff_file}"
}

# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------
print_summary() {
    local total_domains="$1"
    local success_count="$2"
    local fail_count="$3"

    section "Summary"

    local unique_registrars unique_ns privacy_count
    unique_registrars=$(tail -n +2 "$CSV_FILE" | cut -d',' -f2 | tr -d '"' | sort -u | grep -v '^N/A$' | wc -l)
    unique_ns=$(tail -n +2 "$CSV_FILE" | cut -d',' -f7 | tr -d '"' | tr '|' '\n' | \
        awk -F'.' 'NF>=2{print $(NF-1)"."$NF}' | sort -u | wc -l)
    privacy_count=$(tail -n +2 "$CSV_FILE" | cut -d',' -f8 | tr '[:upper:]' '[:lower:]' | \
        grep -ci "privacy\|protect\|whoisguard\|redacted\|withheld" || true)

    log "  Total domains queried:    ${total_domains}"
    log "  Successful lookups:       ${GREEN}${success_count}${NC}"
    log "  Failed lookups:           ${RED}${fail_count}${NC}"
    log "  Unique registrars:        ${unique_registrars}"
    log "  Unique NS providers:      ${unique_ns}"
    log "  Privacy-protected:        ${YELLOW}${privacy_count}${NC}"

    if [[ -f "${OUTPUT_DIR}/suspicious.txt" ]]; then
        local susp_count
        susp_count=$(wc -l < "${OUTPUT_DIR}/suspicious.txt")
        log "  Suspicious domains:       ${RED}${susp_count}${NC}"
        log "\n${RED}Suspicious domains:${NC}"
        while IFS= read -r s_line; do
            log "  ${RED}▸${NC} ${s_line}"
        done < "${OUTPUT_DIR}/suspicious.txt"
    fi

    log "\n${GREEN}Results saved to:${NC} ${OUTPUT_DIR}/"
    log "  CSV:  ${CSV_FILE}"
    log "  Log:  ${LOG_FILE}"
    log "  Raw:  ${OUTPUT_DIR}/raw/"
}

# ---------------------------------------------------------------------------
# Parse long options manually before getopts
# ---------------------------------------------------------------------------
parse_args() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --diff)
                DIFF_CSV="$2"
                shift 2
                ;;
            --help)
                usage
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done
    # Re-set positional parameters to remaining args
    set -- "${args[@]}"

    local OPTIND=1
    while getopts ":f:D:o:s:h" opt; do
        case "$opt" in
            f) DOMAIN_FILE="$OPTARG" ;;
            D) DOMAIN_LIST="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            s) DELAY="$OPTARG" ;;
            h) usage ;;
            :) log "${RED}[ERROR]${NC} Option -${OPTARG} requires an argument."; exit 1 ;;
            \?) log "${RED}[ERROR]${NC} Unknown option: -${OPTARG}"; usage ;;
        esac
    done

    if [[ -z "$DOMAIN_FILE" && -z "$DOMAIN_LIST" ]]; then
        log "${RED}[ERROR]${NC} Provide -f <file> or -D <domain,list>"
        usage
    fi

    if [[ -n "$DOMAIN_FILE" && ! -f "$DOMAIN_FILE" ]]; then
        log "${RED}[ERROR]${NC} Domain list file not found: ${DOMAIN_FILE}"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    mkdir -p "${OUTPUT_DIR}/raw"
    LOG_FILE="${OUTPUT_DIR}/whois_bulk.log"
    CSV_FILE="${OUTPUT_DIR}/results.csv"
    : > "$LOG_FILE"

    section "PNWC WHOIS Bulk Lookup"
    log "Started:    $(date)"
    log "Output dir: ${OUTPUT_DIR}"
    log "Rate delay: ${DELAY}s"

    check_deps

    # Write CSV header
    echo "domain,registrar,abuse_email,created,expires,updated,nameservers,org,country,status" > "$CSV_FILE"

    # Build domain array
    local domains=()
    if [[ -n "$DOMAIN_FILE" ]]; then
        while IFS= read -r line; do
            line="${line%%#*}"       # strip inline comments
            line="${line//[[:space:]]/}"  # strip whitespace
            [[ -n "$line" ]] && domains+=("$line")
        done < "$DOMAIN_FILE"
    elif [[ -n "$DOMAIN_LIST" ]]; then
        IFS=',' read -ra domains <<< "$DOMAIN_LIST"
    fi

    local total="${#domains[@]}"
    local success_count=0
    local fail_count=0

    log "Domains to process: ${total}"

    for i in "${!domains[@]}"; do
        local domain="${domains[$i]}"
        # Sanitize: only allow valid domain characters
        domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]//g')
        [[ -z "$domain" ]] && continue

        log "\n[${i+1}/${total}]"
        if lookup_domain "$domain"; then
            (( success_count++ ))
        else
            (( fail_count++ ))
        fi

        # Rate limit (skip delay after last domain)
        if [[ $((i + 1)) -lt "$total" ]]; then
            log "${YELLOW}[RATE LIMIT]${NC} Waiting ${DELAY}s..."
            sleep "$DELAY"
        fi
    done

    # Diff if requested
    if [[ -n "$DIFF_CSV" ]]; then
        run_diff "$DIFF_CSV"
    fi

    print_summary "$total" "$success_count" "$fail_count"
}

main "$@"
