#!/usr/bin/env bash
# FILE:        domain_monitor.sh
# USAGE:       domain_monitor.sh --init <domain>
#              domain_monitor.sh --check <domain>
#              domain_monitor.sh --watch <domain> --interval <seconds>
#              domain_monitor.sh --check-all
#              domain_monitor.sh --list
# DESCRIPTION: Cron-friendly domain change monitoring for ongoing fraud/scam cases.
#              Takes a baseline snapshot of a domain's DNS/WHOIS/cert state, then
#              on subsequent runs detects and logs any changes.
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
# Paths and config
# ---------------------------------------------------------------------------
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_KEYS_FILE="${CONFIG_DIR}/api_keys.conf"
MONITOR_DIR="${CONFIG_DIR}/monitor"
SCRIPT_NAME="$(basename "$0")"
LOG_FILE="${CONFIG_DIR}/domain_monitor.log"

# ---------------------------------------------------------------------------
# Load API keys if present
# ---------------------------------------------------------------------------
if [[ -f "${API_KEYS_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${API_KEYS_FILE}"
fi

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

err() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" >&2
}

section() {
    local title="$1"
    local width=70
    local line
    line="$(printf '%*s' "$width" '' | tr ' ' '─')"
    log ""
    log "${CYAN}┌${line}┐${NC}"
    log "${CYAN}│${NC}  ${BLUE}${title}${NC}"
    log "${CYAN}└${line}┘${NC}"
}

# ---------------------------------------------------------------------------
# Ensure config directories exist
# ---------------------------------------------------------------------------
setup_dirs() {
    mkdir -p "${CONFIG_DIR}" "${MONITOR_DIR}"
    touch "${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Domain sanitisation
# ---------------------------------------------------------------------------
sanitise_domain() {
    local raw="$1"
    # strip protocol and trailing slashes/paths
    echo "$raw" | sed 's|^https\?://||; s|/.*$||' | tr '[:upper:]' '[:lower:]'
}

# ---------------------------------------------------------------------------
# Snapshot helpers — each writes one text file inside baseline/
# ---------------------------------------------------------------------------

snapshot_dns_a() {
    local domain="$1"
    local outfile="$2"
    command -v dig &>/dev/null || { warn "dig not found, skipping DNS A"; return; }
    dig +short A "$domain" 2>/dev/null > "$outfile"
}

snapshot_dns_aaaa() {
    local domain="$1"
    local outfile="$2"
    command -v dig &>/dev/null || { warn "dig not found, skipping DNS AAAA"; return; }
    dig +short AAAA "$domain" 2>/dev/null > "$outfile"
}

snapshot_dns_mx() {
    local domain="$1"
    local outfile="$2"
    command -v dig &>/dev/null || { warn "dig not found, skipping DNS MX"; return; }
    dig +short MX "$domain" 2>/dev/null | sort > "$outfile"
}

snapshot_dns_ns() {
    local domain="$1"
    local outfile="$2"
    command -v dig &>/dev/null || { warn "dig not found, skipping DNS NS"; return; }
    dig +short NS "$domain" 2>/dev/null | sort > "$outfile"
}

snapshot_dns_txt() {
    local domain="$1"
    local outfile="$2"
    command -v dig &>/dev/null || { warn "dig not found, skipping DNS TXT"; return; }
    {
        dig +short TXT "$domain" 2>/dev/null | sort
        dig +short TXT "_dmarc.${domain}" 2>/dev/null | sort
    } > "$outfile"
}

snapshot_whois() {
    local domain="$1"
    local outfile="$2"
    command -v whois &>/dev/null || { warn "whois not found, skipping WHOIS"; return; }
    whois "$domain" 2>/dev/null \
        | grep -iE '(registrar:|nameserver:|name server:|creation date:|expir|registrant org|updated date)' \
        | sort -u > "$outfile"
}

snapshot_ssl() {
    local domain="$1"
    local outfile="$2"
    command -v openssl &>/dev/null || { warn "openssl not found, skipping SSL"; return; }
    local cert_text
    cert_text="$(echo "" | openssl s_client -connect "${domain}:443" -servername "$domain" 2>/dev/null \
        | openssl x509 -noout -subject -issuer -dates -fingerprint -ext subjectAltName 2>/dev/null)"
    echo "$cert_text" > "$outfile"
}

snapshot_http_redirect() {
    local domain="$1"
    local outfile="$2"
    command -v curl &>/dev/null || { warn "curl not found, skipping HTTP redirect chain"; return; }
    local effective_url
    effective_url="$(curl -Ls -o /dev/null -w "%{url_effective}" --max-time 15 "http://${domain}" 2>/dev/null)"
    echo "$effective_url" > "$outfile"
}

snapshot_http_headers() {
    local domain="$1"
    local outfile="$2"
    command -v curl &>/dev/null || { warn "curl not found, skipping HTTP headers"; return; }
    local http_code server_header
    http_code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "https://${domain}" 2>/dev/null)"
    server_header="$(curl -sI --max-time 15 "https://${domain}" 2>/dev/null \
        | grep -i '^server:' | head -1 | tr -d '\r')"
    {
        echo "HTTP_CODE=${http_code}"
        echo "SERVER_HEADER=${server_header}"
    } > "$outfile"
}

snapshot_crtsh() {
    local domain="$1"
    local outfile="$2"
    command -v curl &>/dev/null || { warn "curl not found, skipping crt.sh"; return; }
    local count
    count="$(curl -s --max-time 20 \
        "https://crt.sh/?q=${domain}&output=json" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null \
        || echo "0")"
    echo "CERT_COUNT=${count}" > "$outfile"
}

# ---------------------------------------------------------------------------
# Take a full baseline snapshot
# ---------------------------------------------------------------------------
take_baseline() {
    local domain
    domain="$(sanitise_domain "$1")"
    local base_dir="${MONITOR_DIR}/${domain}/baseline"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"

    mkdir -p "$base_dir"

    section "Initialising baseline for: ${domain}"
    log "${GREEN}[INIT]${NC} Timestamp: ${ts}"

    snapshot_dns_a       "$domain" "${base_dir}/dns_a.txt"
    log "${GREEN}[OK]${NC}  DNS A record"

    snapshot_dns_aaaa    "$domain" "${base_dir}/dns_aaaa.txt"
    log "${GREEN}[OK]${NC}  DNS AAAA record"

    snapshot_dns_mx      "$domain" "${base_dir}/dns_mx.txt"
    log "${GREEN}[OK]${NC}  DNS MX records"

    snapshot_dns_ns      "$domain" "${base_dir}/dns_ns.txt"
    log "${GREEN}[OK]${NC}  DNS NS records"

    snapshot_dns_txt     "$domain" "${base_dir}/dns_txt.txt"
    log "${GREEN}[OK]${NC}  DNS TXT records (SPF/DKIM/DMARC)"

    snapshot_whois       "$domain" "${base_dir}/whois.txt"
    log "${GREEN}[OK]${NC}  WHOIS"

    snapshot_ssl         "$domain" "${base_dir}/ssl.txt"
    log "${GREEN}[OK]${NC}  SSL certificate"

    snapshot_http_redirect "$domain" "${base_dir}/http_redirect.txt"
    log "${GREEN}[OK]${NC}  HTTP redirect chain"

    snapshot_http_headers  "$domain" "${base_dir}/http_headers.txt"
    log "${GREEN}[OK]${NC}  HTTP response code and server header"

    snapshot_crtsh       "$domain" "${base_dir}/crtsh.txt"
    log "${GREEN}[OK]${NC}  crt.sh certificate count"

    # Record when baseline was taken
    echo "$ts" > "${MONITOR_DIR}/${domain}/baseline_ts.txt"

    log ""
    log "${GREEN}[DONE]${NC} Baseline saved to: ${base_dir}"
}

# ---------------------------------------------------------------------------
# Compare a single snapshot file against its baseline
# ---------------------------------------------------------------------------
compare_file() {
    local label="$1"
    local baseline_file="$2"
    local current_file="$3"
    local changes_log="$4"

    if [[ ! -f "$baseline_file" ]]; then
        warn "No baseline for ${label}, skipping"
        return 0
    fi

    if [[ ! -f "$current_file" ]]; then
        warn "Cannot check ${label}: current snapshot not written (is the required tool installed?)"
        return 1
    fi

    local diff_output
    diff_output="$(diff "$baseline_file" "$current_file" 2>/dev/null)"

    if [[ -n "$diff_output" ]]; then
        {
            echo "=== CHANGE: ${label} ==="
            echo "--- baseline"
            echo "+++ current"
            echo "$diff_output"
            echo ""
        } | tee -a "$changes_log"
        return 1  # signal: change found
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Run a full check against baseline
# ---------------------------------------------------------------------------
run_check() {
    local domain
    domain="$(sanitise_domain "$1")"
    local base_dir="${MONITOR_DIR}/${domain}/baseline"
    local domain_dir="${MONITOR_DIR}/${domain}"
    local ts
    ts="$(date '+%Y%m%d_%H%M%S')"
    local human_ts
    human_ts="$(date '+%Y-%m-%d %H:%M:%S')"

    if [[ ! -d "$base_dir" ]]; then
        err "No baseline found for '${domain}'. Run --init first."
        return 1
    fi

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    local changes_log="${domain_dir}/changes_${ts}.log"
    local any_changes=0

    section "Checking: ${domain} at ${human_ts}"

    # Collect current state into tmp dir
    snapshot_dns_a          "$domain" "${tmp_dir}/dns_a.txt"
    snapshot_dns_aaaa       "$domain" "${tmp_dir}/dns_aaaa.txt"
    snapshot_dns_mx         "$domain" "${tmp_dir}/dns_mx.txt"
    snapshot_dns_ns         "$domain" "${tmp_dir}/dns_ns.txt"
    snapshot_dns_txt        "$domain" "${tmp_dir}/dns_txt.txt"
    snapshot_whois          "$domain" "${tmp_dir}/whois.txt"
    snapshot_ssl            "$domain" "${tmp_dir}/ssl.txt"
    snapshot_http_redirect  "$domain" "${tmp_dir}/http_redirect.txt"
    snapshot_http_headers   "$domain" "${tmp_dir}/http_headers.txt"
    snapshot_crtsh          "$domain" "${tmp_dir}/crtsh.txt"

    declare -A LABELS
    LABELS["dns_a.txt"]="DNS A Record (IPv4)"
    LABELS["dns_aaaa.txt"]="DNS AAAA Record (IPv6)"
    LABELS["dns_mx.txt"]="DNS MX Records"
    LABELS["dns_ns.txt"]="DNS NS Records"
    LABELS["dns_txt.txt"]="DNS TXT Records (SPF/DKIM/DMARC)"
    LABELS["whois.txt"]="WHOIS Data"
    LABELS["ssl.txt"]="SSL Certificate"
    LABELS["http_redirect.txt"]="HTTP Redirect Chain"
    LABELS["http_headers.txt"]="HTTP Response / Server Header"
    LABELS["crtsh.txt"]="crt.sh Certificate Count"

    for fname in "${!LABELS[@]}"; do
        if ! compare_file "${LABELS[$fname]}" \
                "${base_dir}/${fname}" \
                "${tmp_dir}/${fname}" \
                "$changes_log"; then
            any_changes=1
        fi
    done

    # Update last-checked timestamp
    echo "$human_ts" > "${domain_dir}/last_checked.txt"

    rm -rf "$tmp_dir"

    if [[ "$any_changes" -eq 1 ]]; then
        log ""
        log "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
        log "${RED}║  [CHANGE DETECTED]                                               ║${NC}"
        log "${RED}╠══════════════════════════════════════════════════════════════════╣${NC}"
        log "${RED}║  Domain    : ${domain}${NC}"
        log "${RED}║  Timestamp : ${human_ts}${NC}"
        log "${RED}║  Changes   : see ${changes_log}${NC}"
        log "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
        return 1
    else
        log "${GREEN}[CLEAN]${NC} No changes detected for ${domain} at ${human_ts}"
        # Remove empty changes log
        [[ -f "$changes_log" ]] && rm -f "$changes_log"
        return 0
    fi
}

# ---------------------------------------------------------------------------
# Watch mode — run check in a loop
# ---------------------------------------------------------------------------
run_watch() {
    local domain="$1"
    local interval="$2"

    if [[ -z "$interval" ]] || ! [[ "$interval" =~ ^[0-9]+$ ]]; then
        err "--interval must be a positive integer (seconds)"
        exit 1
    fi

    log "${CYAN}[WATCH]${NC} Monitoring ${domain} every ${interval}s. Press Ctrl+C to stop."
    while true; do
        run_check "$domain"
        log "${YELLOW}[WATCH]${NC} Sleeping ${interval}s …"
        sleep "$interval"
    done
}

# ---------------------------------------------------------------------------
# Check all monitored domains
# ---------------------------------------------------------------------------
check_all() {
    if [[ ! -d "$MONITOR_DIR" ]] || [[ -z "$(ls -A "$MONITOR_DIR" 2>/dev/null)" ]]; then
        log "${YELLOW}[INFO]${NC} No monitored domains found in ${MONITOR_DIR}"
        return 0
    fi

    local any_fail=0
    for domain_dir in "${MONITOR_DIR}"/*/; do
        local domain
        domain="$(basename "$domain_dir")"
        if [[ -d "${domain_dir}/baseline" ]]; then
            run_check "$domain" || any_fail=1
        fi
    done
    return "$any_fail"
}

# ---------------------------------------------------------------------------
# List monitored domains
# ---------------------------------------------------------------------------
list_domains() {
    section "Monitored Domains"

    if [[ ! -d "$MONITOR_DIR" ]] || [[ -z "$(ls -A "$MONITOR_DIR" 2>/dev/null)" ]]; then
        log "${YELLOW}[INFO]${NC} No domains are currently being monitored."
        return 0
    fi

    printf "%-40s %-25s %-25s\n" "DOMAIN" "BASELINE TAKEN" "LAST CHECKED"
    printf "%-40s %-25s %-25s\n" "------" "--------------" "------------"

    for domain_dir in "${MONITOR_DIR}"/*/; do
        [[ -d "$domain_dir" ]] || continue
        local domain
        domain="$(basename "$domain_dir")"
        local baseline_ts last_checked
        baseline_ts="$(cat "${domain_dir}/baseline_ts.txt" 2>/dev/null || echo "unknown")"
        last_checked="$(cat "${domain_dir}/last_checked.txt" 2>/dev/null || echo "never")"
        printf "%-40s %-25s %-25s\n" "$domain" "$baseline_ts" "$last_checked"
    done
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF

${CYAN}${SCRIPT_NAME}${NC} — Domain Change Monitor (PNWC OSINT Toolkit)

${YELLOW}USAGE:${NC}
  $SCRIPT_NAME --init <domain>
  $SCRIPT_NAME --check <domain>
  $SCRIPT_NAME --watch <domain> --interval <seconds>
  $SCRIPT_NAME --check-all
  $SCRIPT_NAME --list
  $SCRIPT_NAME -h | --help

${YELLOW}OPTIONS:${NC}
  --init <domain>             Take baseline snapshot of domain state
  --check <domain>            Compare current state against baseline
  --watch <domain>            Continuously monitor (requires --interval)
  --interval <seconds>        Sleep interval for --watch mode
  --check-all                 Run --check for all monitored domains
  --list                      List all monitored domains and check times
  -h, --help                  Show this help message

${YELLOW}EXAMPLES:${NC}
  $SCRIPT_NAME --init example.com
  $SCRIPT_NAME --check example.com
  $SCRIPT_NAME --watch example.com --interval 3600
  $SCRIPT_NAME --check-all

${YELLOW}STATE DIRECTORY:${NC}
  ~/.config/osint-investigator/monitor/<domain>/

EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    setup_dirs

    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    local mode=""
    local target_domain=""
    local watch_interval=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --init)
                mode="init"
                shift
                target_domain="${1:-}"
                [[ -z "$target_domain" ]] && { err "--init requires a domain argument"; exit 1; }
                shift
                ;;
            --check)
                mode="check"
                shift
                target_domain="${1:-}"
                [[ -z "$target_domain" ]] && { err "--check requires a domain argument"; exit 1; }
                shift
                ;;
            --watch)
                mode="watch"
                shift
                target_domain="${1:-}"
                [[ -z "$target_domain" ]] && { err "--watch requires a domain argument"; exit 1; }
                shift
                ;;
            --interval)
                shift
                watch_interval="${1:-}"
                [[ -z "$watch_interval" ]] && { err "--interval requires a value"; exit 1; }
                shift
                ;;
            --check-all)
                mode="check-all"
                shift
                ;;
            --list)
                mode="list"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                err "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    case "$mode" in
        init)       take_baseline "$target_domain" ;;
        check)      run_check "$target_domain" ;;
        watch)      run_watch "$target_domain" "$watch_interval" ;;
        check-all)  check_all ;;
        list)       list_domains ;;
        *)
            err "No mode specified."
            usage
            exit 1
            ;;
    esac
}

main "$@"
