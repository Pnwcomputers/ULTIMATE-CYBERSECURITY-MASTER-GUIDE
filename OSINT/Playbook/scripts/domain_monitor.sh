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

_PNWC_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/trusted_conf.sh"
# shellcheck source=lib/trusted_conf.sh
source "$_PNWC_LIB" || { echo "Missing helper library: $_PNWC_LIB" >&2; exit 1; }

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
    source_trusted "${API_KEYS_FILE}" || true
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
    line="$(printf '%*s' "$width" '')"
    line="${line// /─}"   # tr is not multibyte-aware and would emit invalid UTF-8
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
#
# A failed collection must never look like "no records": every snapshot keeps the
# tool's stderr in FILE.err and its exit status in FILE.rc, and the helper returns
# non-zero. compare_file() treats a failed baseline or current snapshot as
# UNVERIFIED instead of diffing an empty file against real data.
#   0 = collected   1 = tool failed (see FILE.err)   2 = required tool not installed
# ---------------------------------------------------------------------------

# capture OUT CMD... : stdout -> OUT, stderr -> OUT.err, exit status -> OUT.rc
capture() {
    local out="$1" rc=0
    shift
    "$@" > "$out" 2> "${out}.err" || rc=$?
    echo "$rc" > "${out}.rc"
    return "$rc"
}

need_tool() {  # need_tool TOOL LABEL OUT
    command -v "$1" &>/dev/null && return 0
    warn "$1 not found, skipping $2"
    : > "$3"
    echo "tool-missing:$1" > "${3}.rc"
    return 1
}

# sort_snapshot OUT : sort in place, but only if the collection succeeded
sort_snapshot() { [[ "$(cat "${1}.rc" 2>/dev/null)" == 0 ]] && sort -o "$1" "$1"; }

dig_snapshot() {  # dig_snapshot LABEL OUT NAME TYPE
    need_tool dig "$1" "$2" || return 2
    capture "$2" dig +short +time=5 +tries=2 "$4" "$3"
}

snapshot_dns_a()    { dig_snapshot "DNS A" "$2" "$1" A; }
snapshot_dns_aaaa() { dig_snapshot "DNS AAAA" "$2" "$1" AAAA; }

snapshot_dns_mx() {
    dig_snapshot "DNS MX" "$2" "$1" MX; local rc=$?
    sort_snapshot "$2"
    return "$rc"
}

snapshot_dns_ns() {
    dig_snapshot "DNS NS" "$2" "$1" NS; local rc=$?
    sort_snapshot "$2"
    return "$rc"
}

snapshot_dns_txt() {
    local domain="$1" outfile="$2" rc=0
    need_tool dig "DNS TXT" "$outfile" || return 2
    capture "${outfile}.a" dig +short +time=5 +tries=2 TXT "$domain" || rc=1
    capture "${outfile}.b" dig +short +time=5 +tries=2 TXT "_dmarc.${domain}" || rc=1
    {
        sort "${outfile}.a"
        sort "${outfile}.b"
    } > "$outfile"
    cat "${outfile}.a.err" "${outfile}.b.err" > "${outfile}.err"
    rm -f "${outfile}".a "${outfile}".b "${outfile}".a.err "${outfile}".b.err "${outfile}".a.rc "${outfile}".b.rc
    echo "$rc" > "${outfile}.rc"
    return "$rc"
}

snapshot_whois() {
    local domain="$1" outfile="$2" rc=0
    need_tool whois "WHOIS" "$outfile" || return 2
    capture "${outfile}.raw" whois "$domain" || rc=1
    grep -iE '(registrar:|nameserver:|name server:|creation date:|expir|registrant org|updated date)' \
        "${outfile}.raw" | sort -u > "$outfile"
    # An empty extract from a successful query is a real (empty) answer; a failed query is not.
    mv "${outfile}.raw.err" "${outfile}.err"
    rm -f "${outfile}.raw" "${outfile}.raw.rc"
    echo "$rc" > "${outfile}.rc"
    return "$rc"
}

snapshot_ssl() {
    local domain="$1" outfile="$2" rc=0
    need_tool openssl "SSL" "$outfile" || return 2
    : > "${outfile}.empty"
    capture "${outfile}.pem" openssl s_client -connect "${domain}:443" -servername "$domain" -showcerts < "${outfile}.empty" || rc=1
    if (( rc == 0 )); then
        openssl x509 -noout -subject -issuer -dates -fingerprint -ext subjectAltName \
            < "${outfile}.pem" > "$outfile" 2> "${outfile}.err" || rc=1
    else
        : > "$outfile"
        mv "${outfile}.pem.err" "${outfile}.err"
    fi
    rm -f "${outfile}.empty" "${outfile}.pem" "${outfile}.pem.err" "${outfile}.pem.rc"
    echo "$rc" > "${outfile}.rc"
    return "$rc"
}

snapshot_http_redirect() {
    need_tool curl "HTTP redirect chain" "$2" || return 2
    capture "$2" curl -sS -L -o /dev/null -w "%{url_effective}\n" --max-time 15 "http://${1}"
}

snapshot_http_headers() {
    local domain="$1" outfile="$2" rc=0
    need_tool curl "HTTP headers" "$outfile" || return 2
    capture "${outfile}.hdr" curl -sS -I --max-time 15 -w "HTTP_CODE=%{http_code}\n" "https://${domain}" || rc=1
    {
        grep '^HTTP_CODE=' "${outfile}.hdr" | tail -1
        echo "SERVER_HEADER=$(grep -i '^server:' "${outfile}.hdr" | head -1 | tr -d '\r')"
    } > "$outfile"
    mv "${outfile}.hdr.err" "${outfile}.err"
    rm -f "${outfile}.hdr" "${outfile}.hdr.rc"
    echo "$rc" > "${outfile}.rc"
    return "$rc"
}

snapshot_crtsh() {
    local domain="$1" outfile="$2" rc=0 count
    need_tool curl "crt.sh" "$outfile" || return 2
    capture "${outfile}.json" curl -sS --fail --max-time 20 "https://crt.sh/?q=${domain}&output=json" || rc=1
    if (( rc == 0 )); then
        if count="$(python3 -c "import sys,json; print(len(json.load(sys.stdin)))" < "${outfile}.json" 2>> "${outfile}.json.err")"; then
            echo "CERT_COUNT=${count}" > "$outfile"
        else
            rc=1; : > "$outfile"   # unparsable reply is a failure, not "0 certificates"
        fi
    else
        : > "$outfile"
    fi
    mv "${outfile}.json.err" "${outfile}.err"
    rm -f "${outfile}.json" "${outfile}.json.rc"
    echo "$rc" > "${outfile}.rc"
    return "$rc"
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

    local failed=()
    baseline_step() {  # baseline_step LABEL FUNC FILE
        local label="$1" fn="$2" file="$3" rc=0
        "$fn" "$domain" "${base_dir}/${file}" || rc=$?
        case $rc in
            0) log "${GREEN}[OK]${NC}  ${label}" ;;
            2) log "${YELLOW}[SKIP]${NC} ${label} (required tool not installed)"; failed+=("$label") ;;
            *) log "${RED}[FAILED]${NC} ${label} — see ${base_dir}/${file}.err"; failed+=("$label") ;;
        esac
    }
    baseline_step "DNS A record"                          snapshot_dns_a        dns_a.txt
    baseline_step "DNS AAAA record"                       snapshot_dns_aaaa     dns_aaaa.txt
    baseline_step "DNS MX records"                        snapshot_dns_mx       dns_mx.txt
    baseline_step "DNS NS records"                        snapshot_dns_ns       dns_ns.txt
    baseline_step "DNS TXT records (SPF/DKIM/DMARC)"      snapshot_dns_txt      dns_txt.txt
    baseline_step "WHOIS"                                 snapshot_whois        whois.txt
    baseline_step "SSL certificate"                       snapshot_ssl          ssl.txt
    baseline_step "HTTP redirect chain"                   snapshot_http_redirect http_redirect.txt
    baseline_step "HTTP response code and server header"  snapshot_http_headers  http_headers.txt
    baseline_step "crt.sh certificate count"              snapshot_crtsh        crtsh.txt

    # Record when baseline was taken
    echo "$ts" > "${MONITOR_DIR}/${domain}/baseline_ts.txt"

    log ""
    if (( ${#failed[@]} > 0 )); then
        printf '%s\n' "${failed[@]}" > "${MONITOR_DIR}/${domain}/baseline_incomplete.txt"
        log "${RED}[INCOMPLETE]${NC} Baseline saved to ${base_dir} but ${#failed[@]} item(s) could not be collected:"
        printf '  - %s\n' "${failed[@]}" | tee -a "$LOG_FILE"
        log "Those items will be reported as UNVERIFIED on every check until a complete baseline is taken."
        return 1
    fi
    rm -f "${MONITOR_DIR}/${domain}/baseline_incomplete.txt"
    log "${GREEN}[DONE]${NC} Baseline saved to: ${base_dir}"
}

# ---------------------------------------------------------------------------
# Compare a single snapshot file against its baseline
# ---------------------------------------------------------------------------
# Returns 0 = identical, 1 = changed, 2 = UNVERIFIED (a collection failed, so no
# conclusion can be drawn - this is never reported as "no change").
compare_file() {
    local label="$1"
    local baseline_file="$2"
    local current_file="$3"
    local changes_log="$4"

    if [[ ! -f "$baseline_file" ]]; then
        warn "No baseline for ${label}, skipping"
        return 0
    fi

    local side
    for side in "$baseline_file" "$current_file"; do
        if [[ ! -f "$side" || "$(cat "${side}.rc" 2>/dev/null)" != 0 ]]; then
            {
                echo "=== UNVERIFIED: ${label} ==="
                echo "A collection failed ($( [[ "$side" == "$baseline_file" ]] && echo baseline || echo current ): $(cat "${side}.rc" 2>/dev/null || echo 'no snapshot written')); no comparison was made."
                echo ""
            } | tee -a "$changes_log"
            return 2
        fi
    done

    local diff_output rc=0
    diff_output="$(diff "$baseline_file" "$current_file")" || rc=$?
    if (( rc > 1 )); then
        echo "=== UNVERIFIED: ${label} === (diff failed, rc=${rc})" | tee -a "$changes_log"
        return 2
    fi

    if (( rc == 1 )); then
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

    local unverified=0 crc
    for fname in "${!LABELS[@]}"; do
        crc=0
        compare_file "${LABELS[$fname]}" \
                "${base_dir}/${fname}" \
                "${tmp_dir}/${fname}" \
                "$changes_log" || crc=$?
        case $crc in
            1) any_changes=1 ;;
            2) unverified=$((unverified + 1)) ;;
        esac
    done

    # Keep the tools' stderr from this run: the temp dir is removed below.
    cat "${tmp_dir}"/*.err > "${domain_dir}/check_errors_${ts}.log" 2>/dev/null
    [[ -s "${domain_dir}/check_errors_${ts}.log" ]] || rm -f "${domain_dir}/check_errors_${ts}.log"

    # Update last-checked timestamp
    echo "$human_ts" > "${domain_dir}/last_checked.txt"

    rm -rf "$tmp_dir"

    if [[ "$any_changes" -eq 0 && "$unverified" -gt 0 ]]; then
        log "${YELLOW}[INCOMPLETE]${NC} ${unverified} item(s) for ${domain} could not be verified at ${human_ts}; this is NOT a clean result."
        log "             Details: ${changes_log}"
        return 2
    fi

    if [[ "$any_changes" -eq 1 ]]; then
        log ""
        log "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
        log "${RED}║  [CHANGE DETECTED]                                               ║${NC}"
        log "${RED}╠══════════════════════════════════════════════════════════════════╣${NC}"
        log "${RED}║  Domain    : ${domain}${NC}"
        log "${RED}║  Timestamp : ${human_ts}${NC}"
        log "${RED}║  Changes   : see ${changes_log}${NC}"
        [[ "$unverified" -gt 0 ]] && log "${RED}║  Unverified: ${unverified} item(s) could not be collected${NC}"
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
            local crc=0
            run_check "$domain" || crc=$?
            (( crc > any_fail )) && any_fail=$crc
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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
