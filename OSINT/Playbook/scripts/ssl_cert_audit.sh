#!/usr/bin/env bash
# FILE:        ssl_cert_audit.sh
# USAGE:       ssl_cert_audit.sh -d <domain> [-d <domain2>] [-i <ip>] [-p <port>] [-o output_dir]
#              ssl_cert_audit.sh -f <file_of_domains> [-o output_dir]
# DESCRIPTION: Deep TLS/SSL certificate investigation for a domain or IP.
#              Extracts cert details, checks certificate history via crt.sh,
#              detects suspicious patterns common to scam infrastructure.
# AUTHOR:      Jon-Eric Pienkowski ~ Pacific Northwest Computers (PNWC)
# CONTACT:     jon@pnwcomputers.com
# VERSION:     1.0.0
# CREATED:     2024
# PLATFORM:    Tsurugi Linux / Ubuntu / Debian

set -o pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Config ───────────────────────────────────────────────────────────────────
SCRIPT_NAME="ssl_cert_audit"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${HOME}/OSINT_SSL_Audits"
LOG_FILE="${OUTPUT_DIR}/${SCRIPT_NAME}_${TIMESTAMP}.log"
TLS_PORTS=(443 8443 4443 8080)
declare -a DOMAINS=()
declare -a IPS=()
DOMAIN_FILE=""
CUSTOM_PORT=""

# ─── API Keys (optional for future enrichment) ────────────────────────────────
API_CONF="${HOME}/.config/osint-investigator/api_keys.conf"
if [[ -f "$API_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$API_CONF"
fi

# ─── Logging ──────────────────────────────────────────────────────────────────
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

err() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

redflag() {
    echo -e "${RED}[RED FLAG]${NC} $1" | tee -a "$LOG_FILE"
}

section() {
    log ""
    log "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    log "${CYAN}  $1${NC}"
    log "${CYAN}══════════════════════════════════════════════════════════════${NC}"
}

# ─── Usage ────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BLUE}SSL Certificate Audit Tool — PNWC OSINT Toolkit${NC}"
    echo ""
    echo "Usage:"
    echo "  $(basename "$0") -d <domain> [-d <domain2>] [-i <ip>] [-p <port>] [-o output_dir]"
    echo "  $(basename "$0") -f <file_of_domains> [-o output_dir]"
    echo ""
    echo "Options:"
    echo "  -d <domain>     Domain to audit (repeatable)"
    echo "  -i <ip>         IP address to audit (repeatable)"
    echo "  -f <file>       File containing one domain/IP per line"
    echo "  -p <port>       Custom port (default: scan 443,8443,4443,8080)"
    echo "  -o <dir>        Output directory (default: ~/OSINT_SSL_Audits)"
    echo "  -h              Show this help"
    exit 0
}

# ─── Dependency check ─────────────────────────────────────────────────────────
check_deps() {
    local missing=0
    for tool in openssl curl date; do
        if ! command -v "$tool" &>/dev/null; then
            err "Required tool not found: $tool"
            missing=1
        fi
    done
    if [[ "$missing" -eq 1 ]]; then
        err "Install missing dependencies and re-run."
        exit 1
    fi
    if ! command -v jq &>/dev/null; then
        warn "jq not found — crt.sh JSON parsing will be limited."
    fi
}

# ─── Date math helper ─────────────────────────────────────────────────────────
days_until() {
    local date_str="$1"
    local target_epoch; target_epoch=$(date -d "$date_str" +%s 2>/dev/null) || return 1
    local now_epoch; now_epoch=$(date +%s)
    echo $(( (target_epoch - now_epoch) / 86400 ))
}

days_since() {
    local date_str="$1"
    local target_epoch; target_epoch=$(date -d "$date_str" +%s 2>/dev/null) || return 1
    local now_epoch; now_epoch=$(date +%s)
    echo $(( (now_epoch - target_epoch) / 86400 ))
}

# ─── Extract cert from openssl ────────────────────────────────────────────────
extract_cert_pem() {
    local host="$1"
    local port="$2"
    openssl s_client -connect "${host}:${port}" -showcerts </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null
}

get_raw_pem() {
    local host="$1"
    local port="$2"
    openssl s_client -connect "${host}:${port}" </dev/null 2>/dev/null \
        | openssl x509 2>/dev/null
}

# ─── Audit cert on a single host:port ────────────────────────────────────────
audit_cert() {
    local host="$1"
    local port="$2"

    section "Certificate Audit — ${host}:${port}"

    # Fetch the raw cert text
    local cert_text
    cert_text=$(openssl s_client -connect "${host}:${port}" -showcerts </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null)

    if [[ -z "$cert_text" ]]; then
        warn "No TLS certificate returned from ${host}:${port} — port may not speak TLS."
        return
    fi

    # ── Subject ──────────────────────────────────────────────────────────────
    local subject
    subject=$(openssl s_client -connect "${host}:${port}" </dev/null 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
    log "${GREEN}Subject:${NC}          $subject"

    local cn
    cn=$(echo "$subject" | grep -oP 'CN\s*=\s*\K[^,/]+' | head -1 | xargs)

    local org
    org=$(echo "$subject" | grep -oP '\bO\s*=\s*\K[^,/]+' | head -1 | xargs)

    local country
    country=$(echo "$subject" | grep -oP '\bC\s*=\s*\K[^,/]+' | head -1 | xargs)

    log "  CN:               ${cn:-<none>}"
    log "  O:                ${org:-<none>}"
    log "  C:                ${country:-<none>}"

    # ── Issuer ────────────────────────────────────────────────────────────────
    local issuer
    issuer=$(openssl s_client -connect "${host}:${port}" </dev/null 2>/dev/null \
        | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
    log "${GREEN}Issuer:${NC}           $issuer"

    local issuer_cn
    issuer_cn=$(echo "$issuer" | grep -oP 'CN\s*=\s*\K[^,/]+' | head -1 | xargs)

    local issuer_o
    issuer_o=$(echo "$issuer" | grep -oP '\bO\s*=\s*\K[^,/]+' | head -1 | xargs)

    # Detect CA type
    local ca_type="Unknown"
    if echo "$issuer" | grep -qi "let's encrypt\|letsencrypt"; then
        ca_type="Let's Encrypt (free CA)"
    elif echo "$issuer" | grep -qi "zerossl"; then
        ca_type="ZeroSSL (free CA)"
    elif [[ "$issuer_cn" == "$cn" ]] || echo "$issuer" | grep -qi "self.sign\|Self Signed"; then
        ca_type="SELF-SIGNED"
    else
        ca_type="Commercial: ${issuer_o:-${issuer_cn}}"
    fi
    log "  CA Type:          ${ca_type}"

    # ── Validity ─────────────────────────────────────────────────────────────
    local not_before not_after
    not_before=$(openssl s_client -connect "${host}:${port}" </dev/null 2>/dev/null \
        | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//')
    not_after=$(openssl s_client -connect "${host}:${port}" </dev/null 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    log "${GREEN}Validity:${NC}"
    log "  Not Before:       ${not_before}"
    log "  Not After:        ${not_after}"

    # ── Serial ────────────────────────────────────────────────────────────────
    local serial
    serial=$(openssl s_client -connect "${host}:${port}" </dev/null 2>/dev/null \
        | openssl x509 -noout -serial 2>/dev/null | sed 's/serial=//')
    log "${GREEN}Serial Number:${NC}    ${serial}"

    # ── Fingerprint ───────────────────────────────────────────────────────────
    local fingerprint
    fingerprint=$(openssl s_client -connect "${host}:${port}" </dev/null 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/SHA256 Fingerprint=//')
    log "${GREEN}SHA-256 Fingerprint:${NC}"
    log "  ${fingerprint}"

    # ── Signature algorithm ───────────────────────────────────────────────────
    local sig_alg
    sig_alg=$(echo "$cert_text" | grep -i "Signature Algorithm" | head -1 | awk '{print $NF}')
    log "${GREEN}Signature Algorithm:${NC} ${sig_alg}"

    # ── Key size ──────────────────────────────────────────────────────────────
    local key_info
    key_info=$(echo "$cert_text" | grep -i "Public-Key\|Public Key" | head -1 | grep -oP '\(\K[^)]+')
    log "${GREEN}Key Size:${NC}         ${key_info:-unknown}"

    # ── SANs ─────────────────────────────────────────────────────────────────
    log "${GREEN}Subject Alternative Names:${NC}"
    local sans
    sans=$(echo "$cert_text" | grep -A1 "Subject Alternative Name" | tail -1 \
        | tr ',' '\n' | sed 's/^\s*/  /' | grep -v '^$')
    if [[ -z "$sans" ]]; then
        sans=$(openssl s_client -connect "${host}:${port}" </dev/null 2>/dev/null \
            | openssl x509 -noout -ext subjectAltName 2>/dev/null \
            | grep -v "^X509v3" | tr ',' '\n' | sed 's/^\s*/  /' | grep -v '^$')
    fi
    if [[ -n "$sans" ]]; then
        log "$sans"
    else
        log "  <none detected>"
    fi

    # ─── Suspicious pattern analysis ─────────────────────────────────────────
    section "Suspicious Pattern Analysis — ${host}:${port}"

    local flags_found=0

    # Self-signed
    if [[ "$ca_type" == "SELF-SIGNED" ]]; then
        redflag "Self-signed certificate detected."
        flags_found=$((flags_found + 1))
    fi

    # Cert age — issued within last 7 days
    if [[ -n "$not_before" ]]; then
        local age_days
        age_days=$(days_since "$not_before" 2>/dev/null) || age_days=999
        if [[ "$age_days" -lt 7 ]]; then
            redflag "Certificate issued only ${age_days} day(s) ago (brand-new, possible scam site)."
            flags_found=$((flags_found + 1))
        fi
    fi

    # Expired
    if [[ -n "$not_after" ]]; then
        local expire_days
        expire_days=$(days_until "$not_after" 2>/dev/null) || expire_days=999
        if [[ "$expire_days" -lt 0 ]]; then
            redflag "Certificate is EXPIRED (expired ${expire_days#-} days ago)."
            flags_found=$((flags_found + 1))
        fi

        # Short validity period
        if [[ -n "$not_before" ]]; then
            local start_epoch end_epoch validity_days
            start_epoch=$(date -d "$not_before" +%s 2>/dev/null) || start_epoch=0
            end_epoch=$(date -d "$not_after" +%s 2>/dev/null) || end_epoch=0
            if [[ "$start_epoch" -gt 0 && "$end_epoch" -gt 0 ]]; then
                validity_days=$(( (end_epoch - start_epoch) / 86400 ))
                if [[ "$validity_days" -lt 30 ]]; then
                    redflag "Very short validity period: ${validity_days} days (< 30 days)."
                    flags_found=$((flags_found + 1))
                fi
            fi
        fi
    fi

    # CN mismatch
    if [[ -n "$cn" && -n "$host" ]]; then
        local normalized_host="${host#www.}"
        local normalized_cn="${cn#\*.}"
        normalized_cn="${normalized_cn#www.}"
        if [[ "$normalized_cn" != "$normalized_host" ]] && \
           [[ "$cn" != "*.$normalized_host" ]] && \
           [[ "$cn" != "$host" ]]; then
            redflag "CN mismatch: queried '${host}' but cert CN is '${cn}'."
            flags_found=$((flags_found + 1))
        fi
    fi

    # Let's Encrypt + no org
    if echo "$issuer" | grep -qi "let's encrypt\|letsencrypt"; then
        if [[ -z "$org" ]] || echo "$org" | grep -qi "^$"; then
            redflag "Let's Encrypt cert with no registered organization (common on scam infrastructure)."
            flags_found=$((flags_found + 1))
        fi
    fi

    # SANs contain IP addresses
    if echo "$sans" | grep -qP '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'; then
        redflag "SANs include IP address(es) — unusual, indicates non-standard infrastructure."
        flags_found=$((flags_found + 1))
    fi

    if [[ "$flags_found" -eq 0 ]]; then
        log "${GREEN}No immediate red flags detected for ${host}:${port}.${NC}"
    else
        log "${YELLOW}Total red flags: ${flags_found}${NC}"
    fi

    # Store fingerprint for reuse detection
    if [[ -n "$fingerprint" ]]; then
        echo "${fingerprint}|${host}:${port}" >> "${OUTPUT_DIR}/fingerprints_${TIMESTAMP}.tmp"
    fi
}

# ─── crt.sh history check ─────────────────────────────────────────────────────
check_crtsh() {
    local domain="$1"

    section "Certificate History — crt.sh — ${domain}"

    if ! command -v curl &>/dev/null; then
        warn "curl not found — skipping crt.sh lookup."
        return
    fi

    local crtsh_url="https://crt.sh/?q=${domain}&output=json"
    local crtsh_raw
    crtsh_raw=$(curl -sS --max-time 30 "$crtsh_url" 2>/dev/null)

    if [[ -z "$crtsh_raw" ]] || echo "$crtsh_raw" | grep -q "^<"; then
        warn "crt.sh returned no JSON for domain: ${domain}"
        return
    fi

    if ! command -v jq &>/dev/null; then
        warn "jq not available — showing raw cert count only."
        local count
        count=$(echo "$crtsh_raw" | grep -o '"id"' | wc -l)
        log "  Approx certificates found: ${count}"
        return
    fi

    # Total unique certs
    local total_certs
    total_certs=$(echo "$crtsh_raw" | jq 'length' 2>/dev/null) || total_certs=0
    log "${GREEN}Total certificates found:${NC} ${total_certs}"

    # Unique issuer orgs
    log "${GREEN}Unique Issuer Organizations:${NC}"
    local issuers
    issuers=$(echo "$crtsh_raw" | jq -r '[.[].issuer_name] | unique | .[]' 2>/dev/null \
        | grep -oP '(?<=O=)[^,]+' | sort -u)
    if [[ -n "$issuers" ]]; then
        echo "$issuers" | while IFS= read -r iss; do
            log "  - ${iss}"
        done
    else
        log "  <none extracted>"
    fi

    # All-free-CA check
    local has_commercial
    has_commercial=$(echo "$crtsh_raw" | jq -r '[.[].issuer_name] | .[]' 2>/dev/null \
        | grep -iv "let's encrypt\|letsencrypt\|zerossl\|buypass\|sectigo free\|free\|r3\|r10\|e1\|e5\|e6" \
        | wc -l)
    if [[ "$has_commercial" -eq 0 && "$total_certs" -gt 0 ]]; then
        redflag "All ${total_certs} historical certificates are from free CAs only."
    fi

    # First and most recent issuance
    local first_seen most_recent
    first_seen=$(echo "$crtsh_raw" | jq -r 'sort_by(.not_before) | first | .not_before' 2>/dev/null)
    most_recent=$(echo "$crtsh_raw" | jq -r 'sort_by(.not_before) | last | .not_before' 2>/dev/null)
    log "${GREEN}First issuance:${NC}   ${first_seen:-unknown}"
    log "${GREEN}Most recent:${NC}      ${most_recent:-unknown}"

    # Unique SANs across all certs
    log "${GREEN}All Unique SANs seen across all certs:${NC}"
    local all_sans
    all_sans=$(echo "$crtsh_raw" | jq -r '[.[].name_value] | unique | .[]' 2>/dev/null \
        | sort -u | head -50)
    if [[ -n "$all_sans" ]]; then
        echo "$all_sans" | while IFS= read -r san; do
            log "  ${san}"
        done
    else
        log "  <none>"
    fi

    # Suspicious churn: >5 certs in last 30 days
    local thirty_days_ago
    thirty_days_ago=$(date -d "30 days ago" +%Y-%m-%dT%H:%M:%S 2>/dev/null) || thirty_days_ago=""
    if [[ -n "$thirty_days_ago" ]]; then
        local recent_count
        recent_count=$(echo "$crtsh_raw" \
            | jq --arg cutoff "$thirty_days_ago" \
                '[.[] | select(.not_before >= $cutoff)] | length' 2>/dev/null) || recent_count=0
        log "${GREEN}Certs issued in last 30 days:${NC} ${recent_count}"
        if [[ "$recent_count" -gt 5 ]]; then
            redflag "Certificate churn detected: ${recent_count} certs issued in the last 30 days (> 5)."
        fi
    fi
}

# ─── Multi-port scan ──────────────────────────────────────────────────────────
scan_tls_ports() {
    local host="$1"
    local ports=("${@:2}")

    section "Multi-Port TLS Scan — ${host}"

    for port in "${ports[@]}"; do
        log "${BLUE}Checking ${host}:${port} ...${NC}"
        local probe
        probe=$(openssl s_client -connect "${host}:${port}" </dev/null 2>&1 | head -5)
        if echo "$probe" | grep -q "CONNECTED\|Certificate"; then
            log "${GREEN}  [OPEN/TLS]${NC} Port ${port} responds to TLS"
            audit_cert "$host" "$port"
        else
            log "  [closed/no-TLS] Port ${port}"
        fi
    done
}

# ─── Cert reuse detection ─────────────────────────────────────────────────────
check_cert_reuse() {
    local fp_file="${OUTPUT_DIR}/fingerprints_${TIMESTAMP}.tmp"

    if [[ ! -f "$fp_file" ]]; then
        return
    fi

    section "Certificate Reuse Detection"

    local seen_fps=()
    local duplicates_found=0

    while IFS='|' read -r fp host_port; do
        local already=0
        for prev in "${seen_fps[@]}"; do
            if [[ "$prev" == "$fp" ]]; then
                already=1
                break
            fi
        done
        if [[ "$already" -eq 1 ]]; then
            redflag "Shared certificate fingerprint on ${host_port}: ${fp}"
            redflag "  -> Suggests same infrastructure/operator across multiple targets."
            duplicates_found=$((duplicates_found + 1))
        else
            seen_fps+=("$fp")
        fi
    done < "$fp_file"

    if [[ "$duplicates_found" -eq 0 ]]; then
        log "${GREEN}No shared certificate fingerprints detected.${NC}"
    fi

    rm -f "$fp_file"
}

# ─── Argument parsing ─────────────────────────────────────────────────────────
parse_args() {
    if [[ $# -eq 0 ]]; then
        usage
    fi

    while getopts ":d:i:f:p:o:h" opt; do
        case "$opt" in
            d) DOMAINS+=("$OPTARG") ;;
            i) IPS+=("$OPTARG") ;;
            f) DOMAIN_FILE="$OPTARG" ;;
            p) CUSTOM_PORT="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            h) usage ;;
            :)
                err "Option -${OPTARG} requires an argument."
                exit 1
                ;;
            \?)
                err "Unknown option: -${OPTARG}"
                exit 1
                ;;
        esac
    done

    # Load targets from file
    if [[ -n "$DOMAIN_FILE" ]]; then
        if [[ ! -f "$DOMAIN_FILE" ]]; then
            err "Domain file not found: ${DOMAIN_FILE}"
            exit 1
        fi
        while IFS= read -r line; do
            line="${line// /}"
            [[ -z "$line" || "$line" == \#* ]] && continue
            DOMAINS+=("$line")
        done < "$DOMAIN_FILE"
    fi

    if [[ "${#DOMAINS[@]}" -eq 0 && "${#IPS[@]}" -eq 0 ]]; then
        err "No domains or IPs specified. Use -d, -i, or -f."
        usage
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    check_deps

    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="${OUTPUT_DIR}/${SCRIPT_NAME}_${TIMESTAMP}.log"

    log "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    log "${BLUE}║        SSL/TLS Certificate Audit — PNWC OSINT Toolkit       ║${NC}"
    log "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    log "Started:   $(date)"
    log "Output:    ${OUTPUT_DIR}"
    log "Log:       ${LOG_FILE}"
    log ""

    # Determine ports to scan
    local -a ports_to_scan
    if [[ -n "$CUSTOM_PORT" ]]; then
        ports_to_scan=("$CUSTOM_PORT")
    else
        ports_to_scan=("${TLS_PORTS[@]}")
    fi

    # Process domains
    for domain in "${DOMAINS[@]}"; do
        log ""
        log "${CYAN}▶ Processing domain: ${domain}${NC}"
        check_crtsh "$domain"
        scan_tls_ports "$domain" "${ports_to_scan[@]}"
    done

    # Process IPs
    for ip in "${IPS[@]}"; do
        log ""
        log "${CYAN}▶ Processing IP: ${ip}${NC}"
        scan_tls_ports "$ip" "${ports_to_scan[@]}"
    done

    # Cert reuse check across all targets
    check_cert_reuse

    section "Audit Complete"
    log "Report saved to: ${LOG_FILE}"
    log "Finished: $(date)"
}

main "$@"
