#!/usr/bin/env bash
umask 077
# FILE:        threat_feed_check.sh
# USAGE:       threat_feed_check.sh -i <IOC> [-t ip|domain|url|hash] [-o output_dir]
# DESCRIPTION: Check a single IOC (IP, domain, URL, or file hash) against multiple
#              threat intelligence feeds simultaneously. Autodetects IOC type and
#              runs all feed checks in parallel. Produces per-feed result files and
#              a consolidated threat_summary.txt with feed statuses.
# AUTHOR:      Pacific Northwest Computers (PNWC) ~ github.com/Pnwcomputers
# CONTACT:     see repo for current contact details
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
# Globals
# ---------------------------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR=""
IOC=""
IOC_TYPE=""
LOG_FILE=""
RESULTS_DIR=""

# API key variables — accept canonical names and short doc aliases
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-${ABDB_API_KEY:-}}"
VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-}"
OTX_API_KEY="${OTX_API_KEY:-}"
PHISHTANK_API_KEY="${PHISHTANK_API_KEY:-}"
URLSCAN_API_KEY="${URLSCAN_API_KEY:-}"
URLHAUS_AUTH_KEY="${URLHAUS_AUTH_KEY:-}"
THREATFOX_AUTH_KEY="${THREATFOX_AUTH_KEY:-}"
MALWAREBAZAAR_AUTH_KEY="${MALWAREBAZAAR_AUTH_KEY:-}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log() {
    local level="$1"
    local msg="$2"
    local color=""
    case "$level" in
        INFO)  color="${GREEN}"  ;;
        WARN)  color="${YELLOW}" ;;
        ERROR) color="${RED}"    ;;
        DATA)  color="${CYAN}"   ;;
        *)     color="${NC}"     ;;
    esac
    printf "${color}[%s] [%s] %s${NC}\n" "$(date '+%H:%M:%S')" "$level" "$msg" | tee -a "$LOG_FILE"
}

warn()  { log WARN  "$1"; }
info()  { log INFO  "$1"; }
error() { log ERROR "$1"; }
data()  { log DATA  "$1"; }

section() {
    local title="$1"
    local line
    line="$(printf '%*s' "${#title}" '' | tr ' ' '─')"
    printf "\n${BLUE}┌─%s─┐${NC}\n" "$line"
    printf "${BLUE}│ %s │${NC}\n" "$title"
    printf "${BLUE}└─%s─┘${NC}\n\n" "$line"
} | tee -a "$LOG_FILE"

# ---------------------------------------------------------------------------
# API key loader
# ---------------------------------------------------------------------------
load_api_keys() {
    local key_file="${HOME}/.config/osint-investigator/api_keys.conf"
    if [[ -f "$key_file" ]]; then
        source_trusted "$key_file" || true
        ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-${ABDB_API_KEY:-}}"
        URLSCAN_API_KEY="${URLSCAN_API_KEY:-}"
        THREATFOX_AUTH_KEY="${THREATFOX_AUTH_KEY:-}"
        MALWAREBAZAAR_AUTH_KEY="${MALWAREBAZAAR_AUTH_KEY:-}"
        info "API keys loaded from $key_file"
    else
        warn "API key file not found: $key_file — authenticated feeds will be skipped"
    fi
}

# Keep provider keys out of curl's process arguments. The private config is
# owner-readable only and removed as soon as the request completes.
curl_config_escape() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '%s' "$value"
}

private_curl_status() {
    local out_file="$1" url="$2"; shift 2
    local config http_code rc=0 header
    config="$(mktemp)" || { warn "Could not create private curl config"; return 1; }
    chmod 600 "$config" || { rm -f "$config"; return 1; }
    {
        printf 'silent\nshow-error\nmax-time = 25\noutput = "%s"\nwrite-out = "%%{http_code}"\nurl = "%s"\n' \
            "$(curl_config_escape "$out_file")" "$(curl_config_escape "$url")"
        for header in "$@"; do
            printf 'header = "%s"\n' "$(curl_config_escape "$header")"
        done
    } > "$config"
    http_code="$(curl --config "$config" 2>"${out_file}.err")" || rc=$?
    rm -f "$config"
    if (( rc != 0 )); then
        warn "Request failed (curl exit $rc); result is UNVERIFIED, see ${out_file}.err"
        return 1
    fi
    printf '%s' "$http_code"
}

private_curl_post_status() {
    local out_file="$1" url="$2" post_data="$3"
    shift 3
    local config http_code rc=0 header
    config="$(mktemp)" || { warn "Could not create private curl config"; return 1; }
    chmod 600 "$config" || { rm -f "$config"; return 1; }
    {
        printf 'silent\nshow-error\nmax-time = 25\nrequest = "POST"\noutput = "%s"\nwrite-out = "%%{http_code}"\nurl = "%s"\ndata = "%s"\n' \
            "$(curl_config_escape "$out_file")" "$(curl_config_escape "$url")" "$(curl_config_escape "$post_data")"
        for header in "$@"; do
            printf 'header = "%s"\n' "$(curl_config_escape "$header")"
        done
    } > "$config"
    http_code="$(curl --config "$config" 2>"${out_file}.err")" || rc=$?
    rm -f "$config"
    if (( rc != 0 )); then
        warn "Request failed (curl exit $rc); result is UNVERIFIED, see ${out_file}.err"
        return 1
    fi
    printf '%s' "$http_code"
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    printf "Usage: %s -i <IOC> [-t ip|domain|url|hash] [-o output_dir]\n" "$SCRIPT_NAME"
    printf "\nOptions:\n"
    printf "  -i <IOC>        Indicator of compromise (IP, domain, URL, or file hash)\n"
    printf "  -t <type>       Force IOC type: ip, domain, url, hash (autodetected if omitted)\n"
    printf "  -o <dir>        Output directory (default: ./threat_results_TIMESTAMP)\n"
    printf "  -h              Show this help\n"
    exit 0
}

# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------
detect_ioc_type() {
    local ioc="$1"

    # Hash detection by length
    local len="${#ioc}"
    if [[ "$len" -eq 32 && "$ioc" =~ ^[0-9a-fA-F]+$ ]]; then
        echo "hash_md5"
        return
    fi
    if [[ "$len" -eq 40 && "$ioc" =~ ^[0-9a-fA-F]+$ ]]; then
        echo "hash_sha1"
        return
    fi
    if [[ "$len" -eq 64 && "$ioc" =~ ^[0-9a-fA-F]+$ ]]; then
        echo "hash_sha256"
        return
    fi

    # URL
    if [[ "$ioc" =~ ^https?:// ]]; then
        echo "url"
        return
    fi

    # IPv4
    if [[ "$ioc" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "ip"
        return
    fi

    # IPv6
    if [[ "$ioc" =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:]+ ]]; then
        echo "ip"
        return
    fi

    # Domain (everything else)
    echo "domain"
}

normalize_ioc_type() {
    local raw="$1"
    case "$raw" in
        hash_md5|hash_sha1|hash_sha256) echo "hash" ;;
        *) echo "$raw" ;;
    esac
}

# ---------------------------------------------------------------------------
# Feed: AbuseIPDB (IP only)
# ---------------------------------------------------------------------------
check_abuseipdb() {
    local ioc="$1"
    local out_file="${RESULTS_DIR}/abuseipdb.json"

    [[ "$IOC_TYPE" != "ip" ]] && { info "AbuseIPDB: skipping (not an IP)"; return; }

    command -v curl &>/dev/null || { warn "curl not found, skipping AbuseIPDB"; return; }

    if [[ -z "$ABUSEIPDB_API_KEY" ]]; then
        warn "AbuseIPDB: ABUSEIPDB_API_KEY not set, skipping"
        return
    fi

    info "AbuseIPDB: querying $ioc ..."
    local http_code
    local encoded_ip
    encoded_ip=$(printf '%s' "$ioc" | jq -sRr @uri) || return
    http_code=$(private_curl_status "$out_file" "https://api.abuseipdb.com/api/v2/check?ipAddress=${encoded_ip}&maxAgeInDays=90" \
        "Key: $ABUSEIPDB_API_KEY" "Accept: application/json") || return

    if [[ "${http_code:-000}" == "200" ]]; then
        local score
        score=$(grep -o '"abuseConfidenceScore":[0-9]*' "$out_file" | grep -o '[0-9]*' || echo "0")
        local flagged
        flagged=$(grep -o '"isWhitelisted":false' "$out_file" | wc -l || echo "0")
        data "AbuseIPDB: confidence score=${score}%, whitelisted_flag=${flagged}"
        if [[ "$score" -gt 0 ]]; then
            echo "FLAGGED:AbuseIPDB:score=${score}" > "${RESULTS_DIR}/flags_abuseipdb.txt"
        fi
    else
        warn "AbuseIPDB: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# Feed: URLhaus (domain/URL/hash)
# ---------------------------------------------------------------------------
check_urlhaus() {
    local ioc="$1"
    local out_file="${RESULTS_DIR}/urlhaus.json"

    [[ "$IOC_TYPE" == "ip" ]] && { info "URLhaus: skipping (IP not supported here)"; return; }

    command -v curl &>/dev/null || { warn "curl not found, skipping URLhaus"; return; }
    if [[ -z "${URLHAUS_AUTH_KEY:-}" ]]; then
        printf '{"query_status":"not_run_auth_key_missing"}\n' > "$out_file"
        warn "URLhaus: skipped because URLHAUS_AUTH_KEY is not configured; result is unknown"
        return
    fi

    info "URLhaus: querying $ioc ..."
    local post_field encoded_ioc
    case "$IOC_TYPE" in
        url)
            encoded_ioc=$(printf '%s' "$ioc" | jq -sRr @uri) || return
            post_field="url=${encoded_ioc}"
            ;;
        hash)
            if [[ ${#ioc} -eq 64 ]]; then
                post_field="sha256_hash=${ioc}"
            elif [[ ${#ioc} -eq 32 ]]; then
                post_field="md5_hash=${ioc}"
            else
                printf '{"query_status":"not_run_unsupported_hash"}\n' > "$out_file"
                warn "URLhaus: SHA-1 is unsupported by this lookup; result is unknown"
                return
            fi
            ;;
        domain) post_field="host=${ioc}" ;;
        *)      post_field="url=${ioc}" ;;
    esac

    local http_code
    http_code=$(private_curl_post_status "$out_file" "https://urlhaus-api.abuse.ch/v1/" \
        "$post_field" "Auth-Key: ${URLHAUS_AUTH_KEY}") || return

    if [[ "${http_code:-000}" == "200" ]]; then
        local query_status
        query_status=$(grep -o '"query_status":"[^"]*"' "$out_file" | cut -d'"' -f4 || echo "unknown")
        data "URLhaus: query_status=${query_status}"
        if [[ "$query_status" == "is_available" || "$query_status" == "listed" ]]; then
            echo "FLAGGED:URLhaus:status=${query_status}" > "${RESULTS_DIR}/flags_urlhaus.txt"
        fi
    else
        warn "URLhaus: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# Feed: ThreatFox (IP/domain/hash)
# ---------------------------------------------------------------------------
check_threatfox() {
    local ioc="$1"
    local out_file="${RESULTS_DIR}/threatfox.json"

    command -v curl &>/dev/null || { warn "curl not found, skipping ThreatFox"; return; }
    if [[ -z "${THREATFOX_AUTH_KEY:-}" ]]; then
        printf '{"query_status":"not_run_auth_key_missing"}\n' > "$out_file"
        warn "ThreatFox: skipped because THREATFOX_AUTH_KEY is not configured; result is unknown"
        return
    fi

    local query search_term payload http_code
    if [[ "$IOC_TYPE" == "hash" ]]; then
        if [[ ${#ioc} -eq 32 || ${#ioc} -eq 64 ]]; then
            query="search_hash"
        else
            printf '{"query_status":"not_run_unsupported_hash"}\n' > "$out_file"
            warn "ThreatFox: SHA-1 is unsupported by this lookup; result is unknown"
            return
        fi
        payload=$(jq -nc --arg query "$query" --arg hash "$ioc" '{query:$query,hash:$hash}') || return
    else
        query="search_ioc"
        payload=$(jq -nc --arg query "$query" --arg search_term "$ioc" '{query:$query,search_term:$search_term}') || return
    fi

    info "ThreatFox: querying $IOC_TYPE ..."
    http_code=$(private_curl_post_status "$out_file" "https://threatfox-api.abuse.ch/api/v1/" \
        "$payload" "Content-Type: application/json" "Auth-Key: ${THREATFOX_AUTH_KEY}") || return

    if [[ "${http_code:-000}" == "200" ]]; then
        local query_status
        query_status=$(grep -o '"query_status":"[^"]*"' "$out_file" | cut -d'"' -f4 || echo "unknown")
        data "ThreatFox: query_status=${query_status}"
        if [[ "$query_status" == "ok" ]]; then
            local count
            count=$(grep -o '"id":' "$out_file" | wc -l || echo "0")
            if [[ "$count" -gt 0 ]]; then
                echo "FLAGGED:ThreatFox:matches=${count}" > "${RESULTS_DIR}/flags_threatfox.txt"
            fi
        fi
    else
        warn "ThreatFox: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# Feed: MalwareBazaar (hash only)
# ---------------------------------------------------------------------------
check_malwarebazaar() {
    local ioc="$1"
    local out_file="${RESULTS_DIR}/malwarebazaar.json"

    [[ "$IOC_TYPE" != "hash" ]] && { info "MalwareBazaar: skipping (hash required)"; return; }
    command -v curl &>/dev/null || { warn "curl not found, skipping MalwareBazaar"; return; }
    if [[ -z "${MALWAREBAZAAR_AUTH_KEY:-}" ]]; then
        printf '{"query_status":"not_run_auth_key_missing"}\n' > "$out_file"
        warn "MalwareBazaar: skipped because MALWAREBAZAAR_AUTH_KEY is not configured; result is unknown"
        return
    fi

    local payload http_code
    payload=$(jq -nc --arg hash "$ioc" '{query:"get_info",hash:$hash}') || return
    info "MalwareBazaar: querying hash ..."
    http_code=$(private_curl_post_status "$out_file" "https://mb-api.abuse.ch/api/v1/" \
        "$payload" "Content-Type: application/json" "Auth-Key: ${MALWAREBAZAAR_AUTH_KEY}") || return

    if [[ "${http_code:-000}" == "200" ]]; then
        local query_status
        query_status=$(grep -o '"query_status":"[^"]*"' "$out_file" | cut -d'"' -f4 || echo "unknown")
        data "MalwareBazaar: query_status=${query_status}"
        if [[ "$query_status" == "ok" ]]; then
            local signature
            signature=$(grep -o '"signature":"[^"]*"' "$out_file" | head -1 | cut -d'"' -f4 || echo "unknown")
            echo "FLAGGED:MalwareBazaar:signature=${signature}" > "${RESULTS_DIR}/flags_malwarebazaar.txt"
        fi
    else
        warn "MalwareBazaar: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# Feed: VirusTotal (IP/domain/URL/hash)
# ---------------------------------------------------------------------------
check_virustotal() {
    local ioc="$1"
    local out_file="${RESULTS_DIR}/virustotal.json"

    command -v curl &>/dev/null || { warn "curl not found, skipping VirusTotal"; return; }

    if [[ -z "$VIRUSTOTAL_API_KEY" ]]; then
        warn "VirusTotal: VIRUSTOTAL_API_KEY not set, skipping"
        return
    fi

    local vt_url
    case "$IOC_TYPE" in
        ip)     vt_url="https://www.virustotal.com/api/v3/ip_addresses/${ioc}" ;;
        domain) vt_url="https://www.virustotal.com/api/v3/domains/${ioc}" ;;
        url)
            local encoded
            encoded=$(printf '%s' "$ioc" | base64 | tr -d '=' | tr '+/' '-_')
            vt_url="https://www.virustotal.com/api/v3/urls/${encoded}"
            ;;
        hash)   vt_url="https://www.virustotal.com/api/v3/files/${ioc}" ;;
        *)      warn "VirusTotal: unknown IOC type"; return ;;
    esac

    info "VirusTotal: querying $ioc ..."
    local http_code
    http_code=$(private_curl_status "$out_file" "$vt_url" "x-apikey: $VIRUSTOTAL_API_KEY") || return

    if [[ "${http_code:-000}" == "200" ]]; then
        local malicious
        malicious=$(grep -o '"malicious":[0-9]*' "$out_file" | head -1 | grep -o '[0-9]*' || echo "0")
        local suspicious
        suspicious=$(grep -o '"suspicious":[0-9]*' "$out_file" | head -1 | grep -o '[0-9]*' || echo "0")
        data "VirusTotal: malicious=${malicious}, suspicious=${suspicious}"
        if [[ "$malicious" -gt 0 || "$suspicious" -gt 0 ]]; then
            echo "FLAGGED:VirusTotal:malicious=${malicious},suspicious=${suspicious}" > "${RESULTS_DIR}/flags_virustotal.txt"
        fi
    elif [[ "$http_code" -eq 404 ]]; then
        data "VirusTotal: IOC not found in database"
    else
        warn "VirusTotal: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# Feed: OTX AlienVault (IP/domain/hash)
# ---------------------------------------------------------------------------
check_otx() {
    local ioc="$1"
    local out_file="${RESULTS_DIR}/otx.json"

    [[ "$IOC_TYPE" == "url" ]] && { info "OTX: treating URL host as domain lookup"; }

    command -v curl &>/dev/null || { warn "curl not found, skipping OTX AlienVault"; return; }

    if [[ -z "$OTX_API_KEY" ]]; then
        warn "OTX AlienVault: OTX_API_KEY not set, skipping"
        return
    fi

    local otx_url
    case "$IOC_TYPE" in
        ip)     otx_url="https://otx.alienvault.com/api/v1/indicators/IPv4/${ioc}/general" ;;
        domain) otx_url="https://otx.alienvault.com/api/v1/indicators/domain/${ioc}/general" ;;
        hash)   otx_url="https://otx.alienvault.com/api/v1/indicators/file/${ioc}/general" ;;
        url)    otx_url="https://otx.alienvault.com/api/v1/indicators/url/${ioc}/general" ;;
        *)      warn "OTX: unknown IOC type"; return ;;
    esac

    info "OTX AlienVault: querying $ioc ..."
    local http_code
    http_code=$(private_curl_status "$out_file" "$otx_url" "X-OTX-API-KEY: $OTX_API_KEY") || return

    if [[ "${http_code:-000}" == "200" ]]; then
        local pulse_count
        pulse_count=$(grep -o '"count":[0-9]*' "$out_file" | head -1 | grep -o '[0-9]*' || echo "0")
        data "OTX AlienVault: pulse_count=${pulse_count}"
        if [[ "$pulse_count" -gt 0 ]]; then
            echo "FLAGGED:OTX:pulses=${pulse_count}" > "${RESULTS_DIR}/flags_otx.txt"
        fi
    else
        warn "OTX AlienVault: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# Feed: PhishTank (URL only)
# ---------------------------------------------------------------------------
check_phishtank() {
    local ioc="$1"
    local out_file="${RESULTS_DIR}/phishtank.json"

    [[ "$IOC_TYPE" != "url" ]] && { info "PhishTank: skipping (URL required)"; return; }

    command -v curl &>/dev/null || { warn "curl not found, skipping PhishTank"; return; }

    info "PhishTank: querying $ioc ..."
    local encoded_url post_data encoded_key
    encoded_url=$(printf '%s' "$ioc" | jq -sRr @uri) || return
    post_data="url=${encoded_url}&format=json"
    if [[ -n "$PHISHTANK_API_KEY" ]]; then
        encoded_key=$(printf '%s' "$PHISHTANK_API_KEY" | jq -sRr @uri) || return
        post_data="${post_data}&app_key=${encoded_key}"
    fi

    local http_code
    http_code=$(private_curl_post_status "$out_file" "https://checkurl.phishtank.com/checkurl/" "$post_data") || return

    if [[ "${http_code:-000}" == "200" ]]; then
        local in_database
        in_database=$(grep -o '"in_database":[^,}]*' "$out_file" | cut -d: -f2 | tr -d ' ' || echo "false")
        local valid
        valid=$(grep -o '"valid":[^,}]*' "$out_file" | cut -d: -f2 | tr -d ' ' || echo "false")
        data "PhishTank: in_database=${in_database}, valid=${valid}"
        if [[ "$in_database" == "true" && "$valid" == "true" ]]; then
            echo "FLAGGED:PhishTank:phishing=confirmed" > "${RESULTS_DIR}/flags_phishtank.txt"
        fi
    else
        warn "PhishTank: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# URLScan.io — search existing scans for domain/IP/URL
# ---------------------------------------------------------------------------
check_urlscan() {
    local ioc="$1"
    local out_file="${RESULTS_DIR}/urlscan.json"

    [[ "$IOC_TYPE" == "hash" ]] && { info "URLScan: skipping (not applicable for hashes)"; return; }

    command -v curl &>/dev/null || { warn "curl not found, skipping URLScan"; return; }

    info "URLScan.io: querying $ioc ..."

    local query
    case "$IOC_TYPE" in
        ip)     query="ip:${ioc}" ;;
        url)    query="page.url:${ioc}" ;;
        domain) query="domain:${ioc}" ;;
        *)      query="${ioc}" ;;
    esac

    local encoded_query
    encoded_query=$(printf '%s' "$query" | jq -sRr @uri 2>/dev/null) || { warn "URLScan: could not encode query"; return; }

    local http_code
    if [[ -n "$URLSCAN_API_KEY" ]]; then
        http_code=$(private_curl_status "$out_file" "https://urlscan.io/api/v1/search/?q=${encoded_query}&size=5" "API-Key: $URLSCAN_API_KEY") || return
    else
        http_code=$(curl -sS --max-time 25 -o "$out_file" -w "%{http_code}" \
            "https://urlscan.io/api/v1/search/?q=${encoded_query}&size=5") || { warn "URLScan request failed; UNVERIFIED"; return; }
    fi

    if [[ "${http_code:-000}" == "200" ]]; then
        local total
        total=$(grep -o '"total":[0-9]*' "$out_file" | cut -d: -f2 || echo "0")
        data "URLScan.io: ${total} existing scan(s) found"
        if [[ "${total:-0}" -gt 0 ]]; then
            echo "FLAGGED:URLScan:existing_scans=${total}" > "${RESULTS_DIR}/flags_urlscan.txt"
        fi
    else
        warn "URLScan.io: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# Summary consolidation
# ---------------------------------------------------------------------------
build_summary() {
    local summary_file="${OUTPUT_DIR}/threat_summary.txt"

    section "Threat Intelligence Summary"

    {
        printf "=%.0s" {1..70}; printf "\n"
        printf "THREAT INTELLIGENCE SUMMARY REPORT\n"
        printf "Generated: %s\n" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf "IOC: %s\n" "$IOC"
        printf "Type: %s\n" "$IOC_TYPE"
        printf "=%.0s" {1..70}; printf "\n\n"
    } > "$summary_file"

    local flag_count=0
    if [[ -s "${RESULTS_DIR}/flags.txt" ]]; then
        flag_count=$(wc -l < "${RESULTS_DIR}/flags.txt")
        printf "FLAGGED BY %d FEED(S):\n\n" "$flag_count" >> "$summary_file"
        while IFS= read -r flag_line; do
            printf "  [!] %s\n" "$flag_line" >> "$summary_file"
        done < "${RESULTS_DIR}/flags.txt"
    else
        printf "No positive matches were returned by the available checks. This is not a cleared result.\n" >> "$summary_file"
    fi

    # Count feeds relevant to this IOC type. This is not a confidence score.
    # Failed, unavailable, or skipped feeds must remain unverified.
    local applicable=0
    case "$IOC_TYPE" in
        ip)     applicable=5 ;;   # AbuseIPDB, ThreatFox, VirusTotal, OTX, URLScan
        url)    applicable=6 ;;   # URLhaus, ThreatFox, VirusTotal, OTX, PhishTank, URLScan
        hash)
            if [[ ${#IOC} -eq 40 ]]; then
                applicable=2 # MalwareBazaar and VirusTotal support SHA-1
            else
                applicable=4 # URLhaus, ThreatFox, MalwareBazaar and VirusTotal
            fi
            ;;
        domain) applicable=5 ;;   # URLhaus, ThreatFox, VirusTotal, OTX, URLScan
        *)      applicable=8 ;;
    esac

    {
        printf "\nFeeds with positive matches: %d\n" "$flag_count"
        printf "Applicable feeds: %d (not a probability or completeness score)\n" "$applicable"
        printf "Review per-feed status; errors, missing keys, skips, and rate limits are UNVERIFIED, never clean.\n"
        printf "\nPer-feed raw results: %s/\n" "$RESULTS_DIR"
    } >> "$summary_file"

    printf "Positive matches: %d of %d applicable feeds (review per-feed status; not a confidence score)\n" "$flag_count" "$applicable" | tee -a "$LOG_FILE"
    info "Summary written to: $summary_file"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    local OPTIND opt
    while getopts ":i:t:o:h" opt; do
        case "$opt" in
            i) IOC="$OPTARG" ;;
            t) IOC_TYPE="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            h) usage ;;
            :) error "Option -${OPTARG} requires an argument"; exit 1 ;;
            \?) error "Unknown option: -${OPTARG}"; exit 1 ;;
        esac
    done

    if [[ -z "$IOC" ]]; then
        error "IOC (-i) is required"
        usage
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    # Set up output directory
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="./threat_results_${TIMESTAMP}"
    fi
    RESULTS_DIR="${OUTPUT_DIR}/feeds"
    mkdir -p "$RESULTS_DIR"
    touch "${RESULTS_DIR}/flags.txt"

    LOG_FILE="${OUTPUT_DIR}/threat_feed_check.log"
    touch "$LOG_FILE"

    section "PNWC Threat Feed Checker"
    info "IOC: $IOC"
    info "Output: $OUTPUT_DIR"

    load_api_keys

    # Detect or validate IOC type
    if [[ -z "$IOC_TYPE" ]]; then
        local raw_type
        raw_type=$(detect_ioc_type "$IOC")
        IOC_TYPE=$(normalize_ioc_type "$raw_type")
        info "Autodetected IOC type: ${IOC_TYPE} (raw: ${raw_type})"
    else
        info "IOC type (forced): $IOC_TYPE"
    fi

    section "Running Feed Checks (parallel)"

    # Run all checks in parallel
    check_abuseipdb    "$IOC" &
    check_urlhaus      "$IOC" &
    check_threatfox    "$IOC" &
    check_malwarebazaar "$IOC" &
    check_virustotal   "$IOC" &
    check_otx          "$IOC" &
    check_phishtank    "$IOC" &
    check_urlscan      "$IOC" &

    wait

    # Merge per-feed flag files (written separately to avoid concurrent-write races)
    cat "${RESULTS_DIR}"/flags_*.txt >> "${RESULTS_DIR}/flags.txt" 2>/dev/null || true

    build_summary

    info "Done. All results in: $OUTPUT_DIR"
}

main "$@"
