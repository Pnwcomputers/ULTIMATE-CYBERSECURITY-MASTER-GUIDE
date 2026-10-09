#!/usr/bin/env bash
# FILE:        username_audit.sh
# USAGE:       username_audit.sh -u <username> [-u <username2>] [-e <email>]
#                                [-n "Full Name"] [-o output_dir]
# DESCRIPTION: Comprehensive username/account OSINT. Runs Sherlock, Maigret, and
#              Blackbird, then collates all found profiles into a structured report.
#              Derives username variants from email addresses, full names, and
#              domain registrant info. Outputs a unified found_profiles.md table.
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
# Paths
# ---------------------------------------------------------------------------
CONFIG_DIR="${HOME}/.config/osint-investigator"
API_KEYS_FILE="${CONFIG_DIR}/api_keys.conf"
TOOLS_DIR="${CONFIG_DIR}/tools"
SCRIPT_NAME="$(basename "$0")"
LOG_FILE="${CONFIG_DIR}/username_audit.log"

# Platforms known to return false positives — require manual verification
MANUAL_VERIFY_PLATFORMS="twitter x.com instagram linkedin"

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
# Setup
# ---------------------------------------------------------------------------
setup_dirs() {
    mkdir -p "${CONFIG_DIR}"
    touch "${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Username derivation
# ---------------------------------------------------------------------------
derive_usernames() {
    local input="$1"
    local -a variants=()

    # If it looks like an email, extract the local part and domain user info
    local local_part=""
    if [[ "$input" == *"@"* ]]; then
        local_part="${input%%@*}"
        # Normalise separators to space for name splitting
        local name_guess
        name_guess="$(echo "$local_part" | tr '._ -' ' ')"
        # Recurse on the name guess
        local derived_from_name
        derived_from_name="$(derive_usernames "$name_guess")"
        # Also add the raw local part variants
        variants+=("$local_part")
        variants+=("$(echo "$local_part" | tr -d '.')")
        variants+=("$(echo "$local_part" | tr -d '_')")
        while IFS= read -r v; do
            variants+=("$v")
        done <<< "$derived_from_name"
    else
        # Treat as a name or username
        local cleaned
        cleaned="$(echo "$input" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' ' ' | xargs)"
        read -r -a parts <<< "$cleaned"
        local first="${parts[0]:-}"
        local last="${parts[${#parts[@]}-1]:-}"
        local initial="${first:0:1}"

        # Only add non-empty variants
        [[ -n "$first" ]]                          && variants+=("$first")
        [[ -n "$last" && "$last" != "$first" ]]    && variants+=("$last")
        [[ -n "$first" && -n "$last" && "$first" != "$last" ]] && {
            variants+=("${first}${last}")
            variants+=("${first}_${last}")
            variants+=("${first}.${last}")
            variants+=("${first:0:1}${last}")
            variants+=("${last}${first}")
            variants+=("${last}${first:0:1}")
            variants+=("${initial}${last}")
            variants+=("${first}${last:0:1}")
        }
        # Strip trailing digits and re-add base
        local base_no_digits
        base_no_digits="$(echo "$cleaned" | tr -d '0-9' | tr -s ' ' | xargs)"
        [[ -n "$base_no_digits" && "$base_no_digits" != "$cleaned" ]] && variants+=("${base_no_digits// /}")
    fi

    # Deduplicate and print
    local seen=()
    for v in "${variants[@]}"; do
        [[ -z "$v" ]] && continue
        local already=0
        for s in "${seen[@]}"; do
            [[ "$s" == "$v" ]] && already=1 && break
        done
        if [[ "$already" -eq 0 ]]; then
            seen+=("$v")
            echo "$v"
        fi
    done
}

# ---------------------------------------------------------------------------
# Platform check: does a URL belong to a manual-verify platform?
# ---------------------------------------------------------------------------
is_manual_platform() {
    local url="$1"
    local platform
    for platform in $MANUAL_VERIFY_PLATFORMS; do
        if echo "$url" | grep -qi "$platform"; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# MD5 of a string (for Gravatar)
# ---------------------------------------------------------------------------
md5_string() {
    local input="$1"
    echo -n "$input" | md5sum | awk '{print $1}'
}

# ---------------------------------------------------------------------------
# Run Sherlock for a single username
# ---------------------------------------------------------------------------
run_sherlock() {
    local username="$1"
    local output_dir="$2"
    local outfile="${output_dir}/sherlock_${username}.txt"

    command -v sherlock &>/dev/null || { warn "sherlock not found, skipping Sherlock for ${username}"; return; }

    log "${BLUE}[SHERLOCK]${NC} Scanning: ${username}"
    sherlock --timeout 10 --print-found --output "$outfile" "$username" >> "$LOG_FILE" 2>&1
    log "${GREEN}[SHERLOCK]${NC} Output: ${outfile}"
}

# ---------------------------------------------------------------------------
# Run Maigret for a single username
# ---------------------------------------------------------------------------
run_maigret() {
    local username="$1"
    local output_dir="$2"
    local outjson="${output_dir}/maigret_${username}.json"

    command -v maigret &>/dev/null || { warn "maigret not found, skipping Maigret for ${username}"; return; }

    log "${BLUE}[MAIGRET]${NC} Scanning: ${username}"
    maigret --timeout 10 -a --no-progressbar -J "$outjson" "$username" >> "$LOG_FILE" 2>&1
    log "${GREEN}[MAIGRET]${NC} Output: ${outjson}"
}

# ---------------------------------------------------------------------------
# Run Blackbird for a single username
# ---------------------------------------------------------------------------
run_blackbird() {
    local username="$1"
    local output_dir="$2"
    local outjson="${output_dir}/blackbird_${username}.json"
    local blackbird_script="${TOOLS_DIR}/blackbird/blackbird.py"

    if [[ ! -f "$blackbird_script" ]]; then
        warn "Blackbird not found at ${blackbird_script}, skipping for ${username}"
        return
    fi

    command -v python3 &>/dev/null || { warn "python3 not found, skipping Blackbird"; return; }

    log "${BLUE}[BLACKBIRD]${NC} Scanning: ${username}"
    python3 "$blackbird_script" --username "$username" --json "$outjson" >> "$LOG_FILE" 2>&1
    log "${GREEN}[BLACKBIRD]${NC} Output: ${outjson}"
}

# ---------------------------------------------------------------------------
# Parse Sherlock output (plain text, one URL per line starting with [+])
# Emits: "URL|sherlock"
# ---------------------------------------------------------------------------
parse_sherlock() {
    local txtfile="$1"
    [[ -f "$txtfile" ]] || return
    grep -E '^\[[\+]' "$txtfile" | sed 's/^\[.\] //' | while IFS= read -r line; do
        echo "${line}|sherlock"
    done
}

# ---------------------------------------------------------------------------
# Parse Maigret JSON output
# Emits: "URL|maigret"
# ---------------------------------------------------------------------------
parse_maigret() {
    local jsonfile="$1"
    [[ -f "$jsonfile" ]] || return
    command -v python3 &>/dev/null || return
    python3 - "$jsonfile" <<'PYEOF'
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    sys.exit(0)

sites = data if isinstance(data, dict) else {}
for site_name, info in sites.items():
    if not isinstance(info, dict):
        continue
    status = info.get("status", {})
    if isinstance(status, dict):
        status_id = status.get("id", "")
    else:
        status_id = str(status)
    if status_id in ("found", "claimed", "Claimed"):
        url = info.get("url", info.get("url_user", ""))
        if url:
            print(f"{url}|maigret")
PYEOF
}

# ---------------------------------------------------------------------------
# Parse Blackbird JSON output
# Emits: "URL|blackbird"
# ---------------------------------------------------------------------------
parse_blackbird() {
    local jsonfile="$1"
    [[ -f "$jsonfile" ]] || return
    command -v python3 &>/dev/null || return
    python3 - "$jsonfile" <<'PYEOF'
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    sys.exit(0)

# Blackbird JSON varies by version; handle list or dict
results = data if isinstance(data, list) else data.get("sites", data.get("results", []))
if isinstance(results, dict):
    results = list(results.values())

for entry in results:
    if not isinstance(entry, dict):
        continue
    found = entry.get("found", entry.get("status", ""))
    if str(found).lower() in ("true", "found", "1", "yes"):
        url = entry.get("url", entry.get("uri", ""))
        if url:
            print(f"{url}|blackbird")
PYEOF
}

# ---------------------------------------------------------------------------
# API-based lookups (no dedicated tool required — just curl)
# ---------------------------------------------------------------------------

check_github() {
    local username="$1"
    local output_dir="$2"
    command -v curl &>/dev/null || { warn "curl not found, skipping GitHub lookup"; return; }

    local response
    response="$(curl -s --max-time 10 "https://api.github.com/users/${username}" 2>/dev/null)"
    local login
    login="$(echo "$response" | grep '"login"' | head -1 | sed 's/.*: *"//;s/".*//')"

    if [[ -n "$login" ]]; then
        echo "https://github.com/${login}|api_direct" >> "${output_dir}/api_found.txt"
        log "${GREEN}[GITHUB]${NC} Found: https://github.com/${login}"
    fi
}

check_gitlab() {
    local username="$1"
    local output_dir="$2"
    command -v curl &>/dev/null || { warn "curl not found, skipping GitLab lookup"; return; }

    local response
    response="$(curl -s --max-time 10 "https://gitlab.com/api/v4/users?username=${username}" 2>/dev/null)"
    if echo "$response" | grep -q '"username"'; then
        echo "https://gitlab.com/${username}|api_direct" >> "${output_dir}/api_found.txt"
        log "${GREEN}[GITLAB]${NC} Found: https://gitlab.com/${username}"
    fi
}

check_npm() {
    local username="$1"
    local output_dir="$2"
    command -v curl &>/dev/null || { warn "curl not found, skipping npm lookup"; return; }

    local response
    response="$(curl -s --max-time 10 "https://registry.npmjs.org/-/user/org.couchdb.user:${username}" 2>/dev/null)"
    if echo "$response" | grep -q '"name"'; then
        echo "https://www.npmjs.com/~${username}|api_direct" >> "${output_dir}/api_found.txt"
        log "${GREEN}[NPM]${NC} Found: https://www.npmjs.com/~${username}"
    fi
}

check_gravatar() {
    local email="$1"
    local output_dir="$2"
    [[ -z "$email" ]] && return
    command -v curl &>/dev/null || { warn "curl not found, skipping Gravatar"; return; }

    local hash
    hash="$(md5_string "$(echo "$email" | tr '[:upper:]' '[:lower:]' | xargs)")"
    local gravatar_url="https://www.gravatar.com/${hash}"
    local http_code
    http_code="$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://www.gravatar.com/avatar/${hash}?d=404" 2>/dev/null)"

    if [[ "$http_code" == "200" ]]; then
        echo "${gravatar_url}|api_direct" >> "${output_dir}/api_found.txt"
        log "${GREEN}[GRAVATAR]${NC} Profile found: ${gravatar_url}"
    fi
}

print_intelx_prompt() {
    local username="$1"
    if [[ -n "${INTELX_API_KEY:-}" ]]; then
        log "${YELLOW}[INTELX]${NC} Paste into browser or API client: https://intelx.io/search?q=${username}"
    else
        log "${YELLOW}[INTELX]${NC} (No API key set) Manual search: https://intelx.io/search?q=${username}"
    fi
}

# ---------------------------------------------------------------------------
# Collate all found profiles into a Markdown report
# ---------------------------------------------------------------------------
collate_report() {
    local output_dir="$1"
    local report_file="${output_dir}/found_profiles.md"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    {
        echo "# Username Audit — Found Profiles"
        echo ""
        echo "**Generated:** ${timestamp}"
        echo "**Report:** ${report_file}"
        echo ""
        echo "| Platform | URL | Source Tool(s) | Status |"
        echo "|----------|-----|----------------|--------|"
    } > "$report_file"

    # Collect all raw "URL|source" lines
    local tmpfile
    tmpfile="$(mktemp)"

    # Sherlock
    for f in "${output_dir}"/sherlock_*.txt; do
        [[ -f "$f" ]] && parse_sherlock "$f" >> "$tmpfile"
    done

    # Maigret
    for f in "${output_dir}"/maigret_*.json; do
        [[ -f "$f" ]] && parse_maigret "$f" >> "$tmpfile"
    done

    # Blackbird
    for f in "${output_dir}"/blackbird_*.json; do
        [[ -f "$f" ]] && parse_blackbird "$f" >> "$tmpfile"
    done

    # API direct
    [[ -f "${output_dir}/api_found.txt" ]] && cat "${output_dir}/api_found.txt" >> "$tmpfile"

    # Merge: group by URL, accumulate sources
    command -v python3 &>/dev/null || {
        warn "python3 not found, skipping report collation"
        rm -f "$tmpfile"
        return
    }

    python3 - "$tmpfile" "$report_file" <<'PYEOF'
import sys
from collections import defaultdict
from urllib.parse import urlparse

infile = sys.argv[1]
outfile = sys.argv[2]

url_sources = defaultdict(set)
with open(infile) as f:
    for line in f:
        line = line.strip()
        if not line or '|' not in line:
            continue
        url, source = line.rsplit('|', 1)
        url = url.strip()
        source = source.strip()
        if url:
            url_sources[url].add(source)

MANUAL_PLATFORMS = {"twitter", "x.com", "instagram", "linkedin"}

rows = []
for url, sources in sorted(url_sources.items()):
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        host = url.lower()

    platform = host.replace("www.", "")
    sources_str = ", ".join(sorted(sources))

    needs_manual = any(mp in host for mp in MANUAL_PLATFORMS)
    status = "[MANUAL] Verify manually" if needs_manual else "Found"
    rows.append((platform, url, sources_str, status))

with open(outfile, 'a') as f:
    for platform, url, sources_str, status in rows:
        f.write(f"| {platform} | {url} | {sources_str} | {status} |\n")

print(f"[COLLATE] {len(rows)} unique profile(s) written to report")
PYEOF

    rm -f "$tmpfile"
    log "${GREEN}[REPORT]${NC} ${report_file}"
}

# ---------------------------------------------------------------------------
# Print manual check prompts for false-positive-prone platforms
# ---------------------------------------------------------------------------
print_manual_prompts() {
    local output_dir="$1"
    local report_file="${output_dir}/found_profiles.md"
    [[ -f "$report_file" ]] || return

    local manual_lines
    manual_lines="$(grep '\[MANUAL\]' "$report_file" 2>/dev/null)"
    if [[ -n "$manual_lines" ]]; then
        section "Manual Verification Required"
        log "${YELLOW}The following platforms are known to return false positives.${NC}"
        log "${YELLOW}Please verify each URL manually before marking as confirmed.${NC}"
        log ""
        echo "$manual_lines" | while IFS='|' read -r _ url _ _; do
            url="$(echo "$url" | xargs)"
            log "  ${YELLOW}[MANUAL]${NC} ${url}"
        done
    fi
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF

${CYAN}${SCRIPT_NAME}${NC} — Username OSINT Auditor (PNWC OSINT Toolkit)

${YELLOW}USAGE:${NC}
  $SCRIPT_NAME -u <username> [-u <username2> ...] [-e <email>] [-n "Full Name"] [-o output_dir]
  $SCRIPT_NAME -h | --help

${YELLOW}OPTIONS:${NC}
  -u <username>    Username to investigate (repeatable)
  -e <email>       Email address — derives username variants and checks Gravatar
  -n "Full Name"   Full name — derives username variants
  -o <dir>         Output directory (default: ~/osint-results/<timestamp>)
  -h, --help       Show this help message

${YELLOW}EXAMPLES:${NC}
  $SCRIPT_NAME -u johndoe
  $SCRIPT_NAME -u johndoe -e john.doe@example.com -n "John Doe"
  $SCRIPT_NAME -u johndoe -u jdoe -o /evidence/case42/

${YELLOW}TOOLS REQUIRED:${NC}
  sherlock, maigret, python3 (for blackbird and JSON parsing), curl, md5sum

${YELLOW}OUTPUT:${NC}
  <output_dir>/
    sherlock_<username>.txt
    maigret_<username>.json
    blackbird_<username>.json
    api_found.txt
    found_profiles.md   ← unified report

EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    setup_dirs

    local -a explicit_usernames=()
    local email=""
    local fullname=""
    local output_dir=""

    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u)
                shift
                [[ -z "${1:-}" ]] && { err "-u requires a username"; exit 1; }
                explicit_usernames+=("$1")
                shift
                ;;
            -e)
                shift
                [[ -z "${1:-}" ]] && { err "-e requires an email address"; exit 1; }
                email="$1"
                shift
                ;;
            -n)
                shift
                [[ -z "${1:-}" ]] && { err "-n requires a full name"; exit 1; }
                fullname="$1"
                shift
                ;;
            -o)
                shift
                [[ -z "${1:-}" ]] && { err "-o requires an output directory"; exit 1; }
                output_dir="$1"
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

    # Set default output dir
    if [[ -z "$output_dir" ]]; then
        local ts
        ts="$(date '+%Y%m%d_%H%M%S')"
        output_dir="${HOME}/osint-results/${ts}"
    fi
    mkdir -p "$output_dir"

    section "Username Audit — PNWC OSINT Toolkit"
    log "${CYAN}Output directory:${NC} ${output_dir}"
    log "${CYAN}Started:${NC} $(date '+%Y-%m-%d %H:%M:%S')"

    # Build deduplicated username list
    local -a all_usernames=()

    # Add explicit usernames
    for u in "${explicit_usernames[@]}"; do
        all_usernames+=("$u")
    done

    # Derive from email
    if [[ -n "$email" ]]; then
        section "Deriving usernames from email: ${email}"
        while IFS= read -r variant; do
            [[ -z "$variant" ]] && continue
            local already=0
            for existing in "${all_usernames[@]}"; do
                [[ "$existing" == "$variant" ]] && already=1 && break
            done
            [[ "$already" -eq 0 ]] && all_usernames+=("$variant") && log "  + ${variant}"
        done < <(derive_usernames "$email")
    fi

    # Derive from full name
    if [[ -n "$fullname" ]]; then
        section "Deriving usernames from name: ${fullname}"
        while IFS= read -r variant; do
            [[ -z "$variant" ]] && continue
            local already=0
            for existing in "${all_usernames[@]}"; do
                [[ "$existing" == "$variant" ]] && already=1 && break
            done
            [[ "$already" -eq 0 ]] && all_usernames+=("$variant") && log "  + ${variant}"
        done < <(derive_usernames "$fullname")
    fi

    if [[ ${#all_usernames[@]} -eq 0 ]]; then
        err "No usernames to scan. Provide at least one via -u, -e, or -n."
        exit 1
    fi

    section "Usernames to scan (${#all_usernames[@]} total)"
    for u in "${all_usernames[@]}"; do
        log "  ${CYAN}•${NC} ${u}"
    done

    # Run tool scans
    section "Running Tool Scans"
    for username in "${all_usernames[@]}"; do
        log ""
        log "${BLUE}━━━ Username: ${username} ━━━${NC}"
        run_sherlock  "$username" "$output_dir"
        run_maigret   "$username" "$output_dir"
        run_blackbird "$username" "$output_dir"
    done

    # API-based direct lookups (GitHub, GitLab, npm — per unique username)
    section "API Direct Lookups"
    for username in "${all_usernames[@]}"; do
        check_github "$username" "$output_dir"
        check_gitlab "$username" "$output_dir"
        check_npm    "$username" "$output_dir"
        print_intelx_prompt "$username"
    done

    # Gravatar (email-based)
    if [[ -n "$email" ]]; then
        check_gravatar "$email" "$output_dir"
    fi

    # Collate everything into the unified report
    section "Collating Report"
    collate_report "$output_dir"

    # Print manual-verify prompts
    print_manual_prompts "$output_dir"

    section "Audit Complete"
    log "${GREEN}[DONE]${NC} Report: ${output_dir}/found_profiles.md"
    log "${GREEN}[DONE]${NC} Full log: ${LOG_FILE}"
}

main "$@"
