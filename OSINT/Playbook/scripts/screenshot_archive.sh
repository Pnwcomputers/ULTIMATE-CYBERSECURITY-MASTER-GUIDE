#!/usr/bin/env bash
# FILE:        screenshot_archive.sh
# USAGE:       screenshot_archive.sh -u <url> [-o output_dir]
#              screenshot_archive.sh -f <url_list_file> [-o output_dir] [-j <parallel_jobs>]
#              screenshot_archive.sh -u https://scam.example.com --force
# DESCRIPTION: Capture and archive timestamped screenshots of web evidence (domains, URLs,
#              admin panels). Generates SHA256 integrity hashes and an HTML gallery index
#              for evidence preservation before scam sites go down.
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
OUTPUT_DIR="./screenshot_archive_$(date +%Y%m%d_%H%M%S)"
LOG_FILE=""
CHECKSUM_FILE=""
INDEX_FILE=""
URL_ARG=""
URL_FILE=""
PARALLEL_JOBS=3
FORCE=0

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
${CYAN}${SCRIPT_NAME}${NC} — Web Evidence Screenshot Archiver (PNWC OSINT)

${YELLOW}USAGE:${NC}
  $SCRIPT_NAME -u <url> [-o output_dir] [--force]
  $SCRIPT_NAME -f <url_list_file> [-o output_dir] [-j <parallel_jobs>] [--force]

${YELLOW}OPTIONS:${NC}
  -u <url>       Single URL or domain to capture
  -f <file>      File containing one URL per line
  -o <dir>       Output directory (default: screenshot_archive_<timestamp>)
  -j <n>         Parallel capture jobs (default: 3)
  --force        Re-capture even if same domain+date already archived
  -h             Show this help

${YELLOW}TOOL PREFERENCE:${NC}
  1. gowitness   (best quality)
  2. eyewitness  (fallback)
  3. cutycapt    (fallback)
  4. curl        (HTML source only — last resort)

${YELLOW}OUTPUT:${NC}
  <output_dir>/<domain>_<port>_<timestamp>.png    Screenshots
  <output_dir>/checksums.sha256                   SHA256 integrity hashes
  <output_dir>/index.html                         Evidence gallery
  <output_dir>/screenshot_archive.log             Run log
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Dependency detection
# ---------------------------------------------------------------------------
detect_capture_tool() {
    if command -v gowitness &>/dev/null; then
        echo "gowitness"
    elif command -v eyewitness &>/dev/null || python3 -c "import eyewitness" 2>/dev/null; then
        echo "eyewitness"
    elif command -v cutycapt &>/dev/null; then
        echo "cutycapt"
    elif command -v curl &>/dev/null; then
        echo "curl"
    else
        echo "none"
    fi
}

# ---------------------------------------------------------------------------
# Normalise URL: ensure scheme is present
# ---------------------------------------------------------------------------
normalise_url() {
    local url="$1"
    if [[ "$url" != http://* && "$url" != https://* ]]; then
        url="https://${url}"
    fi
    echo "$url"
}

# ---------------------------------------------------------------------------
# Extract domain and port from URL for filename construction
# ---------------------------------------------------------------------------
url_to_parts() {
    local url="$1"
    local domain port
    # Strip scheme
    local no_scheme="${url#*://}"
    # Extract host:port portion (before first /)
    local hostport="${no_scheme%%/*}"
    if [[ "$hostport" == *:* ]]; then
        domain="${hostport%%:*}"
        port="${hostport##*:}"
    else
        domain="$hostport"
        # Infer port from scheme
        if [[ "$url" == https://* ]]; then
            port="443"
        else
            port="80"
        fi
    fi
    # Sanitise domain for use in filename
    domain=$(echo "$domain" | sed 's/[^a-zA-Z0-9._-]/_/g')
    echo "${domain}_${port}"
}

# ---------------------------------------------------------------------------
# Check if already captured (same domain+date), respecting --force
# ---------------------------------------------------------------------------
already_captured() {
    local domain_port="$1"
    local today
    today=$(date +%Y%m%d)
    if [[ "$FORCE" -eq 1 ]]; then
        return 1   # always re-capture
    fi
    local existing
    existing=$(find "$OUTPUT_DIR" -maxdepth 1 -name "${domain_port}_${today}*.png" 2>/dev/null | head -1)
    [[ -n "$existing" ]]
}

# ---------------------------------------------------------------------------
# Get HTTP response code for a URL
# ---------------------------------------------------------------------------
get_response_code() {
    local url="$1"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -L "$url" 2>/dev/null || echo "000")
    echo "$code"
}

# ---------------------------------------------------------------------------
# Get final redirect URL
# ---------------------------------------------------------------------------
get_redirect_url() {
    local url="$1"
    local final
    final=$(curl -s -o /dev/null -w "%{url_effective}" --max-time 15 -L "$url" 2>/dev/null || echo "$url")
    echo "$final"
}

# ---------------------------------------------------------------------------
# Capture using gowitness
# ---------------------------------------------------------------------------
capture_gowitness() {
    local url="$1"
    local out_dir="$2"
    local out_file="$3"

    gowitness single --url "$url" --screenshot-path "$out_dir" --no-prompt 2>>"$LOG_FILE" || return 1

    # gowitness generates its own filename; find the newest PNG and rename it
    local newest
    newest=$(find "$out_dir" -maxdepth 1 -name "*.png" -newer "$LOG_FILE" | sort | tail -1)
    if [[ -n "$newest" && "$newest" != "$out_file" ]]; then
        mv "$newest" "$out_file"
    fi
    [[ -f "$out_file" ]]
}

# ---------------------------------------------------------------------------
# Capture using eyewitness
# ---------------------------------------------------------------------------
capture_eyewitness() {
    local url="$1"
    local out_dir="$2"
    local out_file="$3"

    local ew_out_dir="${out_dir}/ew_tmp_$$"
    mkdir -p "$ew_out_dir"

    # Try eyewitness as both a command and a python3 module
    if command -v eyewitness &>/dev/null; then
        eyewitness --single "$url" -d "$ew_out_dir" --no-prompt 2>>"$LOG_FILE" || true
    else
        python3 -m eyewitness --single "$url" -d "$ew_out_dir" --no-prompt 2>>"$LOG_FILE" || true
    fi

    local newest
    newest=$(find "$ew_out_dir" -name "*.png" 2>/dev/null | head -1)
    if [[ -n "$newest" ]]; then
        cp "$newest" "$out_file"
        rm -rf "$ew_out_dir"
        return 0
    fi
    rm -rf "$ew_out_dir"
    return 1
}

# ---------------------------------------------------------------------------
# Capture using cutycapt
# ---------------------------------------------------------------------------
capture_cutycapt() {
    local url="$1"
    local out_file="$2"

    cutycapt --url="$url" --out="$out_file" 2>>"$LOG_FILE"
    [[ -f "$out_file" && -s "$out_file" ]]
}

# ---------------------------------------------------------------------------
# Capture HTML source via curl (last resort)
# ---------------------------------------------------------------------------
capture_curl_html() {
    local url="$1"
    local out_file="$2"
    # Save as .html instead of .png
    local html_file="${out_file%.png}.html"

    curl -s -L --max-time 30 -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
        "$url" -o "$html_file" 2>>"$LOG_FILE"
    if [[ -f "$html_file" && -s "$html_file" ]]; then
        # Rename out_file to html_file in caller context
        echo "$html_file"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Append a row to the HTML index
# ---------------------------------------------------------------------------
append_index_row() {
    local url="$1"
    local capture_time="$2"
    local tool_used="$3"
    local http_code="$4"
    local final_url="$5"
    local file_size="$6"
    local sha256="$7"
    local captured_file="$8"
    local is_html_only="$9"

    local filename
    filename=$(basename "$captured_file")
    local thumb_tag

    if [[ "$is_html_only" -eq 1 ]]; then
        thumb_tag="<div class='html-only'>[HTML source only]<br><a href='${filename}'>View HTML</a></div>"
    else
        thumb_tag="<a href='${filename}'><img src='${filename}' loading='lazy' alt='${url}'></a>"
    fi

    cat >> "$INDEX_FILE" <<HTML
    <tr>
      <td>${thumb_tag}</td>
      <td><a href="${url}" target="_blank">${url}</a></td>
      <td>${capture_time}</td>
      <td>${tool_used}</td>
      <td>${http_code}</td>
      <td><small>${final_url}</small></td>
      <td>${file_size}</td>
      <td><code style="font-size:0.7em">${sha256}</code></td>
    </tr>
HTML
}

# ---------------------------------------------------------------------------
# Capture a single URL
# ---------------------------------------------------------------------------
capture_url() {
    local url="$1"
    local tool="$2"

    url=$(normalise_url "$url")
    local domain_port
    domain_port=$(url_to_parts "$url")
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local out_file="${OUTPUT_DIR}/${domain_port}_${timestamp}.png"
    local capture_time
    capture_time=$(date '+%Y-%m-%d %H:%M:%S')

    if already_captured "$domain_port"; then
        log "${YELLOW}[SKIP]${NC} Already captured today: ${domain_port} (use --force to override)"
        return 0
    fi

    log "\n${BLUE}[CAPTURE]${NC} ${url}"
    log "  Tool:      ${tool}"

    # Get HTTP info
    local http_code; http_code=$(get_response_code "$url")
    local final_url; final_url=$(get_redirect_url "$url")
    log "  HTTP code: ${http_code}"
    [[ "$final_url" != "$url" ]] && log "  Redirect:  ${final_url}"

    local tool_used="$tool"
    local is_html_only=0
    local captured_file=""
    local capture_ok=0

    case "$tool" in
        gowitness)
            if capture_gowitness "$url" "$OUTPUT_DIR" "$out_file"; then
                captured_file="$out_file"
                capture_ok=1
            fi
            ;;
        eyewitness)
            if capture_eyewitness "$url" "$OUTPUT_DIR" "$out_file"; then
                captured_file="$out_file"
                capture_ok=1
            fi
            ;;
        cutycapt)
            if capture_cutycapt "$url" "$out_file"; then
                captured_file="$out_file"
                capture_ok=1
            fi
            ;;
        curl)
            local html_out
            html_out=$(capture_curl_html "$url" "$out_file")
            if [[ -n "$html_out" ]]; then
                captured_file="$html_out"
                tool_used="curl (HTML only)"
                is_html_only=1
                capture_ok=1
                log "  ${YELLOW}[HTML ONLY]${NC} No visual screenshot tool available; saved HTML source."
            fi
            ;;
    esac

    if [[ "$capture_ok" -eq 0 || -z "$captured_file" ]]; then
        log "  ${RED}[FAILED]${NC} Capture failed for: ${url}"
        return 1
    fi

    # File size
    local file_size
    file_size=$(du -sh "$captured_file" 2>/dev/null | cut -f1)

    # SHA256 hash
    local sha256
    sha256=$(sha256sum "$captured_file" 2>/dev/null | awk '{print $1}')
    echo "${sha256}  ${captured_file}" >> "$CHECKSUM_FILE"

    log "  ${GREEN}[SAVED]${NC}   $(basename "$captured_file") (${file_size})"
    log "  ${GREEN}[SHA256]${NC}  ${sha256}"

    append_index_row "$url" "$capture_time" "$tool_used" "$http_code" \
        "$final_url" "$file_size" "$sha256" "$captured_file" "$is_html_only"
}

# ---------------------------------------------------------------------------
# HTML index: open
# ---------------------------------------------------------------------------
init_index() {
    cat > "$INDEX_FILE" <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PNWC Evidence Screenshot Archive</title>
  <style>
    body { font-family: monospace; background: #111; color: #ccc; margin: 20px; }
    h1 { color: #0af; }
    p.meta { color: #888; font-size: 0.85em; }
    table { border-collapse: collapse; width: 100%; }
    th { background: #222; color: #0af; padding: 8px; text-align: left; }
    td { border-bottom: 1px solid #333; padding: 8px; vertical-align: top; }
    img { max-width: 200px; max-height: 150px; border: 1px solid #444; }
    a { color: #0af; }
    .html-only { color: #ff0; font-size: 0.85em; }
    code { color: #8f8; }
  </style>
</head>
<body>
  <h1>PNWC Evidence Screenshot Archive</h1>
  <p class="meta">Generated: PLACEHOLDER_DATE &mdash; Pacific Northwest Computers</p>
  <table>
    <tr>
      <th>Screenshot</th>
      <th>URL</th>
      <th>Captured</th>
      <th>Tool</th>
      <th>HTTP</th>
      <th>Final URL</th>
      <th>Size</th>
      <th>SHA256</th>
    </tr>
HTML
    # Replace placeholder with actual date
    local today_str
    today_str=$(date '+%Y-%m-%d %H:%M:%S')
    sed -i "s/PLACEHOLDER_DATE/${today_str}/" "$INDEX_FILE"
}

# ---------------------------------------------------------------------------
# HTML index: close
# ---------------------------------------------------------------------------
close_index() {
    cat >> "$INDEX_FILE" <<'HTML'
  </table>
</body>
</html>
HTML
}

# ---------------------------------------------------------------------------
# Parse long options before getopts
# ---------------------------------------------------------------------------
parse_args() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force)
                FORCE=1
                shift
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
    set -- "${args[@]}"

    local OPTIND=1
    while getopts ":u:f:o:j:h" opt; do
        case "$opt" in
            u) URL_ARG="$OPTARG" ;;
            f) URL_FILE="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            j) PARALLEL_JOBS="$OPTARG" ;;
            h) usage ;;
            :) echo -e "${RED}[ERROR]${NC} Option -${OPTARG} requires an argument."; exit 1 ;;
            \?) echo -e "${RED}[ERROR]${NC} Unknown option: -${OPTARG}"; usage ;;
        esac
    done

    if [[ -z "$URL_ARG" && -z "$URL_FILE" ]]; then
        echo -e "${RED}[ERROR]${NC} Provide -u <url> or -f <url_list_file>"
        usage
    fi
    if [[ -n "$URL_FILE" && ! -f "$URL_FILE" ]]; then
        echo -e "${RED}[ERROR]${NC} URL file not found: ${URL_FILE}"
        exit 1
    fi
    if ! [[ "$PARALLEL_JOBS" =~ ^[0-9]+$ ]] || [[ "$PARALLEL_JOBS" -lt 1 ]]; then
        echo -e "${RED}[ERROR]${NC} -j must be a positive integer"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="${OUTPUT_DIR}/screenshot_archive.log"
    CHECKSUM_FILE="${OUTPUT_DIR}/checksums.sha256"
    INDEX_FILE="${OUTPUT_DIR}/index.html"
    : > "$LOG_FILE"
    : > "$CHECKSUM_FILE"

    section "PNWC Screenshot Archiver"
    log "Started:       $(date)"
    log "Output dir:    ${OUTPUT_DIR}"
    log "Parallel jobs: ${PARALLEL_JOBS}"
    [[ "$FORCE" -eq 1 ]] && log "${YELLOW}Force mode:${NC}    Re-capturing existing"

    # Detect best available tool
    local tool
    tool=$(detect_capture_tool)
    if [[ "$tool" == "none" ]]; then
        log "${RED}[FATAL]${NC} No capture tool found. Install gowitness, eyewitness, cutycapt, or curl."
        exit 1
    fi
    log "Capture tool:  ${GREEN}${tool}${NC}"

    init_index

    # Build URL list
    local urls=()
    if [[ -n "$URL_ARG" ]]; then
        urls+=("$URL_ARG")
    elif [[ -n "$URL_FILE" ]]; then
        while IFS= read -r line; do
            line="${line%%#*}"
            line="${line//[[:space:]]/}"
            [[ -n "$line" ]] && urls+=("$line")
        done < "$URL_FILE"
    fi

    local total="${#urls[@]}"
    log "URLs to capture: ${total}"

    local success_count=0
    local fail_count=0
    local active_jobs=0

    # Temp dir for tracking job results
    local job_tmp_dir
    job_tmp_dir=$(mktemp -d)

    for url in "${urls[@]}"; do
        # Parallel job control
        while [[ "$active_jobs" -ge "$PARALLEL_JOBS" ]]; do
            wait -n 2>/dev/null || wait
            (( active_jobs-- ))
        done

        local job_result_file
        job_result_file="${job_tmp_dir}/$(echo "$url" | md5sum | cut -c1-8).result"

        (
            if capture_url "$url" "$tool"; then
                echo "ok" > "$job_result_file"
            else
                echo "fail" > "$job_result_file"
            fi
        ) &
        (( active_jobs++ ))
    done

    # Wait for all remaining jobs
    wait

    # Tally results
    for result_file in "${job_tmp_dir}"/*.result; do
        [[ -f "$result_file" ]] || continue
        local res; res=$(< "$result_file")
        if [[ "$res" == "ok" ]]; then
            (( success_count++ ))
        else
            (( fail_count++ ))
        fi
    done
    rm -rf "$job_tmp_dir"

    close_index

    section "Summary"
    log "  Total URLs:       ${total}"
    log "  Captured:         ${GREEN}${success_count}${NC}"
    log "  Failed:           ${RED}${fail_count}${NC}"
    log "  Checksums file:   ${CHECKSUM_FILE}"
    log "  HTML gallery:     ${INDEX_FILE}"
    log "\n${GREEN}Done.${NC}"
}

main "$@"
