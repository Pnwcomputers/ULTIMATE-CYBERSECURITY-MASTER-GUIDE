#!/usr/bin/env bash
# FILE:        metadata_stripper.sh
# USAGE:       metadata_stripper.sh -f <file>
#              metadata_stripper.sh -d <directory>
#              metadata_stripper.sh -f <file> --report-only
#              metadata_stripper.sh -d <dir> --strip-only
# DESCRIPTION: Extract and report metadata from evidence files (images, PDFs, documents),
#              then create clean stripped copies for safe sharing. Originals are always
#              preserved — only copies are stripped.
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
OUTPUT_DIR="./metadata_results_$(date +%Y%m%d_%H%M%S)"
LOG_FILE=""
REPORT_FILE=""
TARGET_FILE=""
TARGET_DIR=""
REPORT_ONLY=0
STRIP_ONLY=0

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
${CYAN}${SCRIPT_NAME}${NC} — Evidence Metadata Extractor & Stripper (PNWC OSINT)

${YELLOW}USAGE:${NC}
  $SCRIPT_NAME -f <file>                    # Single file: extract + strip
  $SCRIPT_NAME -d <directory>              # Recursive directory: extract + strip
  $SCRIPT_NAME -f <file> --report-only     # Show metadata only, no stripping
  $SCRIPT_NAME -d <dir> --strip-only       # Strip without detailed report
  $SCRIPT_NAME -o <dir>                    # Custom output directory

${YELLOW}OPTIONS:${NC}
  -f <file>       Target file
  -d <directory>  Target directory (processed recursively)
  -o <dir>        Output directory (default: metadata_results_<timestamp>)
  --report-only   Extract and report metadata only; do not create stripped copies
  --strip-only    Strip metadata only; suppress per-field display
  -h              Show this help

${YELLOW}OUTPUT:${NC}
  <output_dir>/stripped/<filename>    Stripped copies (originals untouched)
  <output_dir>/metadata_report.txt    Full metadata report
  <output_dir>/metadata_stripper.log  Run log
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
check_deps() {
    local missing=0
    if ! command -v exiftool &>/dev/null; then
        log "${RED}[MISSING]${NC} exiftool is required but not installed."
        log "  Install: sudo apt install libimage-exiftool-perl"
        missing=1
    fi
    [[ "$missing" -eq 1 ]] && { log "${RED}[FATAL]${NC} Install missing dependencies and retry."; exit 1; }
}

# ---------------------------------------------------------------------------
# Convert GPS DMS to decimal degrees
# ---------------------------------------------------------------------------
dms_to_decimal() {
    local dms="$1"   # e.g. "37 deg 46' 29.64\" N"
    local sign=1
    [[ "$dms" =~ [SW]$ ]] && sign=-1

    local deg min sec
    deg=$(echo "$dms" | grep -oP '^\d+(?= deg)')
    min=$(echo "$dms" | grep -oP "(?<=deg )\d+(?=')")
    sec=$(echo "$dms" | grep -oP "(?<=')\s*[\d.]+(?=\")" | tr -d ' ')

    if [[ -z "$deg" || -z "$min" || -z "$sec" ]]; then
        echo ""
        return
    fi

    awk -v d="$deg" -v m="$min" -v s="$sec" -v sgn="$sign" \
        'BEGIN { printf "%.6f", sgn * (d + m/60 + s/3600) }'
}

# ---------------------------------------------------------------------------
# Extract and display metadata for a single file
# ---------------------------------------------------------------------------
extract_metadata() {
    local filepath="$1"
    local filename
    filename=$(basename "$filepath")

    log "\n${BLUE}[FILE]${NC} ${filepath}"

    # Run exiftool once, capture all output
    local exif_output
    exif_output=$(exiftool "$filepath" 2>&1)

    if [[ -z "$exif_output" ]]; then
        log "  ${YELLOW}[WARN]${NC} exiftool returned no output."
        return
    fi

    # Helper to pull a field value
    local _exif_get
    _exif_get() {
        echo "$exif_output" | grep -i "^${1}" | head -1 | sed 's/^[^:]*:[[:space:]]*//'
    }

    # Core fields
    local file_type; file_type=$(_exif_get "File Type")
    local mime_type; mime_type=$(_exif_get "MIME Type")
    local make; make=$(_exif_get "Make")
    local model; model=$(_exif_get "Camera Model Name")
    [[ -z "$model" ]] && model=$(_exif_get "Model")
    local software; software=$(_exif_get "Software")
    local creator; creator=$(_exif_get "Creator")
    [[ -z "$creator" ]] && creator=$(_exif_get "Author")
    local last_mod_by; last_mod_by=$(_exif_get "Last Modified By")
    local create_date; create_date=$(_exif_get "Create Date")
    [[ -z "$create_date" ]] && create_date=$(_exif_get "Date\/Time Original")
    [[ -z "$create_date" ]] && create_date=$(_exif_get "Date Created")
    local mod_date; mod_date=$(_exif_get "Modify Date")
    [[ -z "$mod_date" ]] && mod_date=$(_exif_get "File Modification Date\/Time")
    local copyright; copyright=$(_exif_get "Copyright")
    local artist; artist=$(_exif_get "Artist")
    local gps_lat; gps_lat=$(_exif_get "GPS Latitude")
    local gps_lon; gps_lon=$(_exif_get "GPS Longitude")
    local gps_alt; gps_alt=$(_exif_get "GPS Altitude")

    [[ -z "$STRIP_ONLY" ]] && true   # suppress unused warning guard (STRIP_ONLY used in caller)

    if [[ "$STRIP_ONLY" -eq 0 ]]; then
        log "  ${GREEN}File Type:${NC}    ${file_type:-N/A}"
        log "  ${GREEN}MIME Type:${NC}    ${mime_type:-N/A}"
        [[ -n "$make" ]]        && log "  ${GREEN}Camera Make:${NC}  ${make}"
        [[ -n "$model" ]]       && log "  ${GREEN}Camera Model:${NC} ${model}"
        [[ -n "$software" ]]    && log "  ${GREEN}Software:${NC}     ${software}"
        [[ -n "$creator" ]]     && log "  ${GREEN}Author:${NC}       ${creator}"
        [[ -n "$last_mod_by" ]] && log "  ${GREEN}Last Mod By:${NC}  ${last_mod_by}"
        [[ -n "$create_date" ]] && log "  ${GREEN}Created:${NC}      ${create_date}"
        [[ -n "$mod_date" ]]    && log "  ${GREEN}Modified:${NC}     ${mod_date}"
        [[ -n "$copyright" ]]   && log "  ${GREEN}Copyright:${NC}    ${copyright}"
        [[ -n "$artist" ]]      && log "  ${GREEN}Artist:${NC}       ${artist}"
    fi

    # GPS handling — always shown regardless of strip-only
    if [[ -n "$gps_lat" && -n "$gps_lon" ]]; then
        local lat_dec; lat_dec=$(dms_to_decimal "$gps_lat")
        local lon_dec; lon_dec=$(dms_to_decimal "$gps_lon")
        log "  ${RED}[GPS FOUND]${NC} Latitude:  ${gps_lat}"
        log "  ${RED}[GPS FOUND]${NC} Longitude: ${gps_lon}"
        [[ -n "$gps_alt" ]] && log "  ${RED}[GPS FOUND]${NC} Altitude:  ${gps_alt}"
        if [[ -n "$lat_dec" && -n "$lon_dec" ]]; then
            log "  ${RED}[GPS FOUND]${NC} Maps link: https://maps.google.com/?q=${lat_dec},${lon_dec}"
        fi
    fi

    # Dump any custom / non-standard fields to report
    if [[ "$STRIP_ONLY" -eq 0 ]]; then
        local custom_fields
        custom_fields=$(echo "$exif_output" | grep -v -i \
            -e "^File " -e "^MIME" -e "^Make" -e "^Camera" -e "^Model" \
            -e "^Software" -e "^Creator" -e "^Author" -e "^Last Modified" \
            -e "^Date" -e "^Modify" -e "^Copyright" -e "^Artist" \
            -e "^GPS" -e "^Image Size" -e "^Megapixels" -e "^Directory" \
            -e "^ExifTool" -e "^Bits Per" -e "^Color " -e "^Compression" \
            -e "^Encoding" -e "^Interop" -e "^Light Source" -e "^Flash" \
            -e "^Focal" -e "^Exposure" -e "^F Number" -e "^ISO" \
            -e "^Shutter" -e "^Aperture" -e "^Metering" -e "^White Balance" \
            -e "^Scene" -e "^Sensing" -e "^Custom Rendered" -e "^Gain" \
            -e "^Saturation" -e "^Sharpness" -e "^Subject" -e "^Orientation" \
            -e "^Resolution" -e "^YCb" -e "^Exif " -e "^Profile" \
            -e "^X Resolution" -e "^Y Resolution" -e "^Thumbnail" \
            | grep -v '^[[:space:]]*$' || true)
        if [[ -n "$custom_fields" ]]; then
            log "  ${YELLOW}[CUSTOM FIELDS]${NC}"
            while IFS= read -r cf_line; do
                log "    ${cf_line}"
            done <<< "$custom_fields"
        fi
    fi

    # Append to text report
    {
        echo "================================================================"
        echo "FILE: ${filepath}"
        echo "----------------------------------------------------------------"
        echo "$exif_output"
        echo ""
    } >> "$REPORT_FILE"
}

# ---------------------------------------------------------------------------
# Strip metadata from a single file
# ---------------------------------------------------------------------------
strip_metadata() {
    local filepath="$1"
    local stripped_dir="${OUTPUT_DIR}/stripped"
    local filename
    filename=$(basename "$filepath")
    local stripped_path="${stripped_dir}/${filename}"

    # Skip if this file lives inside our own stripped dir
    if [[ "$filepath" == "${stripped_dir}"* ]]; then
        return 0
    fi

    mkdir -p "$stripped_dir"

    exiftool -all= -o "$stripped_path" "$filepath" -overwrite_original 2>&1 | tee -a "$LOG_FILE" >/dev/null

    if [[ -f "$stripped_path" ]]; then
        # Verify strip
        local remaining
        remaining=$(exiftool "$stripped_path" 2>/dev/null | grep -v -e "^File " -e "^MIME" \
            -e "^Directory" -e "^ExifTool" -e "^Image Size" -e "^Megapixels" \
            -e "^Bits Per" -e "^Color " -e "^Compression" \
            -e "^X Resolution" -e "^Y Resolution" -e "^Resolution Unit" \
            -e "^Profile" -e "^Encoding" \
            | grep -v '^[[:space:]]*$' | wc -l)
        if [[ "$remaining" -eq 0 ]]; then
            log "  ${GREEN}[STRIPPED]${NC} ${stripped_path}"
        else
            log "  ${YELLOW}[PARTIAL STRIP]${NC} ${remaining} fields remain: ${stripped_path}"
        fi
        echo "STRIPPED: ${stripped_path}" >> "$REPORT_FILE"
    else
        log "  ${RED}[STRIP FAILED]${NC} Could not create: ${stripped_path}"
        echo "STRIP FAILED: ${filepath}" >> "$REPORT_FILE"
    fi
}

# ---------------------------------------------------------------------------
# Process a single file
# ---------------------------------------------------------------------------
process_file() {
    local filepath="$1"

    if [[ ! -f "$filepath" ]]; then
        log "${RED}[ERROR]${NC} File not found: ${filepath}"
        return 1
    fi

    if [[ "$REPORT_ONLY" -eq 0 ]]; then
        # Check if already-stripped copy exists in output dir
        local filename; filename=$(basename "$filepath")
        local stripped_check="${OUTPUT_DIR}/stripped/${filename}"
        if [[ -f "$stripped_check" ]]; then
            log "${YELLOW}[SKIP]${NC} Already stripped: ${filename}"
            return 0
        fi
    fi

    extract_metadata "$filepath"

    if [[ "$REPORT_ONLY" -eq 0 ]]; then
        strip_metadata "$filepath"
    fi
}

# ---------------------------------------------------------------------------
# Parse long options manually before getopts
# ---------------------------------------------------------------------------
parse_args() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --report-only)
                REPORT_ONLY=1
                shift
                ;;
            --strip-only)
                STRIP_ONLY=1
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
    while getopts ":f:d:o:h" opt; do
        case "$opt" in
            f) TARGET_FILE="$OPTARG" ;;
            d) TARGET_DIR="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            h) usage ;;
            :) echo -e "${RED}[ERROR]${NC} Option -${OPTARG} requires an argument."; exit 1 ;;
            \?) echo -e "${RED}[ERROR]${NC} Unknown option: -${OPTARG}"; usage ;;
        esac
    done

    if [[ -z "$TARGET_FILE" && -z "$TARGET_DIR" ]]; then
        echo -e "${RED}[ERROR]${NC} Provide -f <file> or -d <directory>"
        usage
    fi
    if [[ -n "$TARGET_FILE" && ! -f "$TARGET_FILE" ]]; then
        echo -e "${RED}[ERROR]${NC} File not found: ${TARGET_FILE}"
        exit 1
    fi
    if [[ -n "$TARGET_DIR" && ! -d "$TARGET_DIR" ]]; then
        echo -e "${RED}[ERROR]${NC} Directory not found: ${TARGET_DIR}"
        exit 1
    fi
    if [[ "$REPORT_ONLY" -eq 1 && "$STRIP_ONLY" -eq 1 ]]; then
        echo -e "${RED}[ERROR]${NC} --report-only and --strip-only are mutually exclusive."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    mkdir -p "${OUTPUT_DIR}"
    LOG_FILE="${OUTPUT_DIR}/metadata_stripper.log"
    REPORT_FILE="${OUTPUT_DIR}/metadata_report.txt"
    : > "$LOG_FILE"
    : > "$REPORT_FILE"

    section "PNWC Metadata Stripper"
    log "Started:    $(date)"
    log "Output dir: ${OUTPUT_DIR}"
    [[ "$REPORT_ONLY" -eq 1 ]] && log "${YELLOW}Mode:${NC}       Report only (no stripping)"
    [[ "$STRIP_ONLY" -eq 1 ]]  && log "${YELLOW}Mode:${NC}       Strip only (minimal display)"

    check_deps

    local file_count=0
    local gps_count=0

    if [[ -n "$TARGET_FILE" ]]; then
        process_file "$TARGET_FILE"
        (( file_count++ ))
        grep -q "GPS" "${OUTPUT_DIR}/metadata_report.txt" 2>/dev/null && (( gps_count++ )) || true
    elif [[ -n "$TARGET_DIR" ]]; then
        local abs_target_dir
        abs_target_dir=$(realpath "$TARGET_DIR")
        while IFS= read -r -d '' found_file; do
            process_file "$found_file"
            (( file_count++ ))
        done < <(find "$abs_target_dir" -type f \
            \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" \
               -o -iname "*.pdf" -o -iname "*.docx" -o -iname "*.xlsx" \
               -o -iname "*.pptx" -o -iname "*.mp4" -o -iname "*.mov" \
               -o -iname "*.heic" -o -iname "*.tiff" -o -iname "*.gif" \
               -o -iname "*.bmp" -o -iname "*.webp" \) \
            -print0)
    fi

    gps_count=$(grep -c "GPS FOUND" "$LOG_FILE" 2>/dev/null || true)

    section "Summary"
    log "  Files processed:  ${file_count}"
    log "  GPS hits:         ${RED}${gps_count}${NC}"
    log "  Report:           ${REPORT_FILE}"
    [[ "$REPORT_ONLY" -eq 0 ]] && log "  Stripped copies:  ${OUTPUT_DIR}/stripped/"
    log "\n${GREEN}Done.${NC}"
}

main "$@"
