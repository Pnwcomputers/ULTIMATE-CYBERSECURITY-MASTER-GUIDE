#!/usr/bin/env bash
# FILE:        case_report_generator.sh
# USAGE:       case_report_generator.sh -c <case_id>
#              case_report_generator.sh -d <case_directory>
#              case_report_generator.sh -c <case_id> --pdf
#              case_report_generator.sh --list
# DESCRIPTION: Rolls up all evidence from a PNWC OSINT case directory into a
#              single structured Markdown report, with optional PDF export.
#              Designed for packaging case materials for law enforcement referral.
# AUTHOR:      Jon-Eric Pienkowski ~ Pacific Northwest Computers (PNWC)
# CONTACT:     jon@pnwcomputers.com
# VERSION:     1.0.0
# CREATED:     2024
# PLATFORM:    Tsurugi Linux / Ubuntu / Debian

set -o pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Config ───────────────────────────────────────────────────────────────────
SCRIPT_NAME="case_report_generator"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DATESTAMP="$(date +%Y%m%d)"
CASES_DIR="${HOME}/OSINT_Cases"
CASE_ID=""
CASE_DIR=""
EXPORT_PDF=0
LIST_CASES=0
LOG_FILE="/tmp/${SCRIPT_NAME}_${TIMESTAMP}.log"
# Placeholder defaults — override via local gitignored branding.conf (see Playbook/branding.conf.example)
INVESTIGATOR_NAME="Investigator Name"
INVESTIGATOR_ORG="Your Company Name"
INVESTIGATOR_CONTACT="investigator@example.com"
BRANDING_CONF="${BRANDING_CONF:-${HOME}/.config/osint-investigator/branding.conf}"
# shellcheck source=/dev/null
[[ -f "$BRANDING_CONF" ]] && source "$BRANDING_CONF"

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

section() {
    log ""
    log "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    log "${CYAN}  $1${NC}"
    log "${CYAN}══════════════════════════════════════════════════════════════${NC}"
}

# ─── Usage ────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BLUE}Case Report Generator — PNWC OSINT Toolkit${NC}"
    echo ""
    echo "Usage:"
    echo "  $(basename "$0") -c <case_id>              Generate report for case"
    echo "  $(basename "$0") -d <case_directory>       Generate report from directory"
    echo "  $(basename "$0") -c <case_id> --pdf        Generate report + export PDF"
    echo "  $(basename "$0") --list                    List available cases"
    echo ""
    echo "Options:"
    echo "  -c <case_id>    Case ID (resolves to \${HOME}/OSINT_Cases/<case_id>)"
    echo "  -d <dir>        Path to case directory"
    echo "  --pdf           Export PDF via pandoc/wkhtmltopdf"
    echo "  --list          List available cases in \${HOME}/OSINT_Cases/"
    echo "  -h              Show this help"
    exit 0
}

# ─── Dependency check ─────────────────────────────────────────────────────────
check_deps() {
    for tool in find grep date; do
        if ! command -v "$tool" &>/dev/null; then
            err "Required tool not found: $tool"
            exit 1
        fi
    done
    if ! command -v jq &>/dev/null; then
        warn "jq not found — JSON parsing will be skipped."
    fi
    if [[ "$EXPORT_PDF" -eq 1 ]]; then
        if ! command -v pandoc &>/dev/null && ! command -v wkhtmltopdf &>/dev/null; then
            warn "Neither pandoc nor wkhtmltopdf found — PDF export will be skipped."
            EXPORT_PDF=0
        fi
    fi
}

# ─── List available cases ─────────────────────────────────────────────────────
list_cases() {
    section "Available Cases — ${CASES_DIR}"
    if [[ ! -d "$CASES_DIR" ]]; then
        warn "Cases directory not found: ${CASES_DIR}"
        return
    fi
    local found=0
    while IFS= read -r case_path; do
        local cid
        cid=$(basename "$case_path")
        local cdate
        cdate=$(stat -c %y "$case_path" 2>/dev/null | cut -d' ' -f1)
        local report_count
        report_count=$(find "$case_path/reports" -name "*.md" 2>/dev/null | wc -l)
        log "  ${GREEN}${cid}${NC}  (modified: ${cdate}, reports: ${report_count})"
        found=1
    done < <(find "$CASES_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    if [[ "$found" -eq 0 ]]; then
        log "  No cases found in ${CASES_DIR}"
    fi
}

# ─── Helpers: extract entities from text files ────────────────────────────────
extract_emails() {
    local dir="$1"
    find "$dir" -type f \( -name "*.txt" -o -name "*.log" -o -name "*.json" -o -name "*.md" \) \
        -exec grep -ohP '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}' {} \; 2>/dev/null \
        | sort -u
}

extract_ips() {
    local dir="$1"
    find "$dir" -type f \( -name "*.txt" -o -name "*.log" -o -name "*.json" -o -name "*.md" \) \
        -exec grep -ohP '\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b' {} \; 2>/dev/null \
        | grep -v '^127\.' | grep -v '^0\.' | sort -u
}

extract_domains() {
    local dir="$1"
    find "$dir" -type f \( -name "*.txt" -o -name "*.log" -o -name "*.json" -o -name "*.md" \) \
        -exec grep -ohP '\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b' {} \; 2>/dev/null \
        | grep -vP '^\.' | sort -u | head -100
}

extract_phones() {
    local dir="$1"
    find "$dir" -type f \( -name "*.txt" -o -name "*.log" -o -name "*.json" -o -name "*.md" \) \
        -exec grep -ohP '\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b' {} \; 2>/dev/null \
        | sort -u
}

extract_usernames() {
    local dir="$1"
    if [[ -d "${dir}/usernames" ]]; then
        find "${dir}/usernames" -type f -name "*.txt" \
            -exec grep -ohP '(?<=username:|Username:|user:)\s*\S+' {} \; 2>/dev/null \
            | sed 's/^\s*//' | sort -u
    fi
}

extract_wallet_addresses() {
    local dir="$1"
    find "$dir" -type f \( -name "*.txt" -o -name "*.log" -o -name "*.json" \) \
        -exec grep -ohP '\b(1|3|bc1)[A-HJ-NP-Za-km-z1-9]{25,62}\b|\b0x[a-fA-F0-9]{40}\b' {} \; 2>/dev/null \
        | sort -u
}

# ─── Parse timestamps from log files ─────────────────────────────────────────
build_timeline() {
    local dir="$1"
    find "$dir" -type f \( -name "*.log" -o -name "*.txt" \) \
        -exec grep -ohP '\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?' {} \; 2>/dev/null \
        | sort -u | head -50
}

# ─── Read JSON field safely ────────────────────────────────────────────────────
jq_field() {
    local json_file="$1"
    local field="$2"
    if command -v jq &>/dev/null && [[ -f "$json_file" ]]; then
        jq -r "$field // empty" "$json_file" 2>/dev/null
    fi
}

# ─── Evidence index ────────────────────────────────────────────────────────────
build_evidence_index() {
    local dir="$1"
    local -a rows=()
    while IFS= read -r fpath; do
        local fname size mtime
        fname=$(basename "$fpath")
        size=$(stat -c %s "$fpath" 2>/dev/null || echo "0")
        mtime=$(stat -c %y "$fpath" 2>/dev/null | cut -d'.' -f1 || echo "unknown")
        local rel_path="${fpath#"${CASE_DIR}/"}"
        rows+=("| \`${rel_path}\` | ${fname} | ${size} B | ${mtime} |")
    done < <(find "$dir" -type f | sort)
    printf '%s\n' "${rows[@]}"
}

# ─── Append section heading to report ─────────────────────────────────────────
md_h1() { echo "# $1"; }
md_h2() { echo "## $1"; }
md_h3() { echo "### $1"; }
md_hr() { echo "---"; }

# ─── Generate the Markdown report ─────────────────────────────────────────────
generate_report() {
    local report_dir="${CASE_DIR}/reports"
    mkdir -p "$report_dir"

    local report_file="${report_dir}/case_report_${DATESTAMP}.md"
    local tmp_file
    tmp_file=$(mktemp)

    log "${BLUE}Building report...${NC}"

    # Read case_info.json
    local case_info="${CASE_DIR}/case_info.json"
    local case_type case_notes case_subject
    case_type=$(jq_field "$case_info" '.case_type')
    case_notes=$(jq_field "$case_info" '.notes')
    case_subject=$(jq_field "$case_info" '.subject')
    local evidence_dir="${CASE_DIR}/evidence"

    # Count evidence files
    local ev_count
    ev_count=$(find "$evidence_dir" -type f 2>/dev/null | wc -l)

    # ── Cover Page ─────────────────────────────────────────────────────────────
    {
        md_h1 "PNWC OSINT Case Report"
        echo ""
        echo "| Field | Value |"
        echo "|-------|-------|"
        echo "| **Case ID** | \`${CASE_ID}\` |"
        echo "| **Investigator** | ${INVESTIGATOR_NAME} |"
        echo "| **Organization** | ${INVESTIGATOR_ORG} |"
        echo "| **Contact** | ${INVESTIGATOR_CONTACT} |"
        echo "| **Date Generated** | $(date '+%Y-%m-%d %H:%M:%S') |"
        echo "| **Case Type** | ${case_type:-Unknown} |"
        echo "| **Subject** | ${case_subject:-Unknown} |"
        echo "| **Total Evidence Files** | ${ev_count} |"
        echo ""
        md_hr
        echo ""

        # ── Executive Summary ───────────────────────────────────────────────
        md_h2 "Executive Summary"
        echo ""
        echo "This report was generated by the PNWC OSINT Investigation Toolkit on \`$(date '+%Y-%m-%d')\`."
        echo "Case **\`${CASE_ID}\`** contains **${ev_count}** evidence file(s) across the following"
        echo "investigation categories: IP analysis, domain analysis, email analysis, phone analysis,"
        echo "SSL certificates, threat feeds, cryptocurrency, and usernames."
        echo ""
        if [[ -n "$case_notes" ]]; then
            echo "**Case Notes:** ${case_notes}"
            echo ""
        fi
        md_hr
        echo ""

        # ── Subject Profile ─────────────────────────────────────────────────
        md_h2 "Subject Profile"
        echo ""
        md_h3 "Email Addresses"
        local emails
        emails=$(extract_emails "$evidence_dir")
        if [[ -n "$emails" ]]; then
            echo "$emails" | while IFS= read -r e; do echo "- \`${e}\`"; done
        else
            echo "_No email addresses extracted._"
        fi
        echo ""

        md_h3 "IP Addresses"
        local ips
        ips=$(extract_ips "$evidence_dir")
        if [[ -n "$ips" ]]; then
            echo "$ips" | while IFS= read -r ip; do echo "- \`${ip}\`"; done
        else
            echo "_No IP addresses extracted._"
        fi
        echo ""

        md_h3 "Domains"
        local domains
        domains=$(extract_domains "$evidence_dir")
        if [[ -n "$domains" ]]; then
            echo "$domains" | while IFS= read -r d; do echo "- \`${d}\`"; done
        else
            echo "_No domains extracted._"
        fi
        echo ""

        md_h3 "Phone Numbers"
        local phones
        phones=$(extract_phones "$evidence_dir")
        if [[ -n "$phones" ]]; then
            echo "$phones" | while IFS= read -r ph; do echo "- \`${ph}\`"; done
        else
            echo "_No phone numbers extracted._"
        fi
        echo ""

        md_h3 "Usernames / Handles"
        local usernames
        usernames=$(extract_usernames "$evidence_dir")
        if [[ -n "$usernames" ]]; then
            echo "$usernames" | while IFS= read -r u; do echo "- \`${u}\`"; done
        else
            echo "_No usernames extracted._"
        fi
        echo ""
        md_hr
        echo ""

        # ── Timeline ────────────────────────────────────────────────────────
        md_h2 "Investigation Timeline"
        echo ""
        echo "Timestamps extracted from evidence logs (chronological):"
        echo ""
        local timeline
        timeline=$(build_timeline "$evidence_dir")
        if [[ -n "$timeline" ]]; then
            echo "| Timestamp |"
            echo "|-----------|"
            echo "$timeline" | while IFS= read -r ts; do echo "| ${ts} |"; done
        else
            echo "_No parseable timestamps found in evidence logs._"
        fi
        echo ""
        md_hr
        echo ""

        # ── Domain Analysis ─────────────────────────────────────────────────
        md_h2 "Domain Analysis"
        echo ""
        local domain_dir="${evidence_dir}/domain_analysis"
        if [[ -d "$domain_dir" ]]; then
            while IFS= read -r f; do
                local fname
                fname=$(basename "$f")
                md_h3 "${fname}"
                echo '```'
                head -80 "$f" 2>/dev/null
                echo '```'
                echo ""
            done < <(find "$domain_dir" -type f | sort | head -20)
        else
            echo "_No domain analysis evidence found._"
        fi
        md_hr
        echo ""

        # ── IP Analysis ─────────────────────────────────────────────────────
        md_h2 "IP Analysis"
        echo ""
        local ip_dir="${evidence_dir}/ip_analysis"
        if [[ -d "$ip_dir" ]]; then
            while IFS= read -r f; do
                local fname
                fname=$(basename "$f")
                md_h3 "${fname}"
                echo '```'
                head -80 "$f" 2>/dev/null
                echo '```'
                echo ""
            done < <(find "$ip_dir" -type f | sort | head -20)
        else
            echo "_No IP analysis evidence found._"
        fi
        md_hr
        echo ""

        # ── Email Analysis ──────────────────────────────────────────────────
        md_h2 "Email Analysis"
        echo ""
        local email_dir="${evidence_dir}/email_analysis"
        if [[ -d "$email_dir" ]]; then
            while IFS= read -r f; do
                local fname
                fname=$(basename "$f")
                md_h3 "${fname}"
                echo '```'
                head -80 "$f" 2>/dev/null
                echo '```'
                echo ""
            done < <(find "$email_dir" -type f | sort | head -20)
        else
            echo "_No email analysis evidence found._"
        fi
        md_hr
        echo ""

        # ── Phone Analysis ──────────────────────────────────────────────────
        md_h2 "Phone Analysis"
        echo ""
        local phone_dir="${evidence_dir}/phone_analysis"
        if [[ -d "$phone_dir" ]]; then
            while IFS= read -r f; do
                local fname
                fname=$(basename "$f")
                md_h3 "${fname}"
                echo '```'
                head -80 "$f" 2>/dev/null
                echo '```'
                echo ""
            done < <(find "$phone_dir" -type f | sort | head -20)
        else
            echo "_No phone analysis evidence found._"
        fi
        md_hr
        echo ""

        # ── Cryptocurrency ──────────────────────────────────────────────────
        md_h2 "Cryptocurrency"
        echo ""
        local crypto_dir="${evidence_dir}/crypto"
        if [[ -d "$crypto_dir" ]]; then
            md_h3 "Wallet Addresses Identified"
            local wallets
            wallets=$(extract_wallet_addresses "$crypto_dir")
            if [[ -n "$wallets" ]]; then
                echo "$wallets" | while IFS= read -r w; do echo "- \`${w}\`"; done
            else
                echo "_No wallet addresses extracted._"
            fi
            echo ""
            md_h3 "Raw Evidence"
            while IFS= read -r f; do
                local fname
                fname=$(basename "$f")
                md_h3 "${fname}"
                echo '```'
                head -50 "$f" 2>/dev/null
                echo '```'
                echo ""
            done < <(find "$crypto_dir" -type f | sort | head -10)
        else
            echo "_No cryptocurrency evidence directory found._"
        fi
        md_hr
        echo ""

        # ── Threat Intelligence ─────────────────────────────────────────────
        md_h2 "Threat Intelligence"
        echo ""
        local threat_dir="${evidence_dir}/threat_feeds"
        if [[ -d "$threat_dir" ]]; then
            while IFS= read -r f; do
                local fname
                fname=$(basename "$f")
                md_h3 "${fname}"
                echo '```'
                head -80 "$f" 2>/dev/null
                echo '```'
                echo ""
            done < <(find "$threat_dir" -type f | sort | head -20)
        else
            echo "_No threat intelligence evidence found._"
        fi
        md_hr
        echo ""

        # ── Evidence Index ──────────────────────────────────────────────────
        md_h2 "Evidence Index"
        echo ""
        echo "| Path | Filename | Size | Modified |"
        echo "|------|----------|------|----------|"
        build_evidence_index "$evidence_dir"
        echo ""
        md_hr
        echo ""

        # ── Recommendations ─────────────────────────────────────────────────
        md_h2 "Recommendations"
        echo ""
        echo "Based on the evidence collected in this case, consider the following reporting channels:"
        echo ""
        md_h3 "Law Enforcement Referrals"
        echo ""
        echo "- **FBI Internet Crime Complaint Center (IC3):** [https://ic3.gov](https://ic3.gov)"
        echo "  Submit a complaint with case ID, timeline, and subject profile from this report."
        echo ""
        echo "- **FTC Report Fraud:** [https://reportfraud.ftc.gov](https://reportfraud.ftc.gov)"
        echo "  Relevant for consumer fraud, impersonation, and financial scams."
        echo ""
        echo "- **CISA (Critical Infrastructure):** [https://cisa.gov/report](https://cisa.gov/report)"
        echo "  If infrastructure attack vectors are identified."
        echo ""
        md_h3 "Registrar Abuse Contacts"
        echo ""
        echo "- Identify registrar via WHOIS data in domain analysis section."
        echo "- Most registrars publish an abuse contact at: \`abuse@<registrar-domain>\`"
        echo "- ICANN Registrar Lookup: [https://lookup.icann.org](https://lookup.icann.org)"
        echo ""
        md_h3 "Hosting Provider Abuse"
        echo ""
        echo "- Identify hosting ASN from IP analysis section."
        echo "- Submit abuse reports to the hosting provider's NOC/abuse team."
        echo "- AbuseIPDB reporting: [https://www.abuseipdb.com](https://www.abuseipdb.com)"
        echo ""
        md_h3 "Financial Fraud"
        echo ""
        echo "- **FinCEN (financial crimes):** [https://fincen.gov](https://fincen.gov)"
        echo "- **State AG consumer protection:** Contact your state Attorney General."
        echo "- **CFPB:** [https://consumerfinance.gov/complaint](https://consumerfinance.gov/complaint)"
        echo ""
        md_hr
        echo ""
        echo "_Report generated by PNWC OSINT Toolkit — ${INVESTIGATOR_NAME} — ${INVESTIGATOR_CONTACT}_"
        echo ""
        echo "_Generated: $(date '+%Y-%m-%d %H:%M:%S')_"

    } > "$tmp_file"

    mv "$tmp_file" "$report_file"
    log "${GREEN}Markdown report saved to: ${report_file}${NC}"

    # ── PDF export ──────────────────────────────────────────────────────────
    if [[ "$EXPORT_PDF" -eq 1 ]]; then
        local pdf_file="${report_dir}/case_report_${DATESTAMP}.pdf"
        section "PDF Export"
        if command -v pandoc &>/dev/null; then
            log "Using pandoc for PDF conversion..."
            if command -v wkhtmltopdf &>/dev/null; then
                pandoc "$report_file" --pdf-engine=wkhtmltopdf -o "$pdf_file" 2>/dev/null \
                    && log "${GREEN}PDF saved to: ${pdf_file}${NC}" \
                    || warn "pandoc PDF conversion failed."
            else
                pandoc "$report_file" -o "$pdf_file" 2>/dev/null \
                    && log "${GREEN}PDF saved to: ${pdf_file}${NC}" \
                    || warn "pandoc PDF conversion failed (no PDF engine available)."
            fi
        elif command -v wkhtmltopdf &>/dev/null; then
            log "Using wkhtmltopdf directly..."
            # Convert markdown to HTML first using sed, then to PDF
            local html_tmp
            html_tmp=$(mktemp --suffix=.html)
            {
                echo "<html><body><pre>"
                cat "$report_file"
                echo "</pre></body></html>"
            } > "$html_tmp"
            wkhtmltopdf "$html_tmp" "$pdf_file" 2>/dev/null \
                && log "${GREEN}PDF saved to: ${pdf_file}${NC}" \
                || warn "wkhtmltopdf conversion failed."
            rm -f "$html_tmp"
        else
            warn "No PDF engine available — skipping PDF export."
        fi
    fi

    echo ""
    log "Report saved to: ${report_file}"
}

# ─── Argument parsing ─────────────────────────────────────────────────────────
parse_args() {
    if [[ $# -eq 0 ]]; then
        usage
    fi

    # Handle long options manually before getopts
    local -a remaining=()
    for arg in "$@"; do
        case "$arg" in
            --pdf)   EXPORT_PDF=1 ;;
            --list)  LIST_CASES=1 ;;
            --help)  usage ;;
            *)       remaining+=("$arg") ;;
        esac
    done
    set -- "${remaining[@]}"

    while getopts ":c:d:h" opt; do
        case "$opt" in
            c) CASE_ID="$OPTARG" ;;
            d) CASE_DIR="$OPTARG" ;;
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

    # Resolve case directory
    if [[ -n "$CASE_ID" && -z "$CASE_DIR" ]]; then
        CASE_DIR="${CASES_DIR}/${CASE_ID}"
    fi

    if [[ -n "$CASE_DIR" && -z "$CASE_ID" ]]; then
        CASE_ID=$(basename "$CASE_DIR")
    fi
}

# ─── Validate case directory ──────────────────────────────────────────────────
validate_case_dir() {
    if [[ ! -d "$CASE_DIR" ]]; then
        err "Case directory not found: ${CASE_DIR}"
        err "Use --list to see available cases."
        exit 1
    fi
    if [[ ! -d "${CASE_DIR}/evidence" ]]; then
        warn "No evidence/ subdirectory found in: ${CASE_DIR}"
        warn "Report will be generated but may be mostly empty."
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    log "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    log "${BLUE}║       Case Report Generator — PNWC OSINT Toolkit            ║${NC}"
    log "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    log "Started:   $(date)"
    log ""

    if [[ "$LIST_CASES" -eq 1 ]]; then
        list_cases
        exit 0
    fi

    if [[ -z "$CASE_DIR" ]]; then
        err "No case ID or directory specified. Use -c <case_id> or -d <dir>."
        usage
    fi

    check_deps
    validate_case_dir

    section "Generating Report — Case: ${CASE_ID}"
    log "Case directory: ${CASE_DIR}"
    log "PDF export:     $( [[ "$EXPORT_PDF" -eq 1 ]] && echo 'yes' || echo 'no' )"
    log ""

    generate_report

    section "Done"
    log "Finished: $(date)"
}

main "$@"
