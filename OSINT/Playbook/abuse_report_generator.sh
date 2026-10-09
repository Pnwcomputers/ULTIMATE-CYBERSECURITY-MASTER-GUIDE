#!/bin/bash
#===============================================================================
#
#          FILE: abuse_report_generator.sh
#
#         USAGE: ./abuse_report_generator.sh [case_dir]
#
#   DESCRIPTION: Generate draft abuse report emails for various providers
#                Creates ready-to-send abuse reports for registrars, hosts, ISPs
#
#        AUTHOR: Jon-Eric Pienkowski ~ PNW Computers (jon@pnwcomputers.com)
#       VERSION: 1.0
#
#===============================================================================

set -o pipefail

#-------------------------------------------------------------------------------
# COLORS
#-------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

info() { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

#-------------------------------------------------------------------------------
# CONFIGURATION
#-------------------------------------------------------------------------------
CONFIG_DIR="${HOME}/.config/osint-investigator"
REPORTER_CONFIG="${CONFIG_DIR}/reporter_info.conf"
CASE_BASE_DIR="${HOME}/OSINT_Cases"

# Default reporter info (will be overridden by config)
REPORTER_NAME="Jon-Eric Pienkowski"
REPORTER_EMAIL="support@pnwcomputers.com"
REPORTER_ORG="Pacific NW Computers"
REPORTER_PHONE="360-624-7379"

#-------------------------------------------------------------------------------
# LOAD/SAVE REPORTER INFO
#-------------------------------------------------------------------------------
load_reporter_info() {
    if [[ -f "$REPORTER_CONFIG" ]]; then
        # shellcheck source=/dev/null
        source "$REPORTER_CONFIG"
    fi
}

save_reporter_info() {
    mkdir -p "$CONFIG_DIR"
    cat > "$REPORTER_CONFIG" << EOF
# Reporter Information for Abuse Reports
REPORTER_NAME="${REPORTER_NAME}"
REPORTER_EMAIL="${REPORTER_EMAIL}"
REPORTER_ORG="${REPORTER_ORG}"
REPORTER_PHONE="${REPORTER_PHONE}"
EOF
    chmod 600 "$REPORTER_CONFIG"
}

configure_reporter() {
    echo ""
    echo -e "${CYAN}═══ Configure Reporter Information ═══${NC}"
    echo "This information will be included in abuse reports."
    echo ""
    
    read -rp "Your Name: " REPORTER_NAME
    read -rp "Your Email: " REPORTER_EMAIL
    read -rp "Organization (optional): " REPORTER_ORG
    read -rp "Phone (optional): " REPORTER_PHONE
    
    save_reporter_info
    success "Reporter information saved"
}

resolve_case_dir() {
    local input="$1"
    local base_dir
    base_dir=$(cd "$CASE_BASE_DIR" 2>/dev/null && pwd)

    if [[ -z "$input" || -z "$base_dir" ]]; then
        return 1
    fi

    local candidate
    if [[ "$input" == /* ]]; then
        candidate="$input"
    else
        candidate="${CASE_BASE_DIR}/${input}"
    fi

    candidate=$(cd "$candidate" 2>/dev/null && pwd) || return 1

    if [[ "$candidate" == "$base_dir" || "$candidate" == "$base_dir"/* ]]; then
        printf '%s\n' "$candidate"
        return 0
    fi

    return 1
}

#-------------------------------------------------------------------------------
# ABUSE CONTACT LOOKUP
#-------------------------------------------------------------------------------
lookup_abuse_contact() {
    local target="$1"
    local type="$2"  # ip, domain, email
    
    case "$type" in
        ip)
            # Use whois to find abuse contact
            local abuse_email
            abuse_email=$(whois "$target" 2>/dev/null | grep -iE "abuse.*@|OrgAbuseEmail" | head -1 | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
            echo "$abuse_email"
            ;;
        domain)
            # Get registrar abuse contact
            local abuse_email
            abuse_email=$(whois "$target" 2>/dev/null | grep -iE "Registrar Abuse Contact Email" | head -1 | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
            echo "$abuse_email"
            ;;
        email)
            # Extract domain and lookup
            local domain
            domain=$(echo "$target" | cut -d'@' -f2)
            lookup_abuse_contact "$domain" "domain"
            ;;
    esac
}

get_hosting_info() {
    local ip="$1"

    # Get ASN info
    local asn_info
    asn_info=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | tail -1)
    
    # Get org name
    local org_name
    org_name=$(whois "$ip" 2>/dev/null | grep -iE "^OrgName:|^org-name:|^descr:" | head -1 | cut -d':' -f2- | xargs)
    
    echo "ASN: $(echo "$asn_info" | awk '{print $1}')"
    echo "Organization: $org_name"
    echo "Country: $(echo "$asn_info" | awk '{print $3}')"
}

#-------------------------------------------------------------------------------
# EMAIL TEMPLATES
#-------------------------------------------------------------------------------
generate_domain_registrar_report() {
    local domain="$1"
    local output_file="$2"
    local abuse_type="$3"
    local evidence_summary="$4"
    
    local registrar_email
    registrar_email=$(lookup_abuse_contact "$domain" "domain")
    
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    
    cat > "$output_file" << EOF
================================================================================
ABUSE REPORT - DOMAIN REGISTRAR
================================================================================
Generated: ${timestamp}
Case Reference: ${CASE_ID:-N/A}

TO: ${registrar_email:-[REGISTRAR ABUSE EMAIL - lookup required]}
SUBJECT: Abuse Report - Malicious Domain: ${domain}

--------------------------------------------------------------------------------

Dear Abuse Team,

I am reporting the following domain for ${abuse_type:-fraudulent/malicious activity}:

REPORTED DOMAIN: ${domain}

TYPE OF ABUSE:
${abuse_type:-[ ] Phishing
[ ] Scam/Fraud
[ ] Malware Distribution
[ ] Spam
[ ] Impersonation
[ ] Other: ___________}

INCIDENT DESCRIPTION:
${evidence_summary:-[Describe the malicious activity observed]}

EVIDENCE SUMMARY:
- Domain registration date: [Check WHOIS]
- Malicious content hosted: [Describe]
- Victim reports: [Number if applicable]
- Screenshots/Archives: [Available upon request]

REQUESTED ACTION:
1. Suspend the domain immediately
2. Preserve registration records for law enforcement
3. Provide registrant information via proper legal channels if requested

REPORTER INFORMATION:
Name: ${REPORTER_NAME:-[Your Name]}
Email: ${REPORTER_EMAIL:-[Your Email]}
Organization: ${REPORTER_ORG:-[Your Organization]}
Phone: ${REPORTER_PHONE:-[Your Phone]}

I am available to provide additional evidence or clarification as needed.

Thank you for your prompt attention to this matter.

Best regards,
${REPORTER_NAME:-[Your Name]}

================================================================================
ATTACHMENTS TO INCLUDE:
- [ ] Screenshots of malicious content
- [ ] WHOIS records
- [ ] URL list
- [ ] Victim complaint summary
================================================================================
EOF
    
    success "Domain registrar report: $output_file"
    [[ -n "$registrar_email" ]] && info "Suggested recipient: $registrar_email"
}

generate_hosting_provider_report() {
    local ip="$1"
    local output_file="$2"
    local abuse_type="$3"
    local evidence_summary="$4"
    
    local abuse_email
    abuse_email=$(lookup_abuse_contact "$ip" "ip")
    
    local hosting_info
    hosting_info=$(get_hosting_info "$ip")
    
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    
    cat > "$output_file" << EOF
================================================================================
ABUSE REPORT - HOSTING PROVIDER
================================================================================
Generated: ${timestamp}
Case Reference: ${CASE_ID:-N/A}

TO: ${abuse_email:-[HOSTING ABUSE EMAIL - lookup required]}
SUBJECT: Abuse Report - Malicious Content at IP: ${ip}

--------------------------------------------------------------------------------

Dear Abuse Team,

I am reporting malicious activity originating from infrastructure under your control:

REPORTED IP ADDRESS: ${ip}

HOSTING INFORMATION:
${hosting_info}

TYPE OF ABUSE:
${abuse_type:-[ ] Phishing Site
[ ] Scam Operation
[ ] Malware Hosting
[ ] Command & Control Server
[ ] Spam Source
[ ] Other: ___________}

ASSOCIATED DOMAINS (if known):
[List domains resolving to this IP]

INCIDENT DESCRIPTION:
${evidence_summary:-[Describe the malicious activity observed]}

TECHNICAL DETAILS:
- First observed: [Date/Time]
- Still active: [Yes/No]
- Ports/Services: [List if known]
- Related infrastructure: [Other IPs/domains]

EVIDENCE SUMMARY:
- Screenshots: [Available upon request]
- HTTP headers/responses: [Captured]
- DNS records: [Documented]
- Malware samples: [If applicable]

REQUESTED ACTION:
1. Take down malicious content immediately
2. Suspend the customer account
3. Preserve server logs for law enforcement
4. Notify us of actions taken

REPORTER INFORMATION:
Name: ${REPORTER_NAME:-[Your Name]}
Email: ${REPORTER_EMAIL:-[Your Email]}
Organization: ${REPORTER_ORG:-[Your Organization]}
Phone: ${REPORTER_PHONE:-[Your Phone]}

I am available to provide additional evidence or work with law enforcement as needed.

Best regards,
${REPORTER_NAME:-[Your Name]}

================================================================================
ATTACHMENTS TO INCLUDE:
- [ ] Screenshots of malicious content
- [ ] HTTP response captures
- [ ] Nmap scan results
- [ ] Related domain list
================================================================================
EOF
    
    success "Hosting provider report: $output_file"
    [[ -n "$abuse_email" ]] && info "Suggested recipient: $abuse_email"
}

generate_email_provider_report() {
    local email="$1"
    local output_file="$2"
    local abuse_type="$3"
    local evidence_summary="$4"
    
    local domain
    domain=$(echo "$email" | cut -d'@' -f2)
    
    # Common email provider abuse addresses
    local abuse_email=""
    case "$domain" in
        gmail.com|googlemail.com)
            abuse_email="abuse@google.com"
            ;;
        outlook.com|hotmail.com|live.com|msn.com)
            abuse_email="abuse@outlook.com"
            ;;
        yahoo.com|ymail.com)
            abuse_email="abuse@yahoo.com"
            ;;
        protonmail.com|proton.me)
            abuse_email="abuse@protonmail.com"
            ;;
        icloud.com|me.com|mac.com)
            abuse_email="abuse@icloud.com"
            ;;
        *)
            abuse_email="abuse@${domain}"
            ;;
    esac
    
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    
    cat > "$output_file" << EOF
================================================================================
ABUSE REPORT - EMAIL PROVIDER
================================================================================
Generated: ${timestamp}
Case Reference: ${CASE_ID:-N/A}

TO: ${abuse_email}
SUBJECT: Abuse Report - Fraudulent Email Account: ${email}

--------------------------------------------------------------------------------

Dear Abuse Team,

I am reporting the following email address for ${abuse_type:-fraudulent activity}:

REPORTED EMAIL: ${email}

TYPE OF ABUSE:
${abuse_type:-[ ] Phishing
[ ] Scam/Fraud (Romance, Investment, Tech Support, etc.)
[ ] Impersonation
[ ] Spam
[ ] Harassment
[ ] Other: ___________}

INCIDENT DESCRIPTION:
${evidence_summary:-[Describe the fraudulent activity]}

EVIDENCE:
- Number of victims: [If known]
- Financial losses: [If known]
- Date range of activity: [First seen to last seen]
- Related accounts: [Other emails if known]

EMAIL HEADERS (if available):
[Paste relevant headers here or note "Available upon request"]

REQUESTED ACTION:
1. Terminate the fraudulent account
2. Preserve account data for law enforcement
3. Check for related accounts using same recovery info

REPORTER INFORMATION:
Name: ${REPORTER_NAME:-[Your Name]}
Email: ${REPORTER_EMAIL:-[Your Email]}
Organization: ${REPORTER_ORG:-[Your Organization]}
Phone: ${REPORTER_PHONE:-[Your Phone]}

Note: This report may be shared with law enforcement agencies including the FBI IC3.

Best regards,
${REPORTER_NAME:-[Your Name]}

================================================================================
ATTACHMENTS TO INCLUDE:
- [ ] Original scam emails (as .eml files)
- [ ] Email headers
- [ ] Screenshots of communication
- [ ] Victim statements
================================================================================
EOF
    
    success "Email provider report: $output_file"
    info "Suggested recipient: $abuse_email"
}

generate_isp_report() {
    local ip="$1"
    local output_file="$2"
    local abuse_type="$3"
    local evidence_summary="$4"
    
    local abuse_email
    abuse_email=$(lookup_abuse_contact "$ip" "ip")
    
    local hosting_info
    hosting_info=$(get_hosting_info "$ip")
    
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    
    cat > "$output_file" << EOF
================================================================================
ABUSE REPORT - INTERNET SERVICE PROVIDER
================================================================================
Generated: ${timestamp}
Case Reference: ${CASE_ID:-N/A}

TO: ${abuse_email:-[ISP ABUSE EMAIL - lookup required]}
SUBJECT: Abuse Report - Malicious Activity from IP: ${ip}

--------------------------------------------------------------------------------

Dear Abuse Team,

I am reporting malicious network activity originating from an IP address 
allocated to your organization:

REPORTED IP ADDRESS: ${ip}

NETWORK INFORMATION:
${hosting_info}

TYPE OF ABUSE:
${abuse_type:-[ ] Hacking/Intrusion Attempts
[ ] DDoS Attack Source
[ ] Spam/Phishing Source
[ ] Malware Distribution
[ ] Botnet Activity
[ ] Other: ___________}

INCIDENT TIMELINE:
- First observed: [Date/Time]
- Last observed: [Date/Time]
- Duration: [Ongoing/Concluded]

TECHNICAL DETAILS:
${evidence_summary:-[Describe observed malicious activity]}

LOG EVIDENCE:
[Include relevant log excerpts or note "Available upon request"]

REQUESTED ACTION:
1. Investigate the reported activity
2. Take appropriate action against the subscriber
3. Preserve logs for potential law enforcement request

REPORTER INFORMATION:
Name: ${REPORTER_NAME:-[Your Name]}
Email: ${REPORTER_EMAIL:-[Your Email]}
Organization: ${REPORTER_ORG:-[Your Organization]}
Phone: ${REPORTER_PHONE:-[Your Phone]}

Best regards,
${REPORTER_NAME:-[Your Name]}

================================================================================
ATTACHMENTS TO INCLUDE:
- [ ] Firewall/IDS logs
- [ ] Packet captures
- [ ] Timestamps of activity
================================================================================
EOF
    
    success "ISP report: $output_file"
    [[ -n "$abuse_email" ]] && info "Suggested recipient: $abuse_email"
}

generate_ic3_report() {
    local output_file="$1"
    local evidence_summary="$2"
    
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    
    cat > "$output_file" << EOF
================================================================================
IC3 COMPLAINT PREPARATION WORKSHEET
================================================================================
Generated: ${timestamp}
Case Reference: ${CASE_ID:-N/A}

NOTE: This is a preparation worksheet. Submit the actual complaint at:
https://www.ic3.gov/

--------------------------------------------------------------------------------
VICTIM INFORMATION (to be provided by victim)
--------------------------------------------------------------------------------

Full Name: 
Address:
City, State, ZIP:
Country:
Phone:
Email:
Age Range: [ ] Under 20  [ ] 20-29  [ ] 30-39  [ ] 40-49  [ ] 50-59  [ ] 60+

--------------------------------------------------------------------------------
INCIDENT DETAILS
--------------------------------------------------------------------------------

Type of Crime:
[ ] Romance Scam
[ ] Business Email Compromise (BEC)
[ ] Tech Support Scam
[ ] Investment Fraud
[ ] Ransomware
[ ] Identity Theft
[ ] Non-Delivery of Goods/Services
[ ] Lottery/Sweepstakes Scam
[ ] Other: ___________

Date of Incident: 
Date Discovered:

How did the scammer first contact you?
[ ] Email
[ ] Phone Call
[ ] Social Media
[ ] Dating Website/App
[ ] Other Website
[ ] Text Message
[ ] Other: ___________

--------------------------------------------------------------------------------
FINANCIAL INFORMATION
--------------------------------------------------------------------------------

Total Amount Lost: $

Payment Methods Used:
[ ] Wire Transfer - Amount: $_____ Bank: _____
[ ] Cryptocurrency - Amount: $_____ Type: _____
[ ] Gift Cards - Amount: $_____ Type: _____
[ ] Credit Card - Amount: $_____
[ ] Cash App/Venmo/Zelle - Amount: $_____
[ ] Other: ___________

Bank/Financial Institution Used:

Was the money sent domestically or internationally?
Destination Country (if known):

--------------------------------------------------------------------------------
SUSPECT INFORMATION
--------------------------------------------------------------------------------

Name(s) Used by Scammer:

Email Address(es):
${EMAILS:-[List all known scammer emails]}

Phone Number(s):
${PHONES:-[List all known scammer phones]}

Website(s)/Domain(s):
${DOMAINS:-[List all known scammer domains]}

Social Media Profiles:
${USERNAMES:-[List all known scammer profiles]}

Cryptocurrency Addresses:
${CRYPTO_ADDRESSES:-[List all known crypto wallets]}

IP Addresses (from email headers, etc.):
${IPS:-[List all known IPs]}

Physical Address (if known):

Bank Account Information (if known):

--------------------------------------------------------------------------------
NARRATIVE
--------------------------------------------------------------------------------

Describe what happened (be specific about dates, amounts, communications):

${evidence_summary:-[Provide detailed narrative of the scam]}

--------------------------------------------------------------------------------
EVIDENCE CHECKLIST
--------------------------------------------------------------------------------

[ ] Email communications (.eml format preferred)
[ ] Text messages/chat logs
[ ] Screenshots of websites
[ ] Screenshots of social media profiles
[ ] Bank statements showing transfers
[ ] Wire transfer receipts
[ ] Gift card receipts
[ ] Cryptocurrency transaction records
[ ] Phone records
[ ] Email headers
[ ] Domain WHOIS records
[ ] IP investigation results
[ ] Any documents received from scammer

--------------------------------------------------------------------------------
ADDITIONAL AGENCIES TO NOTIFY
--------------------------------------------------------------------------------

[ ] Local Police Department - File local report
[ ] FTC - reportfraud.ftc.gov
[ ] State Attorney General
[ ] CFPB (if financial institution involved)
[ ] SEC (if investment fraud)
[ ] Social Security Administration (if SSN compromised)
[ ] Credit Bureaus (freeze credit if identity theft)

--------------------------------------------------------------------------------
INVESTIGATION FINDINGS (from OSINT)
--------------------------------------------------------------------------------

[Paste summary of investigation findings here]

================================================================================
EOF
    
    success "IC3 worksheet: $output_file"
    info "Submit actual complaint at: https://www.ic3.gov/"
}

generate_social_media_report() {
    local platform="$1"
    local username="$2"
    local output_file="$3"
    local abuse_type="$4"
    local evidence_summary="$5"
    
    local report_url=""
    local abuse_email=""
    
    case "$platform" in
        facebook|fb)
            report_url="https://www.facebook.com/help/contact/274459462613911"
            abuse_email="abuse@fb.com"
            ;;
        instagram|ig)
            report_url="https://help.instagram.com/contact/383679321740945"
            abuse_email="N/A - Use web form"
            ;;
        twitter|x)
            report_url="https://help.twitter.com/forms/abusiveuser"
            abuse_email="N/A - Use web form"
            ;;
        linkedin)
            report_url="https://www.linkedin.com/help/linkedin/ask/TS-RFA"
            abuse_email="abuse@linkedin.com"
            ;;
        tiktok)
            report_url="https://www.tiktok.com/legal/report/feedback"
            abuse_email="N/A - Use web form"
            ;;
        telegram)
            report_url="https://telegram.org/support"
            abuse_email="abuse@telegram.org"
            ;;
        whatsapp)
            report_url="https://www.whatsapp.com/contact/noclient/"
            abuse_email="support@whatsapp.com"
            ;;
        *)
            report_url="[Look up platform's abuse reporting page]"
            abuse_email="[Look up platform's abuse email]"
            ;;
    esac
    
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    
    cat > "$output_file" << EOF
================================================================================
ABUSE REPORT - ${platform^^}
================================================================================
Generated: ${timestamp}
Case Reference: ${CASE_ID:-N/A}

Report URL: ${report_url}
Email (if available): ${abuse_email}

--------------------------------------------------------------------------------

REPORTED ACCOUNT: ${username}
PLATFORM: ${platform}
PROFILE URL: [Insert full profile URL]

TYPE OF ABUSE:
${abuse_type:-[ ] Scam/Fraud
[ ] Impersonation
[ ] Harassment
[ ] Spam
[ ] Fake Account
[ ] Other: ___________}

INCIDENT DESCRIPTION:
${evidence_summary:-[Describe the fraudulent activity]}

EVIDENCE:
- Screenshots of profile
- Screenshots of messages/posts
- Victim count (if known)
- Financial losses (if known)
- Related accounts (if known)

REPORTER INFORMATION:
Name: ${REPORTER_NAME:-[Your Name]}
Email: ${REPORTER_EMAIL:-[Your Email]}

--------------------------------------------------------------------------------
NOTES FOR REPORTING:
--------------------------------------------------------------------------------

1. Screenshot the profile BEFORE reporting (it may be taken down)
2. Use platform's official reporting mechanism first
3. Document the date/time of your report
4. Save any confirmation/reference number
5. Follow up if no action taken within 7 days

================================================================================
EOF
    
    success "Social media report: $output_file"
    info "Report URL: $report_url"
}

#-------------------------------------------------------------------------------
# BATCH REPORT GENERATION
#-------------------------------------------------------------------------------
generate_all_reports() {
    local case_dir="$1"
    local output_dir="${case_dir}/reports/abuse_reports"
    
    mkdir -p "$output_dir"
    
    echo ""
    echo -e "${CYAN}═══ Generating All Abuse Reports ═══${NC}"
    echo ""
    
    # Load case data if available
    if [[ -f "${case_dir}/.case_state" ]]; then
        # shellcheck source=/dev/null
        source "${case_dir}/.case_state"
    fi
    
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Generate domain reports
    if [[ ${#DOMAINS[@]} -gt 0 ]]; then
        for domain in "${DOMAINS[@]}"; do
            local safe_name
            safe_name=$(echo "$domain" | tr '.' '_')
            generate_domain_registrar_report "$domain" \
                "${output_dir}/registrar_${safe_name}_${timestamp}.txt"
        done
    fi
    
    # Generate IP reports
    if [[ ${#IPS[@]} -gt 0 ]]; then
        for ip in "${IPS[@]}"; do
            local safe_name
            safe_name=$(echo "$ip" | tr '.' '_')
            generate_hosting_provider_report "$ip" \
                "${output_dir}/hosting_${safe_name}_${timestamp}.txt"
            generate_isp_report "$ip" \
                "${output_dir}/isp_${safe_name}_${timestamp}.txt"
        done
    fi
    
    # Generate email reports
    if [[ ${#EMAILS[@]} -gt 0 ]]; then
        for email in "${EMAILS[@]}"; do
            local safe_name
            safe_name=$(echo "$email" | tr '@.' '_')
            generate_email_provider_report "$email" \
                "${output_dir}/email_${safe_name}_${timestamp}.txt"
        done
    fi
    
    # Generate IC3 worksheet
    generate_ic3_report "${output_dir}/IC3_worksheet_${timestamp}.txt"
    
    echo ""
    success "All reports generated in: ${output_dir}"
    echo ""
    echo "Reports created:"
    ls -la "$output_dir"/*.txt 2>/dev/null | awk '{print "  " $NF}'
}

#-------------------------------------------------------------------------------
# INTERACTIVE MENU
#-------------------------------------------------------------------------------
show_menu() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           ABUSE REPORT GENERATOR                             ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║  ${WHITE}[1]${NC}${CYAN}  Domain Registrar Report                               ║${NC}"
    echo -e "${CYAN}║  ${WHITE}[2]${NC}${CYAN}  Hosting Provider Report                               ║${NC}"
    echo -e "${CYAN}║  ${WHITE}[3]${NC}${CYAN}  Email Provider Report                                 ║${NC}"
    echo -e "${CYAN}║  ${WHITE}[4]${NC}${CYAN}  ISP Report                                            ║${NC}"
    echo -e "${CYAN}║  ${WHITE}[5]${NC}${CYAN}  Social Media Report                                   ║${NC}"
    echo -e "${CYAN}║  ${WHITE}[6]${NC}${CYAN}  IC3 Complaint Worksheet                               ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║  ${WHITE}[A]${NC}${CYAN}  Generate All Reports (from case data)                 ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║  ${WHITE}[C]${NC}${CYAN}  Configure Reporter Information                        ║${NC}"
    echo -e "${CYAN}║  ${WHITE}[0]${NC}${CYAN}  Exit                                                  ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

interactive_mode() {
    load_reporter_info
    
    while true; do
        show_menu
        read -rp "Select option: " choice
        
        case $choice in
            1)
                read -rp "Enter domain: " domain
                read -rp "Output file [./domain_report.txt]: " outfile
                outfile="${outfile:-./domain_report.txt}"
                generate_domain_registrar_report "$domain" "$outfile"
                ;;
            2)
                read -rp "Enter IP address: " ip
                read -rp "Output file [./hosting_report.txt]: " outfile
                outfile="${outfile:-./hosting_report.txt}"
                generate_hosting_provider_report "$ip" "$outfile"
                ;;
            3)
                read -rp "Enter email address: " email
                read -rp "Output file [./email_report.txt]: " outfile
                outfile="${outfile:-./email_report.txt}"
                generate_email_provider_report "$email" "$outfile"
                ;;
            4)
                read -rp "Enter IP address: " ip
                read -rp "Output file [./isp_report.txt]: " outfile
                outfile="${outfile:-./isp_report.txt}"
                generate_isp_report "$ip" "$outfile"
                ;;
            5)
                echo "Platforms: facebook, instagram, twitter, linkedin, tiktok, telegram, whatsapp"
                read -rp "Enter platform: " platform
                read -rp "Enter username: " username
                read -rp "Output file [./social_report.txt]: " outfile
                outfile="${outfile:-./social_report.txt}"
                generate_social_media_report "$platform" "$username" "$outfile"
                ;;
            6)
                read -rp "Output file [./ic3_worksheet.txt]: " outfile
                outfile="${outfile:-./ic3_worksheet.txt}"
                generate_ic3_report "$outfile"
                ;;
            [Aa])
                read -rp "Enter case directory or case ID: " case_dir
                local resolved
                resolved=$(resolve_case_dir "$case_dir") || {
                    error "Case directory not found or outside ${CASE_BASE_DIR}: $case_dir"
                    continue
                }
                generate_all_reports "$resolved"
                ;;
            [Cc])
                configure_reporter
                ;;
            0)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                warn "Invalid option"
                ;;
        esac
        
        echo ""
        read -rp "Press Enter to continue..."
    done
}

#-------------------------------------------------------------------------------
# MAIN
#-------------------------------------------------------------------------------
main() {
    case "${1:-}" in
        --help|-h)
            echo "Abuse Report Generator"
            echo ""
            echo "Usage: $0 [case_dir]"
            echo "       $0 --interactive"
            echo "       $0 --config"
            echo ""
            echo "Options:"
            echo "  case_dir      Generate all reports for a case"
            echo "  --interactive Interactive mode with menu"
            echo "  --config      Configure reporter information"
            exit 0
            ;;
        --config|-c)
            configure_reporter
            exit 0
            ;;
        --interactive|-i|"")
            interactive_mode
            ;;
        *)
            local resolved
            resolved=$(resolve_case_dir "$1")

            if [[ -n "$resolved" ]]; then
                load_reporter_info
                generate_all_reports "$resolved"
            else
                error "Not a valid case directory under ${CASE_BASE_DIR}: $1"
                exit 1
            fi
            ;;
    esac
}

main "$@"
