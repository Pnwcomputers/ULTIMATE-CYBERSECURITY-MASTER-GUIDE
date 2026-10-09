#!/usr/bin/env bash
# FILE:        crypto_audit.sh
# USAGE:       crypto_audit.sh -a <address> [-a <address2>] [-f <file>] [-o output_dir]
# DESCRIPTION: Investigate cryptocurrency wallet addresses for scam/fraud OSINT cases.
#              Detects coin type from address format, queries blockchain APIs, and checks
#              against scam databases. Produces per-address reports formatted for
#              IC3/FTC submission (dollar amounts, transaction dates, connected addresses).
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
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR=""
LOG_FILE=""
declare -a ADDRESSES=()
ADDRESS_FILE=""

# API key variables — accept canonical names and short doc aliases
ETHERSCAN_API_KEY="${ETHERSCAN_API_KEY:-${ES_API_KEY:-}}"
BLOCKCHAIR_API_KEY="${BLOCKCHAIR_API_KEY:-}"
BLOCKCYPHER_API_KEY="${BLOCKCYPHER_API_KEY:-}"

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
        # shellcheck source=/dev/null
        source "$key_file"
        ETHERSCAN_API_KEY="${ETHERSCAN_API_KEY:-${ES_API_KEY:-}}"
        BLOCKCYPHER_API_KEY="${BLOCKCYPHER_API_KEY:-}"
        info "API keys loaded from $key_file"
    else
        warn "API key file not found: $key_file — some APIs will use unauthenticated rate limits"
    fi
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    printf "Usage: %s -a <address> [-a <address2> ...] [-f <file>] [-o output_dir]\n" "$SCRIPT_NAME"
    printf "\nOptions:\n"
    printf "  -a <address>    Cryptocurrency wallet address (repeatable)\n"
    printf "  -f <file>       File containing one address per line\n"
    printf "  -o <dir>        Output directory (default: ./crypto_audit_TIMESTAMP)\n"
    printf "  -h              Show this help\n"
    printf "\nSupported chains: BTC, ETH, LTC, BCH, DOGE, XRP, XMR\n"
    exit 0
}

# ---------------------------------------------------------------------------
# Chain detection from address format
# ---------------------------------------------------------------------------
detect_chain() {
    local addr="$1"
    local len="${#addr}"

    # Ethereum: 0x + 40 hex chars = 42 total
    if [[ "$addr" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
        echo "ETH"; return
    fi

    # Bitcoin Cash
    if [[ "$addr" =~ ^bitcoincash: || "$addr" =~ ^q[0-9a-z]{41}$ ]]; then
        echo "BCH"; return
    fi

    # Bitcoin bech32 (SegWit)
    if [[ "$addr" =~ ^bc1 ]]; then
        echo "BTC"; return
    fi

    # Litecoin bech32
    if [[ "$addr" =~ ^ltc1 ]]; then
        echo "LTC"; return
    fi

    # Bitcoin P2PKH (starts with 1) — unambiguously BTC
    if [[ "$addr" =~ ^1[a-km-zA-HJ-NP-Z1-9]{25,34}$ ]]; then
        echo "BTC"; return
    fi

    # P2SH (starts with 3) — format-identical for BTC and LTC; audit both chains
    if [[ "$addr" =~ ^3[a-km-zA-HJ-NP-Z1-9]{25,34}$ ]]; then
        echo "P2SH"; return
    fi

    # Litecoin P2PKH (starts with L or M)
    if [[ "$addr" =~ ^[LM][a-km-zA-HJ-NP-Z1-9]{25,34}$ ]]; then
        echo "LTC"; return
    fi

    # Dogecoin
    if [[ "$addr" =~ ^D[a-km-zA-HJ-NP-Z1-9]{25,34}$ ]]; then
        echo "DOGE"; return
    fi

    # XRP: starts with r, 25-34 chars
    if [[ "$addr" =~ ^r[a-km-zA-HJ-NP-Z1-9]{24,33}$ && "$len" -ge 25 && "$len" -le 34 ]]; then
        echo "XRP"; return
    fi

    # Monero: 95 chars starting with 4
    if [[ "$len" -eq 95 && "$addr" =~ ^4 ]]; then
        echo "XMR"; return
    fi

    echo "UNKNOWN"
}

# ---------------------------------------------------------------------------
# jq helper — use jq if available, else fallback to grep
# ---------------------------------------------------------------------------
jq_or_grep() {
    local json_file="$1"
    local jq_filter="$2"
    local grep_pattern="$3"
    local default_val="${4:-N/A}"

    if command -v jq &>/dev/null; then
        local result
        result=$(jq -r "$jq_filter" "$json_file" 2>/dev/null)
        if [[ -z "$result" || "$result" == "null" ]]; then
            echo "$default_val"
        else
            echo "$result"
        fi
    else
        local result
        result=$(grep -o "$grep_pattern" "$json_file" | head -1 | grep -o '[^":]*$' || echo "$default_val")
        echo "$result"
    fi
}

# ---------------------------------------------------------------------------
# Scam DB check (all chains)
# ---------------------------------------------------------------------------
check_cryptoscamdb() {
    local addr="$1"
    local report_dir="$2"
    local out_file="${report_dir}/cryptoscamdb.json"

    command -v curl &>/dev/null || { warn "curl not found, skipping CryptoScamDB"; return; }

    info "CryptoScamDB: checking ${addr} ..."
    local http_code
    http_code=$(curl -s -o "$out_file" -w "%{http_code}" \
        "https://api.cryptoscamdb.org/v1/check/${addr}")

    if [[ "$http_code" -eq 200 ]]; then
        local success
        success=$(jq_or_grep "$out_file" '.success' '"success":[^,}]*' "false")
        local status
        status=$(jq_or_grep "$out_file" '.result // empty | if type == "array" then .[0].status else .status end' '"status":"[^"]*"' "unknown")
        data "CryptoScamDB: success=${success}, status=${status}"
        if [[ "$status" == "blocked" || "$status" == "scam" ]]; then
            echo "SCAM_CONFIRMED" > "${report_dir}/scam_flag.txt"
            warn "ADDRESS FLAGGED AS SCAM by CryptoScamDB: $addr"
        fi
    else
        warn "CryptoScamDB: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# BTC audit
# ---------------------------------------------------------------------------
audit_btc() {
    local addr="$1"
    local report_dir="$2"
    local report_file="${report_dir}/report.txt"

    command -v curl &>/dev/null || { warn "curl not found, skipping BTC audit"; return; }

    info "BTC: querying blockchain.info for $addr ..."
    local bc_file="${report_dir}/blockchain_info.json"
    local http_code
    http_code=$(curl -s -o "$bc_file" -w "%{http_code}" \
        "https://blockchain.info/rawaddr/${addr}?limit=5")

    if [[ "$http_code" -eq 200 ]]; then
        local total_received total_sent final_balance n_tx
        total_received=$(jq_or_grep "$bc_file" '.total_received' '"total_received":[0-9]*' "0")
        total_sent=$(jq_or_grep "$bc_file" '.total_sent' '"total_sent":[0-9]*' "0")
        final_balance=$(jq_or_grep "$bc_file" '.final_balance' '"final_balance":[0-9]*' "0")
        n_tx=$(jq_or_grep "$bc_file" '.n_tx' '"n_tx":[0-9]*' "0")

        # Convert satoshis to BTC (integer math via awk)
        local btc_received btc_sent btc_balance
        btc_received=$(awk "BEGIN {printf \"%.8f\", ${total_received}/100000000}")
        btc_sent=$(awk "BEGIN {printf \"%.8f\", ${total_sent}/100000000}")
        btc_balance=$(awk "BEGIN {printf \"%.8f\", ${final_balance}/100000000}")

        data "BTC: received=${btc_received} BTC, sent=${btc_sent} BTC, balance=${btc_balance} BTC, txs=${n_tx}"

        {
            printf "BITCOIN ADDRESS AUDIT\n"
            printf "Address:          %s\n" "$addr"
            printf "Total Received:   %s BTC\n" "$btc_received"
            printf "Total Sent:       %s BTC\n" "$btc_sent"
            printf "Current Balance:  %s BTC\n" "$btc_balance"
            printf "Transaction Count:%s\n" "$n_tx"
            printf "\nRECENT TRANSACTIONS (last 5):\n"
        } >> "$report_file"

        if command -v jq &>/dev/null; then
            jq -r '.txs[:5][] | "  TxHash: \(.hash)\n  Time:   \(.time | todate)\n  Inputs: \([.inputs[].prev_out.addr // "coinbase"] | join(", "))\n  Outputs:\([.out[].addr // "?"] | join(", "))\n  ---" ' "$bc_file" 2>/dev/null >> "$report_file" || true
        else
            grep -o '"hash":"[^"]*"' "$bc_file" | head -5 | while IFS= read -r line; do
                printf "  TxHash: %s\n" "$(echo "$line" | cut -d'"' -f4)"
            done >> "$report_file"
        fi
    else
        warn "BTC blockchain.info: HTTP $http_code"
        printf "BTC blockchain.info query failed (HTTP %s)\n" "$http_code" >> "$report_file"
    fi

    # Also query blockchair for additional context
    info "BTC: querying blockchair for $addr ..."
    local bc2_file="${report_dir}/blockchair.json"
    local bc2_url="https://api.blockchair.com/bitcoin/dashboards/address/${addr}"
    if [[ -n "$BLOCKCHAIR_API_KEY" ]]; then
        bc2_url="${bc2_url}?key=${BLOCKCHAIR_API_KEY}"
    fi
    local http_code2
    http_code2=$(curl -s -o "$bc2_file" -w "%{http_code}" "$bc2_url")
    if [[ "$http_code2" -eq 200 ]]; then
        local first_seen last_seen
        first_seen=$(jq_or_grep "$bc2_file" ".data.\"${addr}\".address.first_seen_receiving" '"first_seen_receiving":"[^"]*"' "N/A")
        last_seen=$(jq_or_grep "$bc2_file" ".data.\"${addr}\".address.last_seen_receiving" '"last_seen_receiving":"[^"]*"' "N/A")
        data "BTC blockchair: first_seen=${first_seen}, last_seen=${last_seen}"
        printf "\nFirst Transaction: %s\nLast Transaction:  %s\n" "$first_seen" "$last_seen" >> "$report_file"
    else
        warn "BTC blockchair: HTTP $http_code2"
    fi
}

# ---------------------------------------------------------------------------
# ETH audit
# ---------------------------------------------------------------------------
audit_eth() {
    local addr="$1"
    local report_dir="$2"
    local report_file="${report_dir}/report.txt"

    command -v curl &>/dev/null || { warn "curl not found, skipping ETH audit"; return; }

    if [[ -z "$ETHERSCAN_API_KEY" ]]; then
        warn "ETH: ETHERSCAN_API_KEY not set — Etherscan queries will fail or be rate-limited"
    fi

    info "ETH: querying balance for $addr ..."
    local bal_file="${report_dir}/eth_balance.json"
    local http_code
    http_code=$(curl -s -o "$bal_file" -w "%{http_code}" \
        "https://api.etherscan.io/api?module=account&action=balance&address=${addr}&tag=latest&apikey=${ETHERSCAN_API_KEY}")

    local eth_balance="N/A"
    if [[ "$http_code" -eq 200 ]]; then
        local wei
        wei=$(jq_or_grep "$bal_file" '.result' '"result":"[^"]*"' "0")
        eth_balance=$(awk "BEGIN {printf \"%.8f\", ${wei}/1000000000000000000}" 2>/dev/null || echo "N/A")
        data "ETH: balance=${eth_balance} ETH"
    else
        warn "ETH balance: HTTP $http_code"
    fi

    info "ETH: querying transactions for $addr ..."
    local tx_file="${report_dir}/eth_txlist.json"
    local http_code2
    http_code2=$(curl -s -o "$tx_file" -w "%{http_code}" \
        "https://api.etherscan.io/api?module=account&action=txlist&address=${addr}&startblock=0&endblock=99999999&sort=desc&page=1&offset=5&apikey=${ETHERSCAN_API_KEY}")

    {
        printf "ETHEREUM ADDRESS AUDIT\n"
        printf "Address:          %s\n" "$addr"
        printf "Current Balance:  %s ETH\n" "$eth_balance"
        printf "\nRECENT TRANSACTIONS (last 5):\n"
    } >> "$report_file"

    if [[ "$http_code2" -eq 200 ]]; then
        local api_status
        api_status=$(grep -o '"status":"[^"]*"' "$tx_file" | head -1 | cut -d'"' -f4 || echo "0")
        if [[ "$api_status" != "1" ]]; then
            local api_msg
            api_msg=$(jq -r '.result // "API error"' "$tx_file" 2>/dev/null || grep -o '"result":"[^"]*"' "$tx_file" | head -1 | cut -d'"' -f4 || echo "unknown error")
            warn "ETH txlist API error: ${api_msg}"
            printf "Transaction list: %s\n" "$api_msg" >> "$report_file"
        else
            local tx_count
            tx_count=$(jq_or_grep "$tx_file" '.result | length' '"hash"' "0")
            data "ETH: transaction count (page 1)=${tx_count}"
            printf "Transaction Count (visible): %s\n" "$tx_count" >> "$report_file"

            if command -v jq &>/dev/null; then
                jq -r '.result[]? | "  TxHash:   \(.hash)\n  Time:     \(.timeStamp | tonumber | todate)\n  From:     \(.from)\n  To:       \(.to)\n  Value:    \((.value | tonumber) / 1000000000000000000 | tostring) ETH\n  Status:   \(if .isError == "0" then "Success" else "Failed" end)\n  ---"' "$tx_file" 2>/dev/null >> "$report_file" || true
            else
                grep -o '"hash":"[^"]*"' "$tx_file" | head -5 | while IFS= read -r line; do
                    printf "  TxHash: %s\n" "$(echo "$line" | cut -d'"' -f4)"
                done >> "$report_file"
            fi
        fi
    else
        warn "ETH txlist: HTTP $http_code2"
        printf "Transaction list query failed (HTTP %s)\n" "$http_code2" >> "$report_file"
    fi
}

# ---------------------------------------------------------------------------
# Blockchair-based audit (LTC, DOGE, BCH)
# ---------------------------------------------------------------------------
audit_blockchair() {
    local addr="$1"
    local chain_slug="$2"
    local chain_label="$3"
    local report_dir="$4"
    local report_file="${report_dir}/report.txt"

    command -v curl &>/dev/null || { warn "curl not found, skipping ${chain_label} audit"; return; }

    info "${chain_label}: querying blockchair for $addr ..."
    local bc_file="${report_dir}/blockchair.json"
    local bc_url="https://api.blockchair.com/${chain_slug}/dashboards/address/${addr}"
    if [[ -n "$BLOCKCHAIR_API_KEY" ]]; then
        bc_url="${bc_url}?key=${BLOCKCHAIR_API_KEY}"
    fi

    local http_code
    http_code=$(curl -s -o "$bc_file" -w "%{http_code}" "$bc_url")

    {
        printf "%s ADDRESS AUDIT\n" "$chain_label"
        printf "Address: %s\n" "$addr"
    } >> "$report_file"

    if [[ "$http_code" -eq 200 ]]; then
        local received sent balance tx_count first_seen last_seen
        received=$(jq_or_grep "$bc_file" ".data.\"${addr}\".address.received" '"received":[0-9]*' "0")
        sent=$(jq_or_grep "$bc_file" ".data.\"${addr}\".address.spent" '"spent":[0-9]*' "0")
        balance=$(jq_or_grep "$bc_file" ".data.\"${addr}\".address.balance" '"balance":[0-9]*' "0")
        tx_count=$(jq_or_grep "$bc_file" ".data.\"${addr}\".address.transaction_count" '"transaction_count":[0-9]*' "0")
        first_seen=$(jq_or_grep "$bc_file" ".data.\"${addr}\".address.first_seen_receiving" '"first_seen_receiving":"[^"]*"' "N/A")
        last_seen=$(jq_or_grep "$bc_file" ".data.\"${addr}\".address.last_seen_receiving" '"last_seen_receiving":"[^"]*"' "N/A")

        data "${chain_label}: received=${received}, sent=${sent}, balance=${balance}, txs=${tx_count}"

        {
            printf "Total Received:   %s (satoshi units)\n" "$received"
            printf "Total Sent:       %s (satoshi units)\n" "$sent"
            printf "Current Balance:  %s (satoshi units)\n" "$balance"
            printf "Transaction Count:%s\n" "$tx_count"
            printf "First Transaction:%s\n" "$first_seen"
            printf "Last Transaction: %s\n" "$last_seen"
            printf "\nRECENT TRANSACTIONS (last 5):\n"
        } >> "$report_file"

        if command -v jq &>/dev/null; then
            jq -r ".data.\"${addr}\".transactions[:5][]?" "$bc_file" 2>/dev/null >> "$report_file" || true
        fi
    else
        warn "${chain_label} blockchair: HTTP $http_code"
        printf "Blockchair query failed (HTTP %s)\n" "$http_code" >> "$report_file"
    fi
}

# ---------------------------------------------------------------------------
# XRP audit
# ---------------------------------------------------------------------------
audit_xrp() {
    local addr="$1"
    local report_dir="$2"
    local report_file="${report_dir}/report.txt"

    command -v curl &>/dev/null || { warn "curl not found, skipping XRP audit"; return; }

    info "XRP: querying xrpscan for $addr ..."
    local xrp_file="${report_dir}/xrpscan.json"
    local http_code
    http_code=$(curl -s -o "$xrp_file" -w "%{http_code}" \
        "https://api.xrpscan.com/api/v1/account/${addr}")

    {
        printf "XRP ADDRESS AUDIT\n"
        printf "Address: %s\n" "$addr"
    } >> "$report_file"

    if [[ "$http_code" -eq 200 ]]; then
        local balance tx_count initial_balance
        balance=$(jq_or_grep "$xrp_file" '.xrpBalance' '"xrpBalance":"[^"]*"' "N/A")
        tx_count=$(jq_or_grep "$xrp_file" '.txCount' '"txCount":[0-9]*' "N/A")
        initial_balance=$(jq_or_grep "$xrp_file" '.initial_funding_amount' '"initial_funding_amount":[^,}]*' "N/A")

        data "XRP: balance=${balance} XRP, tx_count=${tx_count}"

        {
            printf "Current Balance:  %s XRP\n" "$balance"
            printf "Transaction Count:%s\n" "$tx_count"
            printf "Initial Funding:  %s drops\n" "$initial_balance"
        } >> "$report_file"
    else
        warn "XRP xrpscan: HTTP $http_code"
        printf "XRPScan query failed (HTTP %s)\n" "$http_code" >> "$report_file"
    fi

    info "XRP: querying recent transactions ..."
    local tx_file="${report_dir}/xrpscan_txs.json"
    local http_code2
    http_code2=$(curl -s -o "$tx_file" -w "%{http_code}" \
        "https://api.xrpscan.com/api/v1/account/${addr}/transactions?limit=5")

    if [[ "$http_code2" -eq 200 ]]; then
        printf "\nRECENT TRANSACTIONS (last 5):\n" >> "$report_file"
        if command -v jq &>/dev/null; then
            jq -r '.[]? | "  TxHash: \(.hash)\n  Time:   \(.date)\n  Type:   \(.TransactionType)\n  Amount: \(.Amount // "N/A")\n  ---"' "$tx_file" 2>/dev/null >> "$report_file" || true
        else
            grep -o '"hash":"[^"]*"' "$tx_file" | head -5 | while IFS= read -r line; do
                printf "  TxHash: %s\n" "$(echo "$line" | cut -d'"' -f4)"
            done >> "$report_file"
        fi
    else
        warn "XRP transactions: HTTP $http_code2"
    fi
}

# ---------------------------------------------------------------------------
# XMR audit (limited — Monero is privacy-focused, minimal public data)
# ---------------------------------------------------------------------------
audit_xmr() {
    local addr="$1"
    local report_dir="$2"
    local report_file="${report_dir}/report.txt"

    {
        printf "MONERO ADDRESS AUDIT\n"
        printf "Address: %s\n" "$addr"
        printf "\nNOTE: Monero (XMR) is a privacy coin. Blockchain data is not publicly\n"
        printf "queryable. Address format validated as XMR (95-char, starts with 4).\n"
        printf "For XMR tracing, contact a specialized blockchain analytics firm.\n"
    } >> "$report_file"

    warn "XMR: Monero blockchain is private; no public API data available"
}

# ---------------------------------------------------------------------------
# BlockCypher cross-reference (BTC + ETH, optional enrichment)
# ---------------------------------------------------------------------------
audit_blockcypher() {
    local addr="$1"
    local chain_slug="$2"
    local report_dir="$3"
    local report_file="${report_dir}/report.txt"

    [[ -z "$BLOCKCYPHER_API_KEY" ]] && return 0

    command -v curl &>/dev/null || return 0

    info "BlockCypher: querying ${chain_slug} for $addr ..."
    local bc_file="${report_dir}/blockcypher.json"
    local url="https://api.blockcypher.com/v1/${chain_slug}/main/addrs/${addr}/balance"
    [[ -n "$BLOCKCYPHER_API_KEY" ]] && url="${url}?token=${BLOCKCYPHER_API_KEY}"

    local http_code
    http_code=$(curl -s -o "$bc_file" -w "%{http_code}" "$url")

    if [[ "$http_code" -eq 200 ]]; then
        local balance tx_count
        balance=$(jq_or_grep "$bc_file" '.balance' '"balance":[0-9]*' "N/A")
        tx_count=$(jq_or_grep "$bc_file" '.n_tx' '"n_tx":[0-9]*' "N/A")
        data "BlockCypher: balance=${balance} satoshis, tx_count=${tx_count}"
        {
            printf "\nBLOCKCYPHER CROSS-REFERENCE\n"
            printf "Balance:           %s satoshis\n" "$balance"
            printf "Transaction Count: %s\n" "$tx_count"
        } >> "$report_file"
    else
        warn "BlockCypher: HTTP $http_code"
    fi
}

# ---------------------------------------------------------------------------
# Per-address audit dispatcher
# ---------------------------------------------------------------------------
audit_address() {
    local addr="$1"
    local safe_addr
    safe_addr=$(printf '%s' "$addr" | tr -cd '[:alnum:]_.-')
    local report_dir="${OUTPUT_DIR}/${safe_addr}"
    mkdir -p "$report_dir"

    local chain
    chain=$(detect_chain "$addr")
    info "Address: $addr | Chain: $chain"

    local report_file="${report_dir}/report.txt"
    {
        printf "=%.0s" {1..70}; printf "\n"
        printf "PNWC CRYPTO AUDIT REPORT\n"
        printf "Generated: %s\n" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf "Investigator Contact: jon@pnwcomputers.com\n"
        printf "Chain: %s\n" "$chain"
        printf "=%.0s" {1..70}; printf "\n\n"
    } > "$report_file"

    case "$chain" in
        BTC)  audit_btc "$addr" "$report_dir"
              audit_blockcypher "$addr" "btc" "$report_dir" ;;
        ETH)  audit_eth "$addr" "$report_dir"
              audit_blockcypher "$addr" "eth" "$report_dir" ;;
        P2SH) warn "P2SH address — format is identical for BTC and LTC; auditing both chains"
              printf "NOTE: P2SH addresses (3...) are format-identical for BTC and LTC.\n" >> "$report_file"
              printf "Results from both chains shown below.\n\n" >> "$report_file"
              audit_btc "$addr" "$report_dir"
              audit_blockchair "$addr" "litecoin" "LITECOIN" "$report_dir"
              audit_blockcypher "$addr" "btc" "$report_dir" ;;
        LTC)  audit_blockchair "$addr" "litecoin"     "LITECOIN" "$report_dir" ;;
        DOGE) audit_blockchair "$addr" "dogecoin"     "DOGECOIN" "$report_dir" ;;
        BCH)  audit_blockchair "$addr" "bitcoin-cash" "BITCOIN CASH" "$report_dir" ;;
        XRP)  audit_xrp "$addr" "$report_dir" ;;
        XMR)  audit_xmr "$addr" "$report_dir" ;;
        UNKNOWN)
            warn "Could not detect chain for address: $addr"
            printf "Chain: UNKNOWN — address format not recognized\n" >> "$report_file"
            ;;
    esac

    # Scam database check (chain-agnostic)
    check_cryptoscamdb "$addr" "$report_dir"

    # Append scam flag to report
    if [[ -f "${report_dir}/scam_flag.txt" ]]; then
        {
            printf "\n[!!! SCAM ALERT !!!]\n"
            printf "This address has been flagged as a SCAM by CryptoScamDB.\n"
            printf "IC3 report recommendation: HIGH PRIORITY\n"
        } >> "$report_file"
    fi

    {
        printf "\n%s\n" "$(printf '=%.0s' {1..70})"
        printf "Raw API responses saved in: %s/\n" "$report_dir"
        printf "For IC3 complaint: https://www.ic3.gov/\n"
        printf "For FTC report:    https://reportfraud.ftc.gov/\n"
    } >> "$report_file"

    info "Report written: $report_file"
}

# ---------------------------------------------------------------------------
# Summary across all addresses
# ---------------------------------------------------------------------------
build_summary() {
    local summary_file="${OUTPUT_DIR}/audit_summary.txt"

    section "Crypto Audit Summary"

    {
        printf "=%.0s" {1..70}; printf "\n"
        printf "PNWC CRYPTOCURRENCY AUDIT SUMMARY\n"
        printf "Generated: %s\n" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf "Investigator: Jon-Eric Pienkowski ~ Pacific Northwest Computers (PNWC)\n"
        printf "Contact: jon@pnwcomputers.com\n"
        printf "=%.0s" {1..70}; printf "\n\n"
        printf "Addresses audited: %d\n\n" "${#ADDRESSES[@]}"
    } > "$summary_file"

    local flagged_count=0
    for addr in "${ADDRESSES[@]}"; do
        local safe_addr
        safe_addr=$(printf '%s' "$addr" | tr -cd '[:alnum:]_.-')
        local chain
        chain=$(detect_chain "$addr")
        printf "  %-60s  Chain: %s" "$addr" "$chain" >> "$summary_file"
        if [[ -f "${OUTPUT_DIR}/${safe_addr}/scam_flag.txt" ]]; then
            printf "  [SCAM FLAGGED]\n" >> "$summary_file"
            (( flagged_count++ ))
        else
            printf "\n" >> "$summary_file"
        fi
    done

    {
        printf "\nScam-flagged addresses: %d / %d\n" "$flagged_count" "${#ADDRESSES[@]}"
        printf "\nPer-address reports: %s/<address>/report.txt\n" "$OUTPUT_DIR"
        printf "\nIC3 Complaint: https://www.ic3.gov/\n"
        printf "FTC Report:    https://reportfraud.ftc.gov/\n"
    } >> "$summary_file"

    info "Summary written: $summary_file"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    local OPTIND opt
    while getopts ":a:f:o:h" opt; do
        case "$opt" in
            a) ADDRESSES+=("$OPTARG") ;;
            f) ADDRESS_FILE="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            h) usage ;;
            :) error "Option -${OPTARG} requires an argument"; exit 1 ;;
            \?) error "Unknown option: -${OPTARG}"; exit 1 ;;
        esac
    done

    # Load addresses from file if provided
    if [[ -n "$ADDRESS_FILE" ]]; then
        if [[ ! -f "$ADDRESS_FILE" ]]; then
            error "Address file not found: $ADDRESS_FILE"
            exit 1
        fi
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"   # strip inline comments
            line="${line// /}"   # strip spaces
            [[ -z "$line" ]] && continue
            ADDRESSES+=("$line")
        done < "$ADDRESS_FILE"
    fi

    if [[ "${#ADDRESSES[@]}" -eq 0 ]]; then
        error "At least one address (-a) or an address file (-f) is required"
        usage
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="./crypto_audit_${TIMESTAMP}"
    fi
    mkdir -p "$OUTPUT_DIR"

    LOG_FILE="${OUTPUT_DIR}/crypto_audit.log"
    touch "$LOG_FILE"

    section "PNWC Cryptocurrency Audit Tool"
    info "Addresses to audit: ${#ADDRESSES[@]}"
    info "Output directory: $OUTPUT_DIR"

    load_api_keys

    for addr in "${ADDRESSES[@]}"; do
        section "Auditing: ${addr}"
        audit_address "$addr"
    done

    build_summary

    info "Audit complete. All results in: $OUTPUT_DIR"
}

main "$@"
