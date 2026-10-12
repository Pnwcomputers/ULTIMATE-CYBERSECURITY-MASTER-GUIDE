#!/usr/bin/env bash
# Shared helpers for the OSINT playbook: load shell-format config files only when
# they are safe to execute, and load case state from validated JSON.
#
# This file is meant to be sourced. It defines functions only.
#
#   trusted_conf FILE     succeeds if FILE is a regular file (not a symlink),
#                         owned by the current user, not group/world-writable
#   source_trusted FILE   sources FILE if trusted_conf passes; otherwise warns on
#                         stderr and returns 1 (nothing from FILE is executed)
#   case_state_load DIR   load DIR/.case_state.json via lib/case_state.py into the
#                         EMAILS, PHONES, DOMAINS, IPS, IPV6S, USERNAMES,
#                         CRYPTO_ADDRESSES, SUBDOMAINS arrays and CASE_TYPE,
#                         COMPANY_NAME_TARGET and HOSTING_* variables; a legacy
#                         shell-format .case_state is NEVER sourced

# shellcheck disable=SC2034  # variables are consumed by the sourcing script
_PNWC_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

trusted_conf() {
    local f="$1" owner mode
    [[ -f "$f" && ! -L "$f" ]] || return 1
    read -r owner mode < <(stat -c '%u %a' -- "$f" 2>/dev/null) || return 1
    [[ "$owner" == "$(id -u)" ]] || return 1
    (( (8#$mode & 8#022) == 0 ))
}

source_trusted() {
    local f="$1"
    [[ -e "$f" ]] || return 0
    if trusted_conf "$f"; then
        # shellcheck source=/dev/null
        source "$f"
    else
        echo "Refusing to load $f: it must be a regular file you own and not group/world-writable (chmod 600)." >&2
        return 1
    fi
}

case_state_load() {
    local dir="$1" tmp key value
    local py="${STATE_PY:-${_PNWC_LIB_DIR}/case_state.py}"
    CASE_TYPE="" COMPANY_NAME_TARGET=""
    HOSTING_PROVIDER="" HOSTING_ASN="" HOSTING_ISP="" HOSTING_REGISTRY=""
    HOSTING_GEOLOCATION="" HOSTING_COORDINATES="" HOSTING_TIMEZONE=""
    EMAILS=() PHONES=() DOMAINS=() IPS=() IPV6S=() USERNAMES=()
    CRYPTO_ADDRESSES=() SUBDOMAINS=()

    if [[ ! -e "$dir/.case_state.json" && ! -L "$dir/.case_state.json" ]]; then
        if [[ -e "$dir/.case_state" ]]; then
            echo "Found a legacy shell-format .case_state in $dir. It is NOT executed; re-enter the indicators so they are saved as JSON." >&2
        fi
        return 1
    fi
    tmp="$(mktemp)" || return 1
    if ! python3 -I "$py" load "$dir" > "$tmp"; then
        rm -f -- "$tmp"
        echo "Case state in $dir failed validation and was NOT loaded." >&2
        return 1
    fi
    while IFS= read -r -d '' key && IFS= read -r -d '' value; do
        case "$key" in
            CASE_ID) ;;
            CASE_TYPE)           CASE_TYPE="$value" ;;
            COMPANY_NAME_TARGET) COMPANY_NAME_TARGET="$value" ;;
            HOSTING_PROVIDER)    HOSTING_PROVIDER="$value" ;;
            HOSTING_ASN)         HOSTING_ASN="$value" ;;
            HOSTING_ISP)         HOSTING_ISP="$value" ;;
            HOSTING_REGISTRY)    HOSTING_REGISTRY="$value" ;;
            HOSTING_GEOLOCATION) HOSTING_GEOLOCATION="$value" ;;
            HOSTING_COORDINATES) HOSTING_COORDINATES="$value" ;;
            HOSTING_TIMEZONE)    HOSTING_TIMEZONE="$value" ;;
            EMAILS)              EMAILS+=("$value") ;;
            PHONES)              PHONES+=("$value") ;;
            DOMAINS)             DOMAINS+=("$value") ;;
            IPS)                 IPS+=("$value") ;;
            IPV6S)               IPV6S+=("$value") ;;
            USERNAMES)           USERNAMES+=("$value") ;;
            CRYPTO_ADDRESSES)    CRYPTO_ADDRESSES+=("$value") ;;
            SUBDOMAINS)          SUBDOMAINS+=("$value") ;;
        esac
    done < "$tmp"
    rm -f -- "$tmp"
}
