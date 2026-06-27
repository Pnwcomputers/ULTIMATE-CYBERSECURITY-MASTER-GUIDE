#!/usr/bin/env bash
#
# uconsole-repair.sh — fix a uConsole that had the wrong CM-specific setup script
#                       run against it (CM4 script on CM5 hardware, or vice versa).
#
# Symptoms that this script repairs:
#   - GPS not working because the wrong UART overlay was written (enable_uart=1
#     on CM5, or dtparam=uart0 on CM4)
#   - RTC not working because the wrong i2c overlay was written (missing
#     i2c_csi_dsi0 remap on CM5, or extra remap that's harmless-but-wrong on CM4)
#   - State file mismatch (cm4-state on CM5 hardware, etc.)
#
# What it does:
#   1. Detects actual hardware (CM4 or CM5) from /proc/device-tree/model
#   2. Scans /boot/firmware/config.txt for telltale markers and overlay lines
#   3. Reports the diagnosis
#   4. With confirmation: backs up config.txt, removes wrong-platform lines,
#      adds correct ones (idempotent), updates state file
#   5. Recommends reboot
#
# Usage:
#   sudo ./uconsole-repair.sh             # diagnose + interactive repair
#   sudo ./uconsole-repair.sh --dry-run   # show what would change, change nothing
#   sudo ./uconsole-repair.sh --diagnose  # report only, never modify
#   sudo ./uconsole-repair.sh --yes       # skip confirmation
#   sudo ./uconsole-repair.sh --help

set -uo pipefail

VERSION="1.0"
DRY_RUN="${DRY_RUN:-no}"
DIAGNOSE_ONLY="${DIAGNOSE_ONLY:-no}"
ASSUME_YES="${ASSUME_YES:-no}"

CONFIG_TXT="/boot/firmware/config.txt"
STATE_DIR="/var/lib/uconsole-setup"
LOG_FILE="/var/log/uconsole-repair.log"

# Colors
if [[ -t 1 ]]; then
    C_RESET='\033[0m'
    C_RED='\033[1;31m'
    C_GREEN='\033[1;32m'
    C_YELLOW='\033[1;33m'
    C_BLUE='\033[1;34m'
    C_CYAN='\033[1;36m'
    C_BOLD='\033[1m'
else
    C_RESET='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN='' C_BOLD=''
fi

log()  { echo -e "${C_BLUE}[$(date +%H:%M:%S)]${C_RESET} $*" | tee -a "$LOG_FILE"; }
info() { echo -e "${C_CYAN}[INFO]${C_RESET}  $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${C_YELLOW}[WARN]${C_RESET}  $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${C_RED}[ERR]${C_RESET}   $*" | tee -a "$LOG_FILE" >&2; }
ok()   { echo -e "${C_GREEN}[OK]${C_RESET}    $*" | tee -a "$LOG_FILE"; }
die()  { err "$*"; exit 1; }
header() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}" | tee -a "$LOG_FILE"
    echo -e "${C_BOLD}${C_BLUE}  $*${C_RESET}" | tee -a "$LOG_FILE"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}" | tee -a "$LOG_FILE"
}

confirm() {
    [[ "$ASSUME_YES" == "yes" ]] && return 0
    local reply
    read -r -p "$(echo -e "${C_YELLOW}?${C_RESET} $1 [y/N] ")" reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

require_root() { [[ $EUID -eq 0 ]] || die "Must be run as root. Try: sudo $0"; }

# ----------------------------------------------------------------------------
# Hardware detection
# ----------------------------------------------------------------------------

detect_hardware() {
    if [[ -r /proc/device-tree/model ]]; then
        local model
        model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null)
        case "$model" in
            *"Compute Module 4"*) echo "cm4" ;;
            *"Compute Module 5"*) echo "cm5" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

# ----------------------------------------------------------------------------
# Config.txt scanning
# ----------------------------------------------------------------------------
# Detection helpers: each returns 0 (true) if the pattern is present in config.txt

has_cm4_marker()   { grep -q "AIO v2 Board Configuration (CM4)" "$CONFIG_TXT" 2>/dev/null; }
has_cm5_marker()   { grep -q "AIO v2 Board Configuration (CM5)" "$CONFIG_TXT" 2>/dev/null; }
has_enable_uart()  { grep -qE "^[[:space:]]*enable_uart=1" "$CONFIG_TXT" 2>/dev/null; }
has_dtparam_uart() { grep -qE "^[[:space:]]*dtparam=uart0" "$CONFIG_TXT" 2>/dev/null; }
has_dtparam_spi()  { grep -qE "^[[:space:]]*dtparam=spi=on" "$CONFIG_TXT" 2>/dev/null; }
has_rtc_off()      { grep -qE "^[[:space:]]*dtparam=rtc=off" "$CONFIG_TXT" 2>/dev/null; }
has_rtc_cm4()      {
    # CM4 RTC overlay: dtoverlay=i2c-rtc,pcf85063a (without the i2c_csi_dsi0 remap)
    grep -qE "^[[:space:]]*dtoverlay=i2c-rtc,pcf85063a[[:space:]]*$" "$CONFIG_TXT" 2>/dev/null
}
has_rtc_cm5()      {
    # CM5 RTC overlay: includes i2c_csi_dsi0
    grep -qE "^[[:space:]]*dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0" "$CONFIG_TXT" 2>/dev/null
}

# ----------------------------------------------------------------------------
# Diagnosis
# ----------------------------------------------------------------------------

diagnose() {
    local hw="$1"
    local wrong_marker=no
    local wrong_uart=no
    local wrong_rtc=no
    local missing_uart=no
    local missing_rtc=no
    local missing_rtc_off=no  # CM5 only
    local stale_state=""

    header "Diagnosis"

    info "Hardware detected:  $hw"
    info "Config file:        $CONFIG_TXT"
    info ""
    info "Markers found in config.txt:"
    has_cm4_marker && info "  ✓ CM4 marker present"
    has_cm5_marker && info "  ✓ CM5 marker present"
    if ! has_cm4_marker && ! has_cm5_marker; then
        info "  (none — config.txt was not modified by either setup script)"
    fi

    info ""
    info "Platform-specific overlays present in config.txt:"
    has_enable_uart  && info "  enable_uart=1                                 [CM4 GPS UART]"
    has_dtparam_uart && info "  dtparam=uart0                                 [CM5 GPS UART]"
    has_dtparam_spi  && info "  dtparam=spi=on                                [CM4 LoRa SPI prep — harmless on CM5]"
    has_rtc_off      && info "  dtparam=rtc=off                               [CM5 internal RTC disable]"
    has_rtc_cm4      && info "  dtoverlay=i2c-rtc,pcf85063a (no remap)        [CM4 RTC overlay]"
    has_rtc_cm5      && info "  dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0      [CM5 RTC overlay]"

    info ""
    info "State files present:"
    for f in "$STATE_DIR"/*-state; do
        [[ -f "$f" ]] && info "  $(basename "$f")  →  $(cat "$f" 2>/dev/null)"
    done
    [[ ! -d "$STATE_DIR" ]] || ! ls "$STATE_DIR"/*-state &>/dev/null && info "  (none)"

    # Determine what's wrong for the detected hardware
    # Only flag "missing" overlays as issues IF there's evidence setup was attempted
    # (marker present or any platform-specific overlay line present) — otherwise the
    # config is just untouched and "missing" is the correct state.
    local setup_attempted=no
    if has_cm4_marker || has_cm5_marker \
       || has_enable_uart || has_dtparam_uart \
       || has_rtc_off || has_rtc_cm4 || has_rtc_cm5; then
        setup_attempted=yes
    fi

    echo ""
    if [[ "$hw" == "cm4" ]]; then
        has_cm5_marker  && wrong_marker=yes
        has_dtparam_uart && wrong_uart=yes
        has_rtc_cm5      && wrong_rtc=yes
        if [[ "$setup_attempted" == "yes" ]]; then
            has_enable_uart  || missing_uart=yes
            has_rtc_cm4      || missing_rtc=yes
        fi
        [[ -f "$STATE_DIR/cm5-state" ]] && stale_state="$STATE_DIR/cm5-state"
    elif [[ "$hw" == "cm5" ]]; then
        has_cm4_marker   && wrong_marker=yes
        has_enable_uart  && wrong_uart=yes
        has_rtc_cm4      && wrong_rtc=yes
        if [[ "$setup_attempted" == "yes" ]]; then
            has_dtparam_uart || missing_uart=yes
            has_rtc_cm5      || missing_rtc=yes
            has_rtc_off      || missing_rtc_off=yes
        fi
        [[ -f "$STATE_DIR/cm4-state" ]] && stale_state="$STATE_DIR/cm4-state"
    else
        die "Cannot detect hardware. Refusing to make changes."
    fi

    local issues=0
    [[ "$wrong_marker"   == "yes" ]] && ((issues++))
    [[ "$wrong_uart"     == "yes" ]] && ((issues++))
    [[ "$wrong_rtc"      == "yes" ]] && ((issues++))
    [[ "$missing_uart"   == "yes" ]] && ((issues++))
    [[ "$missing_rtc"    == "yes" ]] && ((issues++))
    [[ "$missing_rtc_off" == "yes" ]] && ((issues++))
    [[ -n "$stale_state" ]] && ((issues++))

    # Verdict
    echo ""
    if (( issues == 0 )); then
        # If no setup script has touched config.txt at all, nothing to repair OR
        # to do — user should run the appropriate setup script if they want
        if ! has_cm4_marker && ! has_cm5_marker; then
            ok "config.txt has not been modified by either setup script."
            ok "Nothing to repair. If you want to set up the uConsole, run uconsole-${hw}-setup.sh."
        else
            ok "config.txt matches detected hardware ($hw). No repair needed."
        fi
        return 1
    fi

    warn "Detected $issues issue(s) needing repair on $hw hardware:"
    [[ "$wrong_marker"   == "yes" ]] && warn "  ✗ Wrong-platform marker line present"
    [[ "$wrong_uart"     == "yes" ]] && warn "  ✗ Wrong GPS UART overlay (will be removed)"
    [[ "$wrong_rtc"      == "yes" ]] && warn "  ✗ Wrong RTC overlay (will be removed)"
    [[ "$missing_uart"   == "yes" ]] && warn "  ✗ Correct GPS UART overlay missing (will be added)"
    [[ "$missing_rtc"    == "yes" ]] && warn "  ✗ Correct RTC overlay missing (will be added)"
    [[ "$missing_rtc_off" == "yes" ]] && warn "  ✗ dtparam=rtc=off missing (CM5 internal RTC disable — will be added)"
    [[ -n "$stale_state" ]]          && warn "  ✗ Stale state file: $stale_state (will be removed)"

    # Export the findings for repair()
    REPAIR_WRONG_MARKER="$wrong_marker"
    REPAIR_WRONG_UART="$wrong_uart"
    REPAIR_WRONG_RTC="$wrong_rtc"
    REPAIR_MISSING_UART="$missing_uart"
    REPAIR_MISSING_RTC="$missing_rtc"
    REPAIR_MISSING_RTC_OFF="$missing_rtc_off"
    REPAIR_STALE_STATE="$stale_state"

    return 0
}

# ----------------------------------------------------------------------------
# Repair actions
# ----------------------------------------------------------------------------

remove_line() {
    # Remove every line matching the given regex from config.txt.
    # Uses sed with extended regex; pattern must already be regex-safe.
    local pattern="$1"
    local desc="$2"

    if [[ "$DRY_RUN" == "yes" ]]; then
        log "  DRY-RUN: would remove lines matching: $pattern  ($desc)"
        return 0
    fi
    sed -i -E "/^[[:space:]]*${pattern}[[:space:]]*\$/d" "$CONFIG_TXT"
    ok "  Removed: $desc"
}

append_line() {
    local line="$1"
    local desc="$2"

    # Idempotent check
    if grep -qE "^[[:space:]]*${line}[[:space:]]*\$" "$CONFIG_TXT" 2>/dev/null; then
        info "  $desc already present — skipping"
        return 0
    fi

    if [[ "$DRY_RUN" == "yes" ]]; then
        log "  DRY-RUN: would append:  $line  ($desc)"
        return 0
    fi
    printf '%s\n' "$line" >> "$CONFIG_TXT"
    ok "  Added: $desc"
}

ensure_repair_marker() {
    local hw="$1"
    local hw_upper
    hw_upper=$(echo "$hw" | tr '[:lower:]' '[:upper:]')
    local repair_text
    repair_text="# === uConsole repair script: config repaired for $hw on $(date) ==="
    local aio_marker
    aio_marker="# === AIO v2 Board Configuration ($hw_upper) — added by uconsole-${hw}-setup.sh (via repair) ==="

    if [[ "$DRY_RUN" == "yes" ]]; then
        log "  DRY-RUN: would append AIO marker + repair trail:"
        log "    $aio_marker"
        log "    $repair_text"
        return 0
    fi
    {
        printf '\n'
        # Only add the AIO marker if not already present
        if ! grep -q "AIO v2 Board Configuration ($hw_upper)" "$CONFIG_TXT" 2>/dev/null; then
            printf '%s\n' "$aio_marker"
        fi
        printf '%s\n' "$repair_text"
    } >> "$CONFIG_TXT"
}

remove_wrong_marker() {
    local hw="$1"
    local wrong_cm
    [[ "$hw" == "cm4" ]] && wrong_cm="CM5" || wrong_cm="CM4"

    if [[ "$DRY_RUN" == "yes" ]]; then
        log "  DRY-RUN: would remove '$wrong_cm' marker line(s) from config.txt"
        return 0
    fi
    sed -i "/AIO v2 Board Configuration ($wrong_cm)/d" "$CONFIG_TXT"
    ok "  Removed wrong-platform marker ($wrong_cm)"
}

repair() {
    local hw="$1"

    header "Repair"

    # 1. Backup config.txt
    local backup
    backup="${CONFIG_TXT}.bak.repair.$(date +%s)"
    if [[ "$DRY_RUN" == "yes" ]]; then
        log "DRY-RUN: would back up $CONFIG_TXT → $backup"
    else
        cp "$CONFIG_TXT" "$backup"
        ok "Backed up $CONFIG_TXT → $backup"
    fi

    # 2. Remove wrong overlays
    if [[ "$REPAIR_WRONG_UART" == "yes" ]]; then
        if [[ "$hw" == "cm4" ]]; then
            remove_line "dtparam=uart0" "dtparam=uart0 (CM5 GPS UART — not for CM4)"
        else
            remove_line "enable_uart=1" "enable_uart=1 (CM4 GPS UART — not for CM5)"
        fi
    fi

    if [[ "$REPAIR_WRONG_RTC" == "yes" ]]; then
        if [[ "$hw" == "cm4" ]]; then
            remove_line "dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0" "CM5-specific RTC overlay with i2c_csi_dsi0 remap"
        else
            # On CM5, the CM4-style overlay (without i2c_csi_dsi0) is wrong
            remove_line "dtoverlay=i2c-rtc,pcf85063a" "CM4-style RTC overlay (no remap — CM5 needs i2c_csi_dsi0)"
        fi
    fi

    # Remove wrong marker line(s)
    if [[ "$REPAIR_WRONG_MARKER" == "yes" ]]; then
        remove_wrong_marker "$hw"
    fi

    # 3. Add correct overlays
    if [[ "$REPAIR_MISSING_UART" == "yes" ]]; then
        if [[ "$hw" == "cm4" ]]; then
            append_line "enable_uart=1" "CM4 GPS UART (enable_uart=1)"
        else
            append_line "dtparam=uart0" "CM5 GPS UART (dtparam=uart0)"
        fi
    fi

    if [[ "$REPAIR_MISSING_RTC" == "yes" ]]; then
        if [[ "$hw" == "cm4" ]]; then
            append_line "dtoverlay=i2c-rtc,pcf85063a" "CM4 RTC overlay"
        else
            append_line "dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0" "CM5 RTC overlay with i2c_csi_dsi0 remap"
        fi
    fi

    if [[ "$REPAIR_MISSING_RTC_OFF" == "yes" && "$hw" == "cm5" ]]; then
        append_line "dtparam=rtc=off" "Disable CM5 internal RTC (so external PCF85063A can be the system RTC)"
    fi

    # Add a repair marker so it's clear what happened
    ensure_repair_marker "$hw"

    # 4. Remove stale state file
    if [[ -n "$REPAIR_STALE_STATE" ]]; then
        if [[ "$DRY_RUN" == "yes" ]]; then
            log "  DRY-RUN: would remove stale state file: $REPAIR_STALE_STATE"
        else
            rm -f "$REPAIR_STALE_STATE"
            ok "  Removed stale state file: $REPAIR_STALE_STATE"
        fi
    fi

    echo ""
    if [[ "$DRY_RUN" == "yes" ]]; then
        ok "Dry run complete — no changes were actually made."
    else
        ok "Repair complete. config.txt backup: $backup"
        warn "REBOOT REQUIRED for the corrected device-tree overlays to take effect."
        echo ""
        echo "After reboot, verify with:"
        if [[ "$hw" == "cm4" ]]; then
            echo "  - sudo minicom -D /dev/ttyS0  -b 9600   # GPS NMEA"
        else
            echo "  - sudo minicom -D /dev/ttyAMA0 -b 9600  # GPS NMEA"
        fi
        echo "  - sudo hwclock -r                          # RTC"
        echo "  - sudo i2cdetect -y 1                      # I²C bus (should show 0x51)"
    fi
}

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

usage() {
    cat <<EOF
uconsole-repair.sh v$VERSION — fix a uConsole that had the wrong CM script run

USAGE:
    sudo $0 [OPTIONS]

OPTIONS:
    --dry-run        Show what would change, change nothing
    --diagnose       Report findings only, never modify (same as --dry-run with no prompt)
    --yes, -y        Skip confirmation prompt before making changes
    --help, -h       This help

WHAT IT REPAIRS:
    - Wrong-platform overlays in /boot/firmware/config.txt:
        - CM5 hardware with enable_uart=1 (CM4-only)         → swaps in dtparam=uart0
        - CM4 hardware with dtparam=uart0 (CM5-only)         → swaps in enable_uart=1
        - CM5 hardware with CM4-style RTC overlay            → swaps in i2c_csi_dsi0 remap
        - CM4 hardware with CM5-style RTC overlay            → reverts to plain CM4 form
        - Missing dtparam=rtc=off on CM5                     → adds it
    - Wrong-platform marker comment lines
    - Stale state files (e.g. cm4-state on CM5 hardware)

WHAT IT WON'T TOUCH:
    - Lines you added manually (only known overlay/parameter lines are removed)
    - Hardware-agnostic config (SPI overlay, i2c_arm, blacklist, services)
    - cmdline.txt (no hardware-specific edit was made there)
    - aiov2_ctl, AIO board package, Kali tools (those work on both CMs)

Run --diagnose first to see what it found before letting it write anything.

LOG: $LOG_FILE
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)   DRY_RUN=yes ;;
            --diagnose)  DRY_RUN=yes; DIAGNOSE_ONLY=yes; ASSUME_YES=yes ;;
            --yes|-y)    ASSUME_YES=yes ;;
            --help|-h)   usage; exit 0 ;;
            *) err "Unknown option: $1"; usage; exit 1 ;;
        esac
        shift
    done
}

main() {
    parse_args "$@"

    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    header "uConsole Repair v$VERSION — $(date)"
    [[ "$DRY_RUN" == "yes" ]] && warn "DRY-RUN MODE: no changes will be made"

    require_root

    if [[ ! -f "$CONFIG_TXT" ]]; then
        die "Cannot find $CONFIG_TXT. Aborting."
    fi

    local hw
    hw=$(detect_hardware)
    if [[ "$hw" == "unknown" ]]; then
        die "Cannot detect CM4/CM5 hardware. Aborting."
    fi

    if ! diagnose "$hw"; then
        # diagnose() returned non-zero — nothing to repair
        exit 0
    fi

    if [[ "$DIAGNOSE_ONLY" == "yes" ]]; then
        info "Diagnose-only mode — no changes will be made."
        info "Re-run without --diagnose to apply the repair."
        exit 0
    fi

    echo ""
    confirm "Apply the repair listed above?" || die "Aborted by user."

    repair "$hw"
}

main "$@"
