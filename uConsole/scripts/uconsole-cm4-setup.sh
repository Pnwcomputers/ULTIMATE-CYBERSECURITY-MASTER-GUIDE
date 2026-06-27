#!/usr/bin/env bash
#
# uconsole-cm4-setup.sh — automated post-flash setup for the ClockworkPi uConsole CM4
#
# Mirrors the CM4-SETUP.md guide step-by-step, with state tracking so it can
# resume across the three required reboots.
#
# IMPORTANT: Run this BEFORE the first `sudo apt full-upgrade` on a fresh Rex
# image. The pre-flight hardening must happen before any upgrade can break the
# LightDM session or initramfs.
#
# Usage:
#   sudo ./uconsole-cm4-setup.sh                 # auto-detect phase, run forward
#   sudo ./uconsole-cm4-setup.sh --phase=preflight
#   sudo ./uconsole-cm4-setup.sh --help
#
# Hosting: drop this into Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/uConsole/scripts/
#
# CHANGELOG:
#   v1.1 — Bug fixes from real-hardware testing:
#     - Phase 1.2: LightDM session swap is now GUARDED. Only swaps user-session
#       and autologin-session if rpd-labwc.desktop is missing; only swaps
#       greeter-session if pi-greeter-labwc.desktop is missing; skips entirely
#       if clockworkpi-theme is installed. Recognizes the upstream rename of
#       rpd-labwc → LXDE-pi-labwc.
#     - Phase 1.3: raspberrypi-sys-mods removal now checks for cascade into
#       rpd-*, raspberrypi-ui-mods, pi-greeter, wf-panel-pi, wayfire (the
#       load-bearing Pi desktop packages — removing these gives you a black
#       screen with just a cursor). On cascade, skips removal cleanly.
#     - Phase 1.4: Kali pin narrowed from "Package: *" to an allowlist of
#       kali-* names and known security tools. Added a counter-pin for the
#       Pi archive at priority 1001 covering libfm family, lxpanel, libwf,
#       libwlroots, wf-panel-pi, wayfire, pcmanfm, rpd-*, clockworkpi-theme,
#       pi-greeter. Prevents the libfm 1.4.1 ABI mismatch that produced
#       "symbol lookup error: undefined symbol: fm_cell_renderer_pixbuf_get_scale".
#     - Phase 4.3: Symlinks /usr/bin/pcmanfm-pi → /usr/bin/pcmanfm if missing,
#       so Rex's labwc autostart works on Trixie where pcmanfm-pi isn't a
#       distinct binary.
#     - Phase 6: Adds verification checks for the v1.1 safeguards (narrow
#       pin scope, Pi counter-pin, libfm is +rpt build, pcmanfm-pi exists).

set -uo pipefail

# ============================================================================
# Configuration (override via env vars or CLI flags)
# ============================================================================

VERSION="1.1"
HOSTNAME_NEW="${HOSTNAME_NEW:-uconsole}"
KALI_METAPACKAGE="${KALI_METAPACKAGE:-kali-tools-top10}"
INSTALL_WIFI_DKMS="${INSTALL_WIFI_DKMS:-yes}"
INSTALL_KALI_TOOLS="${INSTALL_KALI_TOOLS:-yes}"
ASSUME_YES="${ASSUME_YES:-no}"
DRY_RUN="${DRY_RUN:-no}"
FORCE_PHASE=""

STATE_DIR="/var/lib/uconsole-setup"
STATE_FILE="$STATE_DIR/cm4-state"
LOG_FILE="/var/log/uconsole-setup.log"

CONFIG_TXT="/boot/firmware/config.txt"
CMDLINE_TXT="/boot/firmware/cmdline.txt"
LIGHTDM_CONF="/etc/lightdm/lightdm.conf"

# Phases (in execution order)
PHASES=(preflight update kali_tools aio peripherals finalize)

# ============================================================================
# Color / logging helpers
# ============================================================================

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

log()    { echo -e "${C_BLUE}[$(date +%H:%M:%S)]${C_RESET} $*" | tee -a "$LOG_FILE"; }
info()   { echo -e "${C_CYAN}[INFO]${C_RESET} $*" | tee -a "$LOG_FILE"; }
warn()   { echo -e "${C_YELLOW}[WARN]${C_RESET} $*" | tee -a "$LOG_FILE"; }
err()    { echo -e "${C_RED}[ERR]${C_RESET}  $*" | tee -a "$LOG_FILE" >&2; }
ok()     { echo -e "${C_GREEN}[OK]${C_RESET}   $*" | tee -a "$LOG_FILE"; }
header() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}" | tee -a "$LOG_FILE"
    echo -e "${C_BOLD}${C_BLUE}  $*${C_RESET}" | tee -a "$LOG_FILE"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}" | tee -a "$LOG_FILE"
}

die() { err "$*"; exit 1; }

run() {
    # Wrap each command — log it, honor dry-run, capture failures gracefully.
    # Takes a single shell-command string (allowing pipes, redirects, &&) and
    # runs it via bash -c so we avoid the eval-array footgun (shellcheck SC2294).
    log "\$ $*"
    if [[ "$DRY_RUN" == "yes" ]]; then
        return 0
    fi
    if ! bash -c "$*"; then
        err "Command failed: $*"
        return 1
    fi
}

confirm() {
    local prompt="$1"
    if [[ "$ASSUME_YES" == "yes" ]]; then
        return 0
    fi
    local reply
    read -r -p "$(echo -e "${C_YELLOW}?${C_RESET} ${prompt} [y/N] ")" reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

# ============================================================================
# State management
# ============================================================================

state_init() {
    mkdir -p "$STATE_DIR"
    touch "$STATE_FILE"
}

state_get() {
    [[ -f "$STATE_FILE" ]] || return 1
    cat "$STATE_FILE" 2>/dev/null
}

state_set() {
    local phase="$1"
    echo "$phase" > "$STATE_FILE"
    log "State → $phase"
}

state_has_completed() {
    local phase="$1"
    local current
    current=$(state_get) || return 1
    # Walk phases array — return 0 (true) if $phase appears before $current
    local found_phase=no
    local found_current=no
    for p in "${PHASES[@]}"; do
        [[ "$p" == "$phase" ]] && found_phase=yes
        [[ "$p" == "$current" ]] && found_current=yes
        if [[ "$found_phase" == "yes" && "$found_current" == "no" ]]; then
            return 1
        fi
        [[ "$p" == "$current" ]] && return 0
    done
    return 1
}

next_phase() {
    local current="$1"
    local found=no
    for p in "${PHASES[@]}"; do
        if [[ "$found" == "yes" ]]; then
            echo "$p"
            return 0
        fi
        [[ "$p" == "$current" ]] && found=yes
    done
    echo ""  # no next phase
}

# ============================================================================
# Pre-condition checks
# ============================================================================

require_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root. Try: sudo $0"
}

detect_os() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID,,}" in
            kali)   echo "kali" ;;
            debian) echo "trixie" ;;  # Rex's Trixie image reports as debian
            *)      echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

detect_hardware() {
    local model
    if [[ -r /proc/device-tree/model ]]; then
        model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null)
        case "$model" in
            *"Compute Module 4"*) echo "cm4" ;;
            *"Compute Module 5"*) echo "cm5" ;;
            *) echo "unknown ($model)" ;;
        esac
    else
        echo "unknown"
    fi
}

is_rex_image() {
    # Rex's APT repo source — if this file exists or repo is in apt sources, it's a Rex image
    if grep -rq "ak-rex" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        return 0
    fi
    if [[ -f /etc/apt/sources.list.d/ak-rex.list ]]; then
        return 0
    fi
    return 1
}

preflight_checks() {
    header "Pre-flight environment checks"

    require_root

    local os hw
    os=$(detect_os)
    hw=$(detect_hardware)

    info "OS:       $os"
    info "Hardware: $hw"
    info "Hostname: $(hostname)"
    info "Kernel:   $(uname -r)"

    if [[ "$hw" != "cm4" ]]; then
        warn "Hardware doesn't appear to be a CM4 (detected: $hw)"
        warn "This script is CM4-specific. The CM5 setup script has different GPIO/UART/RTC configs."
        confirm "Continue anyway?" || die "Aborted by user"
    fi

    if ! is_rex_image; then
        warn "This doesn't look like one of Rex's images (no ak-rex APT repo found)."
        warn "The script may still work, but uConsole-specific kernel/drivers aren't guaranteed."
        confirm "Continue anyway?" || die "Aborted by user"
    fi

    if [[ "$os" == "unknown" ]]; then
        die "Could not detect OS. Aborting."
    fi

    if ! command -v apt >/dev/null; then
        die "apt not found — this script targets Debian-based systems only"
    fi

    ok "Environment looks good"
}

# ============================================================================
# Phase 1: Pre-flight hardening
# ============================================================================

phase_preflight() {
    header "Phase 1/6: Pre-flight hardening (cryptsetup, lightdm, raspberrypi-sys-mods, Kali repo)"

    local os
    os=$(detect_os)

    # 1.1 — cryptsetup-initramfs hook
    info "1.1 — Disabling cryptsetup-initramfs hook"
    run "mkdir -p /etc/cryptsetup-initramfs"
    if [[ "$DRY_RUN" != "yes" ]]; then
        echo "CRYPTSETUP=n" > /etc/cryptsetup-initramfs/conf-hook
    fi
    ok "cryptsetup hook neutered"

    # 1.2 — LightDM session pinning (defensive: only swap if Pi files are missing)
    info "1.2 — Checking LightDM session references for safety"
    run "apt-get update -qq"
    run "apt-get install -y lightdm-gtk-greeter labwc rtkit"

    if [[ -f "$LIGHTDM_CONF" && "$DRY_RUN" != "yes" ]]; then
        # Inventory: which session/greeter files and key packages are present?
        local has_rpd_session=no
        local has_lxde_pi_session=no
        local has_pi_greeter=no
        local has_clockworkpi_theme=no

        [ -f /usr/share/wayland-sessions/rpd-labwc.desktop ]        && has_rpd_session=yes
        [ -f /usr/share/wayland-sessions/LXDE-pi-labwc.desktop ]    && has_lxde_pi_session=yes
        [ -f /usr/share/xgreeters/pi-greeter-labwc.desktop ]        && has_pi_greeter=yes
        dpkg -l clockworkpi-theme 2>/dev/null | grep -q '^ii'       && has_clockworkpi_theme=yes

        info "  Session inventory:"
        info "    rpd-labwc.desktop:        $has_rpd_session"
        info "    LXDE-pi-labwc.desktop:    $has_lxde_pi_session"
        info "    pi-greeter-labwc.desktop: $has_pi_greeter"
        info "    clockworkpi-theme:        $has_clockworkpi_theme"

        # If clockworkpi-theme is installed, the session/greeter files are load-bearing
        # on Rex's image and the image is healthy. DO NOT swap anything.
        if [[ "$has_clockworkpi_theme" == "yes" ]]; then
            ok "  clockworkpi-theme installed — leaving LightDM config alone (image is healthy)"
        else
            # user-session and autologin-session: prefer LXDE-pi-labwc → rpd-labwc → labwc
            if [[ "$has_rpd_session" == "no" && "$has_lxde_pi_session" == "yes" ]]; then
                info "  Upstream renamed session: rpd-labwc → LXDE-pi-labwc. Updating lightdm.conf."
                sed -i \
                    -e 's/^user-session=rpd-labwc$/user-session=LXDE-pi-labwc/' \
                    -e 's/^autologin-session=rpd-labwc$/autologin-session=LXDE-pi-labwc/' \
                    "$LIGHTDM_CONF"
            elif [[ "$has_rpd_session" == "no" && "$has_lxde_pi_session" == "no" ]]; then
                warn "  Neither rpd-labwc nor LXDE-pi-labwc present — falling back to plain labwc"
                sed -i \
                    -e 's/^user-session=rpd-labwc$/user-session=labwc/' \
                    -e 's/^autologin-session=rpd-labwc$/autologin-session=labwc/' \
                    "$LIGHTDM_CONF"
            else
                ok "  rpd-labwc.desktop present — leaving user-session/autologin-session alone"
            fi

            # greeter-session: only swap if pi-greeter-labwc is actually missing
            if [[ "$has_pi_greeter" == "no" ]]; then
                warn "  pi-greeter-labwc.desktop missing — falling back to lightdm-gtk-greeter"
                sed -i 's/^greeter-session=pi-greeter-labwc$/greeter-session=lightdm-gtk-greeter/' "$LIGHTDM_CONF"
            else
                ok "  pi-greeter-labwc.desktop present — leaving greeter-session alone"
            fi

            # AccountsService cleanup: only rewrite if rpd-labwc is gone
            if [[ "$has_rpd_session" == "no" ]]; then
                local replacement="labwc"
                [[ "$has_lxde_pi_session" == "yes" ]] && replacement="LXDE-pi-labwc"
                for f in /var/lib/AccountsService/users/*; do
                    [[ -f "$f" ]] || continue
                    if grep -q "^XSession=rpd-labwc" "$f"; then
                        sed -i "s/^XSession=rpd-labwc$/XSession=${replacement}/" "$f"
                    fi
                done
            fi
        fi
    fi

    # Fallback compositor and greeter must always be installable, even if we didn't swap
    if [[ "$DRY_RUN" != "yes" ]]; then
        if [[ ! -f /usr/share/wayland-sessions/labwc.desktop ]]; then
            die "labwc.desktop session file missing after install — something is wrong"
        fi
        if [[ ! -f /usr/share/xgreeters/lightdm-gtk-greeter.desktop ]]; then
            die "lightdm-gtk-greeter.desktop missing after install — something is wrong"
        fi
    fi
    ok "LightDM session check complete"

    # 1.3 — (Trixie only) raspberrypi-sys-mods removal
    if [[ "$os" == "trixie" ]]; then
        info "1.3 — Considering raspberrypi-sys-mods removal (Trixie + Kali path)"
        if dpkg -l raspberrypi-sys-mods 2>/dev/null | grep -q '^ii'; then
            # Dry-run check — make sure removal won't take out anything critical
            local removal_preview
            removal_preview=$(apt-get -s remove raspberrypi-sys-mods 2>/dev/null | grep -E "^Remv" || true)

            # Tier 1: kernel/firmware/device-tree — removal of these bricks the system
            local critical_pattern="linux-image|raspberrypi-kernel|raspi-firmware|device-tree"
            # Tier 2: load-bearing Pi desktop packages — removal breaks the desktop
            #         (rpd-*, raspberrypi-ui-mods ship lwrespawn + session files; pi-greeter
            #         ships the greeter session; wf-panel-pi is the taskbar)
            local desktop_pattern="rpd-|raspberrypi-ui-mods|raspberrypi-net-mods|pi-greeter|wf-panel-pi|wayfire"

            if echo "$removal_preview" | grep -qE "$critical_pattern"; then
                err "Removing raspberrypi-sys-mods would also pull out CRITICAL packages:"
                echo "$removal_preview" | tee -a "$LOG_FILE"
                err "Aborting. Use --force-overwrite path manually instead — see CM4-SETUP.md troubleshooting."
                return 1
            fi

            if echo "$removal_preview" | grep -qE "$desktop_pattern"; then
                warn "Removing raspberrypi-sys-mods would cascade into Pi desktop packages:"
                echo "$removal_preview" | grep -E "$desktop_pattern" | tee -a "$LOG_FILE"
                warn "Skipping removal — keeping the desktop intact."
                warn "Future apt operations will use --force-overwrite to handle the diversion conflict instead."
                info "(This is the safe path on Rex's image where the desktop is healthy.)"
            else
                run "apt-get remove -y raspberrypi-sys-mods"
            fi
        else
            info "raspberrypi-sys-mods not installed — skipping"
        fi

        # Clean stale EXTERNALLY-MANAGED diversion
        local extmgd
        extmgd=$(ls /usr/lib/python3.*/EXTERNALLY-MANAGED 2>/dev/null | head -1 || true)
        if [[ -n "$extmgd" ]]; then
            run "rm -f '$extmgd'"
            run "dpkg-divert --package raspberrypi-sys-mods --remove --rename '$extmgd' 2>/dev/null || true"
        fi
        ok "raspberrypi-sys-mods cleaned up"

        # 1.4 — Add Kali repo + NARROW pin + Pi counter-pin
        info "1.4 — Adding Kali rolling repo with narrow pin scope"
        if [[ "$DRY_RUN" != "yes" ]]; then
            echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" \
                > /etc/apt/sources.list.d/kali.list

            curl -fsSL https://archive.kali.org/archive-key.asc \
                | gpg --dearmor -o /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg

            # NARROW Kali pin: ONLY Kali-named packages and known security tools.
            # The old "Package: *" pin pulled in Kali's newer runtime libs (libfm 1.4.1)
            # which ABI-conflict with Pi-archive binaries (pcmanfm 1.4.0) and produce
            # "symbol lookup error: undefined symbol: fm_cell_renderer_pixbuf_get_scale"
            # at runtime. Allowlist scope only.
            cat > /etc/apt/preferences.d/kali-pin <<'EOF'
# Kali rolling: ONLY for Kali-named packages and security tools.
# Do NOT pin Kali for system libraries — they ABI-conflict with Pi-archive binaries.

Package: kali-* metasploit-framework
Pin: release o=Kali
Pin-Priority: 990

Package: aircrack-ng* bettercap* hydra* nmap responder impacket-* crackmapexec netexec wireshark* burpsuite sqlmap john* hashcat* gobuster ffuf nikto wpscan
Pin: release o=Kali
Pin-Priority: 990
EOF

            # Counter-pin: Pi archive at priority 1001 (>1000 means "downgrade if needed")
            # for runtime libraries ABI-coupled to Pi-built binaries. Without this, Kali's
            # libfm 1.4.1 silently replaces Pi's libfm 1.4.0 and breaks pcmanfm/lxpanel.
            cat > /etc/apt/preferences.d/uconsole-keep-pi-libs <<'EOF'
# Pi-archive versions of runtime libraries ABI-coupled to Pi-built binaries
# (pcmanfm, lxpanel, wf-panel-pi, raspberrypi-ui-mods, etc.).
# Priority 1001 means apt will downgrade to maintain these if Kali ships newer.

Package: libfm-data libfm-gtk-data libfm-modules libfm4t64 libfm-extra4t64 libfm-gtk3-4t64
Pin: release o=Raspberry Pi Foundation
Pin-Priority: 1001

Package: lxpanel lxpanel-data lxpanel-* libwf-* libwlroots-* wf-panel-pi wayfire
Pin: release o=Raspberry Pi Foundation
Pin-Priority: 1001

Package: pcmanfm raspberrypi-ui-mods rpd-* clockworkpi-theme pi-greeter pi-greeter-* labwc-prompt
Pin: release o=Raspberry Pi Foundation
Pin-Priority: 1001
EOF
        fi
        run "apt-get update"
        ok "Kali repo configured with narrow pin + Pi-archive counter-pin"
    else
        info "Kali image detected — skipping raspberrypi-sys-mods removal and Kali repo setup"
    fi

    state_set "preflight"
    ok "Phase 1 complete — pre-flight hardening done"
}

# ============================================================================
# Phase 2: First full system upgrade
# ============================================================================

phase_update() {
    header "Phase 2/6: First system upgrade (now safe after pre-flight)"

    info "Running apt update + full-upgrade"
    run "apt-get update"

    if ! run "apt-get -o Dpkg::Options::='--force-overwrite' full-upgrade -y"; then
        warn "full-upgrade hit errors — attempting --fix-broken"
        run "apt-get -o Dpkg::Options::='--force-overwrite' --fix-broken install -y" || true
        run "apt-get -o Dpkg::Options::='--force-overwrite' full-upgrade -y" \
            || die "full-upgrade failed twice — investigate before proceeding"
    fi

    info "Setting hostname to $HOSTNAME_NEW"
    run "hostnamectl set-hostname $HOSTNAME_NEW"

    info "You'll need to run these manually after the script finishes:"
    info "  sudo dpkg-reconfigure tzdata   # set your timezone"
    info "  passwd                          # change your password"

    state_set "update"
    ok "Phase 2 complete — system upgraded"
    warn "REBOOT REQUIRED. Re-run this script after reboot to continue."
    REBOOT_REQUIRED=yes
}

# ============================================================================
# Phase 3: Install Kali tools (Trixie only)
# ============================================================================

phase_kali_tools() {
    header "Phase 3/6: Install Kali tools (Trixie only)"

    local os
    os=$(detect_os)

    if [[ "$os" != "trixie" ]]; then
        info "Not on Trixie — Kali tools already pre-installed in Kali image. Skipping."
        state_set "kali_tools"
        return 0
    fi

    if [[ "$INSTALL_KALI_TOOLS" != "yes" ]]; then
        info "INSTALL_KALI_TOOLS=no — skipping at user request"
        state_set "kali_tools"
        return 0
    fi

    info "Installing $KALI_METAPACKAGE"
    if ! run "apt-get install -y --no-install-recommends '$KALI_METAPACKAGE'" 2>&1; then
        warn "Initial install hit conflicts — applying --force-overwrite"
        run "apt-get -o Dpkg::Options::='--force-overwrite' --fix-broken install -y"
        run "apt-get -o Dpkg::Options::='--force-overwrite' install -y '$KALI_METAPACKAGE'" \
            || die "Kali tools install failed"
    fi

    # Make force-overwrite persistent so future upgrades don't bite
    if [[ "$DRY_RUN" != "yes" && ! -f /etc/apt/apt.conf.d/99-force-overwrite ]]; then
        echo 'Dpkg::Options { "--force-overwrite"; }' > /etc/apt/apt.conf.d/99-force-overwrite
        info "Made --force-overwrite persistent in /etc/apt/apt.conf.d/99-force-overwrite"
    fi

    state_set "kali_tools"
    ok "Phase 3 complete — Kali tools installed"
}

# ============================================================================
# Phase 4: Install aiov2_ctl + AIO board package
# ============================================================================

phase_aio() {
    header "Phase 4/6: Install aiov2_ctl and the HackerGadgets AIO board package"

    # 4.1 — aiov2_ctl
    info "4.1 — Installing aiov2_ctl from upstream git"
    run "apt-get install -y python3 python3-pyqt6 git"

    local clone_dir="/opt/aiov2_ctl"
    if [[ -d "$clone_dir" ]]; then
        info "$clone_dir already exists — pulling latest"
        run "git -C '$clone_dir' pull --ff-only" || warn "git pull failed; continuing with existing checkout"
    else
        run "git clone https://github.com/hackergadgets/aiov2_ctl.git '$clone_dir'"
    fi
    run "cd '$clone_dir' && python3 ./aiov2_ctl.py --install"

    if [[ "$DRY_RUN" != "yes" ]] && ! command -v aiov2_ctl >/dev/null; then
        if [[ -f "/usr/local/bin/aiov2_ctl" ]]; then
            run "ln -sf /usr/local/bin/aiov2_ctl /usr/bin/aiov2_ctl"
        else
            die "aiov2_ctl install failed: binary not found in /usr/local/bin"
        fi
    fi
    ok "aiov2_ctl installed"

    # 4.2 — AIO board package (Rex's recommended command)
    info "4.2 — Installing hackergadgets-uconsole-aio-board (+ recommends)"
    run "apt-get update"
    if ! run "apt-get --install-recommends install -y hackergadgets-uconsole-aio-board"; then
        warn "AIO board package failed — applying the documented /tmp script fix (purge + retry)"
        run "apt-get purge -y hackergadgets-uconsole-aio-board" || true
        run "apt-get update"
        run "apt-get --install-recommends install -y hackergadgets-uconsole-aio-board" \
            || die "AIO board package install failed twice — see /var/log/uconsole-setup.log"
    fi

    # 4.3 — Ensure /usr/bin/pcmanfm-pi exists so Rex's labwc autostart works
    info "4.3 — Ensuring /usr/bin/pcmanfm-pi exists for Rex's autostart"
    if [[ "$DRY_RUN" != "yes" ]]; then
        if [[ ! -e /usr/bin/pcmanfm-pi && -x /usr/bin/pcmanfm ]]; then
            run "ln -sf /usr/bin/pcmanfm /usr/bin/pcmanfm-pi"
            ok "  Symlinked /usr/bin/pcmanfm-pi → /usr/bin/pcmanfm"
            info "  (Rex's /etc/xdg/labwc/autostart calls pcmanfm-pi but Trixie's pcmanfm"
            info "   package installs only /usr/bin/pcmanfm — the symlink bridges the gap.)"
        elif [[ -e /usr/bin/pcmanfm-pi ]]; then
            info "  /usr/bin/pcmanfm-pi already present — skipping"
        else
            warn "  Neither pcmanfm-pi nor pcmanfm found — desktop file manager will not autostart"
            warn "  Install pcmanfm with: sudo apt install pcmanfm"
        fi
    fi

    # 4.4 — Fix missing dependencies for meshtasticd on Trixie/Kali
    info "4.4 — Checking older dependencies required for LoRa services..."
    
    if ! apt-cache show libgpiod2 >/dev/null 2>&1; then
        info "  libgpiod2 not found in apt repos. Fetching from Bookworm..."
        if [[ "$DRY_RUN" != "yes" ]]; then
            run "wget -q -O /tmp/libgpiod2.deb http://ftp.us.debian.org/debian/pool/main/libg/libgpiod/libgpiod2_1.6.3-1+b3_arm64.deb"
            run "dpkg -i /tmp/libgpiod2.deb" || warn "Failed to inject libgpiod2"
        fi
    fi

    if ! apt-cache show libyaml-cpp0.7 >/dev/null 2>&1; then
        info "  libyaml-cpp0.7 not found in apt repos. Fetching from Bookworm..."
        if [[ "$DRY_RUN" != "yes" ]]; then
            run "wget -q -O /tmp/libyaml-cpp0.7.deb http://ftp.us.debian.org/debian/pool/main/y/yaml-cpp/libyaml-cpp0.7_0.7.0+dfsg-8+b1_arm64.deb"
            run "dpkg -i /tmp/libyaml-cpp0.7.deb" || warn "Failed to inject libyaml-cpp0.7"
        fi
    fi

    # Install meshtastic-mui with auto-recovery for dependency snags
    info "Installing meshtastic-mui (LoRa Web UI)..."
    if ! run "apt-get install -y meshtastic-mui"; then
        warn "  meshtastic-mui install hit a snag — attempting --fix-broken and retrying..."
        run "apt-get --fix-broken install -y" || true
        run "apt-get -o Dpkg::Options::='--force-overwrite' install -y meshtastic-mui" \
            || warn "  meshtastic-mui still failing — non-fatal, continuing."
    fi

    # 4.5 — ADS-B Tracking (readsb + tar1090)
    info "4.5 — Installing ADS-B Tracking (readsb + tar1090)"
    
    # Power on the SDR rail LIVE so the hardware is immediately visible to the installer
    if [[ "$DRY_RUN" != "yes" ]]; then
        run "aiov2_ctl --sdr on"
        run "sleep 3" # Give the USB bus a few seconds to enumerate the Realtek device
    fi

    # Install the backend decoder FIRST so it claims the SDR and creates aircraft.json
    info "  Installing readsb (Backend Decoder)..."
    if ! run "bash -c \"\$(wget -q -O - https://github.com/wiedehopf/adsb-scripts/raw/master/readsb-install.sh)\""; then
        warn "  readsb installation hit a snag — check if the SDR is visible via lsusb"
    fi

    # Install the frontend web map SECOND, now that the backend is running
    info "  Installing tar1090 (Frontend Map)..."
    run "bash -c \"\$(wget -nv -O - https://github.com/wiedehopf/tar1090/raw/master/install.sh)\""
    
    ok "ADS-B ecosystem installed"

    state_set "aio"
    ok "Phase 4 complete — AIO board ecosystem installed"
    warn "REBOOT REQUIRED so kernel modules and services load cleanly."
    REBOOT_REQUIRED=yes
}
# ============================================================================
# Phase 5: Peripheral configuration (config.txt, cmdline.txt, groups, blacklists)
# ============================================================================

config_txt_has() {
    local pattern="$1"
    grep -qE "^[[:space:]]*${pattern}" "$CONFIG_TXT" 2>/dev/null
}

config_txt_append() {
    local marker="$1"
    local content="$2"
    if config_txt_has "$marker"; then
        info "config.txt already has '$marker' — skipping"
        return 0
    fi
    info "Adding to config.txt: $marker"
    if [[ "$DRY_RUN" != "yes" ]]; then
        printf '\n%s\n' "$content" >> "$CONFIG_TXT"
    fi
}

phase_peripherals() {
    header "Phase 5/6: Peripheral configuration (GPS UART, SPI, RTC, dialout, blacklists)"

    # 5.1 — config.txt additions
    info "5.1 — Updating /boot/firmware/config.txt"

    # Add a block header so the user can see where this script wrote
    if ! grep -q "AIO v2 Board Configuration (CM4)" "$CONFIG_TXT" 2>/dev/null; then
        if [[ "$DRY_RUN" != "yes" ]]; then
            cat >> "$CONFIG_TXT" <<'EOF'

# === AIO v2 Board Configuration (CM4) — added by uconsole-cm4-setup.sh ===
EOF
        fi
    fi

    config_txt_append "enable_uart=1"    "enable_uart=1"
    config_txt_append "dtparam=spi=on"   "dtparam=spi=on"
    config_txt_append "dtoverlay=spi1-1cs" "dtoverlay=spi1-1cs"
    config_txt_append "dtparam=i2c_arm=on" "dtparam=i2c_arm=on"
    config_txt_append "dtoverlay=i2c-rtc,pcf85063a" "dtoverlay=i2c-rtc,pcf85063a"

    # 5.2 — cmdline.txt: remove console=serial0,115200
    info "5.2 — Freeing /dev/ttyS0 for GPS in cmdline.txt"
    if grep -q "console=serial0,115200" "$CMDLINE_TXT" 2>/dev/null; then
        if [[ "$DRY_RUN" != "yes" ]]; then
            cp "$CMDLINE_TXT" "${CMDLINE_TXT}.bak.$(date +%s)"
            sed -i 's/console=serial0,115200 \?//' "$CMDLINE_TXT"
            # Collapse any double spaces left behind
            sed -i 's/  */ /g' "$CMDLINE_TXT"
        fi
        ok "Removed console=serial0,115200 (backup saved next to cmdline.txt)"
    else
        info "cmdline.txt already clean — skipping"
    fi

    # 5.3 — dialout group for the invoking user
    info "5.3 — Adding user(s) to the dialout group"
    local target_user="${SUDO_USER:-${USER:-pi}}"
    if id "$target_user" &>/dev/null; then
        run "usermod -a -G dialout '$target_user'"
        ok "Added $target_user to dialout"
    else
        warn "Could not determine non-root user — add manually with 'sudo usermod -aG dialout <user>'"
    fi

    # 5.4 — Blacklist DVB-T driver (lets SDR software claim the RTL chip)
    info "5.4 — Blacklisting dvb_usb_rtl28xxu (SDR support)"
    if [[ ! -f /etc/modprobe.d/blacklist-rtl.conf ]]; then
        if [[ "$DRY_RUN" != "yes" ]]; then
            echo "blacklist dvb_usb_rtl28xxu" > /etc/modprobe.d/blacklist-rtl.conf
        fi
        run "rmmod dvb_usb_rtl28xxu 2>/dev/null || true"
        ok "DVB-T driver blacklisted"
    else
        info "Blacklist already present — skipping"
    fi

    # 5.5 — Disable devterm-printer.service (conflicts with LoRa on SPI1)
    info "5.5 — Disabling devterm-printer.service (SPI1 conflict with LoRa)"
    if systemctl list-unit-files | grep -q "^devterm-printer.service"; then
        run "systemctl stop devterm-printer.service 2>/dev/null || true"
        run "systemctl disable devterm-printer.service 2>/dev/null || true"
        ok "devterm-printer disabled"
    else
        info "devterm-printer.service not present — skipping"
    fi

    # 5.6 — Optional WiFi DKMS driver
    if [[ "$INSTALL_WIFI_DKMS" == "yes" ]]; then
        info "5.6 — Installing RTL8812AU/RTL8814AU DKMS driver"
        # Rex's image ships kernel headers — DKMS should build cleanly
        if run "apt-get install -y realtek-rtl88xxau-dkms"; then
            if [[ "$DRY_RUN" != "yes" ]]; then
                local dkms_status
                dkms_status=$(dkms status 2>/dev/null | grep -E "rtl88|8812au" || true)
                if [[ -n "$dkms_status" ]]; then
                    ok "RTL8812AU DKMS module registered:"
                    echo "$dkms_status" | tee -a "$LOG_FILE"
                else
                    warn "DKMS install succeeded but module isn't visible — may need 'dkms autoinstall' or a reboot"
                fi
            fi
        else
            warn "RTL8812AU DKMS install failed — check kernel headers with: ls /lib/modules/\$(uname -r)/build"
        fi
    else
        info "Skipping WiFi DKMS install (INSTALL_WIFI_DKMS=no)"
    fi

    # 5.7 — Set boot rails for peripherals (so they come up on next boot)
    info "5.7 — Configuring boot rails for GPS, LoRa, SDR"
    if command -v aiov2_ctl >/dev/null; then
        run "aiov2_ctl --boot-rail GPS on" || warn "Failed to set GPS boot rail — set manually post-reboot"
        run "aiov2_ctl --boot-rail LORA on" || warn "Failed to set LORA boot rail — set manually post-reboot"
        run "aiov2_ctl --boot-rail SDR on" || warn "Failed to set SDR boot rail — set manually post-reboot"
    else
        warn "aiov2_ctl not on PATH — skipping boot rail config. Run manually after reboot."
    fi

    state_set "peripherals"
    ok "Phase 5 complete — peripherals configured"
    warn "REBOOT REQUIRED so config.txt overlays take effect."
    REBOOT_REQUIRED=yes
}

# ============================================================================
# Phase 6: Finalize (verification + handoff to manual steps)
# ============================================================================

phase_finalize() {
    header "Phase 6/6: Verification and handoff"

    info "Verifying components installed by previous phases..."

    local checks_passed=0
    local checks_failed=0

    check() {
        local desc="$1"
        local cmd="$2"
        if eval "$cmd" &>/dev/null; then
            ok "  ✓ $desc"
            ((checks_passed++))
        else
            err "  ✗ $desc"
            ((checks_failed++))
        fi
    }

    check "aiov2_ctl on PATH"          "command -v aiov2_ctl"
    check "hackergadgets-uconsole-aio-board installed" "dpkg -l hackergadgets-uconsole-aio-board | grep -q '^ii'"
    check "labwc compositor available" "[ -f /usr/share/wayland-sessions/labwc.desktop ]"
    check "lightdm-gtk-greeter available" "[ -f /usr/share/xgreeters/lightdm-gtk-greeter.desktop ]"
    check "cryptsetup hook disabled"   "grep -q 'CRYPTSETUP=n' /etc/cryptsetup-initramfs/conf-hook"
    check "config.txt has enable_uart" "grep -q '^enable_uart=1' $CONFIG_TXT"
    check "config.txt has SPI overlays" "grep -q 'dtoverlay=spi1-1cs' $CONFIG_TXT"
    check "config.txt has RTC overlay" "grep -q 'pcf85063a' $CONFIG_TXT"
    check "cmdline.txt console freed"  "! grep -q 'console=serial0,115200' $CMDLINE_TXT"
    check "DVB-T blacklist present"    "[ -f /etc/modprobe.d/blacklist-rtl.conf ]"
    check "devterm-printer disabled"   "! systemctl is-enabled devterm-printer.service 2>/dev/null | grep -q enabled"
    check "pcmanfm-pi exists (binary or symlink)" "[ -e /usr/bin/pcmanfm-pi ]"

    # Trixie-only checks (Kali image won't have these pin files)
    if [[ "$(detect_os)" == "trixie" ]]; then
        check "Kali pin is narrow (no Package:* wildcard)" \
            "[ -f /etc/apt/preferences.d/kali-pin ] && ! grep -qE '^Package:[[:space:]]*\\*[[:space:]]*\$' /etc/apt/preferences.d/kali-pin"
        check "Pi-archive lib counter-pin in place" \
            "[ -f /etc/apt/preferences.d/uconsole-keep-pi-libs ]"
        check "libfm-modules is Pi-archive build (no ABI mismatch)" \
            "dpkg -l libfm-modules 2>/dev/null | grep -qE '\\+rpt[0-9]'"
    fi

    echo "" | tee -a "$LOG_FILE"
    if (( checks_failed == 0 )); then
        ok "All $checks_passed verification checks passed."
    else
        warn "$checks_passed passed, $checks_failed FAILED. Review the log."
    fi

    cat <<EOF | tee -a "$LOG_FILE"

────────────────────────────────────────────────────────────────────
MANUAL STEPS REMAINING (script can't do these for you):

  1. Run:  sudo dpkg-reconfigure tzdata
  2. Run:  passwd          (change default password)
  3. Connect antennas to the SDR, LoRa, and GPS IPEX connectors
  4. Open https://localhost in a browser, configure Meshtastic:
     - Config → LoRa → Region: US (or your region)
     - Config → LoRa → Modem Preset: LongFast (slot 20 for US)
  5. Test peripherals:
     - aiov2_ctl --status
     - sudo minicom -D /dev/ttyS0 -b 9600     (GPS NMEA stream)
     - sdrpp                                    (SDR++)
     - sudo hwclock -r && sudo aiov2_ctl --sync-rtc  (RTC)
  6. (If using NVMe Battery Board) See CM4-SETUP.md Step 14
────────────────────────────────────────────────────────────────────
EOF

    state_set "finalize"
    ok "Setup complete!"
}

# ============================================================================
# Dispatcher
# ============================================================================

REBOOT_REQUIRED=no

run_phase() {
    local phase="$1"
    case "$phase" in
        preflight)   phase_preflight ;;
        update)      phase_update ;;
        kali_tools)  phase_kali_tools ;;
        aio)         phase_aio ;;
        peripherals) phase_peripherals ;;
        finalize)    phase_finalize ;;
        *) die "Unknown phase: $phase" ;;
    esac
}

run_from() {
    # Run phases from $1 onwards, stopping at any reboot point
    local start_phase="$1"
    local found=no
    for p in "${PHASES[@]}"; do
        [[ "$p" == "$start_phase" ]] && found=yes
        if [[ "$found" == "yes" ]]; then
            run_phase "$p" || die "Phase '$p' failed — check $LOG_FILE"
            if [[ "$REBOOT_REQUIRED" == "yes" ]]; then
                echo "" | tee -a "$LOG_FILE"
                warn "═══════════════════════════════════════════════════════════════"
                warn "  Reboot now, then re-run this script to continue."
                warn "  Command:  sudo $0"
                warn "═══════════════════════════════════════════════════════════════"
                exit 0
            fi
        fi
    done
}

# ============================================================================
# CLI argument parsing
# ============================================================================

usage() {
    cat <<EOF
uconsole-cm4-setup.sh v$VERSION — automated post-flash setup for ClockworkPi uConsole CM4

USAGE:
    sudo $0 [OPTIONS]

OPTIONS:
    --phase=PHASE           Run only one phase
                            (preflight|update|kali_tools|aio|peripherals|finalize)
    --hostname=NAME         Hostname to set (default: $HOSTNAME_NEW)
    --kali-meta=PKG         Kali metapackage (default: $KALI_METAPACKAGE)
                            Options: kali-tools-top10, kali-linux-headless, kali-linux-default
    --skip-wifi-dkms        Skip RTL8812AU DKMS install
    --skip-kali-tools       Skip Kali tools entirely (Trixie only)
    --yes, -y               Don't prompt for confirmations
    --dry-run               Show what would be done, don't actually do it
    --reset                 Wipe state file and start over
    --status                Show current phase and exit
    --help, -h              This help

ENV VAR OVERRIDES:
    HOSTNAME_NEW, KALI_METAPACKAGE, INSTALL_WIFI_DKMS, INSTALL_KALI_TOOLS,
    ASSUME_YES, DRY_RUN

EXAMPLES:
    # Default: auto-detect phase from state file, run to next reboot point
    sudo $0

    # Re-run a single phase
    sudo $0 --phase=peripherals

    # Trixie with the full Kali default toolkit, no prompts
    sudo $0 --kali-meta=kali-linux-default --yes

    # See what would happen without doing it
    sudo $0 --dry-run

STATE:    $STATE_FILE
LOG:      $LOG_FILE
GUIDE:    https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/uConsole/CM4-SETUP.md
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --phase=*)         FORCE_PHASE="${1#*=}" ;;
            --hostname=*)      HOSTNAME_NEW="${1#*=}" ;;
            --kali-meta=*)     KALI_METAPACKAGE="${1#*=}" ;;
            --skip-wifi-dkms)  INSTALL_WIFI_DKMS=no ;;
            --skip-kali-tools) INSTALL_KALI_TOOLS=no ;;
            --yes|-y)          ASSUME_YES=yes ;;
            --dry-run)         DRY_RUN=yes ;;
            --reset)
                rm -f "$STATE_FILE"
                ok "State file wiped. Next run starts from preflight."
                exit 0
                ;;
            --status)
                if [[ -f "$STATE_FILE" ]]; then
                    info "Last completed phase: $(cat "$STATE_FILE")"
                    info "Next phase: $(next_phase "$(cat "$STATE_FILE")")"
                else
                    info "No state file — script has not run yet."
                fi
                exit 0
                ;;
            --help|-h)         usage; exit 0 ;;
            *) err "Unknown option: $1"; usage; exit 1 ;;
        esac
        shift
    done
}

# ============================================================================
# Entry point
# ============================================================================

main() {
    parse_args "$@"

    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"

    header "uConsole CM4 Setup v$VERSION — $(date)"
    [[ "$DRY_RUN" == "yes" ]] && warn "DRY-RUN MODE: no changes will be made"

    preflight_checks
    state_init

    if [[ -n "$FORCE_PHASE" ]]; then
        info "Running only --phase=$FORCE_PHASE"
        run_phase "$FORCE_PHASE" || die "Phase '$FORCE_PHASE' failed"
        ok "Done. (Note: state file NOT advanced when using --phase)"
        exit 0
    fi

    local last_done next
    if last_done=$(state_get) && [[ -n "$last_done" ]]; then
        next=$(next_phase "$last_done")
        if [[ -z "$next" ]]; then
            ok "All phases already complete. (Use --reset to start over.)"
            exit 0
        fi
        info "Last completed phase: $last_done — resuming at: $next"
    else
        next="preflight"
        info "No prior state — starting from preflight"
    fi

    confirm "Proceed with phase '$next' and continue forward?" || die "Aborted by user"
    run_from "$next"

    ok "Script complete. No further reboots required."
}

main "$@"
