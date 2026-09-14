#!/usr/bin/env bash
# uConsole CM5 Parrot post-flash setup, v1.0 (experimental).
# Adapted from uconsole-cm5-setup.sh v1.4. Requires existing Parrot OS.
# Does not install an OS or convert Debian/Kali into Parrot.
# Preserve the image's display/session configuration. This is NOT a repair script.
# Package installation can still run maintainer scripts: image backup and device
# validation remain necessary. See ../CM5-DISPLAY-RECOVERY.md.
set -uo pipefail

VERSION=1.0
STATE_DIR=/var/lib/uconsole-parrot-setup
STATE_FILE=$STATE_DIR/cm5-state
VERSION_FILE=$STATE_DIR/cm5-version
LOG_FILE=/var/log/uconsole-parrot-setup.log
APT_DIR=/etc/apt
OS_RELEASE=/etc/os-release
MODEL_FILE=/proc/device-tree/model
DRY_RUN=${DRY_RUN:-no}
ASSUME_YES=${ASSUME_YES:-no}
INSTALL_AIO=${INSTALL_AIO:-no}
INSTALL_PARROT_TOOLS=${INSTALL_PARROT_TOOLS:-no}
INSTALL_WIFI_DKMS=${INSTALL_WIFI_DKMS:-no}
PARROT_METAPACKAGE=${PARROT_METAPACKAGE:-parrot-tools-infogathering}
WIFI_DKMS_PACKAGE=${WIFI_DKMS_PACKAGE:-realtek-rtl88xxau-dkms}
HOSTNAME_NEW=${HOSTNAME_NEW:-}
export LC_ALL=C
FORCE_PHASE=
ACTION=run
PHASES=(preflight update parrot_tools aio peripherals finalize)

log() {
    printf '%s\n' "$*"
    if [[ "$DRY_RUN" != yes && "$ACTION" == run ]]; then
        printf '%s\n' "$*" >> "$LOG_FILE" || return 1
    fi
}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
run() {
    local rendered
    printf -v rendered '%q ' "$@"
    log "+ $rendered" || return 1
    [[ "$DRY_RUN" == yes ]] && return 0
    "$@"
}
usage() {
    cat <<HELP
uconsole-cm5-parrot-setup.sh v$VERSION (experimental)
Usage: sudo bash $0 [OPTIONS]

Requires existing Parrot OS on ARM64 CM5 with working uConsole hardware support.
Default: back up configuration and audit packages. No packages installed.
No OS conversion, repository changes, system upgrade, rotation or boot edits.

  --install-parrot-tools Install Parrot tool group with recommended tools
  --parrot-meta=PKG      Select/enable parrot-tools or parrot-tools-* group
                        Default: parrot-tools-infogathering
  --skip-parrot-tools    Skip tool installation (default)
  --with-aio            Install Rex's package from existing configured sources
  --skip-aio            Skip AIO installation (default)
  --install-wifi-dkms   Opt in after checking chipset and matching headers
  --wifi-dkms=PKG       Select/enable a chipset-appropriate *-dkms package
  --skip-wifi-dkms      Skip driver installation (default)
  --hostname=NAME       Optionally change hostname
  --phase=PHASE         Run one phase without advancing completion state:
                        preflight|update|parrot_tools|aio|peripherals|finalize
  --dry-run            Simulate selected packages using cached APT lists;
                        do not refresh lists or write logs/backups/state
  --yes, -y            Accept the initial confirmation; guards still apply
  --status             Read this script's completion state
  --reset              Archive this script's state; does NOT undo installation
  --help, -h           Show help

Debian and Kali are rejected. OS conversion is a separate, unvalidated project.
A generic Parrot Pi image is not proof of uConsole compatibility.
APT plans are checked for removals and protected boot/desktop package changes.
Other dependencies and package maintainer scripts can still change the system.
Back up the full boot/storage media and test on spare media first.
HELP
}
parse_args() {
    while (( $# )); do
        case "$1" in
            --with-aio) INSTALL_AIO=yes ;;
            --skip-aio) INSTALL_AIO=no ;;
            --install-parrot-tools) INSTALL_PARROT_TOOLS=yes ;;
            --skip-parrot-tools) INSTALL_PARROT_TOOLS=no ;;
            --parrot-meta=*) PARROT_METAPACKAGE=${1#*=}; INSTALL_PARROT_TOOLS=yes ;;
            --install-wifi-dkms) INSTALL_WIFI_DKMS=yes ;;
            --wifi-dkms=*) WIFI_DKMS_PACKAGE=${1#*=}; INSTALL_WIFI_DKMS=yes ;;
            --skip-wifi-dkms) INSTALL_WIFI_DKMS=no ;;
            --hostname=*) HOSTNAME_NEW=${1#*=} ;;
            --phase=*) FORCE_PHASE=${1#*=} ;;
            --dry-run) DRY_RUN=yes ;;
            --yes|-y) ASSUME_YES=yes ;;
            --status) ACTION=status ;;
            --reset) ACTION=reset ;;
            --help|-h) ACTION=help ;;
            *) die "Unknown option: $1" ;;
        esac
        shift
    done
    local value
    for value in "$INSTALL_AIO" "$INSTALL_PARROT_TOOLS" "$INSTALL_WIFI_DKMS" "$DRY_RUN" "$ASSUME_YES"; do
        [[ "$value" == yes || "$value" == no ]] || die 'Boolean options must be yes or no'
    done
    [[ "$PARROT_METAPACKAGE" =~ ^parrot-tools(-[a-z0-9][a-z0-9+.-]*)?$ ]] || die 'Use parrot-tools or a parrot-tools-* metapackage'
    [[ "$WIFI_DKMS_PACKAGE" =~ ^[a-z0-9][a-z0-9+.-]*-dkms$ ]] || die 'Invalid DKMS package name'
    if [[ -n "$HOSTNAME_NEW" ]]; then
        [[ ${#HOSTNAME_NEW} -le 63 && "$HOSTNAME_NEW" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || die 'Use a hostname label of 1–63 letters, digits or internal hyphens'
    fi
    case "$FORCE_PHASE" in
        ''|preflight|update|parrot_tools|aio|peripherals|finalize) ;;
        *) die "Unknown phase: $FORCE_PHASE" ;;
    esac
}
detect_os() {
    local ID= VERSION_CODENAME= VERSION_ID=
    [[ -r "$OS_RELEASE" ]] || return 1
    # shellcheck disable=SC1090
    . "$OS_RELEASE"
    [[ "${ID,,}" == parrot ]] || return 1
    printf 'parrot\n'
}
check_sources() {
    # Check legacy and Deb822 sources, including local mirrors of Kali suites.
    # Conservatively reject active Kali entries. This is not a complete audit of
    # package origins; installed foreign packages can remain after sources removal.
    python3 - "$APT_DIR" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
paths = [root / 'sources.list', *sorted((root / 'sources.list.d').glob('*.list')),
         *sorted((root / 'sources.list.d').glob('*.sources'))]
bad = []
for path in paths:
    if not path.exists():
        continue
    data = '\n'.join(line.split('#', 1)[0] for line in path.read_text().splitlines())
    if path.suffix == '.sources':
        for stanza in re.split(r'\n\s*\n', data):
            fields = {}
            key = None
            for line in stanza.splitlines():
                if line[:1].isspace() and key:
                    fields[key] += ' ' + line.strip()
                elif ':' in line:
                    key, val = line.split(':', 1)
                    key = key.lower().strip()
                    fields[key] = val.strip()
            if fields.get('enabled', 'yes').lower() == 'no':
                continue
            active = fields.get('uris', '') + ' ' + fields.get('suites', '')
            if 'kali' in active.lower():
                bad.append(str(path))
    elif any(re.match(r'^\s*deb(?:-src)?\s', line) and 'kali' in line.lower()
             for line in data.splitlines()):
        bad.append(str(path))
if bad:
    print('Active Kali sources on Parrot: ' + ', '.join(sorted(set(bad))), file=sys.stderr)
    sys.exit(1)
PY
}
preflight_checks() {
    (( EUID == 0 )) || die 'Run with sudo (help and status do not require root)'
    local os model audit cmd
    os=$(detect_os) || die 'Requires existing Parrot OS (ID=parrot). Debian/Kali conversion is not performed.'
    model=$(tr -d '\0' < "$MODEL_FILE" 2>/dev/null) || die 'Cannot read CM5 hardware model'
    [[ "$model" == *'Compute Module 5'* ]] || die "Not a CM5: $model"
    for cmd in python3 apt-get apt-cache dpkg dpkg-query; do
        command -v "$cmd" >/dev/null || die "Required command missing: $cmd"
    done
    [[ "$(dpkg --print-architecture)" == arm64 ]] || die 'Requires ARM64 userspace'
    [[ -r /boot/firmware/config.txt && -r /boot/firmware/cmdline.txt ]] ||
        die 'Expected uConsole boot files missing under /boot/firmware'
    check_sources || die 'Active Kali sources must be investigated before setup; removing sources does not repair installed packages.'
    if [[ -s "$STATE_FILE" && (! -f "$VERSION_FILE" || "$(cat "$VERSION_FILE")" != "$VERSION") ]]; then
        die 'Incompatible Parrot setup state. Diagnose first; --reset only archives state.'
    fi
    audit=$(dpkg --audit) || die 'dpkg audit failed'
    [[ -z "$audit" ]] || die 'Unfinished package operations; investigate before setup. No automatic fix-broken.'
    if phase_selected peripherals && [[ "$INSTALL_WIFI_DKMS" == yes ]]; then
        [[ -d "/lib/modules/$(uname -r)/build" ]] || die 'Missing headers for the running kernel'
    fi
    printf 'Detected %s; %s; kernel %s\n' "$os" "$model" "$(uname -r)"
}
phase_selected() {
    [[ -z "$FORCE_PHASE" || "$FORCE_PHASE" == "$1" ]]
}
backup_config() {
    [[ "$DRY_RUN" == yes ]] && { log 'Would save a root-only configuration/package snapshot'; return; }
    local dest path
    dest=$(mktemp -d "$STATE_DIR/cm5-backup.XXXXXXXX") || return 1
    chmod 700 "$dest" || return 1
    for path in /etc/lightdm /etc/X11 /etc/xdg /etc/apt /var/lib/AccountsService/users /boot/firmware/config.txt /boot/firmware/cmdline.txt; do
        [[ -e "$path" ]] || continue
        cp -a --parents "$path" "$dest/" || return 1
    done
    dpkg-query -W > "$dest/packages.tsv" || return 1
    log "Configuration snapshot: $dest (not a full disk or user-home backup)"
}
phase_preflight() {
    log 'Preserving LightDM, AccountsService, desktop autostart, Python protections and cryptsetup.'
}
phase_update() {
    log 'System upgrade skipped. Review image-maintainer guidance and apt simulation separately.'
    if [[ -n "$HOSTNAME_NEW" ]]; then
        run hostnamectl set-hostname "$HOSTNAME_NEW" || return 1
    fi
}
# Conservative name-based guard, not a sandbox for package maintainer scripts.
check_package_plan() {
    python3 -c '
import re, sys
protected = re.compile(
    r"^(linux-(image|headers|modules|base)|raspberrypi-|raspi-|rpi-|"
    r"firmware-|device-tree|u-boot|grub|initramfs|cryptsetup|"
    r"systemd|udev$|libudev|libsystemd|"
    r"lightdm|sddm|gdm3|labwc|wayfire|wf-panel|rpd-|pi-greeter|"
    r"clockworkpi-|devterm-|libfm|pcmanfm|lxpanel|libwlroots|libwf-|"
    r"xserver-xorg|xwayland|libdrm|libgbm|libegl|libgl|mesa-|"
    r"plasma-|kwin-|kde-|xfce4|mate-|gnome-shell|"
    r"parrot-(desktop|interface)|polkit|policykit|lxpolkit|"
    r"network-manager|networkmanager|wpasupplicant|dhcpcd|libc6|libc-bin)"
)
bad = []
for line in sys.stdin:
    parts = line.split()
    if parts and parts[0] in ("Remv", "Purg"):
        bad.append(line.rstrip())
    elif len(parts) > 1 and parts[0] in ("Inst", "Conf"):
        if protected.search(parts[1].split(":")[0]):
            bad.append(line.rstrip())
if bad:
    print("Blocked package plan: removal or protected system package change:", file=sys.stderr)
    print("\n".join(bad), file=sys.stderr)
    sys.exit(1)
'
}
simulate_packages() {
    local plan
    plan=$(apt-get --simulate --no-remove install "$@" 2>&1) || {
        log "$plan"
        log 'Package resolution failed. Check package availability and configured repositories.'
        return 1
    }
    log "$plan" || return 1
    printf '%s\n' "$plan" | check_package_plan
}
install_packages() {
    if [[ "$DRY_RUN" == yes ]]; then
        log 'Simulation uses cached APT metadata; a successful plan is not hardware validation.' || return 1
        simulate_packages "$@" || return 1
        run apt-get --no-remove install -y "$@"
        return
    fi
    simulate_packages "$@" || return 1
    # Authentication stays enabled. No forced overwrites/removals/retries.
    # Dependency upgrades outside the protected names remain possible.
    run apt-get --no-remove install -y "$@"
}
prepare_packages() {
    local -a selected=()
    if phase_selected parrot_tools && [[ "$INSTALL_PARROT_TOOLS" == yes ]]; then
        selected+=("$PARROT_METAPACKAGE")
    fi
    if phase_selected aio && [[ "$INSTALL_AIO" == yes ]]; then
        selected+=(hackergadgets-uconsole-aio-board)
    fi
    if phase_selected peripherals && [[ "$INSTALL_WIFI_DKMS" == yes ]]; then
        selected+=("$WIFI_DKMS_PACKAGE")
    fi
    (( ${#selected[@]} )) || return 0
    if [[ "$DRY_RUN" != yes ]]; then
        run apt-get -o APT::Update::Error-Mode=any update || return 1
    fi
    # Resolve all groups before changing hostname or installing anything.
    # Parrot tool group contents are predominantly Recommends.
    simulate_packages --install-recommends "${selected[@]}"
}
phase_parrot_tools() {
    [[ "$INSTALL_PARROT_TOOLS" == yes ]] || { log 'Parrot tools skipped'; return; }
    [[ "$(detect_os)" == parrot ]] || return 1
    install_packages --install-recommends "$PARROT_METAPACKAGE"
}
phase_aio() {
    [[ "$INSTALL_AIO" == yes ]] || { log 'AIO package skipped: no --with-aio'; return; }
    # Let Rex's package manage its supported dependencies. Stop on incompatibility.
    # Follow the board vendor's current instructions for aiov2_ctl and rail setup.
    install_packages --install-recommends hackergadgets-uconsole-aio-board
}
phase_peripherals() {
    log 'Boot overlays, rotation and authentication agents are unchanged by this script.'
    log 'For fitted AIO hardware, follow the current Rex/HackerGadgets configuration guide.'
    if [[ "$INSTALL_WIFI_DKMS" == yes ]]; then
        [[ -d "/lib/modules/$(uname -r)/build" ]] || { log 'Missing matching kernel headers'; return 1; }
        install_packages --install-recommends "$WIFI_DKMS_PACKAGE" || return 1
    fi
}
phase_finalize() {
    if [[ "$DRY_RUN" == yes ]]; then
        log 'Would audit requested packages; desktop and hardware require device testing.'
        return
    fi
    local audit package
    local -a expected=()
    audit=$(dpkg --audit) || return 1
    [[ -z "$audit" ]] || { log "$audit"; return 1; }
    [[ "$INSTALL_AIO" == no ]] || expected+=(hackergadgets-uconsole-aio-board)
    [[ "$INSTALL_PARROT_TOOLS" == no ]] || expected+=("$PARROT_METAPACKAGE")
    [[ "$INSTALL_WIFI_DKMS" == no ]] || expected+=("$WIFI_DKMS_PACKAGE")
    for package in "${expected[@]}"; do
        [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" == 'install ok installed' ]] ||
            { log "Requested package is not installed: $package"; return 1; }
    done
    log 'Package audit finished. Verify login, orientation, panel and input on the device.'
}
record_completion() {
    [[ "$DRY_RUN" == yes || -n "$FORCE_PHASE" ]] && return 0
    printf '%s\n' "$VERSION" > "$VERSION_FILE" || return 1
    printf 'finalize\n' > "$STATE_FILE"
}
main() {
    umask 077
    parse_args "$@"
    case "$ACTION" in
        help) usage; return ;;
        status)
            if [[ -f "$STATE_FILE" ]]; then cat "$STATE_FILE"; else printf 'No completion state\n'; fi
            return ;;
        reset)
            (( EUID == 0 )) || die 'State reset requires sudo'
            [[ "$DRY_RUN" == yes ]] && { printf 'Would archive completion state; no system repair\n'; return; }
            local archive marker
            mkdir -p "$STATE_DIR" || die 'Cannot create state directory'
            archive=$(mktemp -d "$STATE_DIR/cm5-reset.XXXXXXXX") || die 'Cannot create archive'
            for marker in "$STATE_FILE" "$VERSION_FILE"; do
                [[ ! -e "$marker" ]] || mv -- "$marker" "$archive/" || die 'Cannot archive state'
            done
            printf 'State archived to %s. System changes were NOT undone.\n' "$archive"
            return ;;
    esac
    preflight_checks
    if [[ "$ASSUME_YES" != yes && "$DRY_RUN" != yes ]]; then
        local reply
        read -r -p "Back up configuration and run selected operations (AIO=$INSTALL_AIO, Parrot=$INSTALL_PARROT_TOOLS, Wi-Fi=$INSTALL_WIFI_DKMS)? [y/N] " reply
        [[ "$reply" =~ ^[Yy]$ ]] || die 'Aborted'
    fi
    if [[ "$DRY_RUN" != yes ]]; then
        mkdir -p "$STATE_DIR" || die 'Cannot create state directory'
        touch "$LOG_FILE" || die 'Cannot create log'
        chmod 600 "$LOG_FILE" || die 'Cannot protect log'
    fi
    backup_config || die 'Snapshot failed; no setup operations were run'
    prepare_packages || die 'Package plan rejected; no hostname or package changes were made'
    local phase
    for phase in "${PHASES[@]}"; do
        [[ -z "$FORCE_PHASE" || "$phase" == "$FORCE_PHASE" ]] || continue
        log "Phase: $phase" || die 'Log write failed'
        "phase_$phase" || die "Phase $phase failed; stopped without advancing completion state"
    done
    record_completion || die 'Cannot record completion'
    log 'Selected operations completed. This is not proof of a working desktop.'
    log 'If packages were installed, reboot manually when ready, then test the device.'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
