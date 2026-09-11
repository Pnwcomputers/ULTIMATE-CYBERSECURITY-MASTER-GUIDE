#!/usr/bin/env bash
# uConsole CM5 conservative post-flash setup, v1.4.
# Preserve the image's display/session configuration. This is NOT a repair script.
# Package installation can still run maintainer scripts: image backup and device
# validation remain necessary. See ../CM5-DISPLAY-RECOVERY.md.
set -uo pipefail

VERSION=1.4
STATE_DIR=/var/lib/uconsole-setup
STATE_FILE=$STATE_DIR/cm5-state
VERSION_FILE=$STATE_DIR/cm5-version
LOG_FILE=/var/log/uconsole-setup.log
APT_DIR=/etc/apt
OS_RELEASE=/etc/os-release
MODEL_FILE=/proc/device-tree/model
DRY_RUN=${DRY_RUN:-no}
ASSUME_YES=${ASSUME_YES:-no}
INSTALL_AIO=${INSTALL_AIO:-no}
INSTALL_KALI_TOOLS=${INSTALL_KALI_TOOLS:-no}
INSTALL_WIFI_DKMS=${INSTALL_WIFI_DKMS:-no}
KALI_METAPACKAGE=${KALI_METAPACKAGE:-kali-tools-top10}
HOSTNAME_NEW=${HOSTNAME_NEW:-}
FORCE_PHASE=
ACTION=run
PHASES=(preflight update kali_tools aio peripherals finalize)

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
uconsole-cm5-setup.sh v$VERSION
Usage: sudo $0 [OPTIONS]

Default: inventory/back up the current configuration; preserve the desktop.
No distribution conversion, system upgrade, display rotation, or boot edits.

  --with-aio             Install Rex's AIO board package; only for fitted hardware
  --skip-aio             Skip AIO installation (default)
  --install-kali-tools   Install a metapackage on a native Kali image only
  --kali-meta=PKG        Select and enable Kali metapackage installation
  --skip-kali-tools      Skip tool installation (default)
  --install-wifi-dkms    Opt in AFTER confirming chipset and matching kernel headers
  --skip-wifi-dkms       Skip Wi-Fi driver installation (default)
  --hostname=NAME        Optionally change hostname
  --phase=PHASE          Run one phase without advancing completion state
                        preflight|update|kali_tools|aio|peripherals|finalize
  --dry-run             Print planned commands; do not write logs/backups/state
  --yes, -y             Accept the initial setup confirmation
  --status              Read recorded state
  --reset               Archive state markers; does NOT undo an earlier install
  --help, -h            Show help

Existing v1.3 installations: read CM5-DISPLAY-RECOVERY.md first.
There is no automatic migration or desktop repair. Hardware functions have not
been verified by the software regression tests. Reboot manually after optional
package installation and check the desktop before adding more software.
HELP
}
parse_args() {
    while (( $# )); do
        case "$1" in
            --with-aio) INSTALL_AIO=yes ;;
            --skip-aio) INSTALL_AIO=no ;;
            --install-kali-tools) INSTALL_KALI_TOOLS=yes ;;
            --skip-kali-tools) INSTALL_KALI_TOOLS=no ;;
            --kali-meta=*) KALI_METAPACKAGE=${1#*=}; INSTALL_KALI_TOOLS=yes ;;
            --install-wifi-dkms) INSTALL_WIFI_DKMS=yes ;;
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
    for value in "$INSTALL_AIO" "$INSTALL_KALI_TOOLS" "$INSTALL_WIFI_DKMS" "$DRY_RUN" "$ASSUME_YES"; do
        [[ "$value" == yes || "$value" == no ]] || die 'Boolean options must be yes or no'
    done
    [[ "$KALI_METAPACKAGE" =~ ^kali-[a-z0-9][a-z0-9+.-]*$ ]] || die 'Invalid Kali metapackage name'
    if [[ -n "$HOSTNAME_NEW" ]]; then
        [[ ${#HOSTNAME_NEW} -le 63 && "$HOSTNAME_NEW" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || die 'Use a hostname label of 1–63 letters, digits or internal hyphens'
    fi
    case "$FORCE_PHASE" in
        ''|preflight|update|kali_tools|aio|peripherals|finalize) ;;
        *) die "Unknown phase: $FORCE_PHASE" ;;
    esac
}
detect_os() {
    local ID= VERSION_CODENAME= VERSION_ID=
    [[ -r "$OS_RELEASE" ]] || return 1
    # shellcheck disable=SC1090
    . "$OS_RELEASE"
    case "$ID" in
        kali) printf 'kali\n' ;;
        debian)
            [[ "$VERSION_CODENAME" == trixie && "$VERSION_ID" == 13 ]] || return 1
            printf 'trixie\n' ;;
        *) return 1 ;;
    esac
}
check_debian_sources() {
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
    print('Active Kali sources on Debian: ' + ', '.join(sorted(set(bad))), file=sys.stderr)
    sys.exit(1)
PY
}
preflight_checks() {
    (( EUID == 0 )) || die 'Run with sudo (help and status do not require root)'
    local os model audit
    os=$(detect_os) || die 'Supported OS: Rex Debian 13 (trixie) or native Kali. Check /etc/os-release.'
    model=$(tr -d '\0' < "$MODEL_FILE" 2>/dev/null) || die 'Cannot read CM5 hardware model'
    [[ "$model" == *'Compute Module 5'* ]] || die "Not a CM5: $model"
    command -v python3 >/dev/null || die 'python3 is required for source validation'
    command -v apt-get >/dev/null || die 'apt-get is required'
    if [[ "$os" == trixie ]]; then
        check_debian_sources || die 'Stop: review CM5-DISPLAY-RECOVERY.md before any further package changes.'
        [[ "$INSTALL_KALI_TOOLS" == no ]] || die 'Do not add Kali repositories/metapackages to Debian. Use Debian packages or a separate Kali image.'
    fi
    if [[ -s "$STATE_FILE" && (! -f "$VERSION_FILE" || "$(cat "$VERSION_FILE")" != "$VERSION") ]]; then
        die 'Legacy setup state found. Diagnose/recover first; --reset only archives state, not system changes.'
    fi
    audit=$(dpkg --audit) || die 'dpkg audit failed'
    [[ -z "$audit" ]] || die 'dpkg reports unfinished package operations. Investigate before setup; no automatic fix-broken will run.'
    printf 'Detected %s; %s; kernel %s\n' "$os" "$model" "$(uname -r)"
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
install_packages() {
    run apt-get -o APT::Update::Error-Mode=any update || return 1
    # No forced overwrites, removals, purges, cross-release dependency injection,
    # or fix-broken retries. --no-remove does not prevent dependency upgrades or
    # changes made by package maintainer scripts.
    run apt-get --no-remove install -y "$@"
}
phase_kali_tools() {
    [[ "$INSTALL_KALI_TOOLS" == yes ]] || { log 'Kali tools skipped'; return; }
    [[ "$(detect_os)" == kali ]] || return 1
    install_packages --no-install-recommends "$KALI_METAPACKAGE"
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
        install_packages realtek-rtl88xxau-dkms || return 1
    fi
}
phase_finalize() {
    if [[ "$DRY_RUN" == yes ]]; then
        log 'Would audit package state; desktop and hardware require device testing.'
        return
    fi
    local audit
    audit=$(dpkg --audit) || return 1
    [[ -z "$audit" ]] || { log "$audit"; return 1; }
    if [[ "$INSTALL_AIO" == yes ]]; then
        [[ "$(dpkg-query -W -f='${Status}' hackergadgets-uconsole-aio-board 2>/dev/null)" == 'install ok installed' ]] || return 1
    fi
    log 'Package audit finished. Verify login, orientation, panel and input on the device.'
}
record_completion() {
    [[ "$DRY_RUN" == yes || -n "$FORCE_PHASE" ]] && return 0
    printf '%s\n' "$VERSION" > "$VERSION_FILE" || return 1
    printf 'finalize\n' > "$STATE_FILE"
}
main() {
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
        read -r -p "Back up configuration and run selected operations (AIO=$INSTALL_AIO, Kali=$INSTALL_KALI_TOOLS, Wi-Fi=$INSTALL_WIFI_DKMS)? [y/N] " reply
        [[ "$reply" =~ ^[Yy]$ ]] || die 'Aborted'
    fi
    if [[ "$DRY_RUN" != yes ]]; then
        mkdir -p "$STATE_DIR" || die 'Cannot create state directory'
        touch "$LOG_FILE" || die 'Cannot create log'
        chmod 600 "$LOG_FILE" || die 'Cannot protect log'
    fi
    backup_config || die 'Snapshot failed; no setup operations were run'
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
