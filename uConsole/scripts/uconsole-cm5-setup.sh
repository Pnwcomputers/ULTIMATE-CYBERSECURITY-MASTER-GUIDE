#!/usr/bin/env bash
# uConsole CM5 conservative post-flash setup, v1.5.
# Preserve the image's display/session configuration. This is NOT a repair script.
# v1.5: read-only --hw-check for the HackerGadgets AIO v2, NVMe/battery board and
# upgrade kit; Wi-Fi DKMS restricted to native Kali; hostname change keeps
# /etc/hosts resolvable.
# Package installation can still run maintainer scripts: image backup and device
# validation remain necessary. See ../CM5-DISPLAY-RECOVERY.md.
set -uo pipefail

VERSION=1.5
STATE_DIR=/var/lib/uconsole-setup
STATE_FILE=$STATE_DIR/cm5-state
VERSION_FILE=$STATE_DIR/cm5-version
LOG_FILE=/var/log/uconsole-setup.log
APT_DIR=/etc/apt
OS_RELEASE=/etc/os-release
MODEL_FILE=/proc/device-tree/model
HOSTS_FILE=/etc/hosts
CONFIG_TXT=/boot/firmware/config.txt
CMDLINE_TXT=/boot/firmware/cmdline.txt
SYS_ROOT=/sys
DEV_ROOT=/dev
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
  --hostname=NAME        Optionally change hostname (also updates the 127.0.1.1
                        entry in /etc/hosts so sudo can resolve it)
  --hw-check             Read-only AIO v2 / NVMe / battery / boot-config report;
                        makes no changes (root adds EEPROM boot-order readout)
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
            --hw-check) ACTION=hwcheck ;;
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
    local ID='' VERSION_CODENAME='' VERSION_ID=''
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
        [[ "$INSTALL_WIFI_DKMS" == no ]] || die 'realtek-rtl88xxau-dkms is a Kali package. Use a driver packaged for Debian trixie.'
    fi
    # v1.4 and v1.5 share the same conservative state format; v1.3 and older do not.
    if [[ -s "$STATE_FILE" && (! -f "$VERSION_FILE" || ! "$(cat "$VERSION_FILE")" =~ ^1\.[45]$) ]]; then
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
    for path in /etc/lightdm /etc/X11 /etc/xdg /etc/apt /var/lib/AccountsService/users /etc/hostname "$HOSTS_FILE" "$CONFIG_TXT" "$CMDLINE_TXT"; do
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
        update_hosts_entry || return 1
    fi
}
update_hosts_entry() {
    # Debian maps the hostname via 127.0.1.1; without it sudo warns
    # "unable to resolve host". HOSTNAME_NEW is validated in parse_args.
    if [[ -f "$HOSTS_FILE" ]] && grep -qE '^127\.0\.1\.1([[:space:]]|$)' "$HOSTS_FILE"; then
        run sed -i -E "s/^127\.0\.1\.1([[:space:]].*)?\$/127.0.1.1\t$HOSTNAME_NEW/" "$HOSTS_FILE"
    else
        log "+ append 127.0.1.1 $HOSTNAME_NEW to $HOSTS_FILE" || return 1
        [[ "$DRY_RUN" == yes ]] && return 0
        printf '127.0.1.1\t%s\n' "$HOSTNAME_NEW" >> "$HOSTS_FILE"
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
        # realtek-rtl88xxau-dkms is a Kali package; Debian trixie does not ship it.
        [[ "$(detect_os)" == kali ]] || { log 'Wi-Fi DKMS package is native-Kali only; use a driver packaged for this image'; return 1; }
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
# ---------------------------------------------------------------------------
# Read-only hardware/boot-configuration report (--hw-check). Never writes.
# Sources: HackerGadgets AIO V2 setup guide (CM5 lines), aiov2_ctl, Raspberry Pi
# PCIe/EEPROM documentation. See ../CM5-SETUP.md.
# ---------------------------------------------------------------------------
HW_FAILS=0
hw() {
    # hw LEVEL MESSAGE ; LEVEL = PASS|WARN|FAIL|INFO
    printf '[%s] %s\n' "$1" "$2"
    [[ "$1" != FAIL ]] || HW_FAILS=$((HW_FAILS + 1))
}
check_config_txt() {
    # Evaluate only lines that apply to a CM5: no filter, [all], [pi5], [cm5].
    # Last applicable assignment wins; edit lines in place instead of appending.
    python3 - "$CONFIG_TXT" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
if not path.is_file():
    print(f'[WARN] {path} not found; boot configuration not checked')
    sys.exit(0)
CM5 = {'pi5', 'cm5'}
OTHER = {'pi0', 'pi0w', 'pi02', 'pi1', 'pi2', 'pi3', 'pi3+', 'pi4', 'pi400', 'pi500',
         'cm0', 'cm1', 'cm3', 'cm4', 'cm4s', 'none'}
filters, params, overlays, uncertain, includes = [], {}, [], set(), []
for raw in path.read_text(errors='replace').splitlines():
    line = raw.split('#', 1)[0].strip()
    if not line:
        continue
    if line.startswith('[') and line.endswith(']'):
        name = line[1:-1].strip().lower()
        filters = [] if name == 'all' else filters + [name]
        continue
    if any(f in OTHER for f in filters):
        continue
    odd = [f for f in filters if f not in CM5]
    if line.startswith('include '):
        includes.append(line.split(None, 1)[1])
        continue
    if '=' not in line:
        continue
    key, value = (x.strip() for x in line.split('=', 1))
    if odd:
        uncertain.update(odd)
    if key == 'dtparam':
        for item in value.split(','):
            k, _, v = item.partition('=')
            params[k.strip().lower()] = (v.strip().lower() or 'on')
    elif key == 'dtoverlay':
        parts = [x.strip().lower() for x in value.split(',') if x.strip()]
        if parts:
            overlays.append(parts)
on = lambda k: params.get(k) in ('on', 'true', 'yes', '1')
def has_overlay(name, *args):
    return any(o[0] == name and all(a in o[1:] for a in args) for o in overlays)
out = []
out.append(('PASS', 'GPS UART: dtparam=uart0 (/dev/ttyAMA0)') if on('uart0') else
           ('FAIL', 'GPS UART: add dtparam=uart0 for /dev/ttyAMA0'))
out.append(('PASS', 'LoRa SPI1: dtoverlay=spi1-1cs') if has_overlay('spi1-1cs') else
           ('FAIL', 'LoRa SPI1: add dtoverlay=spi1-1cs (Rex AIO package handles CM5 SPI/display plumbing)'))
out.append(('PASS', 'Internal CM5 RTC disabled: dtparam=rtc=off') if params.get('rtc') == 'off' else
           ('FAIL', 'RTC: add dtparam=rtc=off so the AIO PCF85063A becomes the system RTC'))
out.append(('PASS', 'AIO RTC overlay: i2c-rtc,pcf85063a,i2c_csi_dsi0') if has_overlay('i2c-rtc', 'pcf85063a', 'i2c_csi_dsi0') else
           ('FAIL', 'RTC: add dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0 (CM5 remaps i2c0 to GPIO38/39)'))
pcie = params.get('pciex1', params.get('nvme'))
if pcie is None:
    out.append(('WARN', 'PCIe: no dtparam=pciex1; the connector is only enabled for HAT+ devices. Add dtparam=pciex1 for the NVMe battery board'))
elif pcie in ('off', 'false', 'no', '0'):
    out.append(('FAIL', 'PCIe: dtparam=pciex1=off is set. Change that line to dtparam=pciex1 instead of adding another'))
else:
    out.append(('PASS', 'PCIe: dtparam=pciex1 enabled'))
gen = params.get('pciex1_gen')
if gen == '3':
    out.append(('WARN', 'PCIe: pciex1_gen=3 is not certified by Raspberry Pi; drop it if the NVMe link is unstable'))
elif gen:
    out.append(('INFO', f'PCIe: pciex1_gen={gen}'))
if on('i2c_arm'):
    out.append(('INFO', 'dtparam=i2c_arm=on is not part of the vendor CM5 RTC block; keep only if another device needs I2C1'))
if uncertain:
    out.append(('WARN', 'Lines under non-model filters were counted; confirm they apply: ' + ', '.join(sorted(uncertain))))
for inc in includes:
    out.append(('WARN', f'include {inc} not evaluated; check it manually'))
for level, msg in out:
    print(f'[{level}] {msg}')
PY
}
report_bootloader_config() {
    local cfg order probe
    if ! cfg=$(rpi-eeprom-config 2>/dev/null) || [[ -z "$cfg" ]]; then
        hw WARN 'Could not read the bootloader EEPROM configuration'
        return
    fi
    order=$(sed -n 's/^BOOT_ORDER=//p' <<<"$cfg" | tail -n1)
    probe=$(sed -n 's/^PCIE_PROBE=//p' <<<"$cfg" | tail -n1)
    hw INFO "BOOT_ORDER=${order:-not reported} PCIE_PROBE=${probe:-not reported}"
    if [[ "$order" == *6* && "$probe" != 1 ]]; then
        hw WARN 'For a non-HAT+ NVMe board, confirm PCIE_PROBE=1 before attempting NVMe boot'
    elif [[ -n "$order" && "$order" != *6* ]]; then
        hw INFO 'NVMe (6) not in BOOT_ORDER: see CM5-SETUP.md Step 14 if you intend to boot from NVMe'
    fi
}

hw_check() {
    local model f name val config_report line
    model=$(tr -d '\0' < "$MODEL_FILE" 2>/dev/null) || model=unknown
    printf 'uconsole-cm5-setup.sh v%s hardware check (read-only)\nModel: %s\n' "$VERSION" "$model"
    [[ "$model" == *'Compute Module 5'* ]] || hw WARN 'Not a CM5; results below assume CM5 overlays'
    command -v python3 >/dev/null || { hw FAIL 'python3 is required for config.txt checks'; return 1; }

    printf -- '-- %s --\n' "$CONFIG_TXT"
    if ! config_report=$(check_config_txt); then
        hw FAIL "Could not evaluate $CONFIG_TXT"
    fi
    while IFS= read -r line; do
        [[ "$line" == '[FAIL]'* ]] && HW_FAILS=$((HW_FAILS + 1))
        printf '%s\n' "$line"
    done <<<"$config_report"

    printf -- '-- %s --\n' "$CMDLINE_TXT"
    if [[ -r "$CMDLINE_TXT" ]]; then
        if grep -qE '(^|[[:space:]])console=ttyAMA0(,|[[:space:]]|$)' "$CMDLINE_TXT"; then
            hw FAIL 'console=ttyAMA0 claims the GPS UART; remove that console= entry'
        elif grep -qE '(^|[[:space:]])console=serial0' "$CMDLINE_TXT"; then
            hw INFO 'console=serial0 present; on CM5 serial0 is the debug UART (ttyAMA10), not the GPS port'
        else
            hw PASS 'No serial console on the GPS UART'
        fi
    else
        hw WARN "$CMDLINE_TXT not readable"
    fi

    printf -- '-- Devices (power rails must be on: aiov2_ctl GPS on / LORA on) --\n'
    [[ -e "$DEV_ROOT/ttyAMA0" ]] && hw PASS 'GPS UART /dev/ttyAMA0 present (9600 baud NMEA)' \
        || hw WARN '/dev/ttyAMA0 missing: dtparam=uart0 not active yet (reboot?)'
    [[ -e "$DEV_ROOT/spidev1.0" ]] && hw PASS 'LoRa SPI /dev/spidev1.0 present' \
        || hw WARN '/dev/spidev1.0 missing: spi1-1cs not active, or claimed by a driver'
    name=
    for f in "$SYS_ROOT"/class/rtc/rtc*/name; do
        [[ -r "$f" ]] || continue
        if grep -qi pcf85063 "$f"; then name=${f%/name}; break; fi
    done
    [[ -n "$name" ]] && hw PASS "AIO RTC PCF85063A registered as ${name##*/}" \
        || hw WARN 'PCF85063A RTC not registered: check overlay, CR1220 cell and orientation'
    name=
    for f in "$SYS_ROOT"/class/nvme/nvme*/model; do
        [[ -r "$f" ]] || continue
        name=$(tr -s ' ' < "$f"); break
    done
    [[ -n "$name" ]] && hw PASS "NVMe controller: ${name% }" \
        || hw WARN 'No NVMe controller: check pciex1, PCIe ribbon, board seating and the battery-board LED'
    name=
    for f in "$SYS_ROOT"/bus/usb/devices/*/idVendor; do
        [[ -r "$f" ]] || continue
        val=$(<"$f")
        [[ "$val" == 0bda ]] || continue
        case "$(<"${f%/idVendor}/idProduct")" in 2838|2832) name=yes; break ;; esac
    done
    [[ -n "$name" ]] && hw PASS 'RTL-SDR (0bda:2838/2832) enumerated' \
        || hw WARN 'RTL-SDR not enumerated: SDR rail off (aiov2_ctl SDR on) or USB issue'
    [[ -e "$SYS_ROOT/module/dvb_usb_rtl28xxu" ]] && hw WARN 'dvb_usb_rtl28xxu loaded; blacklist it so librtlsdr can claim the SDR'

    printf -- '-- Power --\n'
    f="$SYS_ROOT/class/power_supply/axp20x-battery"
    if [[ -d "$f" ]]; then
        hw PASS "Battery (AXP): $(cat "$f/capacity" 2>/dev/null || echo '?')% $(cat "$f/status" 2>/dev/null || echo '?'), $(( $(cat "$f/voltage_now" 2>/dev/null || echo 0) / 1000 )) mV"
    else
        hw WARN 'axp20x-battery power_supply missing; aiov2_ctl battery telemetry will be unavailable'
    fi

    printf -- '-- Software --\n'
    command -v aiov2_ctl >/dev/null && hw PASS "aiov2_ctl: $(command -v aiov2_ctl)" \
        || hw INFO 'aiov2_ctl not installed (see CM5-SETUP.md Step 5)'
    if command -v systemctl >/dev/null && [[ "$(systemctl is-enabled devterm-printer.service 2>/dev/null)" == enabled ]]; then
        hw WARN 'devterm-printer.service is enabled and can conflict with LoRa SPI'
    fi

    printf -- '-- Bootloader EEPROM (read-only) --\n'
    if (( EUID == 0 )) && command -v rpi-eeprom-config >/dev/null; then
        report_bootloader_config
    else
        hw INFO 'EEPROM readout skipped (needs sudo and rpi-eeprom-config)'
    fi
    printf 'Summary: %d failing check(s). No changes were made.\n' "$HW_FAILS"
    (( HW_FAILS == 0 ))
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
        hwcheck) hw_check; return ;;
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
