#!/usr/bin/env bash
# Safe-by-default uConsole CM4 setup v2.0 (legacy v1.x was unsafe).
set -uo pipefail
DRY=no; AIO=no; KALI=no; YES=no; SNAP=no; META=kali-tools-top10
say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; return 1; }
usage() {
cat <<'HELP'
uConsole CM4 v2.0 — read-only preflight and opt-in installs
  bash uconsole-cm4-setup.sh                 # read-only inspection
  bash uconsole-cm4-setup.sh --dry-run --with-aio
  sudo bash uconsole-cm4-setup.sh --snapshot # config-only backup
  sudo bash uconsole-cm4-setup.sh --with-aio # Debian/RPi OS only
  sudo bash uconsole-cm4-setup.sh --kali-tools # native Kali only
Options: --status --dry-run --snapshot --with-aio --kali-tools
         --kali-meta=kali-tools-top10 --yes --help
No implicit upgrade, repository mixing, force-overwrites, remote script
execution, display/boot/EEPROM changes, GPIO writes, or SD/NVMe cloning.
HELP
}
os_name() {
  [[ -r /etc/os-release ]] || { echo unknown; return; }
  local id; id=$(sed -n 's/^ID=//p' /etc/os-release | head -1 | tr -d '"')
  case "$id" in debian|raspbian) echo debian;; kali) echo kali;; *) echo unknown;; esac
}
hw_name() {
  [[ -r /proc/device-tree/model ]] || { echo unknown; return; }
  local model; model=$(tr -d '\000' < /proc/device-tree/model)
  case "$model" in *"Compute Module 4"*) echo cm4;; *"Compute Module 5"*) echo cm5;; *) echo unknown;; esac
}
mixed_sources() {
  local f
  while IFS= read -r -d '' f; do
    if grep -Eiq '^[[:space:]]*(deb[[:space:]].*kali|URIs:[[:space:]].*(kali\.org|kali\.linux)|Suites:[[:space:]]*kali-rolling)' "$f"; then
      return 0
    fi
  done < <(find /etc/apt -maxdepth 3 -type f \( -name '*.list' -o -name '*.sources' -o -name 'sources.list' \) -print0 2>/dev/null)
  return 1
}
backup_configs() {
  local name="/var/backups/uconsole-cm4/cm4-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar.gz"
  umask 077
  mkdir -p /var/backups/uconsole-cm4 || return 1
  chmod 700 /var/backups/uconsole-cm4 || return 1
  tar -czf "$name" -C / --etc 2>/dev/null && return 0
  # Explicit known paths, not whole /etc or any user secrets:
  tar -czf "$name" -C / etc/os-release etc/apt boot/firmware/config.txt boot/firmware/cmdline.txt \
    2>/dev/null || { rm -f "$name"; return 1; }
  chmod 600 "$name"
  say "Root-only config backup: $name (not full SD/eMMC/NVMe backup)"
}
pkg_install() {
  local pkg="$1" option="$2" plan
  apt-get update || return 1
  plan=$(apt-get -s --no-remove "$option" install "$pkg") || return 1
  printf '%s\n' "$plan"
  if grep -q '^Remv ' <<< "$plan"; then die "APT would remove packages"; return 1; fi
  apt-get --no-remove "$option" install "$pkg"
}
main() {
  while (($#)); do
    case "$1" in
      --help|-h) usage; return 0;;
      --status) ;;
      --dry-run) DRY=yes;;
      --snapshot) SNAP=yes;;
      --with-aio) AIO=yes;;
      --kali-tools) KALI=yes;;
      --kali-meta=*) META=$(printf '%s' "$1" | cut -d= -f2-); KALI=yes;;
      --yes) YES=yes;;
      *) die "Unsupported flag: $1"; return 2;;
    esac
    shift
  done
  local os hw
  os=$(os_name); hw=$(hw_name)
  say "CM4 v2.0: hardware=$hw OS=$os"
  [[ "$hw" == cm4 ]] || { die "Not verified CM4 hardware"; return 1; }
  [[ "$os" == debian || "$os" == kali ]] || { die "Unsupported OS"; return 1; }
  if [[ "$os" == debian ]] && mixed_sources; then die "Kali APT sources on Debian"; return 1; fi
  [[ "$META" =~ ^kali-[a-z0-9][a-z0-9.+-]*$ ]] || { die "Invalid metapackage"; return 1; }
  if [[ "$AIO" == yes && "$os" != debian ]]; then die "AIO opt-in only on Debian/RPi OS"; return 1; fi
  if [[ "$KALI" == yes && "$os" != kali ]]; then die "Kali tools require native Kali"; return 1; fi
  if [[ "$AIO" != yes && "$KALI" != yes && "$SNAP" != yes ]]; then
    say "Read-only preflight complete; no files or packages changed."; return 0
  fi
  say "Requested: AIO=$AIO Kali=$KALI Snapshot=$SNAP"
  if [[ "$DRY" == yes ]]; then say "DRY RUN: no writes or downloads."; return 0; fi
  [[ "$EUID" -eq 0 ]] || { die "Root required for opt-in changes"; return 1; }
  if [[ "$YES" != yes ]]; then
    local reply
    read -r -p "Proceed with opt-in changes? [y/N] " reply || return 1
    [[ "$reply" =~ ^[Yy]$ ]] || return 1
  fi
  backup_configs || { die "Backup failed, aborting"; return 1; }
  if [[ "$AIO" == yes ]]; then
    pkg_install hackergadgets-uconsole-aio-board --install-recommends || return 1
  fi
  if [[ "$KALI" == yes ]]; then
    pkg_install "$META" --no-install-recommends || return 1
  fi
  say "Complete. Verify desktop, keyboard, battery, AIO hardware manually."
}
main "$@"
