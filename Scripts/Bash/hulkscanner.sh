#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 --authorized <single-owned-lab-IPv4>" >&2
  echo "Scans only TCP ports 1-1024 on one explicitly authorized lab host." >&2
}

if [[ $# -ne 2 || "$1" != "--authorized" ]]; then
  usage
  exit 2
fi

target="$2"
if [[ ! "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Error: provide one IPv4 address, not a hostname or network range." >&2
  exit 2
fi

IFS='.' read -r -a octets <<< "$target"
for octet in "${octets[@]}"; do
  if (( 10#$octet > 255 )); then
    echo "Error: invalid IPv4 address." >&2
    exit 2
  fi
done

if ! command -v nc >/dev/null 2>&1; then
  echo "Error: netcat (nc) is required." >&2
  exit 2
fi

tmp_output="$(mktemp)"
trap 'rm -f -- "$tmp_output"' EXIT

echo "Scanning TCP ports 1-1024 on authorized lab host $target (1-second per-port timeout)."
nc -nvz -w 1 "$target" 1-1024 >"$tmp_output" 2>&1 || true
tac -- "$tmp_output"
