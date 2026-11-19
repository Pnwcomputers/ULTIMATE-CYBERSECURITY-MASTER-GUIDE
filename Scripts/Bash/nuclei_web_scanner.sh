#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <explicitly-authorized-target> [target ...]" >&2
  echo "Runs high/critical Nuclei checks at no more than 5 requests per second." >&2
  exit 2
fi

if [[ ! -t 0 ]]; then
  echo "Error: run interactively so the authorization check can be confirmed." >&2
  exit 2
fi

printf 'Targets to scan:\n'
printf '  %s\n' "$@"
read -r -p "Confirm every target is explicitly authorized and in scope? Type yes: " confirmation
if [[ "$confirmation" != "yes" ]]; then
  echo "No scan started." >&2
  exit 2
fi

if ! command -v nuclei >/dev/null 2>&1; then
  echo "Error: nuclei is required." >&2
  exit 2
fi

for target in "$@"; do
  printf 'Scanning %s; results stay in this terminal.\n' "$target"
  nuclei -u "$target" -silent -severity high,critical -rate-limit 5
done
