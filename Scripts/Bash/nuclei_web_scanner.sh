#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: NUCLEI_TEMPLATE_PATH=<reviewed-template-or-directory> $0 <authorized-target> [target ...]" >&2
  exit 2
fi

if [[ ! -t 0 ]]; then
  echo "Error: run interactively so the authorization check can be confirmed." >&2
  exit 2
fi

if [[ -z "${NUCLEI_TEMPLATE_PATH:-}" || ! -e "$NUCLEI_TEMPLATE_PATH" ]]; then
  echo "Error: set NUCLEI_TEMPLATE_PATH to an explicitly reviewed local template or directory." >&2
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
  printf 'Scanning %s with the selected local templates at up to 5 requests per second. Results stay in this terminal.\n' "$target"
  nuclei -u "$target" -t "$NUCLEI_TEMPLATE_PATH" -silent -severity high,critical -rate-limit 5
done
