#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
This script probed hard-coded ports and opened a reverse shell to the first reachable listener. Use a reviewed, authorized local alternative with explicit scope and limits.
This path is retained as an inert notice and performs no actions.
NOTICE
exit 2
