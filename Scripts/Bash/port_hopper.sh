#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
Retired: this script probed hard-coded ports and opened a reverse shell to the first reachable listener. Use local simulators and synthetic telemetry.
This path is retained as an inert retirement notice; it performs no actions.
NOTICE
exit 2
