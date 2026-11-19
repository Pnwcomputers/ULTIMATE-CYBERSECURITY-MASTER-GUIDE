#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
Retired: this loop repeatedly opened a reverse shell to a hard-coded listener. Use local simulators and synthetic telemetry for training.
This path is retained as an inert retirement notice; it performs no actions.
NOTICE
exit 2
