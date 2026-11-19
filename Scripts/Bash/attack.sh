#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
Retired: this script launched disruptive wireless deauthentication without verifying a lab-owned target. Use passive detection or an isolated simulator.
This path is retained as an inert retirement notice; it performs no actions.
NOTICE
exit 2
