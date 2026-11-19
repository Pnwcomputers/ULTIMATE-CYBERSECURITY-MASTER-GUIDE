#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
This script launched disruptive wireless deauthentication without verifying a lab-owned target. Use passive detection or an isolated simulator.
This path is retained as an inert notice and performs no actions.
NOTICE
exit 2
