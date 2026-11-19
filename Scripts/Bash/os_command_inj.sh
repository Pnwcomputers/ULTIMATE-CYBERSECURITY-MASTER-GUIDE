#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
This client sent arbitrary commands to an unauthenticated, cleartext HTTP injection endpoint. Use an intentionally vulnerable local fixture that cannot reach other hosts.
This path is retained as an inert notice and performs no actions.
NOTICE
exit 2
