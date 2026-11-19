#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
Retired: this client sent arbitrary commands to an unauthenticated, cleartext HTTP injection endpoint. Use an intentionally vulnerable local fixture that cannot reach other hosts.
This path is retained as an inert retirement notice; it performs no actions.
NOTICE
exit 2
