#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
This passphrase-guessing example exposed candidate strings and exported a discovered private key. Use an approved offline key-recovery process that never logs secrets.
This path is retained as an inert notice and performs no actions.
NOTICE
exit 2
