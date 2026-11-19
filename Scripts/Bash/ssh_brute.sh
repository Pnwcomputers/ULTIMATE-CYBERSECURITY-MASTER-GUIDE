#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
This password-guessing example has been retired. It exposed candidate and valid
passwords, disabled SSH host-key checks, and had no attempt limit or delay.
Do not use password guessing as an account-audit method. Use approved identity
provider controls, server-side authentication logs, and a documented test plan.
NOTICE
exit 2
