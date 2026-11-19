#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
This credential-exfiltration demo has been disabled.

The previous version prompted for a sudo password and sent it to a hard-coded
plain-HTTP endpoint. Never enter a real password into a security demonstration.
Use a non-secret fixture in an isolated lab if you need to study credential
handling, and send it only to a local mock receiver.
NOTICE
exit 1
