#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
This launcher killed network processes and started wireless attack tooling without a safe target/scope check. Use a dedicated isolated lab image and reviewed procedures.
This path is retained as an inert notice and performs no actions.
NOTICE
exit 2
