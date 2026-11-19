#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
This launcher cloned and ran unpinned third-party email tooling. Use an approved local mail test sink and reviewed, pinned dependencies.
This path is retained as an inert notice and performs no actions.
NOTICE
exit 2
