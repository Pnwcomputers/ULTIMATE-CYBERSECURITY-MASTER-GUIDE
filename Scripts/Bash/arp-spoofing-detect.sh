#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
Retired: this launcher cloned and ran unpinned third-party code. Use a maintained package or a reviewed, commit-pinned source in an isolated lab.
This path is retained as an inert retirement notice; it performs no actions.
NOTICE
exit 2
