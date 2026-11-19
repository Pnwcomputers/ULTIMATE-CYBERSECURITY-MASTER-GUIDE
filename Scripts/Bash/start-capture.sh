#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
This launcher started a webcam stream with the default credential admin:kali and no verified bind restriction. Use a reviewed, authorized local alternative with explicit scope and limits.
This path is retained as an inert notice and performs no actions.
NOTICE
exit 2
