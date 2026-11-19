#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'NOTICE'
Retired: this launcher started a webcam stream with the public default credential admin:kali and no verified bind restriction. Use a reviewed local-only capture setup with unique credentials.
This path is retained as an inert retirement notice; it performs no actions.
NOTICE
exit 2
