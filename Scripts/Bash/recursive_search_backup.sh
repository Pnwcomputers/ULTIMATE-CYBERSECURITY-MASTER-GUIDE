#!/usr/bin/env bash
set -euo pipefail
umask 077

# Create a unique, owner-readable archive of readable regular files.
# Usage: ./recursive_search_backup.sh [directory]
DIR_SEARCH="${1:-/var/log}"
if (( $# > 1 )); then
    printf 'Usage: %s [directory]\n' "$0" >&2
    exit 2
fi

if [[ ! -d "$DIR_SEARCH" ]]; then
    printf 'Not a directory: %s\n' "$DIR_SEARCH" >&2
    exit 1
fi

DIR_SEARCH="$(realpath -e -- "$DIR_SEARCH")"
HOME_REAL="$(realpath -e -- "$HOME")"

# The archive is created in HOME; refuse a source tree that contains HOME,
# which would otherwise include the archive in its own input.
case "$HOME_REAL/" in
    "$DIR_SEARCH/"*)
        printf 'Refusing to archive a directory that contains the output location (%s). Choose a narrower source directory.\n' "$HOME_REAL" >&2
        exit 1
        ;;
esac

ARCHIVE="$(mktemp "$HOME_REAL/files.XXXXXX.tar.gz")"
cleanup() {
    local status=$?
    if (( status != 0 )); then
        rm -f -- "$ARCHIVE"
    fi
}
trap cleanup EXIT

if ! find "$DIR_SEARCH" -type f -readable -print0 |
    tar --create --gzip --file="$ARCHIVE" --null --files-from=- --absolute-names; then
    printf 'Archive creation failed; incomplete output was removed.\n' >&2
    exit 1
fi

printf 'Archive created: %s\n' "$ARCHIVE"
