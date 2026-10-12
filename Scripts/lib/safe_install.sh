#!/usr/bin/env bash
# =============================================================================
#  safe_install.sh — shared helpers for the PNWC installers
#
#  Source this file; do not execute it. Sourcing has no side effects.
#
#  Provides:
#    - private temporary directories with cleanup
#    - SHA-256 verification BEFORE any extraction or execution
#    - HTTPS-only downloads that fail closed on verification errors
#    - safe single-member archive extraction (tar.gz / zip)
#    - data-only pin lookup (tool_pins.conf is parsed, never sourced)
#    - explicit architecture detection (unsupported targets are rejected)
#
#  Nothing here invents versions, commits or checksums. A missing pin means the
#  caller must refuse the install (or, for git/go sources only, require the
#  explicit PNWC_ALLOW_UNPINNED=1 opt-in).
# =============================================================================

# Guard against double-sourcing.
if [[ -n "${_PNWC_SAFE_INSTALL_LOADED:-}" ]]; then
    return 0 2>/dev/null || true
fi
_PNWC_SAFE_INSTALL_LOADED=1

SAFE_TMP_DIRS=()

# -----------------------------------------------------------------------------
# Private temporary directories
# -----------------------------------------------------------------------------

# safe_mktemp_dir VARNAME
#   Creates a 0700 directory and stores its path in VARNAME. A command
#   substitution would lose the cleanup registration, hence the by-name result.
safe_mktemp_dir() {
    local -n _pnwc_out="$1"
    local _pnwc_d
    _pnwc_d=$(mktemp -d "${TMPDIR:-/tmp}/pnwc.XXXXXXXXXX") || return 1
    if ! chmod 700 "$_pnwc_d"; then
        rm -rf -- "$_pnwc_d"
        return 1
    fi
    SAFE_TMP_DIRS+=("$_pnwc_d")
    _pnwc_out="$_pnwc_d"
}

safe_cleanup() {
    local d
    for d in "${SAFE_TMP_DIRS[@]:-}"; do
        [[ -n "$d" && -d "$d" && "$d" == */pnwc.* ]] && rm -rf -- "$d"
    done
    SAFE_TMP_DIRS=()
}

# -----------------------------------------------------------------------------
# Checksums
# -----------------------------------------------------------------------------

safe_sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$1" | awk '{print $1}'
    else
        echo "no sha256 tool available" >&2
        return 1
    fi
}

# safe_verify_sha256 FILE EXPECTED_HEX
#   0 = match, 1 = mismatch/unreadable, 2 = EXPECTED_HEX is not 64 hex chars.
safe_verify_sha256() {
    local file="$1" want="${2:-}" got
    want="${want,,}"
    [[ "$want" =~ ^[0-9a-f]{64}$ ]] || return 2
    [[ -f "$file" && ! -L "$file" ]] || return 1
    got=$(safe_sha256_of "$file") || return 1
    [[ "$got" == "$want" ]]
}

# -----------------------------------------------------------------------------
# Downloads
# -----------------------------------------------------------------------------

# safe_fetch_verified URL EXPECTED_SHA256 DEST_FILE
#   Downloads into a private temp dir, verifies, then moves into place.
#   DEST_FILE does not exist after any failure.
#   Return: 0 ok | 2 invalid expected hash | 3 hash mismatch | 4 download failed
#           5 URL scheme refused
#   file:// URLs are accepted ONLY when SAFE_ALLOW_FILE_URLS=1 (used by tests).
safe_fetch_verified() {
    local url="$1" want="${2:-}" dest="$3"
    local protos='=https'

    [[ "${want,,}" =~ ^[0-9a-f]{64}$ ]] || return 2

    case "$url" in
        https://*) ;;
        file://*)
            [[ "${SAFE_ALLOW_FILE_URLS:-0}" == 1 ]] || return 5
            protos='=file'
            ;;
        *) return 5 ;;
    esac

    # This function owns its scratch directory and always removes it, so callers
    # need no trap for it. (safe_mktemp_dir is for caller-owned scratch space.)
    local tmpd rc
    tmpd=$(mktemp -d "${TMPDIR:-/tmp}/pnwc.XXXXXXXXXX") || return 4
    chmod 700 "$tmpd" || { rm -rf -- "$tmpd"; return 4; }

    _safe_fetch_into "$url" "$want" "$dest" "$protos" "$tmpd/download.part"
    rc=$?
    rm -rf -- "$tmpd"
    return $rc
}

_safe_fetch_into() {
    local url="$1" want="$2" dest="$3" protos="$4" part="$5"

    if ! curl --fail --silent --show-error --location \
              --proto "$protos" --proto-redir '=https' \
              --max-time "${SAFE_FETCH_TIMEOUT:-600}" \
              -o "$part" -- "$url"; then
        rm -f -- "$dest"
        return 4
    fi

    if ! safe_verify_sha256 "$part" "$want"; then
        rm -f -- "$dest"
        return 3
    fi

    chmod 600 "$part"
    mv -f -- "$part" "$dest"
}

# -----------------------------------------------------------------------------
# Archive extraction (single named member only)
# -----------------------------------------------------------------------------

# safe_member_name_ok NAME — rejects absolute paths and parent traversal.
safe_member_name_ok() {
    local n="$1"
    [[ -n "$n" ]] || return 1
    [[ "$n" != /* && "$n" != -* ]] || return 1
    [[ "$n" != ".." && "$n" != ../* && "$n" != */../* && "$n" != */.. ]] || return 1
    # unzip interprets member arguments as glob patterns; refuse them outright.
    [[ "$n" != *[\*\?\[]* ]] || return 1
}

# safe_extract_member ARCHIVE MEMBER DEST_DIR
#   Supports .tar.gz/.tgz and .zip. Extracts exactly one regular file and
#   rejects symlinks and hard links. Verify the archive hash BEFORE calling.
safe_extract_member() {
    local archive="$1" member="$2" destdir="$3"

    safe_member_name_ok "$member" || { echo "unsafe member name: $member" >&2; return 1; }
    [[ -d "$destdir" ]] || { echo "destination is not a directory: $destdir" >&2; return 1; }

    case "$archive" in
        *.tar.gz|*.tgz)
            # Verbose listing: the first character is the entry type ('-' is a
            # regular file; 'l' symlink, 'h' hard link). Require exactly that.
            if ! tar -tzvf "$archive" 2>/dev/null | awk -v m="$member" '
                    { t=substr($1,1,1); name=$NF
                      if (name==m && t=="-") f=1
                      if (name==m && t!="-") bad=1 }
                    END { exit !(f && !bad) }'; then
                echo "member missing or not a regular file: $member" >&2
                return 1
            fi
            tar -xzf "$archive" -C "$destdir" --no-same-owner --no-same-permissions -- "$member" || return 1
            ;;
        *.zip)
            if ! unzip -Z1 "$archive" 2>/dev/null | grep -Fxq -- "$member"; then
                echo "member not found: $member" >&2
                return 1
            fi
            # Reject symlink entries: zipinfo marks them with 'l' in the mode field.
            if unzip -Z "$archive" "$member" 2>/dev/null | grep -q '^l'; then
                echo "refusing symlink member: $member" >&2
                return 1
            fi
            unzip -qo -j "$archive" "$member" -d "$destdir" || return 1
            ;;
        *)
            echo "unsupported archive type: $archive" >&2
            return 1
            ;;
    esac

    local out="$destdir/${member##*/}"
    if [[ ! -f "$out" || -L "$out" ]]; then
        echo "extracted entry is not a regular file: $out" >&2
        rm -f -- "$out"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Architecture
# -----------------------------------------------------------------------------

# safe_detect_arch — prints amd64 or arm64; any other machine is rejected.
safe_detect_arch() {
    # SAFE_UNAME_M exists only so tests can simulate other machines.
    case "${SAFE_UNAME_M-$(uname -m)}" in
        x86_64|amd64)  echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) return 1 ;;
    esac
}

# -----------------------------------------------------------------------------
# Pins — data only. The file is parsed line by line and NEVER sourced.
# -----------------------------------------------------------------------------

# Format: KEY=VALUE, one per line; '#' comments and blank lines ignored.
#   KEY   : [A-Za-z0-9:_./@+-]+
#   VALUE : [A-Za-z0-9._/+-]*   (no spaces, quotes, $, backticks or ;)

# safe_pin_get FILE KEY
#   Prints the value; returns 1 if the key is absent or its value is empty or
#   malformed. Malformed lines are ignored, never interpreted.
safe_pin_get() {
    local file="$1" key="$2" line k v
    [[ -f "$file" && ! -L "$file" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[A-Za-z0-9:_./@+-]+=[A-Za-z0-9._/+-]*$ ]] || continue
        k="${line%%=*}"
        v="${line#*=}"
        if [[ "$k" == "$key" ]]; then
            [[ -n "$v" ]] || return 1
            printf '%s\n' "$v"
            return 0
        fi
    done < "$file"
    return 1
}

safe_allow_unpinned() { [[ "${PNWC_ALLOW_UNPINNED:-0}" == 1 ]]; }

safe_is_commit()  { [[ "${1:-}" =~ ^[0-9a-f]{40}$ ]]; }
safe_is_version() { [[ "${1:-}" =~ ^v?[0-9]+(\.[0-9A-Za-z+_-]+)*$ ]]; }
