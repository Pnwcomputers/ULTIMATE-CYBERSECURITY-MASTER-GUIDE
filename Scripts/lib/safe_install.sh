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

# _safe_path_ok NAME — rejects absolute paths and parent traversal.
_safe_path_ok() {
    local n="$1"
    [[ -n "$n" ]] || return 1
    [[ "$n" != /* ]] || return 1
    [[ "$n" != ".." && "$n" != ../* && "$n" != */../* && "$n" != */.. ]] || return 1
}

# safe_member_name_ok NAME — strict check for a member passed on a command line.
safe_member_name_ok() {
    local n="$1"
    _safe_path_ok "$n" || return 1
    [[ "$n" != -* ]] || return 1
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

# safe_extract_all ARCHIVE DEST_DIR
#   Extracts a whole .tar.gz/.tgz/.zip, but only after every entry has been
#   checked: no absolute paths, no parent traversal, and nothing other than
#   regular files and directories (no symlinks, hard links, devices or FIFOs).
#   Verify the archive hash BEFORE calling.
safe_extract_all() {
    local archive="$1" destdir="$2" name bad=0
    [[ -d "$destdir" ]] || { echo "destination is not a directory: $destdir" >&2; return 1; }

    case "$archive" in
        *.tar.gz|*.tgz)
            while IFS= read -r name; do
                _safe_path_ok "$name" || { echo "unsafe entry: $name" >&2; bad=1; }
            done < <(tar -tzf "$archive" 2>/dev/null)
            # Verbose listing: type is the first character; allow only '-' and 'd'.
            if tar -tzvf "$archive" 2>/dev/null | awk '{t=substr($1,1,1); if (t!="-" && t!="d") exit 1}'; then
                :
            else
                echo "archive contains links or special files" >&2
                bad=1
            fi
            (( bad == 0 )) || return 1
            tar -xzf "$archive" -C "$destdir" --no-same-owner --no-same-permissions || return 1
            ;;
        *.zip)
            while IFS= read -r name; do
                _safe_path_ok "$name" || { echo "unsafe entry: $name" >&2; bad=1; }
            done < <(unzip -Z1 "$archive" 2>/dev/null)
            # zipinfo short listing: first character of the permissions field is the type.
            if unzip -Z "$archive" 2>/dev/null | grep -Eq '^[lbcps]'; then
                echo "archive contains links or special files" >&2
                bad=1
            fi
            (( bad == 0 )) || return 1
            unzip -qo "$archive" -d "$destdir" || return 1
            ;;
        *)
            echo "unsupported archive type: $archive" >&2
            return 1
            ;;
    esac

    # Belt and braces: nothing extracted may be a symlink.
    if find "$destdir" -type l -print -quit | grep -q .; then
        echo "extraction produced a symlink; refusing" >&2
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Architecture
# -----------------------------------------------------------------------------

# safe_machine — the machine name being evaluated. SAFE_UNAME_M exists only so
# tests can simulate other machines.
safe_machine() { printf '%s\n' "${SAFE_UNAME_M-$(uname -m)}"; }

# safe_detect_arch — prints amd64 or arm64; any other machine is rejected.
safe_detect_arch() {
    case "$(safe_machine)" in
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

# =============================================================================
#  Pin policy layer
#
#  Every external source must be pinned in $PINS_FILE (see Scripts/PINNING.md).
#  A missing pin means "skip and report". --allow-unpinned is the only override,
#  and only for pip / go / git / gem sources. Downloaded binaries, archives,
#  repository keys and installer scripts ALWAYS require a pinned SHA-256.
#
#  The sourcing script must define:
#    info ok warn error            logging functions
#    FAILED_TOOLS SKIPPED_TOOLS MANUAL_TOOLS UNPINNED_USED   arrays
#    PINS_FILE                     path to tool_pins.conf
#  and may define:
#    LOGFILE                       (default /dev/null)
#    PNWC_TOOLS_DIR                git checkouts go here   (default $INSTALL_DIR)
#    PNWC_GOPATH                   Go workspace            (default /opt/go)
#    PNWC_VENV_PYTHON              shared-venv interpreter (default $INSTALL_DIR/venv/bin/python)
# =============================================================================

_pnwc_tools_dir()   { printf '%s' "${PNWC_TOOLS_DIR:-${INSTALL_DIR:?PNWC_TOOLS_DIR or INSTALL_DIR must be set}}"; }
_pnwc_gopath()      { printf '%s' "${PNWC_GOPATH:-/opt/go}"; }
_pnwc_venv_python() { printf '%s' "${PNWC_VENV_PYTHON:-${INSTALL_DIR:?PNWC_VENV_PYTHON or INSTALL_DIR must be set}/venv/bin/python}"; }

# Every external source must be pinned in $PINS_FILE (see Scripts/PINNING.md).
# A missing pin means "skip and report". --allow-unpinned is the only override,
# and only for pip / go / git / gem sources. Downloaded binaries, archives,
# repository keys and installer scripts ALWAYS require a pinned SHA-256.
pin_get()     { safe_pin_get "$PINS_FILE" "$1"; }
pin_version() { local v; v=$(pin_get "dl:$1:version") && safe_is_version "$v" && printf '%s\n' "$v"; }

# unpinned_ok KEY — true only with the explicit opt-in; always loud and recorded.
unpinned_ok() {
    local key="$1"
    if safe_allow_unpinned; then
        warn "  UNPINNED (--allow-unpinned): $key — installing whatever upstream serves today"
        UNPINNED_USED+=("$key")
        return 0
    fi
    warn "  $key: no pin in $PINS_FILE — skipping (lab-only override: --allow-unpinned)"
    SKIPPED_TOOLS+=("$key (no pin)")
    return 1
}

# pip_spec NAME — prints NAME==VERSION. 0 pinned | 1 no pin | 2 invalid pin.
pip_spec() {
    local name="$1" ver
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || return 2
    ver=$(pin_get "pip:$name") || return 1
    safe_is_version "$ver" || return 2
    printf '%s==%s\n' "$name" "$ver"
}

# resolve_pip NAME — sets PIP_SPEC; returns 1 if the package must be skipped.
resolve_pip() {
    local name="$1" rc
    PIP_SPEC=""
    PIP_SPEC=$(pip_spec "$name") && rc=0 || rc=$?
    case "$rc" in
        0) return 0 ;;
        2) error "  invalid pin for pip:$name"; FAILED_TOOLS+=("pip:$name (invalid pin)"); return 1 ;;
        *) if unpinned_ok "pip:$name"; then PIP_SPEC="$name"; return 0; fi; return 1 ;;
    esac
}

# pipx install — isolated per-tool virtualenv; avoids system package conflicts
pipx_install() {
    for pkg in "$@"; do
        resolve_pip "$pkg" || continue
        info "  pipx install: $PIP_SPEC"
        if pipx install "$PIP_SPEC" >> "${LOGFILE:-/dev/null}" 2>&1; then
            ok "  $pkg (pipx) installed"
        else
            warn "  pipx failed for $pkg"
            FAILED_TOOLS+=("pipx:$pkg")
        fi
    done
}

# Python tools and libraries use a dedicated environment, never system pip.
pip_install() {
    for pkg in "$@"; do
        resolve_pip "$pkg" || continue
        info "  pip install: $PIP_SPEC"
        if "$(_pnwc_venv_python)" -m pip install --quiet "$PIP_SPEC" >> "${LOGFILE:-/dev/null}" 2>&1; then
            ok "  $pkg (pip) installed"
        else
            warn "  pip failed for $pkg"
            FAILED_TOOLS+=("pip:$pkg")
        fi
    done
}

# go install — requires go in PATH. Pass the package path WITHOUT a version;
# the version comes from the pin (go:<path>=<version>). Go's checksum database
# verifies the module content, so GOSUMDB must not be disabled.
go_install() {
    local pkg="${1%%@*}" ver target rc
    if ! command -v go &>/dev/null; then
        warn "Go not in PATH — skipping $pkg"
        SKIPPED_TOOLS+=("go:$pkg")
        return 0
    fi
    if [[ "${GOSUMDB:-}" == "off" ]]; then
        error "GOSUMDB=off disables Go module verification; refusing to install $pkg"
        FAILED_TOOLS+=("go:$pkg (GOSUMDB=off)")
        return 0
    fi
    ver=$(pin_get "go:$pkg") && rc=0 || rc=1
    if (( rc == 0 )); then
        safe_is_version "$ver" || { error "  invalid pin for go:$pkg"; FAILED_TOOLS+=("go:$pkg (invalid pin)"); return 0; }
        target="$pkg@$ver"
    elif unpinned_ok "go:$pkg"; then
        target="$pkg@latest"
    else
        return 0
    fi
    info "  go install: $target"
    if env -u GONOSUMDB -u GONOSUMCHECK -u GOINSECURE GOPATH="$(_pnwc_gopath)" go install "$target" >> "${LOGFILE:-/dev/null}" 2>&1; then
        ok "  $pkg (go) installed"
    else
        warn "  go install failed for $pkg"
        FAILED_TOOLS+=("go:$pkg")
    fi
}

# git clone a tool into the tools directory, checked out at the pinned commit
# (git:<name>=<40-hex>). Existing checkouts are never modified or "pulled".
git_clone_tool() {
    local name="$1" url="$2" commit rc target
    target="$(_pnwc_tools_dir)/$name"
    if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then
        error "  invalid tool name: $name"; return 0
    fi
    if [[ "$url" != https://* ]]; then
        warn "  refusing non-HTTPS clone URL for $name"
        FAILED_TOOLS+=("git:$name (non-https url)")
        return 0
    fi

    commit=$(pin_get "git:$name") && rc=0 || rc=1
    if (( rc == 0 )); then
        if ! safe_is_commit "$commit"; then
            error "  invalid pin for git:$name (need 40 lowercase hex characters)"
            FAILED_TOOLS+=("git:$name (invalid pin)")
            return 0
        fi
        if [[ -d "$target/.git" && "$(git -C "$target" rev-parse HEAD 2>/dev/null)" == "$commit" ]]; then
            ok "  $name already at pinned commit ${commit:0:12}"
            return 0
        fi
        if [[ -e "$target" ]]; then
            warn "  $target exists but is not at the pinned commit; not modifying it (remove it to reinstall)"
            FAILED_TOOLS+=("git:$name (existing checkout differs from pin)")
            return 0
        fi
        info "  Fetching $name at pinned commit ${commit:0:12}"
        if git init -q "$target" >> "${LOGFILE:-/dev/null}" 2>&1 \
           && git -C "$target" remote add origin "$url" \
           && git -C "$target" fetch -q --depth=1 origin "$commit" >> "${LOGFILE:-/dev/null}" 2>&1 \
           && git -C "$target" checkout -q --detach FETCH_HEAD >> "${LOGFILE:-/dev/null}" 2>&1 \
           && [[ "$(git -C "$target" rev-parse HEAD)" == "$commit" ]]; then
            ok "  $name checked out at ${commit:0:12}"
        else
            warn "  Failed to fetch pinned commit for $name"
            rm -rf -- "$target"
            FAILED_TOOLS+=("git:$name")
        fi
        return 0
    fi

    if [[ -e "$target" ]]; then
        warn "  $name already present; not updating (no pin recorded)"
        return 0
    fi
    unpinned_ok "git:$name" || return 0
    info "  Cloning $name from $url (UNPINNED)"
    if git clone --depth=1 -q "$url" "$target" >> "${LOGFILE:-/dev/null}" 2>&1; then
        ok "  $name cloned to $target"
    else
        warn "  Failed to clone $name"
        FAILED_TOOLS+=("git:$name")
    fi
}

# fetch_pinned NAME ARCH URL DEST — download and verify against the pinned
# SHA-256 (dl:<NAME>:sha256:<ARCH>). There is NO bypass for a missing pin.
fetch_pinned() {
    local name="$1" tag="$2" url="$3" dest="$4" sha rc
    if ! sha=$(pin_get "dl:${name}:sha256:${tag}"); then
        warn "  $name: no pinned SHA-256 (dl:${name}:sha256:${tag}) — not downloading"
        SKIPPED_TOOLS+=("dl:${name} (no pinned SHA-256)")
        return 10
    fi
    safe_fetch_verified "$url" "$sha" "$dest" && rc=0 || rc=$?
    case "$rc" in
        0) return 0 ;;
        3) error "  $name: SHA-256 MISMATCH — refusing to use the download"
           FAILED_TOOLS+=("dl:${name} (checksum mismatch)") ;;
        2) error "  $name: pinned SHA-256 is malformed"
           FAILED_TOOLS+=("dl:${name} (invalid pin)") ;;
        *) warn "  $name: download failed"
           FAILED_TOOLS+=("dl:${name} (download failed)") ;;
    esac
    return "$rc"
}

# release_prereqs NAME [any] — sets REL_VER (pinned version) and REL_ARCH.
# shellcheck disable=SC2034  # REL_VER / REL_ARCH are outputs read by the sourcing script
release_prereqs() {
    local name="$1" arch_mode="${2:-arch}"
    REL_VER=""; REL_ARCH="any"
    # A source may be pinned by release version (dl:NAME:version) or, for raw files
    # served from a repository, by a 40-hex commit (dl:NAME:commit).
    local c
    if c=$(pin_get "dl:${name}:commit") && safe_is_commit "$c"; then
        REL_VER="$c"
    elif ! REL_VER=$(pin_version "$name"); then
        REL_VER=""
        warn "  $name: no pinned version (dl:${name}:version or dl:${name}:commit) in $PINS_FILE — not installing"
        SKIPPED_TOOLS+=("dl:${name} (no pinned version)")
        return 1
    fi
    if [[ "$arch_mode" != any ]]; then
        if ! REL_ARCH=$(safe_detect_arch); then
            warn "  $name: unsupported architecture $(safe_machine) — not installing"
            SKIPPED_TOOLS+=("dl:${name} (unsupported architecture $(safe_machine))")
            return 1
        fi
    fi
}

# install_release_member NAME URL ARCH MEMBER DESTDIR — verified single-file install.
install_release_member() {
    local name="$1" url="$2" arch="$3" member="$4" destdir="$5" d archive
    safe_mktemp_dir d
    archive="$d/${url##*/}"
    fetch_pinned "$name" "$arch" "$url" "$archive" || return 0
    mkdir "$d/x"
    if safe_extract_member "$archive" "$member" "$d/x" \
       && install -m 0755 "$d/x/${member##*/}" "$destdir/${member##*/}"; then
        ok "$name installed"
    else
        warn "$name extraction/installation failed"
        FAILED_TOOLS+=("bin:$name")
    fi
}

# print_proposed_pins — values for human review; never written automatically.
print_proposed_pins() {
    (( ${#UNPINNED_USED[@]} > 0 )) || return 0
    echo ""
    echo "# Proposed pins — REVIEW each one before recording it in $PINS_FILE"
    echo "# (see Scripts/PINNING.md). These reflect what was installed just now."
    local key kind name bin ver
    for key in "${UNPINNED_USED[@]}"; do
        kind="${key%%:*}"; name="${key#*:}"
        case "$kind" in
            git)
                ver=$(git -C "$(_pnwc_tools_dir)/$name" rev-parse HEAD 2>/dev/null) || ver=""
                [[ -n "$ver" ]] && echo "git:$name=$ver" || echo "# git:$name — checkout not found"
                ;;
            go)
                bin="${name##*/}"
                ver=$(go version -m "$(_pnwc_gopath)/bin/$bin" 2>/dev/null | awk '$1=="mod"{print $3; exit}') || ver=""
                [[ -n "$ver" ]] && echo "go:$name=$ver" || echo "# go:$name — version not found"
                ;;
            pip)
                ver=$("$(_pnwc_venv_python)" -m pip show "$name" 2>/dev/null | awk '/^Version:/{print $2}') || ver=""
                [[ -n "$ver" ]] && echo "pip:$name=$ver" || echo "# pip:$name — not in the shared venv (see: pipx list)"
                ;;
            gem)
                ver=$(gem list -e "$name" 2>/dev/null | sed -n 's/.*(\([0-9][^ ,)]*\).*/\1/p' | head -1) || ver=""
                [[ -n "$ver" ]] && echo "gem:$name=$ver" || echo "# gem:$name — version not found"
                ;;
        esac
    done
}

