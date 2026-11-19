#!/bin/sh
# This script installs AnythingLLMDesktop on Linux.
# On systems with AppArmor enabled, the AppImage needs to also create a userspace
# apparmor profile so that the AppImage can be run without SUID requirements due to root chromium ownership.
#
# Todo: Detect the current location of the AppImage so that we can update the application
# in-place without the user needed to manually move the application to the new location.
# This is also useful so that the apparmor location is always correct if the user edits it.
set -eu

status() { echo "$*" >&2; }
error() { echo "ERROR $*"; exit 1; }
warning() { echo "WARNING: $*"; }

# Do not create a profile that claims to confine the AppImage while using
# flags=(unconfined). A real least-privilege profile needs application-specific
# review and testing; this installer leaves AppArmor policy to the operator.
check_to_create_apparmor_profile() {
    if [ -f /sys/kernel/security/apparmor/profiles ]; then
        status "AppArmor is enabled. No profile was installed: this installer does not"
        status "claim confinement or disable the AppImage SUID sandbox."
        status "If startup fails, follow current AnythingLLM and distribution guidance"
        status "and review any proposed profile before loading it."
    else
        status "AppArmor was not detected; no AppArmor profile was created."
    fi
}

check_or_create_desktop_profile() {
    if ! [ -f "$HOME/.local/share/applications/anythingllmdesktop.desktop" ]; then
        status "Desktop profile not found. Creating..."

        # Default Exec command
        EXEC_CMD="$INSTALL_DIR/AnythingLLMDesktop.AppImage"

        # Check for Wayland + KDE specifically
        # We check XDG_SESSION_TYPE for "wayland"
        # We check XDG_CURRENT_DESKTOP for "KDE" (handles "KDE", "KDE-Plasma", etc)
        # We use ':-' to safely handle unbound variables in 'set -u' mode
        if [ "${XDG_SESSION_TYPE:-}" = "wayland" ]; then
            case "${XDG_CURRENT_DESKTOP:-}" in
                *"KDE"*)
                    status "Detected KDE Plasma on Wayland. Adding specific flags for IME support."
                    EXEC_CMD="$INSTALL_DIR/AnythingLLMDesktop.AppImage --enable-features=UseOzonePlatform --ozone-platform=wayland --enable-wayland-ime"
                    ;;
            esac
        fi

        DESKTOP_CONTENT=$(cat <<EOF
[Desktop Entry]
StartupWMClass=anythingllm-desktop
Type=Application
Name=AnythingLLM Desktop
Exec=$EXEC_CMD
Icon=$HOME/.config/anythingllm-desktop/storage/icon.png
Categories=Utility;
EOF
)
        mkdir -p "$HOME/.local/share/applications"
        echo "$DESKTOP_CONTENT" | tee "$HOME/.local/share/applications/anythingllmdesktop.desktop" > /dev/null
        status "Desktop profile created!"
    fi
}

# Compare against a digest copied from the vendor's release metadata over a
# separately trusted channel. A checksum downloaded beside the artifact would
# not provide independent provenance.
verify_vendor_sha256() {
    expected=$1
    artifact=$2
    label=$3
    case "$expected" in
        ''|*[!0-9a-fA-F]*)
            warning "$label SHA-256 is missing or malformed."
            return 1
            ;;
    esac
    [ "${#expected}" -eq 64 ] || {
        warning "$label SHA-256 must contain exactly 64 hexadecimal characters."
        return 1
    }
    command -v sha256sum >/dev/null 2>&1 || {
        warning "sha256sum is required to verify $label."
        return 1
    }
    actual=$(sha256sum "$artifact" | awk '{print $1}' | tr '[:upper:]' '[:lower:]') || return 1
    expected=$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')
    [ "$actual" = "$expected" ] || {
        warning "$label SHA-256 mismatch; refusing to install."
        return 1
    }
}

# Stage downloads next to the destination so the final rename stays on one filesystem.
download_appimage() (
    stage=$(mktemp "$INSTALL_DIR/.anythingllm.XXXXXXXX") || exit 1
    trap 'rm -f "$stage"' EXIT
    trap 'exit 1' HUP INT TERM
    curl --fail --show-error --location --progress-bar -o "$stage" "$APPIMAGE_URL" || exit 1
    # ELF magic only identifies a file type; the vendor digest establishes the expected artifact.
    magic=$(od -An -tx1 -N4 "$stage" | tr -d ' \n')
    [ "$magic" = 7f454c46 ] || { warning "Download is not an ELF AppImage"; exit 1; }
    verify_vendor_sha256 "$APPIMAGE_SHA256" "$stage" "AnythingLLM AppImage" || exit 1
    chmod +x "$stage" || exit 1
    mv -f "$stage" "$INSTALL_DIR/$APPIMAGE_FILE"
)

install_ollama_engine() (
    command -v zstd >/dev/null 2>&1 || {
        warning "zstd is required for the optional engine; existing engine preserved."
        exit 1
    }
    case "$arch" in arm64|aarch64) archive=linux-arm64.tar.zst ;; *) archive=linux-amd64.tar.zst ;; esac
    parent=$(dirname "$OLLAMA_ENGINE_DIR")
    mkdir -p "$parent" || exit 1
    stage=$(mktemp -d "$parent/.ollama-stage.XXXXXXXX") || exit 1
    backup=
    cleanup_engine() {
        # Restore the previous engine if publication was interrupted after moving it.
        if [ -n "$backup" ] && [ -d "$backup/engine" ]; then
            if [ ! -e "$OLLAMA_ENGINE_DIR" ]; then
                mv "$backup/engine" "$OLLAMA_ENGINE_DIR" || {
                    warning "Recovery required: previous engine is in $backup/engine"
                    return
                }
            fi
            rm -rf "$backup"
        elif [ -n "$backup" ]; then
            rmdir "$backup" 2>/dev/null || true
        fi
        rm -rf "$stage"
    }
    trap cleanup_engine EXIT
    trap 'exit 1' HUP INT TERM
    curl --fail --show-error --location --progress-bar -o "$stage/engine.tar.zst" \
        "https://cdn.anythingllm.com/support/ollama/$OLLAMA_VERSION/$archive" || exit 1
    verify_vendor_sha256 "$OLLAMA_SHA256" "$stage/engine.tar.zst" "Ollama engine archive" || exit 1
    mkdir "$stage/new" || exit 1
    tar --zstd -xf "$stage/engine.tar.zst" -C "$stage/new" || exit 1
    [ -s "$stage/new/bin/ollama" ] || { warning "Archive lacks engine binary"; exit 1; }
    mv "$stage/new/bin/ollama" "$stage/new/bin/llm" || exit 1
    chmod +x "$stage/new/bin/llm" || exit 1
    if ! command -v nvidia-smi >/dev/null 2>&1; then
        rm -rf "$stage/new/lib/ollama/cuda_v12" "$stage/new/lib/ollama/cuda_v13"
    fi
    printf '%s' "$OLLAMA_VERSION" > "$stage/new/.ollama-version" || exit 1
    if [ -e "$OLLAMA_ENGINE_DIR" ]; then
        backup=$(mktemp -d "$parent/.ollama-backup.XXXXXXXX") || exit 1
        mv "$OLLAMA_ENGINE_DIR" "$backup/engine" || exit 1
    fi
    mv "$stage/new" "$OLLAMA_ENGINE_DIR" || exit 1
    status "Ollama engine v$OLLAMA_VERSION installed successfully."
)

main() {
arch=$(uname -m)
[ "$(uname -s)" = "Linux" ] || error 'This script is intended to run on Linux only.'
if [ "$(id -u)" -eq 0 ]; then
    status "This script should not be run as root. Please run it as a regular user."
    exit 1
fi

# Allow custom installation directory via ANYTHING_LLM_INSTALL_DIR environment variable
# Defaults to $HOME if not set
INSTALL_DIR="${ANYTHING_LLM_INSTALL_DIR:-$HOME}"

status "#########################################################"
status " Welcome to the AnythingLLM Desktop Installer"
status " by Mintplex Labs Inc (team@mintplexlabs.com)"
status " Architecture: $arch"
status " Install Directory: $INSTALL_DIR"
status "#########################################################"

if [ "$arch" = "arm64" ] || [ "$arch" = "aarch64" ]; then
    APPIMAGE_URL="https://cdn.anythingllm.com/latest/AnythingLLMDesktop-Arm64.AppImage"
else
    APPIMAGE_URL="https://cdn.anythingllm.com/latest/AnythingLLMDesktop.AppImage"
fi
APPIMAGE_FILE="AnythingLLMDesktop.AppImage"
APPIMAGE_SHA256="${ANYTHINGLLM_APPIMAGE_SHA256:-}"
OLLAMA_SHA256="${ANYTHINGLLM_OLLAMA_SHA256:-}"

mkdir -p "$INSTALL_DIR"
SHOULD_DOWNLOAD="true"
if [ -f "$INSTALL_DIR/$APPIMAGE_FILE" ]; then
    status "Existing installation found at $INSTALL_DIR/$APPIMAGE_FILE"
    printf '%s' "Do you want to re-download and overwrite it? (y/n): "
    read -r overwrite
    case "$overwrite" in [yY]) ;; *) SHOULD_DOWNLOAD="false" ;; esac
fi

if [ "$SHOULD_DOWNLOAD" = "true" ]; then
    status "Downloading AnythingLLM Desktop..."
    download_appimage || error "AppImage download failed; existing installation preserved."
fi

# ====================== Ollama Engine Download ======================
OLLAMA_VERSION="0.20.7"
OLLAMA_ENGINE_DIR="$HOME/.config/anythingllm-desktop/storage/engines/ollama"


SHOULD_INSTALL_OLLAMA="true"
if [ -f "$OLLAMA_ENGINE_DIR/.ollama-version" ]; then
    INSTALLED_OLLAMA_VERSION=$(cat "$OLLAMA_ENGINE_DIR/.ollama-version" 2>/dev/null || echo "")
    if [ "$INSTALLED_OLLAMA_VERSION" = "$OLLAMA_VERSION" ] && [ -f "$OLLAMA_ENGINE_DIR/bin/llm" ]; then
        status "Ollama engine v${OLLAMA_VERSION} already installed. Skipping download."
        SHOULD_INSTALL_OLLAMA="false"
    else
        status "Ollama engine version mismatch (installed: ${INSTALLED_OLLAMA_VERSION}, expected: ${OLLAMA_VERSION}). Updating..."
    fi
fi

if [ "$SHOULD_INSTALL_OLLAMA" = "true" ]; then
    if ! install_ollama_engine; then
        warning "Optional engine update skipped; continuing desktop setup."
    fi
fi

status "AnythingLLM Desktop is ready to run!"
status "$INSTALL_DIR/$APPIMAGE_FILE to start AnythingLLMDesktop"
status "\e[36mHeads up!\e[0m You can rerun this installer anytime to get the latest version of AnythingLLM without effecting your existing data."
status "Documentation: https://docs.anythingllm.com"
status "Issues: https://github.com/Mintplex-Labs/anything-llm"
status "\e[36mThanks for using AnythingLLM!\e[0m\n\n"

status "Next, we will create the desktop launcher. No AppArmor confinement profile"
status "is generated; supply vendor-published SHA-256 values to verify downloads."

check_or_create_desktop_profile
check_to_create_apparmor_profile

printf '%s' "Do you want to start AnythingLLMDesktop now? (y/n): "

read -r start
case "$start" in [yY]) start="y" ;; esac
if [ "$start" = "y" ]; then
    "$INSTALL_DIR/$APPIMAGE_FILE"
fi
}

# Source helpers for fixture tests without downloading or changing this host.
if [ "${ANYTHINGLLM_SOURCE_ONLY:-0}" != 1 ]; then
    main "$@"
fi
