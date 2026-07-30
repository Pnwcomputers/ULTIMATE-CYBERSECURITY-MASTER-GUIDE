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

# Detect AppArmor major version so we generate compatible profile syntax.
# AppArmor 4.x (Ubuntu 24.04+) supports abi declarations and userns rules;
# older versions (Ubuntu 20.04/22.04) need classic syntax only.
get_apparmor_major_version() {
    if command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser --version 2>/dev/null | grep -oE '[0-9]+' | head -1
    else
        echo "0"
    fi
}

# Create an AppArmor profile for AnythingLLMDesktop for systems with AppArmor enabled
# https://askubuntu.com/questions/1512287/obsidian-appimage-the-suid-sandbox-helper-binary-was-found-but-is-not-configu/1528215#1528215
create_apparmor_profile() {
    status "Checking for sudo privileges..."
    sudo -v
    if [ $? -ne 0 ]; then
        error "Failed to get sudo privileges! Aborting..."
        exit 1
    fi

    AA_MAJOR=$(get_apparmor_major_version)
    status "Creating AppArmor profile for AnythingLLM (AppArmor version ${AA_MAJOR}.x detected)..."

    if [ "${AA_MAJOR}" -ge 4 ] 2>/dev/null; then
        APP_ARMOR_CONTENT=$(cat <<'EOF'
# AnythingLLMDesktop AppArmor profile (4.x syntax)
abi <abi/4.0>,
include <tunables/global>

profile anythingllmdesktop /**/AnythingLLMDesktop.AppImage flags=(unconfined) {
  userns,
}
EOF
)
    else
        APP_ARMOR_CONTENT=$(cat <<'EOF'
# AnythingLLMDesktop AppArmor profile (classic syntax for AppArmor 2.x/3.x)
#include <tunables/global>

profile anythingllmdesktop /**/AnythingLLMDesktop.AppImage flags=(unconfined) {
}
EOF
)
    fi

    echo "$APP_ARMOR_CONTENT" | sudo tee /etc/apparmor.d/anythingllmdesktop > /dev/null
    status "Reloading AppArmor service..."
    if sudo apparmor_parser -r /etc/apparmor.d/anythingllmdesktop 2>/dev/null; then
        status "AppArmor profile created - you can now run AnythingLLMDesktop without SUID requirements."
    elif sudo systemctl reload apparmor.service 2>/dev/null; then
        status "AppArmor profile created - you can now run AnythingLLMDesktop without SUID requirements."
    else
        warning "AppArmor reload failed. The profile was written to /etc/apparmor.d/anythingllmdesktop"
        warning "but could not be loaded. You may need to reboot or run:"
        warning "  sudo apparmor_parser -r /etc/apparmor.d/anythingllmdesktop"
        warning "If issues persist, you can disable the profile for this app only:"
        warning "  sudo ln -sf /etc/apparmor.d/anythingllmdesktop /etc/apparmor.d/disable/"
        warning "  sudo systemctl reload apparmor"
    fi
}

check_to_create_apparmor_profile() {
    # Check if the system has AppArmor enabled
    if [ -f /sys/kernel/security/apparmor/profiles ]; then
        if ! [ -f /etc/apparmor.d/anythingllmdesktop ]; then
            status "AppArmor is enabled on this system."
            status "\e[31m[Warning]\e[0m You will get an error about SUID permission issues when running the AppImage without creating an AppArmor profile."
            status "This requires sudo privileges. If you are unsure, you can create an AppArmor profile manually."
            read -p "Do you want to auto-create an AppArmor profile for AnythingLLM now? (y/n): " create_apparmor
            case "$create_apparmor" in [yY]) create_apparmor="y" ;; esac
            if [ "$create_apparmor" = "y" ]; then
                create_apparmor_profile
            else
                status "AppArmor is enabled on this system."
                status "AppArmor profile creation skipped. You may not be able to run AnythingLLMDesktop without it."
            fi
        else
            status "AppArmor profile already exists."
            read -p "Do you want to overwrite it with the latest version? (y/n): " overwrite_apparmor
            case "$overwrite_apparmor" in [yY]) overwrite_apparmor="y" ;; esac
            if [ "$overwrite_apparmor" = "y" ]; then
                create_apparmor_profile
            fi
        fi
    else
        status "AppArmor could not be automatically detected or does not exist. If you get an SUID error on startup, you may need to create an AppArmor profile for AnythingLLMDesktop.AppImage manually."
    fi  
}

check_or_create_desktop_profile() {
    if ! [ -f $HOME/.local/share/applications/anythingllmdesktop.desktop ]; then
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
        mkdir -p $HOME/.local/share/applications
        echo "$DESKTOP_CONTENT" | tee $HOME/.local/share/applications/anythingllmdesktop.desktop > /dev/null
        status "Desktop profile created!"
    fi
}

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

mkdir -p "$INSTALL_DIR"
SHOULD_DOWNLOAD="true"
if [ -f "$INSTALL_DIR/$APPIMAGE_FILE" ]; then
    status "Existing installation found at $INSTALL_DIR/$APPIMAGE_FILE"
    read -p "Do you want to re-download and overwrite it? (y/n): " overwrite
    case "$overwrite" in [yY]) ;; *) SHOULD_DOWNLOAD="false" ;; esac
fi

if [ "$SHOULD_DOWNLOAD" = "true" ]; then
    status "Downloading AnythingLLM Desktop..."
    curl --fail --show-error --location --progress-bar -o "$INSTALL_DIR/$APPIMAGE_FILE" "$APPIMAGE_URL"
    chmod +x "$INSTALL_DIR/$APPIMAGE_FILE"
fi

# ====================== Ollama Engine Download ======================
OLLAMA_VERSION="0.20.7"
OLLAMA_ENGINE_DIR="$HOME/.config/anythingllm-desktop/storage/engines/ollama"

install_ollama_engine() {
    if [ "$arch" = "arm64" ] || [ "$arch" = "aarch64" ]; then
        OLLAMA_ARCHIVE="linux-arm64.tar.zst"
    else
        OLLAMA_ARCHIVE="linux-amd64.tar.zst"
    fi
    OLLAMA_URL="https://cdn.anythingllm.com/support/ollama/${OLLAMA_VERSION}/${OLLAMA_ARCHIVE}"

    if ! command -v zstd >/dev/null 2>&1; then
        warning "zstd is required to extract the Ollama engine."
        warning "Install with: apt install zstd (Debian/Ubuntu) or yum install zstd (RHEL/CentOS)"
        warning "Skipping Ollama engine download. The built-in LLM engine will not be available."
        return 1
    fi

    # Wipe existing engine directory for a clean install
    if [ -d "$OLLAMA_ENGINE_DIR" ]; then
        status "Removing existing Ollama engine for clean install..."
        rm -rf "$OLLAMA_ENGINE_DIR"
    fi

    mkdir -p "$OLLAMA_ENGINE_DIR"
    status "Downloading Ollama engine v${OLLAMA_VERSION}..."
    if ! curl --fail --show-error --location --progress-bar -o "$OLLAMA_ENGINE_DIR/${OLLAMA_ARCHIVE}" "$OLLAMA_URL"; then
        warning "Failed to download Ollama engine. The built-in LLM engine will not be available."
        rm -rf "$OLLAMA_ENGINE_DIR"
        return 1
    fi

    status "Extracting Ollama engine..."
    tar --zstd -xf "$OLLAMA_ENGINE_DIR/${OLLAMA_ARCHIVE}" -C "$OLLAMA_ENGINE_DIR"
    rm -f "$OLLAMA_ENGINE_DIR/${OLLAMA_ARCHIVE}"

    # Rename the binary to our expected name
    if [ -f "$OLLAMA_ENGINE_DIR/bin/ollama" ]; then
        mv "$OLLAMA_ENGINE_DIR/bin/ollama" "$OLLAMA_ENGINE_DIR/bin/llm"
    fi

    # Mark binaries as executable
    chmod +x "$OLLAMA_ENGINE_DIR/bin/llm"

    # If nvidia-smi is not available, drop CUDA folders to save disk space
    if ! command -v nvidia-smi >/dev/null 2>&1; then
        status "No NVIDIA GPU detected (nvidia-smi not found). Removing CUDA libraries to save space..."
        rm -rf "$OLLAMA_ENGINE_DIR/lib/ollama/cuda_v12" 2>/dev/null
        rm -rf "$OLLAMA_ENGINE_DIR/lib/ollama/cuda_v13" 2>/dev/null
    else
        status "NVIDIA GPU detected. Keeping CUDA libraries."
    fi

    # Write version marker
    echo -n "$OLLAMA_VERSION" > "$OLLAMA_ENGINE_DIR/.ollama-version"
    status "Ollama engine v${OLLAMA_VERSION} installed successfully."
}

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
    install_ollama_engine
fi

status "AnythingLLM Desktop is ready to run!"
status "$INSTALL_DIR/$APPIMAGE_FILE to start AnythingLLMDesktop"
status "\e[36mHeads up!\e[0m You can rerun this installer anytime to get the latest version of AnythingLLM without effecting your existing data."
status "Documentation: https://docs.anythingllm.com"
status "Issues: https://github.com/Mintplex-Labs/anything-llm"
status "\e[36mThanks for using AnythingLLM!\e[0m\n\n"

status "Next, we will create a desktop profile and AppArmor profile for AnythingLLMDesktop."
status "This is required for the AppImage to be able to run without SUID requirements."
status "You can manually create these profiles if you prefer."

check_or_create_desktop_profile
check_to_create_apparmor_profile

read -p "Do you want to start AnythingLLMDesktop now? (y/n): " start
case "$start" in [yY]) start="y" ;; esac
if [ "$start" = "y" ]; then
    "$INSTALL_DIR/$APPIMAGE_FILE"
fi