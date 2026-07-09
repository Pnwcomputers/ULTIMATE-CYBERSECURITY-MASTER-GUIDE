# BlackArch Linux Setup Reference

## 🎯 Purpose
Quick-reference commands for bootstrapping and maintaining a BlackArch or Arch-based penetration testing environment - covering repository installation, network adapter activation, pacman keyring management, mirror optimization, tool category installation, and full system upgrades.

## ⚙️ Function
Covers: adding the BlackArch repository to Arch/Manjaro via `strap.sh` or manual method, installing tools by category or individually, bringing up network adapters and DHCP, enabling NetworkManager, clearing/regenerating GNUPG keyring, setting BlackArch and Arch mirrors, removing conflicting packages, running full system updates, and searching for tools.

## 🏆 Goal
Serve as a copy-paste command reference for the initial BlackArch setup steps, tool category installation, and routine maintenance tasks that are easily forgotten between uses.

## 📋 When to Use
- Initial setup after installing Arch or Manjaro to add the BlackArch repository overlay
- Adding BlackArch as a repository to an existing Arch/Manjaro install
- Recovering from broken pacman keyring errors
- Resolving package conflicts before a major system update
- Activating a new wireless or USB network adapter in a live environment
- Installing tools by category for a specific engagement type

---

## 1. Add the BlackArch Repository

BlackArch is used as a **repository overlay** on top of a standard Arch Linux or Manjaro install. You do not need to install a separate distro.

### Method 1: strap.sh (Recommended)

The official and fastest way to bootstrap the BlackArch repository.

```bash
# Download and verify the strap script
curl -O https://blackarch.org/strap.sh

# Verify SHA1 sum matches https://blackarch.org/strap.sh before running
sha1sum strap.sh

# Run as root
sudo bash strap.sh
```

> **Note:** The SHA1 checksum is posted on https://blackarch.org/downloads.html — always verify before executing any bootstrap script.

### Method 2: Manual pacman.conf Edit

If you prefer not to run strap.sh, add the repo manually.

```bash
# Add to /etc/pacman.conf
[blackarch]
Server = https://www.blackarch.org/blackarch/$arch
```

Then import the BlackArch signing key:
```bash
sudo pacman-key --recv-keys 4345771566D76038C7FEB43863EC0ADBEA87E4E3
sudo pacman-key --lsign-key 4345771566D76038C7FEB43863EC0ADBEA87E4E3
sudo pacman -Sy
```

---

## 2. Identify and Bring Up Network Adapters

```bash
# List all interfaces
ip link show

# Bring up an interface
sudo ip link set <dev> up

# Request DHCP lease (verbose)
sudo dhclient <dev>
sudo dhclient -v <dev>
```

---

## 3. Enable NetworkManager

```bash
# Enable and start NetworkManager at boot
sudo systemctl enable --now NetworkManager

# Open the NetworkManager text UI (interactive connection config)
sudo nmtui
```

---

## 4. Fix Pacman Keyring

Run this before any updates on a new or broken install.

```bash
# Clear existing keys
sudo rm -rf /etc/pacman.d/gnupg

# Re-initialize and populate keys
sudo pacman-key --init
sudo pacman-key --populate archlinux blackarch

# Sync keyrings
sudo pacman -Sy archlinux-keyring blackarch-keyring
```

---

## 5. Optimize Mirrors

### Arch/Manjaro Mirrors (via reflector)

```bash
sudo pacman -S reflector
sudo reflector --country US --age 12 --protocol https --sort rate --save /etc/pacman.d/mirrorlist
```

### BlackArch Mirror List

To use a specific regional BlackArch mirror, edit or replace the server line in `/etc/pacman.conf`:

```
Server = https://www.blackarch.org/blackarch/$arch
```

A full mirror list is at: https://blackarch.org/downloads.html#mirror-list

---

## 6. Full System Update

```bash
# Standard update
sudo pacman -Syu

# Accept all prompts automatically (use with care - selects defaults on interactive prompts)
sudo pacman -Syu --noconfirm

# Overwrite conflicting files (resolves package conflicts)
sudo pacman -Syu --overwrite '*' --noconfirm
```

---

## 7. Remove Conflicting Packages (Pre-Update)

Remove packages that commonly conflict with BlackArch tool installations:

```bash
sudo pacman -Rdd \
  jre-openjdk jdk-openjdk jre11-openjdk jdk11-openjdk \
  jdk17-openjdk jre17-openjdk jre17-openjdk-headless \
  erlang-nox jre11-openjdk-headless python-gast python-uvicorn
```

> **Tip:** Only remove packages listed above if you actually have them installed. Run `pacman -Q <pkg>` first to check.

---

## 8. Install BlackArch Tools

BlackArch provides ~2,800+ tools organized by category. Install individually or by group.

### Install All Tools (Large Download — ~50+ GB)

```bash
sudo pacman -S blackarch
```

### Install by Category (Recommended)

Install only the tools relevant to your work:

```bash
# List all available tool groups
sudo pacman -Sg | grep blackarch

# Show tools in a specific group
pacman -Sg blackarch-wireless

# Install a specific tool group
sudo pacman -S blackarch-wireless        # Wi-Fi auditing tools
sudo pacman -S blackarch-exploitation    # Exploitation frameworks
sudo pacman -S blackarch-recon           # Reconnaissance tools
sudo pacman -S blackarch-webapp          # Web application testing
sudo pacman -S blackarch-forensic        # Digital forensics tools
sudo pacman -S blackarch-crypto          # Cryptography tools
sudo pacman -S blackarch-networking      # Network attack tools
sudo pacman -S blackarch-scanner         # Port/vulnerability scanners
sudo pacman -S blackarch-social          # Social engineering tools
sudo pacman -S blackarch-bluetooth       # Bluetooth attack tools
sudo pacman -S blackarch-mobile          # Mobile security tools
sudo pacman -S blackarch-nfc             # NFC/RFID tools
sudo pacman -S blackarch-reversing       # Reverse engineering tools
sudo pacman -S blackarch-binary          # Binary analysis tools
sudo pacman -S blackarch-malware         # Malware analysis
sudo pacman -S blackarch-misc            # Miscellaneous tools
```

### Install a Specific Tool

```bash
sudo pacman -S <toolname>

# Examples
sudo pacman -S aircrack-ng
sudo pacman -S metasploit
sudo pacman -S bettercap
sudo pacman -S wireshark-qt
sudo pacman -S nmap
```

---

## 9. Search for Tools

```bash
# Search in BlackArch repo by name
pacman -Ss <keyword>

# Example: find all Wi-Fi related tools
pacman -Ss wireless | grep blackarch

# Search tool descriptions on the BlackArch website
# https://blackarch.org/tools.html

# List all installed packages from BlackArch
pacman -Sl blackarch | grep '\[installed\]'
```

---

## 10. Pacman Quick Reference

| Command | Purpose |
|---------|---------|
| `sudo pacman -S <pkg>` | Install a package |
| `sudo pacman -Syu` | Update all packages |
| `sudo pacman -Rns <pkg>` | Remove package + config + orphan deps |
| `sudo pacman -Rdd <pkg>` | Remove package ignoring dependencies |
| `pacman -Q <pkg>` | Check if package is installed |
| `pacman -Qm` | List packages not in any repo (manually installed) |
| `pacman -Ss <keyword>` | Search available packages |
| `pacman -Qs <keyword>` | Search installed packages |
| `pacman -Sg <group>` | List packages in a group |
| `sudo pacman -Sc` | Clean old cached packages |
| `sudo pacman -Scc` | Clean entire cache |
| `sudo paccache -r` | Keep only last 3 versions in cache |

---

## 11. AUR Helpers

The Arch User Repository (AUR) contains community-maintained build scripts for virtually any Linux software. AUR helpers automate the build/install process.

### Install yay (Most Common)

```bash
sudo pacman -S base-devel git
git clone https://aur.archlinux.org/yay.git
cd yay && makepkg -si
```

### Install paru (Rust-based, stricter PKGBUILD review)

```bash
git clone https://aur.archlinux.org/paru.git
cd paru && makepkg -si
```

### AUR Helper Comparison

| Task | yay | paru | pamac |
| :--- | :--- | :--- | :--- |
| Update all (incl. AUR) | `yay -Syu` | `paru -Syu` | `pamac update` |
| Install | `yay -S <pkg>` | `paru -S <pkg>` | `pamac install <pkg>` |
| Search | `yay -Ss <kw>` | `paru -Ss <kw>` | `pamac search <kw>` |
| Remove cleanly | `yay -Rns <pkg>` | `paru -Rns <pkg>` | `pamac remove <pkg>` |
| List AUR packages | `yay -Qm` | `paru -Qm` | `pamac list -f` |
| Update git-tracked AUR | `yay --devel -Syu` | `paru --devel -Syu` | — |
| Open PKGBUILD before build | — | `paru --fm nvim -S <pkg>` | — |

---

## 12. makepkg and PKGBUILD

Build packages manually from AUR or custom PKGBUILDs.

```bash
# Clone an AUR package and build it
git clone https://aur.archlinux.org/<pkg>.git
cd <pkg>
makepkg -si          # -s: install deps, -i: install result

# Common makepkg flags
makepkg -s           # Install missing dependencies
makepkg -i           # Install the package after building
makepkg -c           # Clean build directory after build
makepkg -f           # Force rebuild even if package already built
makepkg --skipchecksums     # Skip checksum validation (not recommended)
makepkg --skippgpcheck      # Skip PGP signature check (not recommended)

# Build without installing (creates .pkg.tar.zst)
makepkg

# Install a manually built package
sudo pacman -U <package>.pkg.tar.zst
```

### Minimal PKGBUILD Template

```bash
# Maintainer: Your Name <email>
pkgname=mypackage
pkgver=1.0.0
pkgrel=1
pkgdesc="Short description"
arch=('x86_64')
url="https://example.com"
license=('MIT')
depends=('python')
makedepends=('git')
source=("$pkgname-$pkgver.tar.gz::https://example.com/releases/v$pkgver.tar.gz")
sha256sums=('SKIP')     # Replace with actual checksum

build() {
    cd "$pkgname-$pkgver"
    python setup.py build
}

package() {
    cd "$pkgname-$pkgver"
    python setup.py install --root="$pkgdir" --optimize=1
}
```

---

## 13. pacman Cache Management (paccache)

```bash
# Install paccache (part of pacman-contrib)
sudo pacman -S pacman-contrib

# Keep last 3 versions of each cached package (default)
sudo paccache -r

# Keep only last 1 version
sudo paccache -rk1

# Remove all cached versions of uninstalled packages
sudo paccache -ruk0

# Enable automatic cache cleanup (weekly timer)
sudo systemctl enable --now paccache.timer
```

---

## 14. Kernel and Module Management

```bash
# List installed kernels
pacman -Q | grep linux

# Install alternate kernels
sudo pacman -S linux-lts          # LTS kernel
sudo pacman -S linux-zen          # Zen kernel (desktop-optimized)
sudo pacman -S linux-hardened     # Hardened/security kernel

# Install kernel headers (required for DKMS drivers like rtl8812au)
sudo pacman -S linux-headers      # For standard linux kernel
sudo pacman -S linux-lts-headers  # For linux-lts kernel

# List loaded kernel modules
lsmod

# Load a module
sudo modprobe <module_name>

# Load module with parameters
sudo modprobe <module_name> param=value

# Unload a module
sudo modprobe -r <module_name>

# Show module info
modinfo <module_name>

# Permanently load a module at boot
echo "<module_name>" | sudo tee /etc/modules-load.d/<module_name>.conf

# Blacklist a module (prevent auto-load)
echo "blacklist <module_name>" | sudo tee /etc/modprobe.d/blacklist-<module_name>.conf

# Rebuild DKMS modules for current kernel
sudo dkms autoinstall

# Regenerate initramfs (after kernel or module config changes)
sudo mkinitcpio -P
```

---

## 15. pacman.conf Reference

Key options in `/etc/pacman.conf`:

```ini
# Enable multilib (32-bit support — needed for Wine, Steam)
[multilib]
Include = /etc/pacman.d/mirrorlist

# Add BlackArch repo
[blackarch]
Server = https://www.blackarch.org/blackarch/$arch

# Enable colored output
Color

# Enable verbose package lists (shows old→new versions during upgrade)
VerbosePkgLists

# Enable parallel downloads (default: 5)
ParallelDownloads = 5
```

```bash
# Edit pacman config
sudo nvim /etc/pacman.conf

# Sync after editing
sudo pacman -Sy
```

---

## 16. Arch Maintenance Checklist

Run these periodically to keep an Arch/Manjaro/BlackArch system healthy:

```bash
# 1. Update everything (official repos)
sudo pacman -Syu

# 2. Update AUR packages including git-tracking ones
yay -Syu --devel

# 3. Remove orphaned packages
sudo pacman -Rns $(pacman -Qdtq)

# 4. Clean old package cache (keep last 3 versions)
sudo paccache -r

# 5. Check for .pacnew / .pacsave config files to merge
sudo find /etc -name "*.pacnew" -o -name "*.pacsave" 2>/dev/null

# 6. Check for failed services
systemctl --failed

# 7. Check systemd journal disk usage and trim
sudo journalctl --disk-usage
sudo journalctl --vacuum-size=500M

# 8. Rebuild DKMS modules if kernel was updated
sudo dkms autoinstall
```

---

## Related Files
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [LinuxCheatSheet.md](LinuxCheatSheet.md) - Full Debian/apt + Arch/pacman combined reference; WSL2 section
- [ArchLinux_CheatSheet.md](ArchLinux_CheatSheet.md) - Arch-flavored version of LinuxCheatSheet.md: same 15-section structure, all commands tailored for Arch/pacman
- [../Scripts/pnwc_install_tools.sh](../Scripts/pnwc_install_tools.sh) - Automated cybersecurity tool installer for Arch/Manjaro (pacman/BlackArch repo)
