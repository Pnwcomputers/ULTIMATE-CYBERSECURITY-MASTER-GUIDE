# Arch Linux Command Cheat Sheet

## 🎯 Purpose
Arch Linux-specific command reference for pacman, AUR helpers, makepkg, systemd, kernel management, and system maintenance - the Arch-native equivalent of the Debian/apt sections in LinuxCheatSheet.md.

## ⚙️ Function
Organized by domain: package management (pacman + AUR helpers + makepkg), system maintenance, kernel and module management, storage/filesystem, networking, services, dotfile/config management, and security tooling. Each command includes its purpose and explanation.

## 🏆 Goal
Serve as a field reference for Arch/Manjaro/EndeavourOS users who need fast access to pacman syntax, AUR workflow, PKGBUILD structure, and Arch-specific system administration without reading the full ArchWiki.

## 📋 When to Use
- Day-to-day package management on Arch, Manjaro, EndeavourOS, or any Arch derivative
- Building packages from the AUR or from a PKGBUILD
- Kernel and module management on a bare-metal Arch system
- Provisioning a new Arch install for security or development work

---

## 1. pacman — Core Package Management

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -Syu` | **Full System Update** | Sync repos and upgrade all installed packages. Always run before installing new packages. |
| `sudo pacman -S <pkg>` | **Install Package** | Install from official repos or any enabled repo (e.g. BlackArch). |
| `sudo pacman -Ss <keyword>` | **Search Repos** | Search package names and descriptions across all enabled repos. |
| `sudo pacman -Si <pkg>` | **Package Info (Remote)** | Show detailed info (size, deps, description) for a repo package. |
| `sudo pacman -Rns <pkg>` | **Clean Remove** | Remove package, its config files, and any now-orphaned dependencies. |
| `sudo pacman -Rdd <pkg>` | **Force Remove** | Remove ignoring dependency checks. Use with care. |
| `sudo pacman -Sc` | **Clean Old Cache** | Remove all cached versions of packages no longer installed. Keeps all cached versions of currently installed packages. |
| `sudo pacman -Scc` | **Clear Entire Cache** | Remove all cached packages. Frees disk space. |
| `pacman -Q <pkg>` | **Check Installed** | Confirm if a package is installed and show its version. |
| `pacman -Qs <keyword>` | **Search Installed** | Search names/descriptions of installed packages only. |
| `pacman -Qi <pkg>` | **Local Package Info** | Show detailed info for an installed package. |
| `pacman -Ql <pkg>` | **List Package Files** | List all files owned by an installed package. |
| `pacman -Qo <file>` | **File Ownership** | Show which package owns a given file. |
| `pacman -Qdt` | **List Orphans** | List packages installed as dependencies that are no longer required. |
| `sudo pacman -Rns $(pacman -Qdtq)` | **Remove All Orphans** | Bulk-remove all orphaned packages. |
| `pacman -Qm` | **List Foreign Packages** | List packages not in any repo (AUR-installed, manually built). |
| `pacman -Sg <group>` | **List Group Contents** | Show all packages in a group (e.g. `blackarch-wireless`). |
| `sudo pacman -Sg` | **List All Groups** | Show all available package groups. |

### pacman Flags Reference

| Flag | Meaning |
| :--- | :--- |
| `-S` | Sync (install from repo) |
| `-R` | Remove |
| `-Q` | Query (local database) |
| `-U` | Upgrade (install a local package file) |
| `-D` | Database (change install reason) |
| `y` | Refresh package databases |
| `u` | Upgrade installed packages |
| `s` | Search |
| `i` | Info |
| `l` | List files |
| `o` | Owner (which pkg owns this file) |
| `q` | Quiet output |
| `t` | List orphans (unrequired) |
| `n` | Remove .pac* config backups |
| `d` | Skip dependency check |
| `--noconfirm` | Skip confirmation prompts |
| `--overwrite '*'` | Overwrite conflicting files |
| `--needed` | Skip packages already at latest version |

---

## 2. AUR Helpers

The Arch User Repository (AUR) contains community-maintained packages. Official Arch does not support AUR helpers, but they are standard on Manjaro and common on Arch.

### yay (Most Common)

```bash
# Install yay (if not present)
sudo pacman -S base-devel git
git clone https://aur.archlinux.org/yay.git
cd yay && makepkg -si

# Use yay (same syntax as pacman, plus AUR)
yay -Syu                    # Update everything including AUR packages
yay -S <pkg>                # Install from AUR or official repos
yay -Ss <keyword>           # Search both repos and AUR
yay -Rns <pkg>              # Remove cleanly
yay -Qm                     # List AUR-installed packages
yay --devel -Syu            # Update AUR packages that track git commits
```

### paru (Rust-based alternative)

```bash
# Install paru
git clone https://aur.archlinux.org/paru.git
cd paru && makepkg -si

# Use paru
paru -Syu                   # Update everything
paru -S <pkg>               # Install from AUR
paru -Ss <keyword>          # Search
paru --fm nvim -S <pkg>     # Open PKGBUILD in nvim before building
```

### pamac (Manjaro default)

```bash
pamac update                # Update all packages including AUR
pamac install <pkg>         # Install (AUR or repo)
pamac search <keyword>      # Search repos and AUR
pamac remove <pkg>          # Remove
pamac build <pkg>           # Build and install from AUR
pamac info <pkg>            # Package info
```

---

## 3. makepkg and PKGBUILD

Build packages manually from AUR or custom PKGBUILDs.

```bash
# Clone an AUR package and build it
git clone https://aur.archlinux.org/<pkg>.git
cd <pkg>
makepkg -si                 # Build and install (-s: install deps, -i: install result)

# Common makepkg flags
makepkg -s                  # Install missing dependencies
makepkg -i                  # Install the package after building
makepkg -c                  # Clean build directory after build
makepkg -f                  # Force rebuild even if package already built
makepkg --skipchecksums     # Skip checksum validation (not recommended)
makepkg --skippgpcheck      # Skip PGP signature check (not recommended)

# Build without installing (creates .pkg.tar.zst)
makepkg

# Install the built package manually
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

## 4. pacman Cache Management

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

## 5. Mirror Management

```bash
# Install reflector
sudo pacman -S reflector

# Generate an optimized mirrorlist (US, HTTPS, sort by speed)
sudo reflector --country US --age 12 --protocol https --sort rate --save /etc/pacman.d/mirrorlist

# Multiple countries
sudo reflector --country 'US,CA,GB' --latest 10 --sort rate --save /etc/pacman.d/mirrorlist

# Enable automatic mirror updates
sudo systemctl enable --now reflector.timer

# Edit reflector config for automatic runs
sudo nvim /etc/xdg/reflector/reflector.conf
```

---

## 6. Keyring Management

```bash
# Initialize pacman keyring
sudo pacman-key --init

# Populate with Arch keys
sudo pacman-key --populate archlinux

# Populate with BlackArch keys (if BlackArch repo is added)
sudo pacman-key --populate blackarch

# Refresh all keys
sudo pacman-key --refresh-keys

# Trust a specific key
sudo pacman-key --recv-keys <KEY_ID>
sudo pacman-key --lsign-key <KEY_ID>

# Fix broken keyring (nuclear option)
sudo rm -rf /etc/pacman.d/gnupg
sudo pacman-key --init
sudo pacman-key --populate archlinux
sudo pacman -Sy archlinux-keyring
```

---

## 7. Kernel and Module Management

```bash
# List installed kernels
pacman -Q | grep linux

# Install alternate kernels
sudo pacman -S linux-lts          # LTS kernel
sudo pacman -S linux-zen          # Zen kernel (desktop-optimized)
sudo pacman -S linux-hardened     # Hardened kernel

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
```

---

## 8. systemd Service Management

| Command | Purpose |
| :--- | :--- |
| `sudo systemctl start <svc>` | Start a service |
| `sudo systemctl stop <svc>` | Stop a service |
| `sudo systemctl restart <svc>` | Restart a service |
| `sudo systemctl reload <svc>` | Reload config without restart |
| `sudo systemctl enable <svc>` | Enable at boot |
| `sudo systemctl disable <svc>` | Disable at boot |
| `sudo systemctl enable --now <svc>` | Enable and start immediately |
| `systemctl status <svc>` | Show service status |
| `systemctl is-active <svc>` | Check if running |
| `systemctl is-enabled <svc>` | Check if enabled at boot |
| `systemctl list-units --type=service` | List all services |
| `systemctl list-units --failed` | Show failed services |
| `sudo journalctl -u <svc>` | Show service logs |
| `sudo journalctl -u <svc> -f` | Follow service logs live |
| `sudo journalctl -u <svc> --since "1 hour ago"` | Recent logs |
| `sudo systemctl daemon-reload` | Reload systemd after editing unit files |

### Common Security-Related Services

```bash
sudo systemctl enable --now sshd          # SSH server
sudo systemctl enable --now NetworkManager
sudo systemctl enable --now ufw           # Uncomplicated Firewall
sudo systemctl enable --now firewalld     # firewalld (alternative)
sudo systemctl enable --now bluetooth     # Bluetooth
sudo systemctl enable --now docker        # Docker daemon
```

---

## 9. Storage and Filesystem

```bash
# List block devices
lsblk
lsblk -f                               # Include filesystem type and UUID

# Mount a drive
sudo mount /dev/<device> /mnt/<point>
sudo mount -t exfat /dev/sdb1 /mnt/usb # ExFAT (native kernel 5.7+; exfatprogs for mkfs.exfat/fsck.exfat)
sudo mount -t ntfs-3g /dev/sdb1 /mnt/usb # NTFS

# Unmount
sudo umount /mnt/<point>

# Check filesystems
sudo fsck /dev/<device>                 # Run fsck (unmount first)

# Manage LVM
sudo lvdisplay                          # List logical volumes
sudo vgdisplay                          # List volume groups
sudo pvdisplay                          # List physical volumes

# Format a partition
sudo mkfs.ext4 /dev/<device>
sudo mkfs.fat -F32 /dev/<device>
sudo mkfs.btrfs /dev/<device>

# Btrfs subvolumes (common on Arch installs)
sudo btrfs subvolume list /             # List subvolumes
sudo btrfs subvolume create /mnt/sub    # Create subvolume
sudo btrfs filesystem show              # Show Btrfs filesystems

# Get disk UUIDs (for /etc/fstab)
sudo blkid
```

---

## 10. Network Configuration

```bash
# NetworkManager (recommended on desktop/laptop)
nmcli device status                     # List network devices
nmcli connection show                   # List saved connections
nmcli device wifi list                  # Scan for Wi-Fi networks
nmcli device wifi connect <SSID> password <pw>  # Connect to Wi-Fi

# iwd (alternative Wi-Fi daemon, lighter than NetworkManager)
sudo systemctl enable --now iwd
iwctl device list
iwctl station <dev> scan
iwctl station <dev> get-networks
iwctl station <dev> connect <SSID>

# ip commands
ip a                                    # Show all interfaces and addresses
ip link show                            # Show link status
ip route show                           # Show routing table
sudo ip link set <dev> up               # Bring interface up
sudo ip addr add 192.168.1.100/24 dev <dev>   # Set static IP
sudo ip route add default via 192.168.1.1     # Set default gateway

# DNS (resolved)
systemctl status systemd-resolved
resolvectl status
resolvectl query <domain>
```

---

## 11. System Information

```bash
# OS info
cat /etc/os-release
uname -r                               # Kernel version
uname -a                               # Full kernel info

# CPU
lscpu
grep "model name" /proc/cpuinfo | head -1

# Memory
free -h
cat /proc/meminfo | head -5

# Disk usage
df -h                                  # Disk usage per filesystem
ncdu                                   # Interactive disk usage (install: pacman -S ncdu)

# Hardware
lshw                                   # Full hardware list (pacman -S lshw)
lspci                                  # PCI devices
lsusb                                  # USB devices
inxi -Fxz                              # System summary (pacman -S inxi)

# Processes
htop                                   # Interactive process viewer (pacman -S htop)
btop                                   # Modern resource monitor (pacman -S btop)
ps aux                                 # All processes
ps aux | grep <name>                   # Find specific process

# Logs
sudo journalctl -b                     # Logs from current boot
sudo journalctl -b -1                  # Logs from last boot
sudo journalctl -p err -b              # Error-level logs from current boot
sudo journalctl --disk-usage           # How much disk journald is using
sudo journalctl --vacuum-size=500M     # Trim logs to 500 MB
```

---

## 12. pacman.conf and Repo Management

Common `/etc/pacman.conf` options:

```ini
# Enable multilib (32-bit support, needed for Wine, Steam)
[multilib]
Include = /etc/pacman.d/mirrorlist

# Add BlackArch repo
[blackarch]
Server = https://www.blackarch.org/blackarch/$arch

# Enable colored output
Color

# Enable verbose package lists (shows old→new versions)
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

## 13. Security-Specific Arch Setup

```bash
# Install base security tooling
sudo pacman -S nmap wireshark-qt tcpdump openbsd-netcat aircrack-ng hashcat john \
               hydra metasploit sqlmap gobuster ffuf

# Add BlackArch repo first (see blackarch.md), then install tool groups
sudo pacman -S blackarch-wireless      # All Wi-Fi tools
sudo pacman -S blackarch-exploitation  # Exploitation frameworks
sudo pacman -S blackarch-scanner       # Scanners
sudo pacman -S blackarch-webapp        # Web app pentesting

# Install Python security libraries
sudo pacman -S python-pip python-scapy python-cryptography python-requests

# Install common AUR security tools
yay -S bloodhound crackmapexec evil-winrm impacket

# Enable firewall
sudo pacman -S ufw
sudo systemctl enable --now ufw
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh

# SSH hardening (edit /etc/ssh/sshd_config)
# PermitRootLogin no
# PasswordAuthentication no
# PubkeyAuthentication yes
```

---

## 14. Arch Maintenance Checklist

Run these periodically to keep an Arch system healthy:

```bash
# Update everything
sudo pacman -Syu
yay -Syu --devel        # Also update AUR packages tracking git

# Clean orphans
sudo pacman -Rns $(pacman -Qdtq)

# Clean cache (keep last 3 versions)
sudo paccache -r

# Check for failed services
systemctl --failed

# Check journal disk usage
sudo journalctl --disk-usage
sudo journalctl --vacuum-size=500M

# Check for .pacnew / .pacsave config files to merge
sudo find /etc -name "*.pacnew" -o -name "*.pacsave" 2>/dev/null
```

---

## Related Files
- [LinuxCheatSheet.md](LinuxCheatSheet.md) - Full Debian/apt + Arch/pacman combined reference; WSL2 section; fresh-install one-liners
- [blackarch.md](blackarch.md) - BlackArch repository installation, tool categories, and keyring bootstrap
- [../Scripts/pnwc_install_tools.sh](../Scripts/pnwc_install_tools.sh) - Automated cybersecurity tool installer for Arch/Manjaro (pacman/BlackArch repo)
- [README.md](README.md) - Documentation section index
