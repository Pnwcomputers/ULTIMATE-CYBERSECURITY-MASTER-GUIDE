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
  jre-openjdk jdk-openjdk-headless jdk-openjdk jre11-openjdk jdk11-openjdk \
  jdk17-openjdk jre17-openjdk jre17-openjdk-headless \
  erlang-nox jre11-openjdk-headless python-gast03 python-uvicorn
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
pacman -Qm | grep -i <keyword>
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

## Related Files
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [LinuxCheatSheet.md](LinuxCheatSheet.md) - Full Arch/pacman and Debian/apt command reference
- [ArchLinux_CheatSheet.md](ArchLinux_CheatSheet.md) - Arch-specific deep reference: pacman, AUR, makepkg, systemd, kernel, PKGBUILD
- [../Scripts/pnwc_install_tools.sh](../Scripts/pnwc_install_tools.sh) - Automated cybersecurity tool installer for Arch/Manjaro (pacman/BlackArch repo)
