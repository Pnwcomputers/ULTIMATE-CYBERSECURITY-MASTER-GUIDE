# 🐧 Arch Linux Command Cheat Sheet and Reference

## 🎯 Purpose
Quick reference for common Linux system administration, networking, security auditing, and hardware interface commands — Arch/Manjaro/EndeavourOS focused, using pacman, AUR helpers, and Arch-native tooling throughout.

## ⚙️ Function
Organized by domain: SSH/permissions, package management, diagnostics/system info, storage/filesystem, network configuration/scanning, service management, samba, application removal, stress testing, fresh install one-liners, AUR/package building, hardware hacking toolkit, Arch daily workflow, and OSINT. Each command includes its purpose and a plain-English explanation.

## 🏆 Goal
Serve as a field reference for security professionals and system administrators to quickly find the right command for Arch/Manjaro systems without needing to search the ArchWiki — structured identically to [LinuxCheatSheet.md](LinuxCheatSheet.md) for easy side-by-side comparison.

## 📋 When to Use
- Day-to-day system administration on Arch, Manjaro, EndeavourOS, or BlackArch
- Quickly finding the right networking or security command during an engagement
- Hardware interface work (USB, serial, JTAG) requiring specific Linux commands
- Provisioning a new Arch install for security or hardware-hacking work

This document serves as a quick reference for common system administration, networking, security auditing, and hardware hacking commands on **Arch/Manjaro-based systems**. It mirrors the structure of [LinuxCheatSheet.md](LinuxCheatSheet.md) section-for-section, replacing all `apt`/Debian commands with their `pacman`/AUR equivalents.

---

# Arch/Manjaro Quick Reference:

[Arch Linux](https://archlinux.org/) replaces `apt` with [`pacman`](https://wiki.archlinux.org/title/Pacman) (official repos) and AUR helpers like [`yay`](https://aur.archlinux.org/packages/yay) or [`paru`](https://github.com/Morganamilo/paru) for community packages. Manjaro also ships [`pamac`](https://github.com/manjaro/pamac) as a GUI/CLI frontend with built-in AUR support. The [Arch User Repository (AUR)](https://aur.archlinux.org/) is Arch's killer feature — virtually any Linux software can be compiled and installed directly from community-maintained build scripts.

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -Syu` | **System Update** | Syncs repos and upgrades all installed packages. Run before any testing session. |
| `sudo pacman -S <pkg>` | **Install Package** | Install from official repos or any enabled repo (BlackArch, multilib). |
| `sudo pacman -Rns <pkg>` | **Remove Package Cleanly** | Removes the package, config files, and any now-orphaned dependencies. |
| `pacman -Qdt` | **List Orphans** | Lists packages installed as dependencies that are no longer needed. |
| `sudo pacman -Sc` | **Clean Old Cache** | Removes cached packages for packages no longer installed. Keeps cache for installed packages. |
| `yay -S <pkg>` | **Install from AUR** | Builds and installs a community package from the Arch User Repository. |

---

# Arch/Manjaro Reference Guide:

Arch uses a **rolling release** model — packages are always up-to-date rather than pinned to a release cycle. The [ArchWiki](https://wiki.archlinux.org/) is the best documentation resource in Linux. For BlackArch-specific setup (repo overlay, tool categories, keyring), see [blackarch.md](blackarch.md). For deep pacman/AUR/makepkg reference, see [ArchLinux_CheatSheet.md](ArchLinux_CheatSheet.md).

## 1. SSH and File Permissions

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `ssh-keygen -R 192.168.0.1` | **Remove SSH Key** | Removes the host key for the specified IP from your `known_hosts` file. Use this if the remote server key changes. |
| `sudo chmod u+x my_script.sh` | **Allow Execution** | Adds the **e**xecute permission (`+x`) for the **u**ser (`u+`) who owns the file, making a script runnable. |
| `sudo chmod 644` | **File Permissions** | Owner can read/write; Group/Others can only read (standard file permission). |
| `sudo chmod 755` | **Script/Directory Permissions** | Owner can read/write/execute; Group/Others can read/execute (standard directory/script permission). |

---

## 2. Package Management (`pacman`) Repairs

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -Syu --overwrite '*'` | **Fix File Conflicts** | Forces an upgrade, overwriting files that conflict between packages. Use when pacman refuses to install due to file ownership conflicts. |
| `sudo pacman -Rdd <pkg>` | **Force Remove (Ignore Deps)** | Removes a package while ignoring dependency checks. Use when a package is blocking an update. |
| `sudo pacman -Rns <pkg>` | **Remove Package Cleanly** | Removes the package, its configuration files, and any now-orphaned dependencies. |
| `sudo pacman -Rns $(pacman -Qdtq)` | **Remove All Orphans** | Bulk-removes all orphaned packages in one pass. Run `pacman -Qdt` first to preview. |
| `sudo pacman -Sc` | **Clean Old Cache** | Removes cached package files for packages that are no longer installed. |
| `sudo pacman -Scc` | **Clear Entire Cache** | Removes all cached packages including those currently installed. Frees maximum disk space. |

### pacman Flags Reference

| Flag | Meaning |
| :--- | :--- |
| `-S` | Sync (install from repo) |
| `-R` | Remove |
| `-Q` | Query (local database) |
| `-U` | Upgrade (install a local `.pkg.tar.zst` file) |
| `y` | Refresh package databases |
| `u` | Upgrade installed packages |
| `s` | Search |
| `i` | Info |
| `q` | Quiet output |
| `t` | List orphans (unrequired deps) |
| `n` | Remove `.pac*` config backups on remove |
| `d` | Skip dependency check |
| `--noconfirm` | Skip confirmation prompts |
| `--overwrite '*'` | Overwrite conflicting files |
| `--needed` | Skip packages already at latest version |

---

## 3. Diagnostics and System Info

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `ls -la /usr/folder1/folder2/` | **Check Files/Folders** | Lists all (`-a`) files in the path with long format details (`-l`). |
| `lsblk` | **List Disks** | Lists all block devices (drives and partitions) on the system. |
| `lsusb` | **List USB Devices** | Lists USB devices connected to the system. |
| `lspci` | **List PCI Devices** | Lists PCI buses and devices. |
| `lshw` | **Hardware Info** | Lists detailed hardware configuration. Install: `sudo pacman -S lshw`. |
| `inxi -Fxz` | **System Summary** | Concise hardware and OS summary. Install: `sudo pacman -S inxi`. |
| `dmesg \| tail -n 50` | **Kernel Messages** | Shows the last 50 kernel ring buffer messages (great for USB/hardware issues). |
| `free -h` | **Memory Usage** | Displays free, used, and total system memory and swap in human-readable format. |
| `sudo iftop` | **Network Traffic (General)** | Displays network bandwidth usage on an interface in real-time. |
| `sudo nethogs` | **Network Traffic (Per Process)** | Displays which process/program is using the most network bandwidth. |
| `ncdu` | **Disk Usage** | Interactive ncurses utility for visualizing disk space usage. Install: `sudo pacman -S ncdu`. |
| `htop` | **Process Viewer** | Interactive, improved version of `top`. Install: `sudo pacman -S htop`. |
| `btop` | **Modern Monitor** | Feature-rich, visually appealing resource monitor. Install: `sudo pacman -S btop`. |

---

## 4. Storage and File System Management

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo mount -t exfat /dev/sdXN /mnt/your_mount_point` | **Mount ExFAT Drive** | Mounts an ExFAT-formatted drive. Arch kernel 5.7+ includes native ExFAT support. Install `exfatprogs` for `mkfs.exfat`/`fsck.exfat`. |
| `sudo umount /mnt/your_mount_point` | **Unmount Drive** | Safely unmounts the drive at the specified mount point. |
| `lsblk -f` | **Filesystem Info** | Lists block devices with filesystem type, label, and UUID. |
| `sudo blkid` | **Get Drive UUIDs** | Locates and prints block device attributes (used for `/etc/fstab` entries). |

**ExFAT tools on Arch:**
```bash
# Install ExFAT userspace tools (kernel 5.7+ has native ExFAT — exfatprogs provides mkfs/fsck)
sudo pacman -S exfatprogs

# Mount ExFAT drive
sudo mount -t exfat /dev/sdb1 /mnt/usb

# Format ExFAT
sudo mkfs.exfat /dev/sdb1
```

---

## 5. Network Configuration and Scanning

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `ip a` | **View IP Addresses** | Displays address information for all network interfaces (modern replacement for `ifconfig`). |
| `ifconfig` | **Network Config (Legacy)** | Older command to display/configure network interfaces. Install: `sudo pacman -S net-tools`. |
| `iw dev` | **Wireless Info** | Shows detailed information about wireless devices. |
| `sudo iwconfig` | **Wireless Config** | Displays/sets basic wireless interface parameters. Install: `sudo pacman -S wireless_tools`. |
| `sudo ip link set wlan1 down` | **Disable Interface** | Brings down the specified wireless interface. |
| `sudo ip link set wlan1 name wlan1mon` | **Rename Interface** | Renames the wireless interface (useful for monitor mode setup). |
| `airmon-ng` | **Monitor Mode** | Puts a wireless card into monitor mode for security auditing. Install: `sudo pacman -S aircrack-ng`. |
| `sudo arp-scan -l` | **ARP Scan** | Scans the local network segment using ARP packets to discover active hosts. Install: `sudo pacman -S arp-scan`. |

**ARP Scan Usage Example:**
```bash
cd /tmp/
sudo arp-scan -l
```

> **Note:** Wireless monitor mode and packet injection require **bare-metal Linux** or a passed-through USB Wi-Fi adapter.

---

## 6. Wireless Adapter (Alfa/Realtek) Setup

This covers installing the `rtl88xxau` or `rtl8812au` driver, often needed for high-power Wi-Fi adapters.

**Option 1: AUR (DKMS — Recommended)**
```bash
# Install build dependencies
sudo pacman -S dkms linux-headers base-devel

# Install the driver from AUR
yay -S rtl88xxau-dkms-git
# or
yay -S rtl8812au-dkms-git
```

**Option 2: Compile from Source**
```bash
sudo pacman -S git dkms linux-headers base-devel
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
```

> **Kernel Headers Note:** Arch ships `linux-headers` for the standard kernel. If you're on `linux-lts`, install `linux-lts-headers` instead. Run `uname -r` to check your running kernel.

---

## 7. System Services and Control

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `systemctl reboot -i` | **Reboot System** | Initiates a system reboot. |
| `sudo systemctl <cmd> <service>` | **Manage Services** | Standard format to control system services (start, stop, status, enable, disable). |
| `sudo systemctl disable hciuart.service` | **Disable Bluetooth Console** | Stops the serial Bluetooth management service (common on Raspberry Pi). |
| `sudo systemctl disable avahi-daemon.socket avahi-daemon.service` | **Disable Avahi** | Disables the Zeroconf/mDNS daemon used for local network discovery. |
| `sudo journalctl -u <service> -f` | **Follow Service Logs** | Tail the systemd journal for a specific service in real-time. |

---

## 8. Samba (Network File Sharing)

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -S usbmuxd` | **USB Multiplexer** | USB device multiplexing daemon (useful for iOS device access). |
| `sudo pacman -S samba` | **Install Samba** | Installs Samba for Windows/Linux file sharing. |
| `sudo tail -f /var/log/samba/log.smbd` | **Monitor Samba Log** | Displays the log file and follows it (`-f`) for real-time troubleshooting. |
| `smbclient -L //hostname -U user` | **List Shares** | Lists available SMB shares on a remote host. |

**Samba Quick Setup on Arch:**
```bash
# Install Samba
sudo pacman -S samba

# Copy the example config as a starting point
sudo cp /etc/samba/smb.conf.default /etc/samba/smb.conf

# Set a Samba password for your user
sudo smbpasswd -a $USER

# Enable and start Samba services
sudo systemctl enable --now smb nmb
```

---

## 9. Application Removal

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -Rns <pkg>` | **Remove Package Cleanly** | Removes the package, its config files, and orphaned dependencies. Standard removal command. |
| `sudo pacman -Rns $(pacman -Qdtq)` | **Remove All Orphans** | Removes all packages that are no longer required by anything. |
| `sudo pacman -Rdd <pkg>` | **Force Remove** | Removes package ignoring dependency checks. Use when removing conflicting packages before updates. |

**Common pre-update conflict removal (BlackArch):**
```bash
sudo pacman -Rdd \
  jre-openjdk jdk-openjdk jre11-openjdk jdk11-openjdk \
  jdk17-openjdk jre17-openjdk jre17-openjdk-headless \
  erlang-nox jre11-openjdk-headless python-gast python-uvicorn
```

> **Tip:** Only remove packages you actually have installed. Run `pacman -Q <pkg>` first to check.

---

## 10. System Stress and Temperature Monitoring

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -S stress-ng` | **Install Stress Tool** | Installs a utility to generate system load for stability testing. |
| `sudo pacman -S sysbench` | **Install Benchmark Tool** | Installs a multi-threaded benchmark and stress-test utility. |
| `stress-ng --cpu 4 --timeout 300s` | **CPU Stress Test** | Puts a high load on 4 CPU cores for 300 seconds (5 minutes). |
| `watch -n 1 vcgencmd measure_temp` | **Monitor Temperature (Pi)** | Runs the temperature command every second (Raspberry Pi only). |
| `sensors` | **Monitor Temperature (x86)** | Reads on-board temp sensors via `lm-sensors`. Install: `sudo pacman -S lm_sensors`. |

**lm_sensors setup on Arch:**
```bash
sudo pacman -S lm_sensors
sudo sensors-detect   # auto-detect sensors (say YES to load on boot)
sensors               # read temps
```

---

## 11. Fresh Install - Arch / Manjaro

This section is for **Arch-based systems** — bare-metal, VM, or Manjaro — provisioned for security and hardware-hacking work.

### 11.1 Base System Tools (One-Liner)

A comprehensive suite of development, network, and security tools via pacman:

```bash
sudo pacman -Syu && sudo pacman -S --needed \
linux-cpupower screen tmux git git-lfs nano vim python python-pip python-pipx \
python-requests python-yaml python-tkinter python-psutil \
wget curl jq unzip zip rsync tree expect base-devel pkg-config cmake \
bind-tools net-tools arp-scan iftop iotop lm_sensors sysstat smartmontools \
nmap mtr traceroute whois iperf3 tcpdump openbsd-netcat ethtool \
aircrack-ng reaver hashcat hydra netdiscover wifite \
samba cifs-utils smbclient nfs-utils sshfs rclone \
vnstat glances fail2ban logrotate \
ncdu htop btop lshw lsof parted \
psmisc figlet lolcat fastfetch \
avahi nss-mdns
```

> **Manjaro note:** Replace `fastfetch` with `neofetch` if not available; on Manjaro most of these are pre-installed.

### 11.2 Hardware Hacking & Programming Add-On (Arch)

Adds USB serial tools, microcontroller flashers, SDR utilities, reverse engineering tools, logic analyzers, and Bluetooth hardware support:

```bash
sudo pacman -S --needed \
cmake ninja autoconf automake libtool clang gdb \
ripgrep fd fzf bat eza zoxide direnv \
tio minicom picocom usbutils pciutils socat \
avrdude dfu-util stm32flash openocd flashrom \
hackrf rtl-sdr \
gnuradio gr-osmosdr gqrx inspectrum multimon-ng \
fftw \
binwalk radare2 squashfs-tools cpio cabextract \
qemu-user-static \
sigrok-cli pulseview wireshark-qt tshark \
bluez bluez-utils \
xxd p7zip \
github-cli pandoc imagemagick ffmpeg
```

**AUR additions (requires yay or paru):**
```bash
yay -S --needed \
ubertooth \
platformio-core \
arduino-cli \
zoxide \
bat-extras
```

**Add yourself to device groups (one-time, then log out and back in):**
```bash
sudo usermod -aG plugdev,uucp,wireshark,tty $USER
```

### 11.3 Python Tools via pipx (Arch)

These tools are not in official repos or are too outdated there. Install in user space:

```bash
pipx ensurepath && \
pipx install platformio && \
pipx install esptool && \
pipx install urh && \
pipx install meshtastic && \
pipx install rns && \
pipx install nomadnet && \
pipx install lxmf && \
pipx install unblob && \
pipx install rfcat && \
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 11.4 Build-from-Source Tools (Arch)

**`kalibrate-hackrf`** — clock calibration for HackRF (not packaged):
```bash
mkdir -p ~/tools && cd ~/tools
git clone https://github.com/scateu/kalibrate-hackrf
cd kalibrate-hackrf && ./bootstrap && ./configure && make && sudo make install
```

**`arduino-cli`** — official installer:
```bash
curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh
```

**`Ghidra`** — manual download (needs JDK 17+):
```bash
sudo pacman -S jdk17-openjdk
# Download latest from: https://github.com/NationalSecurityAgency/ghidra/releases
```

### 11.5 AUR Helper Setup

Install `yay` (most common AUR helper) if not already present:

```bash
sudo pacman -S base-devel git
git clone https://aur.archlinux.org/yay.git
cd yay && makepkg -si
```

Or `paru` (Rust-based, stricter PKGBUILD review):
```bash
git clone https://aur.archlinux.org/paru.git
cd paru && makepkg -si
```

---

## 12. AUR and Package Building

The Arch User Repository contains community-maintained build scripts for virtually any Linux software. Understanding how to work with it is essential for Arch users.

### 12.1 AUR Helper Reference

| Task | yay | paru | pamac |
| :--- | :--- | :--- | :--- |
| Update all (incl. AUR) | `yay -Syu` | `paru -Syu` | `pamac update` |
| Install | `yay -S <pkg>` | `paru -S <pkg>` | `pamac install <pkg>` |
| Search | `yay -Ss <kw>` | `paru -Ss <kw>` | `pamac search <kw>` |
| Remove cleanly | `yay -Rns <pkg>` | `paru -Rns <pkg>` | `pamac remove <pkg>` |
| Build from AUR | `yay -S <pkg>` | `paru -S <pkg>` | `pamac build <pkg>` |
| List AUR packages | `yay -Qm` | `paru -Qm` | `pamac list -f` |
| Update git-tracked AUR | `yay --devel -Syu` | `paru --devel -Syu` | — |

### 12.2 Manual AUR Build (makepkg)

```bash
# Clone an AUR package and build
git clone https://aur.archlinux.org/<pkg>.git
cd <pkg>
makepkg -si           # -s: install deps, -i: install result

# Common makepkg flags
makepkg -s            # Install missing dependencies only
makepkg -i            # Install the package after building
makepkg -c            # Clean build directory after build
makepkg -f            # Force rebuild even if package already built
```

### 12.3 Minimal PKGBUILD Template

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

### 12.4 pacman Cache and Mirror Management

```bash
# Install paccache (pacman-contrib)
sudo pacman -S pacman-contrib

# Keep last 3 versions per cached package (default)
sudo paccache -r

# Keep only last 1 version
sudo paccache -rk1

# Remove all cached versions of uninstalled packages
sudo paccache -ruk0

# Automated weekly cache cleanup
sudo systemctl enable --now paccache.timer

# Optimize mirrorlist (US, HTTPS, fastest 10)
sudo pacman -S reflector
sudo reflector --country US --age 12 --protocol https --sort rate --save /etc/pacman.d/mirrorlist

# Auto-run reflector weekly
sudo systemctl enable --now reflector.timer
```

### 12.5 Fix Broken Keyring

```bash
# Nuclear fix for pacman GPG errors
sudo rm -rf /etc/pacman.d/gnupg
sudo pacman-key --init
sudo pacman-key --populate archlinux
sudo pacman -Sy archlinux-keyring

# If BlackArch is installed
sudo pacman-key --populate blackarch
sudo pacman -Sy blackarch-keyring
```

### 12.6 Kernel Management

```bash
# List installed kernels
pacman -Q | grep linux

# Install alternate kernels
sudo pacman -S linux-lts          # Long-term support
sudo pacman -S linux-zen          # Desktop-optimized
sudo pacman -S linux-hardened     # Security-hardened

# Kernel headers (needed for DKMS drivers)
sudo pacman -S linux-headers      # For linux kernel
sudo pacman -S linux-lts-headers  # For linux-lts kernel

# List loaded modules
lsmod

# Load / unload a module
sudo modprobe <module>
sudo modprobe -r <module>

# Blacklist a module (prevent auto-load)
echo "blacklist <module>" | sudo tee /etc/modprobe.d/blacklist-<module>.conf

# Rebuild DKMS for current kernel
sudo dkms autoinstall
```

---

## 13. Hardware Hacking Toolkit Reference

Quick descriptions of what each tool does, organized by category.

### 13.1 Serial / USB Console

| Tool | Purpose |
| :--- | :--- |
| `tio` | Modern serial terminal - autoconnect, logging, hex mode, dead simple. **Recommended default.** |
| `minicom` | Classic serial terminal, menu-driven config. |
| `picocom` | Lightweight terminal, scriptable. |
| `screen` | Doubles as a serial terminal: `screen /dev/ttyUSB0 115200`. |
| `socat` | Tunnel serial over network, create virtual serial pairs, bridge protocols. |
| `usbutils` | Provides `lsusb` for enumerating USB devices. |
| `setserial` | Configure serial port parameters (latency, baud rate aliases). |

### 13.2 Microcontroller Flashing & Debugging

| Tool | Purpose |
| :--- | :--- |
| `platformio` | All-in-one toolchain: ESP32, ESP8266, AVR, STM32, RP2040, nRF, etc. Integrates with VSCode. |
| `arduino-cli` | Official Arduino CLI - sketches, libraries, board management. |
| `esptool.py` | ESP32 / ESP8266 flashing, fuse reading, security operations. |
| `avrdude` | AVR / ATmega / ATtiny flashing with USBasp, AVRISP, Arduino-as-ISP. |
| `dfu-util` | USB DFU mode flashing (STM32, many bootloaders). |
| `stm32flash` | STM32 UART/I2C bootloader flashing. |
| `openocd` | JTAG / SWD debugging - works with ST-Link, J-Link, CMSIS-DAP, FT2232. |
| `flashrom` | SPI flash chip read/write - BIOS dumps, router firmware extraction (CH341A, Bus Pirate, FT2232). |
| `picotool` | RP2040 (Pico) inspection and flashing utility. |

### 13.3 SDR / RF

| Tool | Purpose |
| :--- | :--- |
| `hackrf` | HackRF One control - `hackrf_info`, `hackrf_transfer`, `hackrf_sweep`. |
| `rtl-sdr` | RTL2832U-based dongles - `rtl_sdr`, `rtl_fm`, `rtl_433`, `rtl_tcp`. |
| `gnuradio` | Visual signal processing flowgraphs (GNU Radio Companion). |
| `gr-osmosdr` | GNU Radio source/sink for HackRF, RTL-SDR, BladeRF, etc. |
| `gqrx` | GUI spectrum analyzer / receiver. |
| `inspectrum` | Burst analysis and demodulation visualization. |
| `urh` | Universal Radio Hacker - sub-GHz protocol reverse engineering, OOK/FSK decoding. |
| `rfcat` | Yard Stick One / IM-Me control library. |
| `multimon-ng` | Decode POCSAG, FLEX, AFSK, DTMF, AX.25 from audio streams. |
| `kalibrate-hackrf` | GSM-based clock calibration for HackRF (build from source). |

### 13.4 Reverse Engineering & Firmware

| Tool | Purpose |
| :--- | :--- |
| `binwalk` | Firmware signature scanning and extraction. |
| `unblob` | Modern firmware unpacker - generally faster and more accurate than binwalk. |
| `radare2` | Reverse engineering framework - disassembly, debugging, patching. |
| `cutter` | GUI for radare2/rizin. Install: `yay -S cutter-re`. |
| `Ghidra` | NSA's reverse engineering suite with decompiler. Needs JDK 17+. |
| `qemu-user-static` | Run foreign-architecture binaries (MIPS/ARM firmware on x86). |
| `squashfs-tools` | Mount and extract SquashFS filesystems (common in router firmware). |
| `cpio` / `cabextract` | Extract initramfs and Microsoft cabinet archives. |

### 13.5 Logic Analysis & Protocol Decoding

| Tool | Purpose |
| :--- | :--- |
| `sigrok-cli` | CLI for logic analyzers - Saleae clones, FX2, DSLogic, etc. |
| `pulseview` | GUI sigrok front-end with protocol decoders (I²C, SPI, UART, 1-Wire, CAN, etc.). |
| `wireshark` / `tshark` | Network packet analysis. Also reads Ubertooth and SDR captures. |
| `tcpdump` | CLI packet capture. |

### 13.6 Bluetooth / RF Sniffing

| Tool | Purpose |
| :--- | :--- |
| `ubertooth` | Ubertooth One BT classic / BLE sniffing (`ubertooth-rx`, `ubertooth-btle`). Install: `yay -S ubertooth`. |
| `bluez` / `bluez-utils` | Linux Bluetooth stack - `bluetoothctl`, `hcitool`, `gatttool`. |

### 13.7 Mesh Networking (LoRa / Reticulum)

| Tool | Purpose |
| :--- | :--- |
| `rns` | Reticulum Network Stack - `rnsd`, `rnsh`, `rnstatus`, `rnodeconf`. |
| `nomadnet` | Reticulum chat / pages / files application. |
| `lxmf` | Lightweight Extensible Messaging Format library. |
| `meshtastic` | Meshtastic CLI - flash, configure, message LoRa nodes. |

### 13.8 Quality-of-Life Shell Tools

| Tool | Purpose |
| :--- | :--- |
| `ripgrep` (`rg`) | Fast recursive grep. |
| `fd` | Fast user-friendly `find` replacement. (Package: `fd`) |
| `fzf` | Fuzzy finder - fuzzy history search, file picker. |
| `bat` | `cat` with syntax highlighting and git integration. |
| `eza` | Modern `ls` replacement. |
| `zoxide` | Smarter `cd` that learns from your habits. |
| `direnv` | Per-directory environment variables. |
| `github-cli` | GitHub CLI - issues, PRs, repo management. |
| `pandoc` | Convert between markup formats (Markdown ↔ DOCX ↔ PDF ↔ HTML). |

---

## 14. Arch Daily Workflow Cheats

| Task | Command |
| :--- | :--- |
| Full system update | `sudo pacman -Syu` |
| Update incl. AUR | `yay -Syu` or `paru -Syu` |
| Check for orphans | `pacman -Qdt` |
| Remove all orphans | `sudo pacman -Rns $(pacman -Qdtq)` |
| Find `.pacnew` configs to merge | `sudo find /etc -name "*.pacnew" -o -name "*.pacsave" 2>/dev/null` |
| List AUR-installed packages | `pacman -Qm` |
| Which package owns a file | `pacman -Qo /path/to/file` |
| Check for failed services | `systemctl --failed` |
| View boot logs | `sudo journalctl -b` |
| Trim journal to 500 MB | `sudo journalctl --vacuum-size=500M` |
| Rebuild DKMS modules | `sudo dkms autoinstall` |
| Regenerate initramfs | `sudo mkinitcpio -P` |
| Open ArchWiki quickly | `xdg-open "https://wiki.archlinux.org/title/<topic>"` |
| Show package info | `pacman -Si <pkg>` (repo) / `pacman -Qi <pkg>` (installed) |

### Arch Maintenance Checklist (Run Periodically)

```bash
# 1. Update everything
sudo pacman -Syu
yay -Syu --devel        # Also update AUR git-tracking packages

# 2. Remove orphans
sudo pacman -Rns $(pacman -Qdtq)

# 3. Clean cache (keep last 3 versions per package)
sudo paccache -r

# 4. Merge .pacnew config files
sudo find /etc -name "*.pacnew" -o -name "*.pacsave" 2>/dev/null

# 5. Check for failed services
systemctl --failed

# 6. Trim systemd journal
sudo journalctl --vacuum-size=500M
```

---

## 15. OSINT (Open Source Intelligence)

Quick-reference for Linux-based OSINT tooling. For full methodology, workflows, and tool documentation see [`OSINT/OSINT_GUIDE.md`](../OSINT/OSINT_GUIDE.md) and [`OSINT/OSINT_CHEATSHEET.md`](../OSINT/OSINT_CHEATSHEET.md).

> **OPSEC**: Always operate through a VPN or Tor during OSINT work. Use dedicated VMs or burner accounts - never your personal identity.

---

### 15.1 Phase 1 - Identity & Social Hunting

*Start when you have a username, real name, or email address.*

| Tool             | Command                                  | Purpose                                            |
| ---------------- | ---------------------------------------- | -------------------------------------------------- |
| `sherlock`       | `sherlock <username>`                    | Username search across 400+ social platforms.      |
| `maigret`        | `maigret <username>`                     | Advanced username enum with extra data extraction. |
| `holehe`         | `holehe <email>`                         | Checks which services an email is registered on.   |
| `h8mail`         | `h8mail -t <email>`                      | Breach hunting - finds passwords linked to email.  |
| `theHarvester`   | `theHarvester -d <domain> -b google`     | Scrapes emails, names, subdomains from search engines. |

---

### 15.2 Phase 2 - Infrastructure & Domain Recon

*Start when you have a domain, IP, or URL.*

| Tool          | Command                            | Purpose                                                   |
| ------------- | ---------------------------------- | --------------------------------------------------------- |
| `amass`       | `amass enum -d <domain>`           | Deep DNS enumeration and subdomain mapping.               |
| `amass`       | `amass enum -passive -d <domain>`  | Passive-only mode (no active probing).                    |
| `subfinder`   | `subfinder -d <domain>`            | Fast subdomain discovery from passive sources.            |
| `photon`      | `python photon.py -u <url> -l 3`   | Crawls for endpoints, keys, emails, JS files.             |
| `whatweb`     | `whatweb <target>`                 | Fingerprint web technologies and CMS.                     |
| `whois`       | `whois <domain>`                   | Registrar, owner, nameserver lookup.                      |
| `dig`         | `dig <domain> ANY`                 | DNS records - A, MX, NS, TXT, SOA.                        |
| `shodan`      | `shodan host <IP>`                 | Open ports and running services on a target IP.           |

**Google Dorking Quick Reference:**
```bash
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
"@target.com" site:pastebin.com
site:*.target.com -www
```

---

### 15.3 Phase 3 - Communication Intelligence

*Start when you have a phone number.*

| Tool            | Command                           | Purpose                                      |
| --------------- | --------------------------------- | -------------------------------------------- |
| `phoneinfoga`   | `phoneinfoga scan -n +1XXXXXXXXXX` | Carrier lookup, number validation, OSINT.   |

---

### 15.4 Phase 4 - Analysis & Automation

*Automate collection and visualize relationships.*

| Tool         | Command / Usage                  | Purpose                                                    |
| ------------ | -------------------------------- | ---------------------------------------------------------- |
| `spiderfoot` | `spiderfoot -s <target>`         | Runs 100+ automated modules against a single target.       |
| `recon-ng`   | `recon-ng` (interactive)         | Framework with workspace management and module marketplace. |
| Maltego      | GUI - drag-and-drop              | Visual link analysis and entity relationship mapping.      |

**Recon-ng Quick Start:**
```bash
recon-ng
[recon-ng][default] > workspaces create <case_name>
[recon-ng][case_name] > marketplace install all
[recon-ng][case_name] > modules search
```

---

### 15.5 File & Metadata Analysis

| Command                                              | Purpose                                         |
| ---------------------------------------------------- | ----------------------------------------------- |
| `exiftool image.jpg`                                 | Extract EXIF metadata (GPS, timestamps, device). |
| `exiftool -gpslatitude -gpslongitude image.jpg`      | Pull GPS coords only.                           |
| `metagoofil -d <domain> -t pdf,doc -l 100 -o output` | Harvest metadata from public documents.         |
| `grep -r "regex" ./raw_data/`                        | Search collected data for patterns.             |
| `strings file.bin \| grep -i "http"`                 | Pull URLs/strings from binary files.            |

---

### 15.6 OSINT Tool Installation on Arch (Quick Setup)

**pacman/AUR installs:**
```bash
yay -S sherlock-git amass subfinder
sudo pacman -S whois bind-tools
```

**pip/pipx installs:**
```bash
pipx install maigret
pip3 install h8mail holehe
```

**Git-based installs:**
```bash
mkdir -p ~/osint-tools && cd ~/osint-tools

git clone https://github.com/laramies/theHarvester && \
  cd theHarvester && pip3 install -r requirements.txt && cd ..

git clone https://github.com/smicallef/spiderfoot && \
  cd spiderfoot && pip3 install -r requirements.txt && cd ..

git clone https://github.com/s0md3v/Photon && \
  cd Photon && pip3 install -r requirements.txt && cd ..
```

**Go-based installs:**
```bash
go install -v github.com/owasp-amass/amass/v4/...@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest
```

---

### 15.7 OSINT Reference - Key Web Services

| Service                  | URL                          | Use Case                                  |
| ------------------------ | ---------------------------- | ----------------------------------------- |
| Shodan                   | https://shodan.io            | Internet-connected device search          |
| Censys                   | https://censys.com            | Internet-wide scanning and certificate data|
| Have I Been Pwned        | https://haveibeenpwned.com   | Email breach notification                 |
| Hunter.io                | https://hunter.io            | Email finder and domain email patterns    |
| GreyNoise                | https://greynoise.io         | Background noise / IP reputation          |
| OSINT Framework          | https://osintframework.com   | Tool directory organized by target type   |
| Wayback Machine          | https://archive.org          | Historical snapshots of web pages         |
| Archive.today            | https://archive.is           | On-demand page archiving                  |
| IntelX                   | https://intelx.io            | Breach data and dark web search           |
| VirusTotal               | https://virustotal.com       | IOC enrichment - IPs, domains, hashes     |

---

### 15.8 OSINT OPSEC Checklist

```
✅ Route all traffic through VPN or Tor before investigating
✅ Use a dedicated OSINT VM (Tsurugi, or DIY Arch/Kali)
✅ Never use personal accounts - create isolated sock puppet personas
✅ Use burner email (ProtonMail/Tutanota) and virtual phone numbers
✅ Screenshot and archive evidence as you go (archive.is, Wayback)
✅ Log all commands, queries, and sources
✅ Cross-reference findings from at least two independent sources
✅ Respect ToS - unauthorized scraping can have legal consequences
```

---

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These tools are for **authorized security testing only**. Unauthorized access to networks is illegal. Always:
- Get written permission before testing
- Only test networks you own or have explicit authorization to test
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Use for educational purposes in controlled environments

**Legal Use Cases:**
- Penetration testing with client authorization
- Security research in isolated lab environments
- Testing your own network security
- Educational purposes with proper supervision
- CTF (Capture The Flag) competitions

---

## Related Files
- [LinuxCheatSheet.md](LinuxCheatSheet.md) - Debian/apt + Arch/pacman combined reference; WSL2 section; fresh-install one-liners
- [blackarch.md](blackarch.md) - BlackArch repository installation, tool categories, and keyring bootstrap
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [python.md](python.md) - Python scripting for security: socket programming, Scapy, ctypes/WinAPI automation
- [wireshark.md](wireshark.md) - Wireshark filter reference for the network traffic you'll be capturing on Linux
- [../HardwareHacking/Chapter2.md](../HardwareHacking/Chapter2.md) - Hardware interface fundamentals (UART, SPI, I2C, JTAG) accessed via Linux serial tools
- [../Scripts/pnwc_install_tools.sh](../Scripts/pnwc_install_tools.sh) - Automated cybersecurity tool installer for Arch/Manjaro (pacman/BlackArch repo)

*Last Updated: 07-09-2026*
