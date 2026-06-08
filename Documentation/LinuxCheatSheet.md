# 🐧 Linux Command Cheat Sheet and Reference

This document serves as a quick reference for common system administration, networking, security auditing, and hardware hacking commands on Debian/Ubuntu-based systems. It covers both **bare-metal/VM Linux** and **WSL2 (Windows Subsystem for Linux)** environments, including the differences between them.

---
## Arch Linux Quick Refrence:
[Manjaro](https://manjaro.org/) Arch is based on [Arch](https://archlinux.org/) Linux, meaning [`apt`](https://linuxize.com/post/how-to-use-apt-command/) is replaced by [`pacman`](https://wiki.archlinux.org/title/Pacman) (standard repositories) and [`pamac`](https://github.com/manjaro/pamac) (Manjaro's native package manager with [Arch User Repository / AUR support](https://aur.archlinux.org/)). Arch's killer feature is the AUR or the Arch User Repository. Instead of hunting down PPAs, users can use an [AUR helper](https://wiki.archlinux.org/title/AUR_helpers) (like Manjaro's pamac, or terminal tools like [yay](https://aur.archlinux.org/packages/yay) and [paru](https://github.com/Morganamilo/paru) to automatically compile and install virtually any Linux software in existence directly from source scripts!

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -Syu` | **System Update** | Synchronizes repositories and updates all installed packages. Always do this before testing. |
| `sudo pacman -S [pkg]` | **Install Package** | Basic command to install a software package from the official Manjaro repos. |
| `sudo pacman -Rns [pkg]` | **Remove Package Cleanly** | Removes the package, its configuration files, and any unneeded dependencies. |
| `pacman -Qdt` | **List Orphans** | Lists packages installed as dependencies that are no longer needed. |
| `sudo pacman -Sc` | **Clean Cache** | Clears out the local cache of downloaded package files. |
| `pamac build [pkg]` | **Install from AUR** | Builds and installs a community package from the Arch User Repository (e.g., proprietary benchmarks). |

---

# Debian Based Linux OS Refrence:

Debian maintains massive, heavily vetted official [repositories](https://github.com/InfoSecWarrior/Linux-Essentials/blob/main/Package-Management/Understanding-Repositories.md). If a piece of software isn't in the official repos (short for repositories), users typically add third-party repositories or PPAs [(Personal Package Archives)](https://documentation.ubuntu.com/launchpad/user/reference/packaging/ppas/ppa/). Debian Linux uses [`apt`](https://linuxize.com/post/how-to-use-apt-command/) for it's package installation and management. For a graphical interface, users can also use the [Synaptic Package Manager](https://www.nongnu.org/synaptic/) to easily find and install applications on their system.

## 1. SSH and File Permissions

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `ssh-keygen -R 192.168.0.1` | **Remove SSH Key** | Removes the host key for the specified IP from your `known_hosts` file. Use this if the remote server key changes. |
| `sudo chmod u+x my_script.sh` | **Allow Execution** | Adds the **e**xecute permission (`+x`) for the **u**ser (`u+`) who owns the file, making a script runnable. |
| `sudo chmod 644` | **File Permissions** | Owner can read/write; Group/Others can only read (standard file permission). |
| `sudo chmod 755` | **Script/Directory Permissions** | Owner can read/write/execute; Group/Others can read/execute (standard directory/script permission). |

---

## 2. Package Management (`apt`) Repairs

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo apt --fix-broken install` | **Fix Broken Dependencies** | Attempts to correct a system where packages have unmet dependencies. |
| `sudo apt remove [package_name]` | **Remove Package** | Basic command to uninstall a specified package (requires a package name). |
| `sudo apt autoremove -y` | **Remove Unused Packages** | Removes packages that were installed as dependencies but are no longer required. |
| `sudo apt clean` | **Clean Package Cache** | Clears out the local repository of retrieved package files. |

---

## 3. Diagnostics and System Info

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `ls -la /usr/folder1/folder2/` | **Check Files/Folders** | **L**i**s**ts all (`-a`) files in the path with long format details (`-l`). |
| `lsblk` | **List Disks** | Lists all block devices (drives and partitions) on the system. |
| `lsusb` | **List USB Devices** | Lists USB devices connected to the system. |
| `lspci` | **List PCI Devices** | Lists PCI buses and devices. |
| `lshw` | **Hardware Info** | Lists detailed hardware configuration of the machine. |
| `dmesg \| tail -50` | **Kernel Messages** | Shows the last 50 kernel ring buffer messages (great for USB/hardware issues). |
| `free -h` | **Memory Usage** | Displays free, used, and total system memory and swap space in a **h**uman-readable format. |
| `sudo iftop` | **Network Traffic (General)** | Displays network bandwidth usage on an interface in real-time. |
| `sudo nethogs` | **Network Traffic (Per Process)** | Displays which process/program is using the most network bandwidth. |
| `ncdu` | **Disk Usage** | An interactive ncurses utility for visualizing disk space usage. |
| `htop` | **Process Viewer** | An interactive, improved version of the `top` command for monitoring processes and resources. |
| `btop` | **Modern Monitor** | A feature-rich, visually appealing resource monitor. |

---

## 4. Storage and File System Management

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo mount -t exfat /dev/sdXN /mnt/your_mount_point` | **Mount ExFAT Drive** | Mounts an ExFAT-formatted drive to the specified mount point. Replace `sdXN` with actual device (e.g., `sdb1`). |
| `sudo umount /mnt/your_mount_point` | **Unmount Drive** | Safely unmounts the drive at the specified mount point. |
| `lsblk -f` | **Filesystem Info** | Lists block devices with filesystem type, label, and UUID. |
| `sudo blkid` | **Get Drive UUIDs** | Locates and prints block device attributes (used for `/etc/fstab` entries). |

---

## 5. Network Configuration and Scanning

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `ip a` | **View IP Addresses** | Displays address information for all network interfaces (modern replacement for `ifconfig`). |
| `ifconfig` | **Network Config (Legacy)** | Older command to display/configure network interfaces. |
| `iw dev` | **Wireless Info** | Shows detailed information about wireless devices. |
| `sudo iwconfig` | **Wireless Config** | Displays/sets basic wireless interface parameters. |
| `sudo ip link set wlan1 down` | **Disable Interface** | Brings down the specified wireless interface. |
| `sudo ip link set wlan1 name wlan1mon` | **Rename Interface** | Renames the wireless interface (useful for monitor mode setup). |
| `airmon-ng` | **Monitor Mode** | Puts a wireless card into monitor mode for security auditing. |
| `sudo arp-scan -l` | **ARP Scan** | Scans the local network segment using ARP packets to discover active hosts. |

**ARP Scan Usage Example:**
```bash
cd /tmp/
sudo arp-scan -l
```

> **Note:** Wireless monitor mode and packet injection require **bare-metal Linux** or a passed-through USB Wi-Fi adapter — they do **not** work natively in WSL (no kernel Wi-Fi stack access).

---

## 6. Wireless Adapter (Alfa/Realtek) Setup

This covers installing the `rtl88xxau` or `rtl8812au` driver, often needed for high-power Wi-Fi adapters.

**Option 1: Apt Repository (DKMS)**
```bash
sudo apt install realtek-rtl88xxau-dkms
```

**Option 2: Compile from Source (for `rtl8812au`)**
```bash
sudo apt install git dkms build-essential
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
```

> **WSL Note:** DKMS drivers do not install into the WSL kernel. For Wi-Fi adapter work, use bare-metal Linux or boot from a Kali/Parrot live USB.

---

## 7. System Services and Control

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `systemctl reboot -i` | **Reboot System** | Initiates a system reboot. |
| `sudo systemctl [command] [service]` | **Manage Services** | Standard format to control system services (e.g., start, stop, status, enable, disable). |
| `sudo systemctl disable hciuart.service` | **Disable Bluetooth Console** | Stops the service managing serial communications for the onboard Bluetooth chip (common on Raspberry Pi). |
| `sudo systemctl disable avahi-daemon.socket avahi-daemon.service` | **Disable Avahi** | Disables the Zeroconf/mDNS daemon used for local network discovery. |
| `sudo journalctl -u [service] -f` | **Follow Service Logs** | Tail the systemd journal for a specific service in real-time. |

---

## 8. Samba (Network File Sharing)

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo apt install -y usbmount` | **Auto-Mount USB** | Installs utility to automatically mount USB drives upon insertion. |
| `sudo apt install -y samba samba-common-bin` | **Install Samba** | Installs the core components for Windows/Linux file sharing. |
| `sudo tail -f /var/log/samba/log.smbd` | **Monitor Samba Log** | Displays the log file and follows it (`-f`) for real-time troubleshooting. |
| `smbclient -L //hostname -U user` | **List Shares** | Lists available SMB shares on a remote host. |

---

## 9. Application Removal

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo apt remove -y triggerhappy dphys-swapfile plymouth` | **Remove Apps** | Uninstalls the specified packages. Often used to remove resource-intensive or unnecessary components: `triggerhappy` (hotkey daemon), `dphys-swapfile` (swap management), and `plymouth` (boot splash screen). |

---

## 10. System Stress and Temperature Monitoring

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo apt install stress-ng sysbench` | **Install Stress Tools** | Installs utilities to generate system load for testing stability. |
| `stress-ng --cpu 4 --timeout 300s` | **CPU Stress Test** | Puts a high load on 4 CPU cores for 300 seconds (5 minutes). |
| `watch -n 1 vcgencmd measure_temp` | **Monitor Temperature (Pi)** | Runs the temperature command every 1 second (`-n 1`) to monitor heat output in real-time (Raspberry Pi). |
| `sensors` | **Monitor Temperature (x86)** | Reads on-board temp sensors via `lm-sensors` (run `sudo sensors-detect` first). |

---

## 11. Fresh Install — Bare-Metal / VM / Container Linux

This section is for **standard Linux installs** — desktops, servers, VMs, LXC containers, Raspberry Pi, etc. — *not* WSL. For WSL, see Section 12.

### 11.1 Base System Tools (One-Liner)

This script installs a comprehensive suite of development, network, and security tools.

```bash
sudo apt update && sudo apt upgrade -y && \
sudo apt install -y \
linux-cpupower screen tmux git git-lfs nano vim python3 python3-pip python3-venv \
python3-requests python3-yaml python3-tk python3-psutil pipx \
wget curl jq unzip zip rsync tree expect build-essential pkg-config cmake \
dnsutils net-tools arp-scan iftop iotop lm-sensors sysstat smartmontools \
nmap mtr traceroute whois iperf3 tcpdump ncat netcat-traditional ethtool \
aircrack-ng reaver hashcat hydra netdiscover wifite \
samba cifs-utils smbclient nfs-common sshfs rclone \
vnstat glances fail2ban logrotate \
ncdu htop btop lshw lsof parted \
psmisc moreutils figlet lolcat screenfetch \
avahi-daemon
```

**Alternative minimal install for screen/tmux:**
```bash
sudo apt-get install screen tmux
```

### 11.2 Hardware Hacking & Programming Add-On (Bare-Metal)

This adds USB serial tools, microcontroller flashers, SDR utilities, reverse engineering tools, logic analyzers, and Bluetooth hardware support. Bare-metal Linux has full access to USB devices, kernel modules, and Wi-Fi monitor mode — none of the WSL workarounds in Section 12 are needed.

```bash
sudo apt update && \
sudo apt install -y \
build-essential cmake ninja-build pkg-config autoconf automake libtool \
clang gdb \
ripgrep fd-find fzf bat eza zoxide direnv \
tio minicom picocom usbutils pciutils setserial socat usbip \
avrdude dfu-util stm32flash openocd flashrom \
hackrf libhackrf-dev rtl-sdr librtlsdr-dev \
gnuradio gr-osmosdr gqrx-sdr inspectrum multimon-ng \
libfftw3-dev \
binwalk radare2 squashfs-tools cpio cabextract \
qemu-user-static binfmt-support \
sigrok-cli pulseview wireshark tshark \
ubertooth bluez bluez-tools \
xxd p7zip-full \
gh pandoc imagemagick ffmpeg
```

**Add yourself to device groups (one-time, then log out and back in):**
```bash
sudo usermod -aG plugdev,dialout,wireshark,tty,uucp $USER
```

### 11.3 Python Tools via pipx (Bare-Metal)

These tools are not in apt or are too out-of-date there. Install in user space:

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

### 11.4 Build-from-Source Tools (Bare-Metal)

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
sudo apt install -y openjdk-17-jdk
# Download latest from: https://github.com/NationalSecurityAgency/ghidra/releases
```

---

## 12. Fresh Install — WSL2 (Windows Subsystem for Linux)

WSL2 has some critical differences from bare-metal Linux that affect hardware hacking workflows. This section covers the Windows-side prerequisites, WSL configuration changes, and the corrected install commands that account for what does and doesn't work under WSL.

### 12.1 What's Different Under WSL

| Capability | Bare-Metal Linux | WSL2 |
| :--- | :--- | :--- |
| USB device access | Native | Requires `usbipd-win` passthrough |
| Wi-Fi monitor mode / injection | ✅ Works | ❌ Not supported |
| Bluetooth (built-in) | ✅ Works | ❌ Use Ubertooth via usbipd |
| `linux-cpupower` | ✅ Works | ❌ No CPU freq interface in WSL kernel |
| DKMS Wi-Fi drivers (rtl8812au) | ✅ Works | ❌ WSL kernel is custom |
| systemd | ✅ Default | ⚠️ Must enable in `/etc/wsl.conf` |
| GUI apps (PulseView, Gqrx) | ✅ Native | ✅ Via WSLg (Win11/recent Win10) |
| GPU passthrough (hashcat) | ✅ Native | ⚠️ Limited — use Windows-native hashcat |

### 12.2 Windows-Side Prerequisites

**Install `usbipd-win` from an admin PowerShell:**
```powershell
winget install --interactive --exact dorssel.usbipd-win
```

This is **non-negotiable** for hardware work. Without it, no Flipper, HackRF, RTL-SDR, Ubertooth, ESP board, FTDI adapter, or J-Link can be seen by WSL.

**USB passthrough workflow (run in PowerShell as admin):**
```powershell
usbipd list
usbipd bind --busid <BUSID>          # one-time per device
usbipd attach --wsl --busid <BUSID>  # each time you want to use it
usbipd detach --busid <BUSID>        # to release
```

### 12.3 Enable systemd in WSL

systemd is required for `udev` rules to fire properly — without it, HackRF, Ubertooth, RTL-SDR, and most USB tools demand `sudo` for everything.

```bash
sudo tee /etc/wsl.conf > /dev/null <<'EOF'
[boot]
systemd=true

[interop]
appendWindowsPath=true
EOF
```

Then from PowerShell: `wsl --shutdown`, and reopen your WSL terminal.

### 12.4 Base System Tools for WSL (One-Liner)

This is the bare-metal one-liner from Section 11.1, **adjusted for WSL**:
- `linux-cpupower` removed (no kernel support)
- `wifite` removed (no Wi-Fi monitor mode)

```bash
sudo apt update && sudo apt upgrade -y && \
sudo apt install -y \
screen tmux git git-lfs nano vim python3 python3-pip python3-venv \
python3-requests python3-yaml python3-tk python3-psutil pipx \
wget curl jq unzip zip rsync tree expect build-essential pkg-config cmake \
dnsutils net-tools arp-scan iftop iotop sysstat smartmontools \
nmap mtr traceroute whois iperf3 tcpdump ncat netcat-traditional ethtool \
aircrack-ng reaver hashcat hydra netdiscover \
samba cifs-utils smbclient nfs-common sshfs rclone \
vnstat glances fail2ban logrotate \
ncdu htop btop lshw lsof parted \
psmisc moreutils figlet lolcat screenfetch
```

> **Note:** `aircrack-ng` and `hashcat` install fine and are useful for working with capture files (`.pcap`, `.hccapx`) — they just can't capture live traffic without a passed-through Wi-Fi adapter.

### 12.5 Hardware Hacking & Programming Add-On (WSL)

This is the bare-metal hardware add-on from Section 11.2, **adjusted for WSL**:
- `usbip` replaced with `linux-tools-generic` (the userspace client now ships there)
- `rfcat` and `kalibrate-hackrf` moved to pipx/source builds (not in apt)

```bash
sudo apt update && \
sudo apt install -y \
build-essential cmake ninja-build pkg-config autoconf automake libtool \
clang gdb \
ripgrep fd-find fzf bat eza zoxide direnv \
tio minicom picocom usbutils pciutils setserial socat \
avrdude dfu-util stm32flash openocd flashrom \
hackrf libhackrf-dev rtl-sdr librtlsdr-dev \
gnuradio gr-osmosdr gqrx-sdr inspectrum multimon-ng \
libfftw3-dev \
binwalk radare2 squashfs-tools cpio cabextract \
qemu-user-static binfmt-support \
sigrok-cli pulseview wireshark tshark \
ubertooth bluez bluez-tools \
xxd p7zip-full \
gh pandoc imagemagick ffmpeg \
linux-tools-generic hwdata
```

**Add yourself to device groups:**
```bash
sudo usermod -aG plugdev,dialout,wireshark,tty,uucp $USER
```

### 12.6 Register the WSL `usbip` Client

The `usbip` binary lives in a kernel-version-specific path. Register it as an alternative:

```bash
sudo update-alternatives --install /usr/local/bin/usbip usbip \
  $(ls /usr/lib/linux-tools/*/usbip | tail -n1) 20
```

> Most of the time you won't need this — `usbipd attach --wsl` from the Windows side handles the Linux end automatically. Only needed if attaching to a remote `usbipd` host manually.

### 12.7 Python Tools via pipx (WSL)

Same as bare-metal — these are user-space and work identically:

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

### 12.8 Build-from-Source for WSL

**`kalibrate-hackrf`** (not packaged):
```bash
mkdir -p ~/tools && cd ~/tools
git clone https://github.com/scateu/kalibrate-hackrf
cd kalibrate-hackrf && ./bootstrap && ./configure && make && sudo make install
```

`arduino-cli` and `Ghidra` install identically to the bare-metal instructions in Section 11.4.

---

## 13. Hardware Hacking Toolkit Reference

Quick descriptions of what each tool does, organized by category.

### 13.1 Serial / USB Console

| Tool | Purpose |
| :--- | :--- |
| `tio` | Modern serial terminal — autoconnect, logging, hex mode, dead simple. **Recommended default.** |
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
| `arduino-cli` | Official Arduino CLI — sketches, libraries, board management. |
| `esptool.py` | ESP32 / ESP8266 flashing, fuse reading, security operations. |
| `avrdude` | AVR / ATmega / ATtiny flashing with USBasp, AVRISP, Arduino-as-ISP. |
| `dfu-util` | USB DFU mode flashing (STM32, many bootloaders). |
| `stm32flash` | STM32 UART/I2C bootloader flashing. |
| `openocd` | JTAG / SWD debugging — works with ST-Link, J-Link, CMSIS-DAP, FT2232. |
| `flashrom` | SPI flash chip read/write — BIOS dumps, router firmware extraction (CH341A, Bus Pirate, FT2232). |
| `picotool` | RP2040 (Pico) inspection and flashing utility. |

### 13.3 SDR / RF

| Tool | Purpose |
| :--- | :--- |
| `hackrf` | HackRF One control — `hackrf_info`, `hackrf_transfer`, `hackrf_sweep`. |
| `rtl-sdr` | RTL2832U-based dongles — `rtl_sdr`, `rtl_fm`, `rtl_433`, `rtl_tcp`. |
| `gnuradio` | Visual signal processing flowgraphs (GNU Radio Companion). |
| `gr-osmosdr` | GNU Radio source/sink for HackRF, RTL-SDR, BladeRF, etc. |
| `gqrx-sdr` | GUI spectrum analyzer / receiver. Needs WSLg under WSL. |
| `inspectrum` | Burst analysis and demodulation visualization. |
| `urh` | Universal Radio Hacker — sub-GHz protocol reverse engineering, OOK/FSK decoding. |
| `rfcat` | Yard Stick One / IM-Me control library. |
| `multimon-ng` | Decode POCSAG, FLEX, AFSK, DTMF, AX.25 from audio streams. |
| `kalibrate-hackrf` | GSM-based clock calibration for HackRF. |

### 13.4 Reverse Engineering & Firmware

| Tool | Purpose |
| :--- | :--- |
| `binwalk` | Firmware signature scanning and extraction. |
| `unblob` | Modern firmware unpacker — generally faster and more accurate than binwalk. |
| `radare2` | Reverse engineering framework — disassembly, debugging, patching. |
| `cutter` | GUI for radare2/rizin (needs WSLg under WSL). |
| `Ghidra` | NSA's reverse engineering suite with decompiler. Needs JDK 17+. |
| `qemu-user-static` | Run foreign-architecture binaries directly (MIPS/ARM router firmware on x86). |
| `squashfs-tools` | Mount and extract SquashFS filesystems (common in router firmware). |
| `cpio` / `cabextract` | Extract initramfs and Microsoft cabinet archives. |

### 13.5 Logic Analysis & Protocol Decoding

| Tool | Purpose |
| :--- | :--- |
| `sigrok-cli` | CLI for logic analyzers — Saleae clones, FX2, DSLogic, etc. |
| `pulseview` | GUI sigrok front-end with protocol decoders (I²C, SPI, UART, 1-Wire, CAN, etc.). |
| `wireshark` / `tshark` | Network packet analysis. Also reads Ubertooth and SDR captures. |
| `tcpdump` | CLI packet capture. |

### 13.6 Bluetooth / RF Sniffing

| Tool | Purpose |
| :--- | :--- |
| `ubertooth` | Ubertooth One BT classic / BLE sniffing (`ubertooth-rx`, `ubertooth-btle`). |
| `bluez` / `bluez-tools` | Linux Bluetooth stack — `bluetoothctl`, `hcitool`, `gatttool`. |

### 13.7 Mesh Networking (LoRa / Reticulum)

| Tool | Purpose |
| :--- | :--- |
| `rns` | Reticulum Network Stack — `rnsd`, `rnsh`, `rnstatus`, `rnodeconf`. |
| `nomadnet` | Reticulum chat / pages / files application. |
| `lxmf` | Lightweight Extensible Messaging Format library. |
| `meshtastic` | Meshtastic CLI — flash, configure, message LoRa nodes. |

### 13.8 Quality-of-Life Shell Tools

| Tool | Purpose |
| :--- | :--- |
| `ripgrep` (`rg`) | Fast recursive grep. |
| `fd-find` (`fd`) | Fast user-friendly `find` replacement. |
| `fzf` | Fuzzy finder — fuzzy history search, file picker, command palette. |
| `bat` | `cat` with syntax highlighting and git integration. |
| `eza` | Modern `ls` replacement (Ubuntu 24.04+; not in 22.04 main). |
| `zoxide` | Smarter `cd` that learns from your habits. |
| `direnv` | Per-directory environment variables. |
| `gh` | GitHub CLI — issues, PRs, repo management. |
| `pandoc` | Convert between markup formats (Markdown ↔ DOCX ↔ PDF ↔ HTML). |

---

## 14. WSL-Specific Daily Workflow Cheats

| Task | Command |
| :--- | :--- |
| Shutdown WSL completely | `wsl --shutdown` (from PowerShell) |
| List running distros | `wsl -l -v` (from PowerShell) |
| Open Windows Explorer at current path | `explorer.exe .` |
| Open VSCode at current path | `code .` |
| Copy to Windows clipboard | `cat file.txt \| clip.exe` |
| Paste from Windows clipboard | `powershell.exe Get-Clipboard` |
| Access Windows files | `/mnt/c/Users/<user>/...` |
| List USB devices ready to attach | `usbipd list` (from PowerShell) |
| Attach USB to WSL | `usbipd attach --wsl --busid X-Y` (from PowerShell admin) |

---

## 15. OSINT (Open Source Intelligence)

[#15-osint-open-source-intelligence](#15-osint-open-source-intelligence)

Quick-reference for Linux-based OSINT tooling. For full methodology, workflows, and tool documentation see [`OSINT/OSINT_GUIDE.md`](../OSINT/OSINT_GUIDE.md) and [`OSINT/OSINT_CHEATSHEET.md`](../OSINT/OSINT_CHEATSHEET.md).

> **OPSEC**: Always operate through a VPN or Tor during OSINT work. Use dedicated VMs or burner accounts — never your personal identity.

---

### 15.1 Phase 1 — Identity & Social Hunting

[#151-phase-1--identity--social-hunting](#151-phase-1--identity--social-hunting)

*Start when you have a username, real name, or email address.*

| Tool             | Command                                  | Purpose                                            |
| ---------------- | ---------------------------------------- | -------------------------------------------------- |
| `sherlock`       | `sherlock <username>`                    | Username search across 400+ social platforms.      |
| `maigret`        | `maigret <username>`                     | Advanced username enum with extra data extraction. |
| `holehe`         | `holehe <email>`                         | Checks which services an email is registered on.   |
| `h8mail`         | `h8mail -t <email>`                      | Breach hunting — finds passwords linked to email.  |
| `theHarvester`   | `theHarvester -d <domain> -b google`     | Scrapes emails, names, subdomains from search engines. |

---

### 15.2 Phase 2 — Infrastructure & Domain Recon

[#152-phase-2--infrastructure--domain-recon](#152-phase-2--infrastructure--domain-recon)

*Start when you have a domain, IP, or URL.*

| Tool          | Command                            | Purpose                                                   |
| ------------- | ---------------------------------- | --------------------------------------------------------- |
| `amass`       | `amass enum -d <domain>`           | Deep DNS enumeration and subdomain mapping.               |
| `amass`       | `amass enum -passive -d <domain>`  | Passive-only mode (no active probing).                    |
| `subfinder`   | `subfinder -d <domain>`            | Fast subdomain discovery from passive sources.            |
| `photon`      | `python photon.py -u <url> -l 3`   | Crawls for endpoints, keys, emails, JS files.             |
| `whatweb`     | `whatweb <target>`                 | Fingerprint web technologies and CMS.                     |
| `whois`       | `whois <domain>`                   | Registrar, owner, nameserver lookup.                      |
| `dig`         | `dig <domain> ANY`                 | DNS records — A, MX, NS, TXT, SOA.                        |
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

### 15.3 Phase 3 — Communication Intelligence

[#153-phase-3--communication-intelligence](#153-phase-3--communication-intelligence)

*Start when you have a phone number.*

| Tool            | Command                           | Purpose                                      |
| --------------- | --------------------------------- | -------------------------------------------- |
| `phoneinfoga`   | `phoneinfoga scan -n +1XXXXXXXXXX` | Carrier lookup, number validation, OSINT.    |

---

### 15.4 Phase 4 — Analysis & Automation

[#154-phase-4--analysis--automation](#154-phase-4--analysis--automation)

*Automate collection and visualize relationships.*

| Tool         | Command / Usage                  | Purpose                                                    |
| ------------ | -------------------------------- | ---------------------------------------------------------- |
| `spiderfoot` | `spiderfoot -s <target>`         | Runs 100+ automated modules against a single target.       |
| `recon-ng`   | `recon-ng` (interactive)         | Framework with workspace management and module marketplace. |
| Maltego      | GUI — drag-and-drop              | Visual link analysis and entity relationship mapping.      |

**Recon-ng Quick Start:**
```bash
recon-ng
[recon-ng][default] > workspaces create <case_name>
[recon-ng][case_name] > marketplace install all
[recon-ng][case_name] > modules search
```

---

### 15.5 File & Metadata Analysis

[#155-file--metadata-analysis](#155-file--metadata-analysis)

| Command                                              | Purpose                                         |
| ---------------------------------------------------- | ----------------------------------------------- |
| `exiftool image.jpg`                                 | Extract EXIF metadata (GPS, timestamps, device). |
| `exiftool -gpslatitude -gpslongitude image.jpg`      | Pull GPS coords only.                           |
| `metagoofil -d <domain> -t pdf,doc -l 100 -o output` | Harvest metadata from public documents.         |
| `grep -r "regex" ./raw_data/`                        | Search collected data for patterns.             |
| `strings file.bin | grep -i "http"`                  | Pull URLs/strings from binary files.            |

---

### 15.6 OSINT Tool Installation (Quick Setup)

[#156-osint-tool-installation-quick-setup](#156-osint-tool-installation-quick-setup)

**pip/pipx installs:**
```bash
pipx install sherlock-project
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
go install -v github.com/owasp-amass/amass/v3/...@master
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

### 15.7 OSINT Reference — Key Web Services

[#157-osint-reference--key-web-services](#157-osint-reference--key-web-services)

| Service                  | URL                          | Use Case                                  |
| ------------------------ | ---------------------------- | ----------------------------------------- |
| Shodan                   | https://shodan.io            | Internet-connected device search          |
| Censys                   | https://censys.io            | Internet-wide scanning and certificate data|
| Have I Been Pwned        | https://haveibeenpwned.com   | Email breach notification                 |
| Hunter.io                | https://hunter.io            | Email finder and domain email patterns    |
| GreyNoise                | https://greynoise.io         | Background noise / IP reputation          |
| OSINT Framework          | https://osintframework.com   | Tool directory organized by target type   |
| Wayback Machine          | https://archive.org          | Historical snapshots of web pages         |
| Archive.today            | https://archive.is           | On-demand page archiving                  |
| IntelX                   | https://intelx.io            | Breach data and dark web search           |
| VirusTotal               | https://virustotal.com       | IOC enrichment — IPs, domains, hashes     |

---

### 15.8 OSINT OPSEC Checklist

[#158-osint-opsec-checklist](#158-osint-opsec-checklist)

```
✅ Route all traffic through VPN or Tor before investigating
✅ Use a dedicated OSINT VM (Tsurugi, Buscador, or DIY)
✅ Never use personal accounts — create isolated sock puppet personas
✅ Use burner email (ProtonMail/Tutanota) and virtual phone numbers
✅ Screenshot and archive evidence as you go (archive.is, Wayback)
✅ Log all commands, queries, and sources
✅ Cross-reference findings from at least two independent sources
✅ Respect ToS — unauthorized scraping can have legal consequences
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

*Last Updated: 2026-05-08*
