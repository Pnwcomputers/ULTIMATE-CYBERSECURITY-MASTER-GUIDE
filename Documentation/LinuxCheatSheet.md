# Linux Command Cheat Sheet and Reference 🛠️

This document serves as a quick reference for common system administration, networking, and security auditing commands on Debian/Ubuntu-based systems.

---

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

---

## 3. Diagnostics and System Info

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `ls -la /usr/folder1/folder2/` | **Check Files/Folders** | **L**i**s**ts all (`-a`) files in the path with long format details (`-l`). |
| `lsblk` | **List Disks** | Lists all block devices (drives and partitions) on the system. |
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
| `sudo arp-scan -l++` | **ARP Scan** | Scans the local network segment using ARP packets to discover active hosts. |

**ARP Scan Usage Example:**
```bash
cd /tmp/
sudo arp-scan -l++
```

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

---

## 7. System Services and Control

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `systemctl reboot -i` | **Reboot System** | Initiates a system reboot. |
| `sudo systemctl [command] [service]` | **Manage Services** | Standard format to control system services (e.g., start, stop, status, enable, disable). |
| `sudo systemctl disable hciuart.service` | **Disable Bluetooth Console** | Stops the service managing serial communications for the onboard Bluetooth chip (common on Raspberry Pi). |
| `sudo systemctl disable avahi-daemon.socket avahi-daemon.service` | **Disable Avahi** | Disables the Zeroconf/mDNS daemon used for local network discovery. |

---

## 8. Samba (Network File Sharing)

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo apt install -y usbmount` | **Auto-Mount USB** | Installs utility to automatically mount USB drives upon insertion. |
| `sudo apt install -y samba samba-common-bin` | **Install Samba** | Installs the core components for Windows/Linux file sharing. |
| `sudo tail -f /var/log/samba/log.smbd` | **Monitor Samba Log** | Displays the log file and follows it (`-f`) for real-time troubleshooting. |

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
| `watch -n 1 vcgencmd measure_temp` | **Monitor Temperature** | Runs the temperature command every 1 second (`-n 1`) to monitor heat output in real-time (Raspberry Pi). |

---

## 11. Fresh Install / Batch App Installation (One-Liner)

This script installs a comprehensive suite of development, network, and security tools.

```bash
sudo apt update && sudo apt upgrade -y && \
sudo apt install -y \
linux-cpupower screen tmux git git-lfs nano vim python3 python3-pip python3-venv \
python3-requests python3-yaml python3-tk python3-psutil \
wget curl jq unzip zip rsync tree expect build-essential pkg-config cmake \
dnsutils net-tools arp-scan iftop iotop lm-sensors sysstat smartmontools \
nmap mtr traceroute whois iperf3 tcpdump ncat netcat-traditional ethtool \
aircrack-ng reaver hashcat hydra netdiscover wifite screen tmux\
samba cifs-utils smbclient nfs-common sshfs rclone \
vnstat glances fail2ban logrotate \
ncdu htop btop lshw lsof parted \
psmisc moreutils figlet lolcat screenfetch \
avahi-daemon rsync
```

**Alternative minimal install for screen/tmux:**
```bash
sudo apt-get install screen tmux
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

*Last Updated: 2025-11-03*
