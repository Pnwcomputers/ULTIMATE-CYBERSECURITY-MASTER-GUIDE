# Pwnagotchi Commands and Configuration 🤖

**Reference index and audit status:** [Reviewed cheat sheets and references](./CHEATSHEET-REFERENCE-AUDIT-2026-10-31.md).

> [!WARNING]
> **Reviewed October 31, 2026.** The actively developed [jayofelony fork](https://github.com/jayofelony/pwnagotchi/releases) has newer images than the older v2.9.5.4 example below; **v2.9.5.8** was the most recent reviewed release. Recent releases changed image support, plugin behavior and `.pcapng` storage. Consult the [maintained wiki](https://github.com/jayofelony/pwnagotchi/wiki) for the exact image and config on your hardware, verify the checksum where published, **back up data** and do not assume old paths or plugins work unchanged. This is **not a passive-only device by default**: some modes can transmit/deauthenticate; use explicitly authorized passive modes only where required.

## 🎯 Purpose
Quick-reference for deploying, configuring, and operating a Pwnagotchi - an autonomous AI-driven WiFi handshake capture device built on Raspberry Pi Zero W/2W that can capture WPA/WPA2 traffic using bettercap; features/modes may include **active packet injection** and require authorization.

## ⚙️ Function
Covers installation and flashing, essential config.toml settings, service management, plugin configuration, handshake processing for offline cracking with Hashcat, performance tuning, and troubleshooting. Focuses on the field-capture side of the passive WiFi audit workflow; pair with hcxtoolshashcat.md for the conversion and cracking steps.

## 🏆 Goal
Deploy a set-and-forget passive handshake capture device that autonomously improves its channel-selection strategy via reinforcement learning, outputting .pcap files ready for hcxpcapngtool conversion and Hashcat cracking.

## 📋 When to Use
- Long-duration authorized observation **only after disabling active transmit/deauth features and validating the firmware mode**
- Authorized wardriving and site surveys requiring hands-free capture
- Lab exercises demonstrating WPA2 handshake exposure
- Supplementing active tools (Marauder, Evil-M5) with continuous passive capture in the background



### Basic Setup

> [!CAUTION]
> **Flashing erases the selected storage device**. The commands below are intentionally illustrative because filenames, architecture (32/64-bit), boot paths, and default accounts have changed. Never flash `/dev/sdX` as a literal or assume `pi/raspberry` remains appropriate.

**Install Pwnagotchi (on Raspberry Pi Zero W/2W)**
```bash
# The jayofelony fork is the actively maintained release (evilsocket's original is archived)
# Releases ship as pwnagotchi-32bit-<version>.img.xz / pwnagotchi-64bit-<version>.img.xz -
# pick the correct architecture for your Pi. wget can't glob a wildcard against a remote
# URL, so grab the exact filename from the releases page (or the GitHub API) first:
# curl -s https://api.github.com/repos/jayofelony/pwnagotchi/releases/latest | grep browser_download_url
# Legacy v2.9.5.4 example only: do NOT blindly flash this.
# Select an exact compatible 64-bit image from the upstream release assets.
# Confirm SHA-256 and the destination with: lsblk -o NAME,SIZE,MODEL,TRAN
# Only after verifying both, use an explicit image name in the dd example below.
# Decompress the exact reviewed image; prefer xz -dk <release-image>.img.xz
# DESTRUCTIVE: flashing overwrites /dev/sdX; replace only after checking lsblk
# sudo dd if=<reviewed-image>.img of=/dev/<verified-device> bs=4M status=progress conv=fsync
```

**Initial Configuration**
```bash
# SSH into pwnagotchi (USB connection)
ssh pi@10.0.0.2
# Never assume default credentials: consult the selected release image wizard,
# change default passwords immediately and avoid exposing the Web UI to the LAN.

# Edit config file
sudo nano /etc/pwnagotchi/config.toml
```

### Essential Config.toml Settings

```toml
# Basic settings
main.name = "pwnagotchi"
main.lang = "en"
main.whitelist = []

# Display settings
ui.display.enabled = true
ui.display.type = "waveshare_2"  # or "waveshare_1", "oled", etc.

# Enable web UI only behind trusted management access
ui.web.enabled = true
ui.web.username = "your-unique-admin-name"
ui.web.password = "SET_A_LONG_UNIQUE_PASSWORD"

# Bluetooth tethering
# Bluetooth tethering changed in recent jayofelony releases; check version-specific docs.
# Legacy plugin example (do not assume this still works):
main.plugins.bt-tether.enabled = true
main.plugins.bt-tether.devices.android-phone.enabled = true
main.plugins.bt-tether.devices.android-phone.search_order = 1
main.plugins.bt-tether.devices.android-phone.mac = "AA:BB:CC:DD:EE:FF"
main.plugins.bt-tether.devices.android-phone.ip = "192.168.44.1"

# Grid connection (share handshakes)
main.plugins.grid.enabled = true
main.plugins.grid.report = true
main.plugins.grid.exclude = []
```

### System Management

**Service Control**
```bash
# Check pwnagotchi status
sudo systemctl status pwnagotchi

# Restart pwnagotchi
sudo systemctl restart pwnagotchi

# View logs
sudo journalctl -u pwnagotchi -f

# Check logs for errors
sudo tail -f /var/log/pwnagotchi.log
```

**Backup and Restore**
```bash
# Backup handshakes
rsync -avz pi@10.0.0.2:/root/handshakes/ ./pwnagotchi-backup/

# Backup configuration
scp pi@10.0.0.2:/etc/pwnagotchi/config.toml ./config-backup.toml

# Backup brain (AI data)
scp pi@10.0.0.2:/root/brain.nn ./brain-backup.nn
```

### Plugin Management

**Popular Plugins**

```bash
# Enable essential plugins in config.toml
main.plugins.auto-update.enabled = true
main.plugins.webcfg.enabled = true
main.plugins.grid.enabled = true
main.plugins.session-stats.enabled = true
main.plugins.memtemp.enabled = true
```

**Custom Plugin Installation**
```bash
# Download individual plugin .py files by raw URL (jayofelony fork is actively maintained)
# Example: download a single plugin from the jayofelony fork
cd /usr/local/share/pwnagotchi/custom-plugins/
# Do not download a moving-branch .py directly into a privileged plugin path.
# Use the maintained pwnagotchi plugin manager and review the plugin source.
# See https://github.com/jayofelony/pwnagotchi/wiki/Step-4-Customization

# Add to config.toml
main.plugins.plugin-name.enabled = true
```

### Useful Plugins

| Plugin | Purpose | Config |
| :--- | :--- | :--- |
| `bt-tether` | Bluetooth internet sharing | `main.plugins.bt-tether.enabled = true` |
| `grid` | Share handshakes with pwngrid | `main.plugins.grid.enabled = true` |
| `auto-update` | Auto update pwnagotchi | `main.plugins.auto-update.enabled = true` |
| `memtemp` | Display memory and temp | `main.plugins.memtemp.enabled = true` |
| `session-stats` | Show session statistics | `main.plugins.session-stats.enabled = true` |
| `webcfg` | Web-based configuration | `main.plugins.webcfg.enabled = true` |
| `wigle` | Upload to WiGLE database | `main.plugins.wigle.enabled = true` |
| `gps` | GPS coordinates logging | `main.plugins.gps.enabled = true` |

### Advanced Usage

**Manual Mode (for testing)**
```bash
# Run in manual mode
sudo pwnagotchi --manual --debug

# Run specific AI mode
sudo pwnagotchi --ai --debug
```

**Processing Handshakes**
```bash
# Access handshakes directory
cd /root/handshakes/

# List captured handshakes
ls -lah /home/pi/handshakes/  # recent images; check /root/handshakes/ on legacy images

# Copy handshakes to local machine
scp 'pi@10.0.0.2:/home/pi/handshakes/*.pcapng' ./handshakes/  # adjust per image

# Convert to Hashcat unified format (mode 22000 - replaces deprecated 16800/2500)
hcxpcapngtool -o hashes.hc22000 -E essid_list.txt authorized-capture.pcapng

# Crack with Hashcat (GPU-accelerated, faster than aircrack-ng's CPU cracker)
hashcat -m 22000 hashes.hc22000 /usr/share/wordlists/rockyou.txt

# Or crack directly with aircrack-ng (CPU only, slower)
aircrack-ng -w wordlist.txt handshake.pcap
```
> See [hcxtoolshashcat.md](hcxtoolshashcat.md) for the full conversion and cracking workflow.

**Update Pwnagotchi**
```bash
# Manual update
cd /usr/local/src/pwnagotchi
# Avoid git-pull + global pip installation on prebuilt images.
# Review the upstream release notes and use the fork's supported update/reflash path.
# Back up your configuration and capture evidence first.

# Or use auto-update plugin
# Enable in config.toml: main.plugins.auto-update.enabled = true
```

**Monitoring Performance**
```bash
# Check AI stats
cat /root/.pwnagotchi-auto | jq

# View epochs and training
cat /root/brain.nn

# Network interfaces
iwconfig
ifconfig
```

**Troubleshooting**
```bash
# Check for errors
sudo journalctl -u pwnagotchi --no-pager | grep -i error

# Verify display
sudo systemctl status pwnagotchi-display

# Test web UI
curl http://10.0.0.2:8080

# Reset to factory settings
# DESTRUCTIVE reset omitted; take a backup and follow the version-specific
# upstream factory-reset/reflash procedure instead.
```

### Optimization Tips

**Performance Tuning**
```bash
# Disable unnecessary services
sudo systemctl disable bluetooth  # If not using bt-tether
sudo systemctl disable avahi-daemon

# Overclock (Raspberry Pi Zero W)
sudo nano /boot/config.txt
# Add: arm_freq=1000 or arm_freq=1100

# Increase swap (if needed)
sudo nano /etc/dphys-swapfile
# Change CONF_SWAPSIZE=512
sudo systemctl restart dphys-swapfile
```

**Battery Optimization**
```toml
# In config.toml
main.plugins.logtail.enabled = false  # Reduce disk writes
ui.fps = 1  # Lower refresh rate to save power
```

*****

## Additional Resources 📚

**Documentation**
- Pwnagotchi (jayofelony fork, active): https://github.com/jayofelony/pwnagotchi
- Original evilsocket docs (archived): https://pwnagotchi.ai/

*****

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These tools are for **authorized security testing only**. Unauthorized use is illegal.

* **Pwnagotchi Use:** Get **written permission** before capturing from any network. Only target networks you own or have explicit authorization to test.
* **Cracking Use:** All cracking attempts must be done in an **isolated lab environment** against hashes you are authorized to possess.
* **Legal Compliance:** Strictly comply with all local laws and regulations.

**Legal Use Cases:**
* Penetration testing with client authorization.
* Testing your own home or lab network security.
* Security research in isolated lab environments.

---

## Related Files
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [hcxtoolshashcat.md](hcxtoolshashcat.md) - Full hcxtools + Hashcat mode 22000 workflow for converting and cracking Pwnagotchi captures
- [Aircrack-ng_Commands.md](Aircrack-ng_Commands.md) - Aircrack-ng as alternative CPU-based cracker for .pcap files
- [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) - ESP32 Marauder: active WiFi attack tool that complements Pwnagotchi's passive capture
- [evil_m5.md](evil_m5.md) - M5Cardputer Evil-M5: interactive WiFi attack platform (active deauth + evil twin)
- [bjorn_pi.md](bjorn_pi.md) - Bjorn Pi: autonomous network-service attacker on Pi hardware (different attack surface)

*Last Updated: 2025-11-03*
