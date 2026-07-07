# Pwnagotchi Commands and Configuration 🤖

## 🎯 Purpose
Quick-reference for deploying, configuring, and operating a Pwnagotchi - an autonomous AI-driven WiFi handshake capture device built on Raspberry Pi Zero W/2W that passively collects WPA/WPA2 handshakes using hcxtools and bettercap.

## ⚙️ Function
Covers installation and flashing, essential config.toml settings, service management, plugin configuration, handshake processing for offline cracking with Hashcat, performance tuning, and troubleshooting. Focuses on the field-capture side of the passive WiFi audit workflow; pair with hcxtoolshashcat.md for the conversion and cracking steps.

## 🏆 Goal
Deploy a set-and-forget passive handshake capture device that autonomously improves its channel-selection strategy via reinforcement learning, outputting .pcap files ready for hcxpcapngtool conversion and Hashcat cracking.

## 📋 When to Use
- Long-duration passive WiFi reconnaissance without active deauth or interference
- Authorized wardriving and site surveys requiring hands-free capture
- Lab exercises demonstrating WPA2 handshake exposure
- Supplementing active tools (Marauder, Evil-M5) with continuous passive capture in the background



### Basic Setup

**Install Pwnagotchi (on Raspberry Pi Zero W/2W)**
```bash
# The jayofelony fork is the actively maintained release (evilsocket's original is archived)
# Releases ship as pwnagotchi-32bit-<version>.img.xz / pwnagotchi-64bit-<version>.img.xz -
# pick the correct architecture for your Pi. wget can't glob a wildcard against a remote
# URL, so grab the exact filename from the releases page (or the GitHub API) first:
# curl -s https://api.github.com/repos/jayofelony/pwnagotchi/releases/latest | grep browser_download_url
wget https://github.com/jayofelony/pwnagotchi/releases/download/v2.9.5.4/pwnagotchi-32bit-2.9.5.4.img.xz
unxz pwnagotchi-32bit-2.9.5.4.img.xz
sudo dd if=pwnagotchi-32bit-2.9.5.4.img of=/dev/sdX bs=4M status=progress
```

**Initial Configuration**
```bash
# SSH into pwnagotchi (USB connection)
ssh pi@10.0.0.2
# Default password: raspberry

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

# Enable web UI
ui.web.enabled = true
ui.web.username = "changeme"
ui.web.password = "changeme"

# Bluetooth tethering
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
sudo wget https://raw.githubusercontent.com/jayofelony/pwnagotchi/master/pwnagotchi/plugins/default/example.py

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
ls -lah *.pcap

# Copy handshakes to local machine
scp pi@10.0.0.2:/root/handshakes/*.pcap ./handshakes/

# Convert to Hashcat unified format (mode 22000 - replaces deprecated 16800/2500)
hcxpcapngtool -o hashes.hc22000 -E essid_list.txt handshake.pcap

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
sudo git pull
sudo pip3 install .
sudo systemctl restart pwnagotchi

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
sudo rm -rf /root/brain.nn /root/.pwnagotchi-auto
sudo systemctl restart pwnagotchi
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
