
## Pwnagotchi Commands and Configuration 🤖

### Basic Setup

**Install Pwnagotchi (on Raspberry Pi Zero W/2W)**
```bash
# Download and flash pwnagotchi image
wget https://github.com/evilsocket/pwnagotchi/releases/latest/download/pwnagotchi-raspberrypi-*.img.gz
gunzip pwnagotchi-*.img.gz
sudo dd if=pwnagotchi-*.img of=/dev/sdX bs=4M status=progress
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
# Download plugin
cd /usr/local/share/pwnagotchi/custom-plugins/
sudo wget https://raw.githubusercontent.com/user/plugin.py

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

# Crack handshakes with aircrack-ng
aircrack-ng -w wordlist.txt handshake.pcap
```

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
- Pwnagotchi: https://pwnagotchi.ai/
