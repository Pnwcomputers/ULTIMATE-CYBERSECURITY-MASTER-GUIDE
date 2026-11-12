# Bash Bunny Payload Setup Guide


## 🎯 Purpose
Setup and payload compilation guide for the Hak5 Bash Bunny - a multi-function USB attack platform that emulates keyboards, storage devices, and network adapters for authorized red team physical access testing.

## ⚙️ Function
Covers: Bash Bunny modes (arming vs attack), DuckyScript payload syntax, payload directory structure, LED/ATTACKMODE commands, credential exfiltration via storage emulation, network adapter emulation for MiTM, and example payloads for common authorized test scenarios.

## 🏆 Goal
Enable authorized red team practitioners to write, compile, and deploy Bash Bunny payloads for physical access security assessments.

## 📋 When To Use
- Writing new Bash Bunny payloads for an authorized physical access engagement
- Setting up a Bash Bunny for the first time (arming mode, payload structure)
- Troubleshooting payload execution issues

## Overview
The Bash Bunny is a multi-function USB attack platform that can emulate keyboards, storage devices, network adapters, and serial devices. Payloads are written in bash with special Bash Bunny-specific commands.

## Initial Bash Bunny Setup

### First-time Configuration

1. **Connect Bash Bunny in Arming Mode**
   - Set switch to position closest to USB connector (Switch 3)
   - Plug into computer
   - Wait for LED to turn blue (solid)
   - Bash Bunny appears as USB storage device

2. **Update Firmware (Recommended)**
   - Download latest firmware: https://downloads.hak5.org/bunny
   - Copy firmware `.tar.gz` file to root of Bash Bunny
   - Safely eject
   - Replug - Bash Bunny will update (flashing LEDs)
   - Wait for completion (solid LED)

3. **File System Structure**
```
   /
   ├── payloads/
   │   ├── switch1/
   │   │   └── payload.txt
   │   ├── switch2/
   │   │   └── payload.txt
   │   └── library/          # Payload library
   ├── loot/                 # Data collection folder
   ├── tools/                # Additional tools/scripts
   ├── languages/            # Keyboard layouts
   └── version.txt           # Firmware version
```

## Payload Deployment

### Switch-based Operation

The Bash Bunny has a **3-position switch**:

- **Switch 3 (Closest to USB)**: Arming Mode
  - Access file system
  - Configure payloads
  - Update firmware
  
- **Switch 1**: Runs `/payloads/switch1/payload.txt`
- **Switch 2**: Runs `/payloads/switch2/payload.txt`

### Installing A Payload

1. **Set to Arming Mode** (Switch 3)
2. **Connect** to computer
3. **Navigate** to `/payloads/switch1/` or `/payloads/switch2/`
4. **Copy** your `payload.txt` to the desired switch folder
5. **Safely eject**
6. **Set switch** to position 1 or 2
7. **Plug into target** - payload executes automatically

## Creating Bash Bunny Payloads

### Basic Structure
```bash
#!/bin/bash
#
# Title:         Payload Name
# Description:   What this payload does
# Author:        Your Name
# Version:       1.0
# Category:      Category Name
# Target:        Windows 10/11 (or Linux, macOS)
# Attackmodes:   HID, Storage (or Ethernet, Serial)

# LED feedback for status
LED SETUP

# Set attack mode
ATTACKMODE HID STORAGE

# Wait for target to recognize device
LED ATTACK

# Your payload commands here
RUN WIN notepad
Q DELAY 1000
Q STRING Hello World!
Q ENTER

# Completion
LED FINISH
sync
```

### Attack Modes

The Bash Bunny can operate in multiple modes simultaneously:

**ATTACKMODE [mode1] [mode2] [mode3]**

Available modes:
- `HID` - Keyboard/Mouse emulation
- `STORAGE` - USB Mass Storage (access to /root/udisk)
- `ETHERNET` - Network adapter
- `SERIAL` - Serial console
- `RNDIS_ETHERNET` - Windows RNDIS network
- `ECM_ETHERNET` - Linux/Mac network

**Examples:**
```bash
ATTACKMODE HID                    # Keyboard only
ATTACKMODE HID STORAGE            # Keyboard + storage
ATTACKMODE STORAGE                # Storage only
ATTACKMODE ETHERNET               # Network adapter
ATTACKMODE HID STORAGE ETHERNET   # All three
```

## Led Status Indicators

### Led Colors
```bash
LED R           # Red
LED G           # Green  
LED B           # Blue
LED Y           # Yellow
LED C           # Cyan
LED M           # Magenta
LED W           # White
```

### Led Patterns
```bash
LED R           # Solid red
LED R SLOW      # Slow blinking red
LED R FAST      # Fast blinking red
LED R VERYFAST  # Very fast blinking red
LED R SINGLE    # Single blink
LED R DOUBLE    # Double blink
LED R TRIPLE    # Triple blink
```

### Standard Led Usage
```bash
LED SETUP       # Magenta - Setup/initialization
LED ATTACK      # Yellow - Active attack
LED SPECIAL     # Cyan - Special operation
LED FAIL        # Red - Failure/error
LED FINISH      # Green - Success/complete
```

## Hid (Keyboard) Commands

### Keystroke Injection

For **Windows/Linux**:
```bash
RUN WIN notepad              # Windows + type "notepad"
RUN UNITY gnome-terminal     # Linux Unity
```

**Q Command** - Queue keystrokes:
```bash
Q GUI r                      # Windows + R
Q DELAY 500
Q STRING powershell
Q ENTER
```

### Key Commands
```bash
Q ENTER
Q SPACE
Q TAB
Q BACKSPACE
Q DELETE
Q ESC
Q UP / Q DOWN / Q LEFT / Q RIGHT
Q HOME / Q END
Q PAGEUP / Q PAGEDOWN
Q CTRL / Q ALT / Q SHIFT / Q GUI
Q F1 through Q F12
```

### Key Combinations
```bash
Q CTRL c                     # Ctrl+C
Q ALT F4                     # Alt+F4
Q GUI r                      # Win+R
Q CTRL ALT DELETE            # Ctrl+Alt+Del
```

### Delays
```bash
Q DELAY 500                  # Wait 500ms
```

## Data Exfiltration (Loot)

### Saving Data To Bash Bunny
```bash
# Set attack mode with storage
ATTACKMODE HID STORAGE

# Define loot directory
LOOT_DIR=/root/udisk/loot/payload_name_$(date +%Y%m%d_%H%M%S)
mkdir -p $LOOT_DIR

# Collect data
hostname > $LOOT_DIR/hostname.txt
date > $LOOT_DIR/collection_time.txt

# Example: Copy files from target
cp /path/to/target/file $LOOT_DIR/

# Ensure data is written
sync
```

### Loot Organization
```
/root/udisk/loot/
├── migration_data_20241229_120000/
│   ├── system_info.txt
│   ├── network_config.txt
│   └── installed_software.txt
├── network_scan_20241228_150000/
│   └── scan_results.txt
└── credentials_20241227_100000/
    └── found_creds.txt
```

## Platform-specific Payloads

### Windows Payloads
```bash
#!/bin/bash
# Windows Information Gathering

LED SETUP
ATTACKMODE HID STORAGE

# Create loot directory
LOOT_DIR=/root/udisk/loot/windows_$(date +%Y%m%d_%H%M%S)
mkdir -p $LOOT_DIR

LED ATTACK

# Open PowerShell
RUN WIN powershell
Q DELAY 2000

# Collect system info
Q STRING systeminfo > info.txt
Q ENTER
Q DELAY 3000

# Copy to Bash Bunny
Q STRING "cp info.txt $(ls /media/*BASHBUNNY*/loot/windows_*/)"
Q ENTER

LED FINISH
sync
```

### Linux Payloads
```bash
#!/bin/bash
# Linux Information Gathering

LED SETUP
ATTACKMODE HID STORAGE

LOOT_DIR=/root/udisk/loot/linux_$(date +%Y%m%d_%H%M%S)
mkdir -p $LOOT_DIR

LED ATTACK

# Open terminal (may vary by distro)
RUN UNITY gnome-terminal
Q DELAY 2000

# Collect info
Q STRING "uname -a > /tmp/sysinfo.txt"
Q ENTER
Q DELAY 1000

Q STRING "ifconfig > /tmp/network.txt"
Q ENTER
Q DELAY 1000

# Copy to Bash Bunny
Q STRING "cp /tmp/*.txt /media/*/loot/linux_*/"
Q ENTER

LED FINISH
sync
```

## Network Mode (Ethernet)

### Basic Network Payload
```bash
#!/bin/bash
# Network Attack Mode

LED SETUP
ATTACKMODE ETHERNET

# Configure networking
GET TARGET_IP
GET TARGET_HOSTNAME

LED ATTACK

# Network operations
nmap -sV $TARGET_IP > /root/udisk/loot/nmap_scan.txt

LED FINISH
```

### Getting Target Information
```bash
GET TARGET_IP           # Target's IP address
GET TARGET_HOSTNAME     # Target's hostname
GET HOST_IP             # Bash Bunny's IP
```

## Advanced Features

### Extensions

Load additional functionality:
```bash
# Load extension
source /root/udisk/extensions/extension_name.sh

# Common extensions
GET                     # Network info gathering
RUN                     # Platform detection & app launching
```

### Bunny Helpers
```bash
# Get OS type
GET HOST_OS             # Returns "WINDOWS", "LINUX", "MACOS"

# Wait for target ready
LED SETUP
ATTACKMODE HID
sleep 3                 # Wait for HID to be ready
LED ATTACK
```

## Configuration Files

### Config.txt (Optional)

Create `/root/udisk/config.txt` for global settings:
```bash
# Keyboard layout
DUCKY_LANG=us

# LED brightness (1-4)
LED_BRIGHTNESS=4

# Serial console
SERIAL_CONSOLE_ENABLED=Y
```

### Keyboard Layouts

Available in `/languages/`:
- `us` - US English
- `uk` - UK English  
- `de` - German
- `fr` - French
- `es` - Spanish
- Many more...

**Set in payload:**
```bash
DUCKY_LANG us
```

## Authorized Field Assessment Labs & Deployment Examples

This section extends the setup, switch positions, attack modes, and scripting reference above into **repeatable client-approved tests**, without replacing the existing instructions. Compare the [USB Rubber Ducky compilation guide](../../Ducky/README.md) and [staged assessment blueprint](../../../PlayBooks/assessment-service-integration-map.md).

> [!IMPORTANT]
> Identify original Bash Bunny versus Mark II and record installed firmware. Bash Bunny payloads are Bash shell scripts containing Bash Bunny commands; USB Rubber Ducky compiled `inject.bin` payloads are not interchangeable with `payload.txt`. DuckyScript 3 syntax is not automatically supported. Refer to [Hak5's original payload development reference](https://github.com/hak5/bashbunny-wiki/blob/master/payload_development.md).

### Engagement Preparation

1. Obtain written authorization specifying client, permitted host IDs, USB classes (HID, storage, serial, USB networking), time window, data retention, stop conditions, and physical observer.
2. Use an offline/isolated lab workstation or disposable VM, a synthetic test user, and a blank text editor. Record USB baseline, device-control policy, active network adapters/routes, and EDR health before testing.
3. Backup existing device contents and verify switch assignment, firmware-specific helper support, keyboard layout, and the exact payload source. Never trust an unreviewed community payload.
4. Stop immediately if keystrokes reach an unexpected application, a privileged action occurs, a route/DNS setting changes unexpectedly, or an out-of-scope host enumerates the device.
5. Preserve expected **and** actual observations, not just successful outcomes.

### Lab 1 — Non-destructive HID Marker

**Goal:** validate HID acceptance and monitoring without opening commands or collecting data.

Stage this as `/payloads/switch1/payload.txt` in arming mode:

~~~bash
#!/bin/bash
# PNWC authorized HID test; focus a blank editor manually
LED SETUP
ATTACKMODE HID
sleep 3
LED ATTACK
QUACK STRING PNWC-BASH-BUNNY-LAB
QUACK ENTER
LED FINISH
~~~

1. On the dedicated target, open and focus a blank editor.
2. Safely eject in arming mode, disconnect, move the switch to position 1, and reconnect.
3. Verify only the exact marker was typed. Record USB insertion, HID class, and EDR/device-control alert, if any.
4. Remove the device, capture host logs, and document whether the behavior conformed to written USB/physical security policy.

**Interpretation:** this demonstrates keystroke input to a focused application, not elevated permissions, credential access, or a successful compromise. Repeat with the screen locked only if authorized; do not attempt lock bypass.

### Lab 2 — Removable Storage Policy

1. Capture the baseline removable-disk inventory and applicable allow/deny policy.
2. Stage `ATTACKMODE STORAGE` alone on a test switch; verify the exposed data partition and do not modify the Bunny's system partition.
3. Insert into the approved host. Observe Windows Device Manager and EDR or Linux `lsusb`, `lsblk`, and `journalctl -k`.
4. If policy permits, manually copy a **synthetic** file such as `PNWC-USB-STORAGE-TEST.txt` onto the approved exposed volume; never read/copy arbitrary client folders.
5. Record mount status, read/write restriction, detection and enforcement. Eject safely and remove the synthetic data according to the evidence policy.

### Lab 3 — USB Network Adapter/Route Policy

**Goal:** detect unexpected USB Ethernet interfaces, default routes or DNS changes.

1. Use an isolated host. On Windows, record `Get-NetAdapter`, `Get-NetRoute`, and `Get-DnsClientServerAddress`; on Linux, record `ip -br addr` and `ip route`.
2. Stage the model-appropriate `ATTACKMODE RNDIS_ETHERNET` for supported Windows environments or `ATTACKMODE ECM_ETHERNET` for supported Linux/macOS environments. **Support varies by host, OS and firmware.**
3. Do not enable network interception, forwarding, unauthorized DHCP/DNS services, or scanning. Insert once and record driver/interface enumeration, routing metrics, DNS and alerts.
4. Disconnect immediately if the default route unexpectedly changes; restore network state, compare to baseline, and report any policy mismatch.

### Lab 4 — Serial Device Enumeration

1. Record existing COM/serial interfaces using Device Manager or `ls /dev/ttyACM*` where appropriate.
2. Stage `ATTACKMODE SERIAL` alone. Insert the device and check driver installation, permissions, detection and port disappearance after removal.
3. Do not send commands to an external target or assume console parameters across device generations. Capture events and verify device-control policy.

### Lab 5 — Composite USB Device & Wazuh/EDR Correlation

1. In a disposable lab, define expected policy results for HID and storage independently.
2. Run the HID-only and storage-only labs above, then stage the firmware-documented composite `ATTACKMODE HID STORAGE`.
3. Observe per-interface enumeration. Run only the harmless text marker and synthetic storage-file check.
4. Export real host/EDR telemetry into the approved monitoring system; map the observed source fields to Wazuh alerts instead of inventing event IDs. Record allowed/blocked results.
5. Insert a legitimate keyboard as a **negative control** to evaluate false positives. Restore policies, disconnect, and verify no test device remains.

### Test Result Template

| Evidence Field | Required Record |
|---|---|
| Scope | Engagement ID, authorization, assets, operator, exact UTC times |
| Hardware | Bunny model, firmware, switch position, mode, USB IDs as observed |
| Payload | Source checksum, dependencies, approved test objective |
| Detection | Host logs, EDR/Wazuh source event, expected policy, actual result |
| Outcome | Verified observation versus inference, false-positive checks |
| Closure | Removal, network/policy restoration, synthetic data handling |

### Compatibility & Existing Example Caveats

- A Bash command executed **on the Bunny** does not magically run in the attached Windows host. Injected keystrokes execute in the foreground host application and its current user context.
- The existing Windows/Linux data-transfer examples above use illustrative mount paths and shell assumptions; verify host-specific commands, permissions, transports and filenames independently. They are **not verified drop-in client collection payloads**.
- Earlier references to `ATTACKMODE ETHERNET` may be ambiguous for particular firmware. Use documented `RNDIS_ETHERNET` or `ECM_ETHERNET` when appropriate, and check observed enumeration rather than assuming networking works.
- Device control should consider legitimate keyboards, accessibility devices, docking stations and service peripherals before applying class restrictions.

## Testing & Debugging

### Serial Console Access

1. **Enable serial console** in `config.txt`
2. **Connect** with serial terminal (115200 baud)
   - Linux: `screen /dev/ttyACM0 115200`
   - Windows: Use PuTTY or similar
3. **View** live payload execution and errors

### Debug Output
```bash
# Add debug output to payload
echo "Starting payload..." > /root/udisk/debug.log
echo "Attack mode set" >> /root/udisk/debug.log

# Check LED during execution
LED M SLOW   # Visual checkpoint
sleep 2
```

### Common Issues

**Payload not executing:**
- ✓ Check `payload.txt` is in correct switch folder
- ✓ Verify switch position (1 or 2, not 3)
- ✓ Check file permissions (should be executable)
- ✓ Review serial console for errors

**HID not working:**
- ✓ Increase delays after RUN commands
- ✓ Check keyboard layout matches target
- ✓ Verify ATTACKMODE includes HID

**Storage not mounting:**
- ✓ Ensure ATTACKMODE includes STORAGE
- ✓ Check target OS recognizes USB storage
- ✓ Try different USB port

## Payload Library

### Included Payloads

The Bash Bunny comes with payloads in `/payloads/library/`:
- Information gathering
- Network attacks
- Credential harvesting
- Exfiltration tools

**To use library payload:**
```bash
# Copy from library to switch folder
cp /payloads/library/example_payload/payload.txt /payloads/switch1/
```

## Best Practices

### 1. Led Feedback
Always use LED indicators to show payload status:
```bash
LED SETUP     # Starting
LED ATTACK    # Running
LED SPECIAL   # Optional step
LED FINISH    # Success
LED FAIL      # Error
```

### 2. Sync Data
Always sync before completion:
```bash
sync          # Flush data to storage
LED FINISH
```

### 3. Error Handling
```bash
if [ $? -eq 0 ]; then
    LED FINISH
else
    LED FAIL
fi
```

### 4. Timing
- Add appropriate delays for target OS
- Test on slowest expected hardware
- Allow extra time for USB recognition

### 5. Documentation
```bash
#!/bin/bash
#
# Title:         Clear payload name
# Description:   Detailed description
# Author:        Your name
# Version:       Version number
# Category:      Appropriate category
# Target:        Target OS/version
# Attackmodes:   Modes used
#
# LED Status:
# - Magenta: Setup
# - Yellow: Attack
# - Green: Complete
# - Red: Failure
```

## Security & Legal

### ⚠️ Legal Notice

**Authorized use only:**
- ✓ Personal systems you own
- ✓ Written permission from system owner
- ✓ Professional pentesting with contracts
- ✓ Educational labs with authorization

**Unauthorized computer access is illegal** under:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act
- Similar laws worldwide

### Professional Use

1. **Obtain written authorization**
2. **Define scope clearly**
3. **Document all activities**
4. **Secure loot data appropriately**
5. **Follow responsible disclosure**

## Resources

- **Official Docs**: https://documentation.hak5.org/bash-bunny/
- **Forums**: https://forums.hak5.org/forum/94-bash-bunny/
- **Payload Library**: https://github.com/hak5/bashbunny-payloads
- **Downloads**: https://downloads.hak5.org/bunny
- **Wiki**: https://wiki.bashbunny.com/

## Quick Reference Card
```bash
# Attack Modes
ATTACKMODE HID STORAGE ETHERNET

# LED Commands  
LED R|G|B|Y|C|M|W [SLOW|FAST|VERYFAST|SINGLE|DOUBLE|TRIPLE]
LED SETUP|ATTACK|SPECIAL|FAIL|FINISH

# HID Commands
RUN WIN|UNITY|OSX command
Q KEYSTROKE [DELAY ms]

# File Operations
LOOT_DIR=/root/udisk/loot/name
mkdir -p $LOOT_DIR
cp source $LOOT_DIR/
sync

# Network
GET TARGET_IP|TARGET_HOSTNAME|HOST_IP

# Keyboard Layout
DUCKY_LANG us|uk|de|fr|es
```

## Example Payloads

See individual payload files in this repository for:
- Windows migration data collection
- Linux system profiling
- Network reconnaissance
- Credential gathering
- File exfiltration

---

**Pacific NW Computers**

*Always use responsibly and legally.*

## Related Files
- [../../README.md](../../README.md) - Scripts section index
- [../bash_scripting_cheat-sheet.md](../bash_scripting_cheat-sheet.md) - Bash reference for payload writing
- [../../Ducky/README.md](../../Ducky/README.md) - USB Rubber Ducky: keyboard-only attack platform
- [../../../Documentation/LinuxCheatSheet.md](../../../Documentation/LinuxCheatSheet.md) - Linux commands used in payloads
- [../../../Mobile/mobile_pentest_sop.md](../../../Mobile/mobile_pentest_sop.md) - Mobile pentest SOP (DuckHunter HID on NetHunter uses BashBunny-compatible DuckyScript)
- [../../../Mobile/OnePlus_A6003/Nethunter_SOP.md](../../../Mobile/OnePlus_A6003/Nethunter_SOP.md) - NetHunter DuckHunter HID module SOP
