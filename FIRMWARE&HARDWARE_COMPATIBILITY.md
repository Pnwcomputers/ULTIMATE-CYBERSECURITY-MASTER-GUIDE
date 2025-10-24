# FIRMWARE & HARDWARE COMPATIBILITY CHART
## Wireless Security Testing Devices

**Last Updated:** October 2025  
**Purpose:** Quick reference guide for firmware compatibility across common penetration testing hardware

---

## Quick Reference Compatibility Matrix

| Firmware/Project | ESP32 | ESP32-S2 | ESP32-S3 | ESP32-C3 | LilyGO T-Display | LilyGO TTGO | M5 Cardputer | M5Stick | M5Stick Plus | CC1101 | Raspberry Pi 4 | Pi Zero | Pi Zero W | Pi Zero 2W | Flipper Zero | nRF52840 |
|-----------------|-------|----------|----------|----------|------------------|-------------|--------------|---------|--------------|--------|----------------|---------|-----------|------------|--------------|----------|
| **WiFi Marauder** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ✅ (via ESP32) | ❌ |
| **Bruce** | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Nemo** | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Pwnagotchi** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **Bjorn** | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **P4wnP1 A.L.O.A** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ⚠️ | ❌ | ❌ |
| **RaspyRFM** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Evil-M5Core2** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Deauther V3** | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **FZ-Marauder** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |

**Legend:**
- ✅ = Fully Compatible / Officially Supported
- ⚠️ = Requires Additional Hardware/Module
- ❌ = Not Compatible / Not Supported

---

## Detailed Hardware Specifications

### ESP32 Family

#### ESP32 (Original)
- **Chipset:** Dual-core Xtensa LX6
- **WiFi:** 802.11 b/g/n
- **Bluetooth:** BT 4.2 BR/EDR & BLE
- **Compatible Firmware:** Marauder, Bruce, Nemo, Bjorn, Deauther
- **Common Boards:** 
  - ESP32 DevKit v1
  - ESP32-WROOM-32
  - DOIT ESP32 DevKit
- **Use Cases:** WiFi deauth, packet sniffing, evil twin attacks

#### ESP32-S2
- **Chipset:** Single-core Xtensa LX7
- **WiFi:** 802.11 b/g/n
- **Bluetooth:** ❌ None
- **Compatible Firmware:** Marauder, Bjorn, Deauther
- **Common Boards:**
  - ESP32-S2-Saola
  - ESP32-S2 DevKitM
- **Use Cases:** WiFi-only operations, lower power consumption
- **Note:** No Bluetooth limits functionality for some attacks

#### ESP32-S3
- **Chipset:** Dual-core Xtensa LX7
- **WiFi:** 802.11 b/g/n
- **Bluetooth:** BT 5.0 LE
- **Compatible Firmware:** Marauder, Bruce, Nemo, Bjorn
- **Common Boards:**
  - ESP32-S3-DevKitC
  - LilyGO T-Display-S3
  - ESP32-S3-WROOM
- **Use Cases:** Most advanced ESP32, best for complex operations
- **Note:** Improved performance over original ESP32

#### ESP32-C3
- **Chipset:** Single-core RISC-V
- **WiFi:** 802.11 b/g/n
- **Bluetooth:** BT 5.0 LE
- **Compatible Firmware:** Marauder (limited support)
- **Common Boards:**
  - ESP32-C3-DevKitM
  - ESP32-C3-MINI
- **Use Cases:** Newer architecture, smaller footprint
- **Note:** Some firmware may have limited support

#### ESP8266
- **Chipset:** Single-core Xtensa L106
- **WiFi:** 802.11 b/g/n
- **Bluetooth:** ❌ None
- **Compatible Firmware:** Deauther V3 (primary target), some Marauder ports
- **Common Boards:**
  - NodeMCU
  - Wemos D1 Mini
  - ESP-01
- **Use Cases:** WiFi deauth attacks, packet monitor
- **Note:** Older chip but still very popular for deauther

---

### LilyGO Devices

#### LilyGO TTGO T-Display (ESP32)
- **Specifications:**
  - ESP32 chip
  - 1.14" TFT display (135x240)
  - Battery connector
  - USB-C
- **Compatible Firmware:** Marauder, Bruce, Nemo, Bjorn, Deauther
- **Key Features:** Built-in display makes it ideal for standalone operation
- **Popular Use:** Portable WiFi attacks with visual feedback
- **Price Range:** ~$10-15

#### LilyGO T-Display-S3
- **Specifications:**
  - ESP32-S3 chip
  - 1.9" TFT display (170x320)
  - Battery support
  - USB-C
- **Compatible Firmware:** Marauder, Bruce, Nemo, Bjorn
- **Key Features:** Larger display, more powerful processor
- **Popular Use:** Advanced portable operations
- **Price Range:** ~$15-20

#### LilyGO TTGO LoRa32
- **Specifications:**
  - ESP32 chip
  - SX1276/SX1278 LoRa module
  - OLED display
  - Battery connector
- **Compatible Firmware:** Marauder (with modifications)
- **Key Features:** LoRa radio in addition to WiFi
- **Note:** Primary use is LoRa but WiFi functions work

---

### Raspberry Pi Devices

#### Raspberry Pi 4 Model B
- **Specifications:**
  - Quad-core ARM Cortex-A72 (1.5-1.8GHz)
  - 2GB/4GB/8GB RAM options
  - WiFi 5 (802.11ac) dual-band
  - Bluetooth 5.0
  - Gigabit Ethernet
- **Compatible Firmware:** Pwnagotchi, Bjorn, RaspyRFM (with module)
- **Key Features:** Most powerful Pi, can run multiple tools simultaneously
- **Popular Use:** Pwnagotchi with web interface, network analysis
- **Power:** Requires 5V/3A USB-C

#### Raspberry Pi Zero (Original)
- **Specifications:**
  - Single-core ARM1176JZF-S (1GHz)
  - 512MB RAM
  - ❌ No WiFi (requires USB adapter)
  - ❌ No Bluetooth
  - Mini HDMI
  - Micro USB OTG
- **Compatible Firmware:** RaspyRFM (with WiFi adapter and RF module)
- **Key Features:** Ultra-compact, lowest cost Pi
- **Popular Use:** Limited - requires USB WiFi adapter for wireless testing
- **Power:** 5V/1A micro-USB
- **Price Range:** ~$5 (when available)
- **Note:** Not recommended for wireless testing due to lack of built-in WiFi

#### Raspberry Pi Zero W
- **Specifications:**
  - Single-core ARM1176JZF-S (1GHz)
  - 512MB RAM
  - WiFi 4 (802.11n)
  - Bluetooth 4.1
- **Compatible Firmware:** Pwnagotchi, P4wnP1 A.L.O.A, RaspyRFM, Bjorn
- **Key Features:** Tiny footprint, low power, portable
- **Popular Use:** Pwnagotchi (most common), HID attacks with P4wnP1
- **Power:** 5V/1A micro-USB
- **Price Range:** ~$15 (when available)

#### Raspberry Pi Zero 2 W
- **Specifications:**
  - Quad-core ARM Cortex-A53 (1GHz)
  - 512MB RAM
  - WiFi 4 (802.11n)
  - Bluetooth 4.2
- **Compatible Firmware:** Pwnagotchi, P4wnP1 A.L.O.A (experimental), Bjorn
- **Key Features:** 5x faster than Zero W, same size
- **Popular Use:** Enhanced Pwnagotchi performance
- **Power:** 5V/1A micro-USB
- **Price Range:** ~$15-20
- **Note:** P4wnP1 support is experimental/community builds

#### Raspberry Pi 3 Model B/B+
- **Specifications:**
  - Quad-core ARM Cortex-A53 (1.4GHz)
  - 1GB RAM
  - WiFi 4/5 (B+ has 5GHz)
  - Bluetooth 4.2
- **Compatible Firmware:** Pwnagotchi, Bjorn, RaspyRFM
- **Key Features:** Good balance of power and availability
- **Popular Use:** Pwnagotchi with plugins

---

### Flipper Zero

#### Flipper Zero
- **Specifications:**
  - STM32WB55 (Cortex-M4 + Cortex-M0+)
  - Sub-GHz radio (300-928 MHz)
  - 125kHz RFID
  - 13.56MHz NFC
  - Infrared
  - GPIO pins
  - 1.4" LCD display
- **Native Firmware:** Flipper Firmware (Official), Unleashed, RogueMaster
- **WiFi Support:** ❌ Requires WiFi Dev Board (ESP32)
- **Compatible Add-ons:**
  - WiFi Dev Board (runs Marauder)
  - CC1101 module for extended Sub-GHz
  - NRF24 module
- **Key Features:** Multi-tool for various wireless protocols
- **Popular Use:** RFID/NFC testing, Sub-GHz analysis, IR remote
- **Note:** Requires ESP32 WiFi board for WiFi testing

#### Flipper Zero + WiFi Dev Board
- **Add-on Specs:**
  - ESP32-S2 chip
  - Connects via GPIO
  - Powered by Flipper
- **Compatible Firmware:** Marauder (FZ-Marauder fork)
- **Capabilities:**
  - WiFi deauth
  - Packet sniffing
  - Evil twin attacks
  - WPS testing
- **Price:** ~$12-20 for WiFi board

---

### CC1101 Devices

#### CC1101 Transceiver Module
- **Specifications:**
  - Sub-GHz radio (300-928 MHz)
  - SPI interface
  - Low power consumption
- **Host Devices:**
  - Raspberry Pi (any model with GPIO)
  - ESP32 (via SPI)
  - Flipper Zero
  - Arduino
- **Compatible Firmware:**
  - RaspyRFM (Raspberry Pi)
  - Custom ESP32 firmware
  - Flipper Zero apps
- **Key Features:** Extends Sub-GHz capabilities
- **Popular Use:** 
  - 433MHz signal analysis
  - Garage door/remote testing
  - Wireless sensor monitoring
- **Price Range:** ~$3-8 per module

---

### nRF Devices

#### nRF52840 Dongle
- **Specifications:**
  - ARM Cortex-M4F
  - Bluetooth 5.0 / BLE
  - 802.15.4 support
  - USB dongle form factor
- **Compatible Tools:**
  - Ubertooth firmware (modified)
  - Nordic SDK applications
  - Custom BLE sniffing tools
- **Key Features:** BLE security testing
- **Popular Use:**
  - BLE packet capture
  - BLE device enumeration
  - Bluetooth low energy attacks
- **Note:** Not typically used with the WiFi-focused firmware listed above
- **Price Range:** ~$10

#### nRF52840 DK (Development Kit)
- **Specifications:**
  - Full development board
  - Multiple interfaces
  - Debugging capabilities
- **Use Cases:** BLE development and testing
- **Price Range:** ~$40-50

---

### M5Stack Devices

#### M5Stack Core2
- **Specifications:**
  - ESP32-D0WDQ6-V3
  - 2" TFT touchscreen (320x240)
  - 6-axis IMU
  - Microphone
  - Battery (390mAh)
  - Speaker
- **Compatible Firmware:** Evil-M5Core2, Marauder (modified)
- **Key Features:** All-in-one device with touchscreen interface
- **Popular Use:** WiFi attacks with professional interface
- **Price Range:** ~$50-60

#### M5Stick C
- **Specifications:**
  - ESP32-PICO-D4
  - 0.96" TFT display (80x160)
  - 6-axis IMU
  - Battery (80mAh)
  - Microphone
  - Infrared LED
  - Red LED
- **Compatible Firmware:** Nemo, Marauder (modified), Deauther
- **Key Features:** Ultra-compact, built-in battery, IR capability
- **Popular Use:** Minimal footprint WiFi testing
- **Power:** Built-in 80mAh battery (USB-C charging)
- **Price Range:** ~$12-15
- **Note:** Smaller screen than C Plus, older model

#### M5Stick C Plus
- **Specifications:**
  - ESP32-PICO
  - 1.14" TFT display (135x240)
  - 6-axis IMU
  - Battery (120mAh)
  - Infrared LED
  - Microphone
  - Red LED
- **Compatible Firmware:** Nemo, Marauder (modified), Bruce, Deauther
- **Key Features:** Ultra-portable, built-in battery, larger screen than C
- **Popular Use:** Pocket-sized WiFi testing
- **Price Range:** ~$20-25

#### M5Stick C Plus 2
- **Specifications:**
  - ESP32-PICO-V3-02
  - 1.14" TFT display (135x240)
  - 6-axis IMU (MPU6886)
  - Battery (200mAh) - IMPROVED
  - Infrared LED
  - Microphone
  - Buzzer
  - Red LED
  - RTC (BM8563)
- **Compatible Firmware:** Nemo, Marauder, Bruce, Deauther
- **Key Features:** Improved battery life, RTC for accurate timing, buzzer feedback
- **Popular Use:** Extended operation WiFi testing, wardriving
- **Power:** Built-in 200mAh battery (USB-C charging)
- **Price Range:** ~$18-25
- **Note:** Newest version with significant battery improvement

#### M5Stack Cardputer
- **Specifications:**
  - ESP32-S3-FN8
  - 1.14" TFT display (240x135)
  - Full QWERTY keyboard (56 keys)
  - TF card slot (microSD)
  - 6-axis IMU
  - Microphone
  - Battery connector (supports external battery)
  - Expansion port
  - USB-C
- **Compatible Firmware:** Bruce, Marauder, Nemo, Deauther
- **Key Features:** Built-in keyboard for on-device control, SD card support
- **Popular Use:** Portable pentesting with full input capabilities
- **Price Range:** ~$40-50
- **Note:** Best M5Stack device for complex operations requiring text input

---

## Detailed Firmware Capabilities

### WiFi Marauder
**Primary Platform:** ESP32 family  
**Developer:** justcallmekoko

**Capabilities:**
- WiFi deauthentication attacks
- Beacon frame injection (flooding)
- Probe request/response sniffing
- Packet capture (PCAP format)
- WPS testing
- PMKID capture
- Evil portal attacks
- Multiple attack modes

**Hardware Requirements:**
- Minimum: ESP32 with 4MB flash
- Recommended: ESP32-S3 or S2 for best performance
- Display: Optional but recommended (TFT displays supported)

**Installation:**
- Flash via ESP Web Flasher
- Via Arduino IDE
- Pre-built binaries available

**Best Devices:**
- LilyGO T-Display-S3 (recommended)
- ESP32-WROOM-32
- M5Stack devices

---

### Bruce
**Primary Platform:** ESP32/ESP32-S3  
**Developer:** pr3y/Bruce

**Capabilities:**
- WiFi attacks (deauth, beacon flooding)
- Bluetooth attacks (spam, recon)
- RFID emulation (125kHz)
- NFC tools
- IR remote control
- Bad USB functionality
- SD card support
- Multiple attack vectors in one firmware

**Hardware Requirements:**
- ESP32-S3 (recommended for full features)
- Display required (touchscreen preferred)
- SD card slot (for storing captures/payloads)
- IR LED (for IR functions)

**Installation:**
- Flash via web installer
- Arduino IDE compilation
- Pre-built releases

**Best Devices:**
- M5Stack Cardputer (ideal)
- LilyGO T-Display-S3
- ESP32-S3 with TFT display

**Unique Features:**
- Swiss Army knife approach
- Combines multiple tool capabilities
- SD card for payload/capture storage

---

### Nemo
**Primary Platform:** ESP32/ESP32-S3 (M5Stack focus)  
**Developer:** n0xa

**Capabilities:**
- WiFi reconnaissance
- Deauthentication attacks
- Bluetooth scanning
- Wardriving
- GPS support
- OLED/TFT display interface
- CSV logging

**Hardware Requirements:**
- ESP32 or ESP32-S3
- Display (OLED or TFT)
- Optional: GPS module for wardriving

**Installation:**
- PlatformIO
- Pre-built binaries for specific hardware

**Best Devices:**
- M5Stick C Plus
- M5Stack Core
- LilyGO devices

---

### Pwnagotchi
**Primary Platform:** Raspberry Pi Zero W/2W  
**Developer:** evilsocket

**Capabilities:**
- Automated WPA/WPA2 handshake capture
- AI-based learning (personality system)
- Passive network monitoring
- PCAP file generation for offline cracking
- Web UI for configuration
- Plugin system
- Bluetooth tethering
- OLED display for status

**Hardware Requirements:**
- Raspberry Pi Zero W or Zero 2 W (recommended)
- Waveshare or similar e-ink/OLED display
- WiFi adapter in monitor mode
- Battery pack for portable use

**Installation:**
- Pre-built image for Raspberry Pi
- Manual installation on Raspbian

**Best Devices:**
- Raspberry Pi Zero 2 W (best performance)
- Raspberry Pi Zero W (most common)
- Raspberry Pi 4 (if using web UI heavily)

**Unique Features:**
- "Tamagotchi" personality interface
- Learns optimal attack patterns over time
- Best for long-term passive collection

---

### Bjorn
**Primary Platform:** ESP32, Raspberry Pi  
**Developer:** Bjorn Project

**Capabilities:**
- WiFi network reconnaissance
- Bluetooth device enumeration
- Network mapping
- Packet capture
- Multi-protocol support
- Web interface

**Hardware Requirements:**
- ESP32 or Raspberry Pi
- Optional display
- SD card support helpful

**Installation:**
- Flash tool for ESP32
- Raspberry Pi image available

**Best Devices:**
- ESP32-S3 boards
- Raspberry Pi 4
- LilyGO T-Display

---

### P4wnP1 A.L.O.A (A Little Offensive Appliance)
**Primary Platform:** Raspberry Pi Zero W (ONLY)  
**Developer:** RoganDawes

**Capabilities:**
- USB HID attacks (Rubber Ducky)
- Network attacks (MITM, rogue AP)
- Bluetooth attacks
- Web-based control interface
- WiFi backdoor
- Payload automation
- Smartphone app control

**Hardware Requirements:**
- Raspberry Pi Zero W (specific requirement)
- USB OTG cable
- Battery pack for mobile use
- Optional: Bluetooth keyboard for setup

**Installation:**
- Pre-built Raspberry Pi image
- Flash to SD card

**Best Device:**
- Raspberry Pi Zero W (only supported device)

**Unique Features:**
- Emulates USB devices (keyboard, Ethernet, storage)
- Can attack via USB, WiFi, and Bluetooth simultaneously
- Controlled via smartphone or web UI
- Best for physical penetration tests

---

### Deauther V3
**Primary Platform:** ESP8266 (primary), ESP32  
**Developer:** Spacehuhn

**Capabilities:**
- WiFi deauthentication attacks
- Beacon flooding
- Probe request flooding
- Packet monitor
- Web interface control
- Display support

**Hardware Requirements:**
- ESP8266 (recommended)
- ESP32 (also supported)
- Optional display

**Installation:**
- Web flasher
- Arduino IDE
- Pre-compiled binaries

**Best Devices:**
- NodeMCU ESP8266
- Wemos D1 Mini
- ESP8266 with OLED

**Note:** V3 is the latest major version, optimized for ESP8266

---

### Evil-M5Core2
**Primary Platform:** M5Stack Core2 (ONLY)  
**Developer:** 7h30th3r0n3

**Capabilities:**
- WiFi network attacks
- Evil portal captive portal
- Credential harvesting
- Touchscreen interface
- Multiple attack templates
- Professional UI

**Hardware Requirements:**
- M5Stack Core2 (specific device required)

**Installation:**
- Flash via M5Burner
- Pre-built firmware

**Best Device:**
- M5Stack Core2 (only device)

**Unique Features:**
- Professional touchscreen interface
- Pre-built captive portal templates
- All-in-one device

---

### FZ-Marauder (Flipper Zero Marauder)
**Primary Platform:** Flipper Zero WiFi Dev Board  
**Developer:** justcallmekoko (adapted for Flipper)

**Capabilities:**
- WiFi Marauder features via Flipper interface
- Controlled through Flipper Zero
- Packet capture
- Deauth attacks
- Network scanning

**Hardware Requirements:**
- Flipper Zero
- WiFi Dev Board (ESP32-S2)

**Installation:**
- Flash via Flipper's built-in tools
- qFlipper application

**Best Device:**
- Flipper Zero + Official WiFi Dev Board

---

## Recommended Hardware by Use Case

### Best for Beginners
1. **LilyGO TTGO T-Display + Marauder**
   - Affordable (~$12)
   - Built-in display
   - Easy to use
   - Wide community support

2. **ESP32 DevKit + Marauder**
   - Very cheap (~$5-8)
   - Easy to flash
   - Plenty of tutorials

### Best for Portability
1. **Raspberry Pi Zero 2 W + Pwnagotchi**
   - Tiny size
   - Battery powered
   - Autonomous operation
   - E-ink display

2. **M5Stick C Plus 2 + Nemo**
   - Smallest ESP32 option
   - Built-in 200mAh battery (improved)
   - Pocket-sized
   - RTC for accurate timing

3. **M5Stick C Plus + Nemo/Marauder**
   - Ultra-compact
   - Built-in 120mAh battery
   - Previous generation, still excellent

### Best for Professional Use
1. **M5Stack Core2 + Evil-M5Core2**
   - Professional appearance
   - Touchscreen interface
   - All-in-one device
   - Client-facing friendly

2. **LilyGO T-Display-S3 + Bruce**
   - Multi-tool functionality
   - Good display
   - SD card storage
   - Professional results

### Best for Learning
1. **ESP32-S3 DevKit + Multiple Firmware**
   - Can test different firmware
   - Good for experimentation
   - Affordable mistakes
   - Active community

### Best for Physical Pentests
1. **Raspberry Pi Zero W + P4wnP1**
   - HID attack capability
   - Multiple attack vectors
   - Remote control
   - Easy to hide

### Best Overall Value
1. **LilyGO T-Display-S3 + Marauder**
   - ~$15-20
   - Great display
   - Powerful processor
   - Versatile firmware options

---

## Purchase Recommendations

### Where to Buy

**Official Distributors:**
- LilyGO: Official store on AliExpress
- M5Stack: m5stack.com or Amazon
- Raspberry Pi: Adafruit, SparkFun, approved retailers
- ESP32 DevKits: Amazon, AliExpress, local electronics stores

**Price Ranges (USD):**
- ESP32 Basic: $5-10
- ESP32-S3 Boards: $8-15
- LilyGO T-Display: $10-15
- LilyGO T-Display-S3: $15-20
- Raspberry Pi Zero (no WiFi): $5
- Raspberry Pi Zero W: $15 (MSRP, if available)
- Raspberry Pi Zero 2 W: $15-20
- M5Stick C: $12-15
- M5Stick C Plus: $20-25
- M5Stick C Plus 2: $18-25
- M5Stack Cardputer: $40-50
- M5Stack Core2: $50-60
- Flipper Zero: $169 (official)
- WiFi Dev Board: $12-20

**Budget-Friendly Starter Kit:**
- ESP32 WROOM-32 DevKit: $7
- USB cable: $3
- Total: ~$10 + Marauder (free)

**Ultra-Portable Kit:**
- M5Stick C Plus 2: $22
- Nemo firmware (free)
- Total: ~$22 for pocket-sized testing

**Professional Starter Kit:**
- LilyGO T-Display-S3: $18
- M5Stack Cardputer: $45
- Raspberry Pi Zero 2 W: $18
- Various firmware (free)
- Total: ~$80 for complete toolkit

---

## Firmware Installation Quick Reference

| Firmware | Installation Method | Difficulty | Time Required |
|----------|-------------------|------------|---------------|
| Marauder | Web Flasher | Easy | 5 minutes |
| Bruce | Web Installer | Easy | 5 minutes |
| Nemo | PlatformIO/Arduino | Medium | 15-30 minutes |
| Pwnagotchi | SD Card Image | Easy | 30 minutes |
| Bjorn | Various | Medium | 15-30 minutes |
| P4wnP1 | SD Card Image | Easy | 30 minutes |
| Deauther | Web Flasher | Easy | 5 minutes |
| Evil-M5Core2 | M5Burner | Easy | 10 minutes |

---

## Additional Resources

### Community & Support
- **GitHub:** Most projects have active repos with issues and discussions
- **Discord:** Many projects have community Discord servers
- **Reddit:** r/flipperzero, r/esp32, r/raspberry_pi
- **Forums:** ESP32.com, Raspberry Pi forums

### Learning Resources
- **YouTube:** Numerous tutorial channels
- **Documentation:** Each project maintains docs (check GitHub)
- **Blogs:** Security researcher blogs often cover these tools

### Legal Disclaimer
**IMPORTANT:** These tools are for authorized security testing only. Unauthorized use of these devices and firmware may be illegal in your jurisdiction. Always:
- Obtain written permission before testing
- Only test networks you own or have explicit authorization to test
- Be aware of local laws regarding wireless security testing
- Use responsibly and ethically

---

## Version History

**Version 1.0** - October 2025
- Initial release
- Comprehensive hardware and firmware coverage
- Compatibility matrix
- Purchase recommendations

---

**Maintained by:** Pacific Northwest Computers  
**Contact:** suppor@pnwcomputers.com
**License:** Free to use for educational and professional purposes
