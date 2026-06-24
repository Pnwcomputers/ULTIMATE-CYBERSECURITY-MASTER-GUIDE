# 🏴‍☠️ Bit Pirate

## 📖 Description
*(Note: "Bit Pirate" usually refers to either customized firmware forks of the Bus Pirate or proprietary UART/SPI debugging jigs). It operates similarly to other multi-protocol interfaces by providing a bridge between your computer and low-level hardware buses for embedded systems hacking.*

## 🔗 Reference Links
* **Community Forums:** [Hackaday](https://hackaday.com/) / [EEVblog](https://www.eevblog.com/forum/)

## 🚀 Step-by-Step Example: Setup, Connect, and Use
**Scenario: Gaining a root shell via a UART debug port on an IP camera.**

### 1. Setup
* **Drivers:** Install CH340 or FTDI drivers depending on the chip used by your Bit Pirate interface.
* **Software:** Install PuTTY (Windows) or `screen` (Linux/macOS).

### 2. Connect
* **USB:** Plug the device into your PC.
* **Wiring to Target:** Use a multimeter to identify `GND`, `TX`, and `RX` on your target device's debug header. Connect them to the Bit Pirate:
  * Bit Pirate `GND` ➡️ Target `GND`
  * Bit Pirate `RX` ➡️ Target `TX` (Crucial: RX goes to TX!)
  * Bit Pirate `TX` ➡️ Target `RX`

### 3. Use
* Open your serial terminal using the target device's expected baud rate (115200 is the most common for IoT devices):
   ```bash
   screen /dev/ttyUSB0 115200
   ```
* Power on the IP camera.
* Watch the terminal screen. You should see the bootloader (like U-Boot) scrolling text as the device initializes.
* When it finishes booting, press `Enter`. If a `#` or `$` prompt appears, you have successfully dropped into a root hardware shell!

---
