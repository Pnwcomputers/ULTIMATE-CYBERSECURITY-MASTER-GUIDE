# 🏴‍☠️ Bus Pirate

## 📖 Description
The Bus Pirate is an open-source hacker multi-tool that talks to electronic components from a PC serial terminal. It eliminates the need to write custom code to interact with new chips. It acts as a universal bus interface, allowing you to communicate via protocols like I2C, SPI, UART, JTAG, and more directly from your computer.

## 🔗 Reference Links
* **Product Link:** [Bus Pirate v3.6 / v4 (SparkFun)](https://www.sparkfun.com/products/12942)
* **Reference Material:** [Official Bus Pirate Documentation](http://dangerousprototypes.com/docs/Bus_Pirate)
* **Cheat Sheet:** [Bus Pirate Cheat Sheet](http://dangerousprototypes.com/docs/Bus_Pirate_menu_options_guide)

## 🚀 Step-by-Step Example: Setup, Connect, and Use
**Scenario: Extracting firmware from an SPI EEPROM chip.**

### 1. Setup
* **Drivers:** Most modern OSs automatically install the required FTDI drivers.
* **Software:** You only need a serial terminal emulator. On Linux/macOS, install `screen` or `minicom`. On Windows, install PuTTY.
   ```bash
   sudo apt-get install screen
   ```

### 2. Connect
* **USB:** Plug the Bus Pirate into your PC via the mini-USB/micro-USB cable.
* **Wiring to Target:** Connect the Bus Pirate's wire harness to the SPI chip using a breadboard or test clips:
  * `GND` ➡️ Target `GND`
  * `3V3` ➡️ Target `VCC` (Power)
  * `CS` ➡️ Target `CS` (Chip Select)
  * `MISO` ➡️ Target `DO` (Data Out)
  * `MOSI` ➡️ Target `DI` (Data In)
  * `CLK` ➡️ Target `CLK` (Clock)

### 3. Use
* Open your terminal emulator to communicate with the Bus Pirate (default baud rate is usually 115200):
   ```bash
   sudo screen /dev/ttyUSB0 115200 8N1
   ```
* Press `Enter` to see the `HiZ>` prompt.
* Type `m` and press Enter to open the mode menu. Select the number for **SPI**.
* Accept the default speed and settings by pressing Enter through the prompts.
* Type `W` (capital W) to turn on the power supply to the chip.
* Type `[0x9f r:3]` to send the JEDEC Read ID command and read 3 bytes back. If connected correctly, it will return the manufacturer ID!
* Close `screen` and use `flashrom` to dump the entire chip automatically:
   ```bash
   flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware_dump.bin
   ```
