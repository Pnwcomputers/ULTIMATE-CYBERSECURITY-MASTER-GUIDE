# 🏴‍☠️ Bus Pirate

## 📖 Description
The Bus Pirate is an open-source hacker multi-tool that talks to electronic components from a PC serial terminal. It eliminates the need to write custom code to interact with new chips. It acts as a universal bus interface, allowing you to communicate via protocols like I2C, SPI, UART, JTAG, and more directly from your computer.

## 🔗 Reference Links
* **Product Link:** [Bus Pirate v3.6 / v4 (SparkFun)](https://www.sparkfun.com/products/12942) / [Dangerous Prototypes](http://dangerousprototypes.com/docs/Bus_Pirate)
* **Reference Material:** [Official Bus Pirate Documentation](http://dangerousprototypes.com/docs/Bus_Pirate)
* **Cheat Sheet:** [Bus Pirate Cheat Sheet](http://dangerousprototypes.com/docs/Bus_Pirate_menu_options_guide)

## 🛠️ Setup & Configuration
1. **Connect:** Plug the Bus Pirate into your PC via USB.
2. **Drivers:** Most modern OSs (Linux, macOS, Windows 10+) will automatically install FTDI drivers. On Linux, it typically mounts at `/dev/ttyUSB0`.
3. **Serial Connection:** Connect using a terminal emulator (like `minicom`, `screen`, or PuTTY):
   ```bash
   # Connect via screen on Linux/macOS
   sudo screen /dev/ttyUSB0 115200 8N1
   ```
4. **Initial Setup:** Once connected, type `?` to view the help menu and `m` to change the mode to your desired protocol (e.g., SPI, I2C).

## 🚀 Use & Tutorials
### Tutorial: Dumping an EEPROM via SPI
1. Enter the mode menu by typing `m` and select **SPI**.
2. Set the speed and configuration (defaults are usually fine for basic EEPROMs).
3. Turn on the power supply to the chip by typing `W` (capital W).
4. **Identify the chip:** Use standard SPI commands (e.g., `[0x9f r:3]`) to read the JEDEC ID of the flash memory chip.
5. Use flashrom for automated dumping:
   ```bash
   flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware_dump.bin
   ```
