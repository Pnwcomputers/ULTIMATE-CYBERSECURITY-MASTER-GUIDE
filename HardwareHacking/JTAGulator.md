# 🕷️ JTAGulator

## 📖 Description
The JTAGulator is an open-source hardware tool created by Joe Grand that simplifies the discovery of on-chip debug (OCD) interfaces, specifically JTAG and UART. It brute-forces all possible permutations to identify the correct pinout of a target device.

## 🔗 Reference Links
* **Product Link:** [JTAGulator (Parallax / Grand Idea Studio)](https://grandideastudio.com/jtagulator/)
* **Reference Material:** [JTAGulator GitHub & Documentation](https://github.com/grandideastudio/jtagulator)

## 🚀 Step-by-Step Example: Setup, Connect, and Use
**Scenario: Brute-forcing an unknown 5-pin header to find the JTAG debugging interface.**

### 1. Setup
* **Software:** No custom drivers are usually needed; the device acts as a standard USB serial port. Use a terminal emulator like `screen`, `minicom`, or PuTTY.

### 2. Connect
* **USB:** Connect the JTAGulator to your computer via mini-USB.
* **Wiring to Target:** You have an unknown 5-pin row on a router's motherboard.
  * Use a multimeter to find the `GND` pin on the target board and connect it to the JTAGulator's `GND`.
  * Connect the remaining 4 unknown pins to the JTAGulator's `CH0`, `CH1`, `CH2`, and `CH3`.

### 3. Use
* Open your serial terminal to interface with the JTAGulator (115200 baud):
   ```bash
   screen /dev/ttyUSB0 115200
   ```
* **Set Voltage:** Type `V` to set the target voltage (VADJ). Enter the voltage of your target board (e.g., `3.3`). *Warning: Always verify target logic voltage with a multimeter first to avoid frying it!*
* **Select Mode:** Type `J` to enter JTAG mode.
* **Start Scan:** Type `I` to begin an IDCODE scan.
* When prompted, enter the number of channels you are using (in this case, `4`).
* Press Spacebar to begin. The JTAGulator will rapidly test permutations.
* When it finds the correct JTAG configuration, it will output the mapping on your screen (e.g., `TDI: CH0, TDO: CH1, TCK: CH2, TMS: CH3`). You can now hook up a standard JTAG debugger to those pins.

---
