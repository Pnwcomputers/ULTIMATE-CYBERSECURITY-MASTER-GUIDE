# 🔎 HiLetgo 24MHz 8CH USB Logic Analyzer

## 🎯 Purpose
Budget-friendly Saleae Logic clone logic analyzer (24MHz/8ch) for capturing and decoding UART, SPI, I2C, and other digital protocols using the open-source sigrok/PulseView software - the entry-level standard for hardware security work.

## ⚙️ Function
8 channels at up to 24MHz; works with PulseView (sigrok) for protocol decoding. Primary use case: identifying baud rate and sniffing UART boot logs from embedded devices. Requires Zadig WinUSB driver on Windows. Cost-effective alternative to LA1010 for UART and slow-bus analysis.

## 🏆 Goal
Decode unknown digital communication from a target embedded device - identifying baud rates, reading UART boot logs, and analyzing protocol traffic between chips.

## 📋 When to Use
- Finding the baud rate of an unknown UART port (boot log sniffing)
- Verifying I2C/SPI signal timing for Bus Pirate or GreatFET connections
- Low-cost entry-level logic capture when 24MHz and 8 channels are sufficient
- Open-source toolchain preferred (sigrok/PulseView) over proprietary KingstVIS

## 📖 Description
The HiLetgo USB Logic Analyzer is a cost-effective, 8-channel, 24MHz logic analyzer. It is a Saleae Logic clone and is the absolute standard for beginner and intermediate hardware hacking, allowing you to monitor and decode digital signals.

## 🔗 Reference Links
* **Product Link:** [HiLetgo USB Logic Analyzer (Amazon)](https://www.amazon.com/s?k=HiLetgo+USB+Logic+Analyzer)
* **Required Software:** [sigrok / PulseView](https://sigrok.org/wiki/Downloads)

## 🚀 Step-by-Step Example: Setup, Connect, and Use
**Scenario: Finding the baud rate and sniffing the boot logs of an unknown UART port.**

### 1. Setup
* **Software:** Download and install **PulseView** (from the sigrok suite).
* **Driver (Windows Only):** Plug in the analyzer. Open **Zadig** (often included with PulseView). Select "Unknown Device" (or Saleae Logic) from the drop-down, select the `WinUSB` driver, and click **Replace Driver**.

### 2. Connect
* **USB:** Plug the device into your PC.
* **Wiring to Target:** Connect the female jumper wires to your target board's UART header.
  * Logic Analyzer `GND` ➡️ Target `GND`
  * Logic Analyzer `CH0` ➡️ Target `TX` (We want to sniff what the board is transmitting)

### 3. Use
* Open **PulseView**.
* At the top, select the driver: Choose `fx2lafw` or `Saleae Logic`. The device should connect.
* Set the Sample Rate to `2 MHz` and the Sample Count to `1 M samples`. (UART is slow, so 2MHz is plenty).
* Click the **Run** button (top left).
* Immediately turn on the power to your target device. PulseView will capture the signals and stop.
* Zoom in on the timeline using your scroll wheel until you see distinct square waves.
* Click the **Add Protocol Decoder** button (looks like a yellow/blue tag at the top). Search for **UART** and double-click it.
* A "UART" tag will appear on the left side of the timeline. Click it, set the `RX` channel to `CH0`, and guess the baud rate (try `115200` first).
* Look at the top of the waveform. If you guessed the correct baud rate, you will see readable ASCII text (like "Booting Linux..."). If it looks like gibberish, click the UART tag and try a different baud rate (like `9600` or `57600`).

---

## Related Files
- [README.md](README.md) - HardwareHacking section index: all tools and chapter guide
- [LA1010.md](LA1010.md) - Higher-performance logic analyzer (100MHz/16ch, KingstVIS) for faster buses needing more channels
- [BitPirate.md](BitPirate.md) - Connect a UART adapter to the TX pin you identified with the HiLetgo to interact with the shell
- [BusPirate.md](BusPirate.md) - Use alongside Bus Pirate to verify SPI/I2C signals at the hardware level
- [Chapter2.md](Chapter2.md) - Electrical fundamentals: UART framing, baud rate calculation, and logic threshold levels
