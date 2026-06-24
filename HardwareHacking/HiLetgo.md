# 🔎 HiLetgo 24MHz 8CH USB Logic Analyzer

## 📖 Description
The HiLetgo USB Logic Analyzer is a cost-effective, 8-channel, 24MHz logic analyzer. It is a Saleae Logic clone and is the absolute standard for beginner and intermediate hardware hacking, allowing you to monitor and decode digital signals.

## 🔗 Reference Links
* **Product Link:** [HiLetgo USB Logic Analyzer (Amazon)](https://www.amazon.com/dp/B009OXPEL2)
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
