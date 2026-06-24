# 🦡 GreatFET One (with Add-On Boards)

## 📖 Description
The GreatFET One is the next-generation GoodFET, designed by Great Scott Gadgets. It is an extensible, open-source hardware tool tailored for hardware hackers. With its add-on boards (often named after flowers like Daffodil), it can be used for logic analysis, I2C/SPI manipulation, JTAG debugging, and advanced USB reverse engineering.

## 🔗 Reference Links
* **Product Link:** [GreatFET One (Great Scott Gadgets)](https://greatscottgadgets.com/greatfet/one/)
* **Reference Material:** [GreatFET Wiki & Documentation](https://github.com/greatscottgadgets/greatfet/wiki)
* **Software Repo:** [GreatFET GitHub](https://github.com/greatscottgadgets/greatfet)

## 🛠️ Setup & Configuration
1. **Prerequisites:** Ensure you have Python 3 installed.
2. **Install GreatFET Tools:**
   Install the host software via pip:
   ```bash
   pip3 install --upgrade greatfet
   ```
3. **Firmware Update:** Plug in the GreatFET One and update to the latest firmware:
   ```bash
   greatfet_update
   ```
4. **Verify Connection:**
   ```bash
   greatfet_info
   ```

## 🚀 Use & Tutorials
### Tutorial: Interfacing with I2C using GreatFET
1. Connect your target device's SDA, SCL, and GND pins to the corresponding GreatFET I2C pins.
2. Scan the I2C bus to find connected devices:
   ```bash
   greatfet_i2c -z
   ```
3. Read data from a specific address (e.g., address 0x50):
   ```bash
   greatfet_i2c -a 0x50 -r 256 -f dump.bin
   ```
### Using Add-on Boards
If using a custom add-on board (Neighbors), plug it into the GreatFET headers. The GreatFET software allows you to map custom GPIO pins dynamically depending on the neighbor board attached.

---
