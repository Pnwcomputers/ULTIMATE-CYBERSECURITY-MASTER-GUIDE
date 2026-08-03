# The Microcontroller Workflow

While your Linux laptop can do everything, these devices excel at specific parts of the wireless assessment lifecycle due to their portability and specialized chipsets.

### 1. Passive Reconnaissance & Discovery (The Pwnagotchi)
The Pwnagotchi is an AI-driven, passive reconnaissance tool powered by a Raspberry Pi Zero W.

*   **Workflow Role:** Passive handshake collection.
*   **How it Works:** It uses reinforcement learning to intelligently navigate Wi-Fi channels, looking for the most active networks. It listens for EAPOL packets (the 4-way WPA/WPA2 handshakes) when devices authenticate, and captures them as PCAP files. It also actively deauthenticates clients to force those handshakes, learning over time which strategies yield the most captures.
*   **Lab Application:** Set it up in your lab, let it run, and it will passively harvest handshakes from your test access points without manual intervention. You then offload those PCAPs to your main machine for offline dictionary attacks or analysis.

### 2. Active Discovery & Injection (ESP32 Marauder / Flipper Zero)
The ESP32 microcontroller, especially when running the Marauder firmware (which can be run natively on an ESP32 board, a Cardputer, or as an add-on module for the Flipper Zero), is your active engagement tool.

*   **Workflow Role:** Active scanning, deauthentication, beacon spamming, and evil portal creation.
*   **How it Works:** Marauder leverages the ESP32's Wi-Fi capabilities to perform tasks that typically require a full Linux setup. It can aggressively scan for APs and clients, perform targeted or broadcast deauthentication attacks to knock clients off a network (often used in conjunction with handshake capture), and create "Evil Portals" (captive portals that impersonate legitimate networks to capture credentials).
*   **Lab Application:** You can use your M5Stack Cardputer (running Marauder via the Bruce firmware or M5 Launcher) or your Flipper Zero to actively stress-test your MikroTik router. For instance, you can launch a deauthentication attack against a test client connected to the MikroTik and observe how the router handles the sudden influx of management frames and client disconnections in your traffic capture.

### 3. Sub-GHz Exploration (Flipper Zero + CC1101)
The Flipper Zero's built-in Sub-GHz radio, often augmented by an external CC1101 module, operates on completely different frequencies than standard Wi-Fi (typically around 315 MHz, 433 MHz, 868 MHz, or 915 MHz).

*   **Workflow Role:** Analyzing and interacting with low-power, short-range RF devices (like older garage doors, wireless sensors, and some IoT devices).
*   **How it Works:** The CC1101 allows you to scan for active frequencies, capture raw signals, and, depending on the protocol, decode or replay those signals.
*   **Lab Application:** This won't interact with your MikroTik Wi-Fi setup directly, as it's not Wi-Fi. However, if you have IoT devices in your lab that use Sub-GHz communication, you can use the Flipper + CC1101 to capture their transmissions and analyze the signal structure.

## Tying It Back to Your MikroTik Setup

Your MikroTik router is still the central hub for analyzing the effects of these tools.

*   **Baseline:** Start a clean packet capture on the MikroTik.
*   **Attack:** Launch a specific attack using Marauder (e.g., beacon spamming) or let the Pwnagotchi run its deauth cycles.
*   **Analyze:** Stop the capture and analyze the PCAP file. You'll be able to see exactly what those devices are broadcasting—the flood of fake beacons, the specific structure of the deauthentication frames, and how the target devices (and the router itself) respond at the protocol level.

This hardware-focused approach allows you to quickly deploy attacks and captures without opening a terminal, while your MikroTik provides the ground-truth data on what is actually happening in the air.

## Automated Distributed Workflow Setup

This section details how to set up an automated, distributed workflow shifting from manual laptop tools to microcontrollers for active noise and passive harvesting, utilizing the Command Hub for monitoring.

### Phase 1: Automated Passive Harvesting (The Pwnagotchi)

The Pwnagotchi is designed to run completely autonomously, acting as a passive sensor that collects handshakes.

1.  **Configuration:** Configure the Pwnagotchi to target specific SSIDs or channels relevant to your audit scope, rather than blindly hopping across all channels.
2.  **Deployment:** Power it via a USB power bank and place it in the physical area you are auditing. It will autonomously deauth clients (using its onboard Wi-Fi chip) and capture the resulting 4-way handshakes as they reconnect.
3.  **Automated Extraction:** Pwnagotchis store captures as standard `.pcap` files in `/root/handshakes/`. Set up a simple bash script on your Linux laptop to automate retrieval:
    *   Connect the Pwnagotchi to your laptop via USB (it enumerates as a network interface).
    *   Use an `rsync` or `scp` script over SSH to automatically pull down all new `.pcap` files from the Pwnagotchi to a specific directory on your laptop for offline cracking (e.g., using `hashcat`).

### Phase 2: Active Targeted Attacks (ESP32 Marauder & Flipper Zero)

ESP32 devices running Marauder are used for active engagement to force events captured by the MikroTik or Pwnagotchi.

1.  **Distributed Deauthentication:** Flash Marauder onto standalone ESP32s or the Flipper's Wi-Fi Devboard to handle deauthentication.
2.  **Targeted Execution:** Through the Marauder interface (UI or serial CLI), select a specific AP or client MAC address and launch a continuous deauth attack.
3.  **API / Scripting:** Connect an ESP32 to your laptop via USB and write a Python script that sends serial commands (e.g., `scanap`, `select -a <index>`, `attack -t deauth`) to automate the attack phase without relying on the laptop's built-in Wi-Fi card.

### Phase 3: The Central Monitor (MikroTik & Laptop)

The laptop and MikroTik router act as "ground truth" observers.

1.  **MikroTik Packet Sniffer:** Set the MikroTik router to perform full packet capture on its wireless interfaces.
2.  **Live Streaming to Wireshark:** Configure the MikroTik to stream packet captures over the network using the TZSP protocol directly to the laptop's IP address.
    *   Open Wireshark on the Linux laptop and listen on the interface receiving the stream.
3.  **Analysis:** View the wireless environment live on the laptop. Filter for deauth frames (`wlan.fc.type_subtype == 0x0c`) coming from ESP32s, watch clients disconnect, and verify if Protected Management Frames (802.11w PMF) mitigate attacks.

## Streaming Packet Captures via TZSP

This section details how to configure the MikroTik router to stream wireless packet captures to Wireshark on the laptop using TZSP.

### 1. Prepare your Linux Laptop
TZSP sends data over **UDP port 37008** by default. Open this port to receive the stream.

Using UFW as an example:
```bash
sudo ufw allow 37008/udp
```
Make a note of your laptop's current IP address on the network (e.g., `192.168.88.50`).

### 2. Configure the MikroTik Sniffer
Connect to your MikroTik via SSH or the WinBox terminal. Configure the router's sniffer tool to target the specific wireless interface and point the stream to your laptop's IP.

**Warning: Never set the capture interface to 'all' — sniffing the TZSP packets you are transmitting creates a massive feedback loop that will crash the router.**

Run the following commands:
```text
/tool sniffer
set streaming-enabled=yes streaming-server=192.168.88.50 interface=wlan1
```
*(Ensure you replace `192.168.88.50` with your laptop's actual IP, and `wlan1` with the wireless interface you are auditing).*

### 3. Start the Wireshark Listener
Before the MikroTik starts sending data, get Wireshark ready.

1. Open Wireshark on your laptop.
2. Select the network interface that connects you to the MikroTik (e.g., `eth0` or your primary LAN interface).
3. Start the capture.
4. In the display filter bar at the top, type `tzsp` and hit Enter to filter out standard background traffic.

### 4. Execute the Stream
Return to your MikroTik terminal and start the capture engine:
```text
/tool sniffer start
```

You will immediately see packets flood into Wireshark. When you are done analyzing, remember to run `/tool sniffer stop` on the MikroTik to prevent unnecessary CPU load on the router.

## Wireshark Display Filters

Here are the critical display filters for analyzing wireless lab attacks from the TZSP stream.

### 1. Deauthentication Attacks (Marauder)
*   **The Filter:** 
    ```text
    wlan.fc.type_subtype == 0x000c
    ```
*   **What to look for:** A massive, rapid spike of these frames in your capture. If the `Destination` is `ff:ff:ff:ff:ff:ff`, it's a broadcast deauth targeting everything on that BSSID. If it's a specific MAC, it's a targeted attack.

### 2. The 4-Way Handshake (Pwnagotchi)
*   **The Filter:** 
    ```text
    eapol
    ```
*   **What to look for:** A clean sequence of four packets (Message 1 of 4, Message 2 of 4, etc.) passing between the AP and the client MAC address.

### 3. Beacon Spam / Rickroll Attacks (Marauder)
*   **The Filter:** 
    ```text
    wlan.fc.type_subtype == 0x0008
    ```
*   **What to look for:** Look in the `SSID` column for a sudden explosion of randomized names, or sequential lists (like the lyrics to "Never Gonna Give You Up").

### 4. Isolating a Specific Device
*   **The Filter:** 
    ```text
    wlan.addr == XX:XX:XX:XX:XX:XX
    ```
*   **Pro-Tip for the Lab:** Combine this with other filters using `&&`. For example, to see only the deauth frames hitting your specific test device, use: `wlan.fc.type_subtype == 0x000c && wlan.addr == XX:XX:XX:XX:XX:XX`

### 5. Filtering out the MikroTik Overhead (TZSP)
*   **The Filter:**
    ```text
    tzsp && wlan
    ```
*   **What it does:** Ensures Wireshark only displays packets that have both a TZSP header *and* a decoded 802.11 payload, cleanly stripping out any background Ethernet or standard IP traffic on your laptop's capturing interface.
