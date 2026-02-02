# 📖 Wireless Intrusion & Unauthorized Network Access

**Scenario ID:** IR-NET-001
**Severity:** High
**Context:** A "Rogue Access Point" (Evil Twin) is detected broadcasting your SSID, or an unauthorized physical device (e.g., LAN Turtle/Raspberry Pi) has been plugged into a wall port ("Plant Hack").

## 1. 🏗️ Log Aggregation & Visibility (Preparation)

Before you can respond, you must ensure the correct data is flowing into your SIEM (ELK/Wazuh/Splunk).

### Required Log Sources

| Source | Log Type | What we are looking for |
| :--- | :--- | :--- |
| **Wireless IDS (Kismet/Zeek)** | `alert` / `wireless` | New BSSID (MAC) broadcasting known SSID; Deauthentication frames; Signal strength spikes. |
| **DHCP Server** | `dhcpd` / `leases` | New MAC addresses requesting IPs; Hostnames that don't match naming conventions (e.g., `kali-linux`). |
| **Radius / NAC** | `auth.log` | Failed authentication attempts; MAC address spoofing alerts. |
| **Network Switches** | `SNMP` / `Syslog` | Port status changes (`UP/DOWN`); Unknown MAC on a secured port (Port Security violation). |

### Aggregation Configuration (Example: Rsyslog to SIEM)

*Ensure your listening stations (e.g., a Raspberry Pi running Kismet) forward logs to your central server.*

```bash
# /etc/rsyslog.d/50-remote.conf
# Forward all logs to the SIEM IP
*.* @192.168.1.50:514
```

## 2. 🕵️ Detection & Triage

**Trigger:** An alert fires in the SIEM indicating a "New BSSID" or "Unauthorized MAC."

### Step 1: Verification (Is it real?)

1.  **Check the MAC (BSSID):** Does the MAC address belong to your authorized Access Point vendor (e.g., Ubiquiti/Cisco)?
    * *Tool:* [Wireshark OUI Lookup](https://www.wireshark.org/tools/oui-lookup.html)
    * *Suspicious:* Generic Realtek/Intel chipsets often indicate a laptop/USB dongle, not an enterprise AP.
2.  **Analyze Signal Strength (RSSI):**
    * If the legitimate AP is far away (-80dBm) but the suspect BSSID is screaming loud (-30dBm), it is a local rogue device.
3.  **Check Channel Usage:**
    * Is the suspect AP on a channel your infrastructure *doesn't* use (e.g., Channel 6 when you only use 1 and 11)?

## 3. 🛡️ Response & Containment

**Objective:** Prevent users from connecting to the rogue device and locate the hardware.

### Immediate Actions

1.  **Issue Containment Deauths (Active Defense):**
    * *Note:* Only do this if authorized.
    * Use your WIDS/WIPS to send deauthentication frames to clients connected to the Rogue AP to force them off.
2.  **MAC Filtering / Port Shutdown:**
    * **Wireless:** Add the Rogue BSSID to your WIPS "Blocklist" to alert on any association attempts.
    * **Physical (Plant Hack):** If the device is plugged into a switch, identify the specific port via ARP/CAM tables and issue a `shutdown` command on that interface.

    ```bash
    # Example Cisco Switch Command
    Switch# configure terminal
    Switch(config)# interface gigabitethernet 0/12
    Switch(config-if)# shutdown
    ```

3.  **Physical Triangulation (Fox Hunting):**
    * Use a directional antenna (Yagi) or a mobile app (WiFi Analyzer) to physically locate the source of the signal.

## 4. 🔬 Log Review & Post-Mortem

After the threat is neutralized, analyze the logs to understand the scope.

### SIEM Queries (Review Process)

**Query 1: Who connected to the Rogue AP?**
Look for endpoints that requested an IP or authenticated right after the Rogue AP appeared.

```kql
# Kibana / ELK Query
event.category: "network" AND event.action: "connection_attempt" AND wireless.ssid: "Corporate-Wifi" AND NOT wireless.bssid: "YOUR-KNOWN-BSSIDS"
```

**Query 2: Did the attacker pivot? (Lateral Movement)**
Check if the "Plant" device scanned other internal IPs.

```kql
# Check for port scanning from the suspicious IP
source.ip: "192.168.1.105" AND destination.port: * AND event.count > 100
```

### Artifact Collection

* **PCAP:** Save the packet capture showing the "Evil Twin" beacon frames.
* **Photos:** If a physical device (e.g., WiFi Pineapple) was found, photograph its location and connections before removal.

---
*Part of the [Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)*
