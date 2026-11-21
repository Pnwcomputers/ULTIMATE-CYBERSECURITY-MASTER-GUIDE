# Counter-Surveillance, Rogue Wireless Devices & Defensive Field Tactics

_Reviewed: 2026-11-21. This is a defensive threat-model and lab-validation guide, not evidence that a given device or network is compromised._

> [!CAUTION]
> **Authorized investigation only.** Identifying nearby devices, recording Wi-Fi/BLE frames, scanning a network or examining packet captures may expose private identifiers. Scope sensors and retention before collecting. Do not retaliate by deauthenticating, jamming, spoofing or attacking suspected equipment. See [Legal Notice](../LEGAL.md).

## Purpose & Threat Model

Small security-test devices are easy to conceal, but **a device's presence, branding or radio signature does not prove malicious use**. Focus on observable behavior and protected assets instead of trying to identify an operator by appearance. The same hardware can perform passive inventory, benign lab demonstrations or intrusive active operations depending on its firmware, setup and authorization.

| Platform / Tool | Potential Observable Behavior | Recommended Countermeasure | What You Cannot Conclude |
|---|---|---|---|
| [Pwnagotchi](./pwnagotchi_cheatsheet.md) | Probe/association activity, deauth bursts in active configurations, handshake collection | PMF-capable AP/client, fixed-channel WIDS, correlate AP logs | Unique hardware attribution from a frame |
| [FancyGotchi](./fancygotchi-pwnagotchi.md) | Pi theme/display itself creates no new radio signature; independent CYD firmware differs | Identify **underlying** hardware and configured image | "FancyGotchi" automatically means an attack |
| [Bjorn](./bjorn_pi.md) | Service discovery, repeated login failures, SMB/SSH/FTP requests, unusual data transfers | 802.1X/NAC, internal ACLs, host logging, EDR, Zeek/Suricata | That an e-ink Pi caused an event |
| [Piglet Wardriver](../Wardriving/piglet.md) | Wi-Fi survey sightings, GPS-tagged local records; mesh modes transmit | Minimize sensitive SSIDs, review configuration, protect logs | Passive network discovery equals intrusion |
| [Evil-M5](./evil_m5.md) | Rogue AP/captive-portal impersonation, probe observation, selected deauth/USB behaviors | EAP-TLS/PMF where supported, rogue AP monitoring, endpoint policy | A single SSID match proves an evil twin |
| [Flipper Zero / Bruce / Marauder](./flipper_zero_guide.md) | Radio activity across firmware-specific bands and modules | Device/protocol-specific sensors, physical controls and secure pairing | All firmware functions are available on every board |
| Unknown USB Ethernet or Wi-Fi device | New switch MAC/LLDP/DHCP, rogue DHCP/DNS or new AP | 802.1X/NAC, switch logs, DHCP snooping, port security | MAC/vendor OUI identifies an attacker |

### Observation Layers & Gaps

| Sensor | Can See | Cannot Reliably See |
|---|---|---|
| Wi-Fi monitor radio + Wireshark | 802.11 beacons, probes and unencrypted management frames on **observed channels** | Every channel, encrypted payloads, unseen source identities |
| Kismet/nzyme WIDS | Radio inventory & behavioral detections with correct datasources | All RF activity with one card/hopping source |
| Ethernet TAP/SPAN + Wireshark/Zeek | In-scope wired link traffic, ARP/DHCP/DNS, unusual service flows | Off-link traffic, unrelated WLAN management frames |
| Switch controller/NAC | Port, MAC movement, authorization, VLAN assignment | Over-the-air RF activity |
| AP/controller logs | Associations, PMF state, BSSID/channel and reason events | Proof of transmitter from spoofable radio identifiers |
| DNS/IdP/EDR logs | Resolver changes, abnormal destinations, login and process events | Hidden encrypted DNS or air-layer-only activity without endpoint signals |

## Countermeasures By Scenario

| Scenario | What to Inspect | Protection & Response |
|---|---|---|
| Repeated disconnections | 802.11 deauth/disassoc counts, AP logs, PMF negotiation, RSSI/channel interference | Require PMF where practical; improve RF channel planning; investigate jamming separately |
| Lookalike SSID / rogue AP | BSSID, security suite, RSN/PMF fields, AP/controller allowlist, trusted certificate | WPA-Enterprise EAP-TLS with validated server certificates, disable unsafe autojoin |
| Suspicious captive portal | DNS/HTTP redirects, TLS certificate errors, captive portal policy | Use known official domain, managed profiles, disable auto-connect, user reporting |
| Unexpected Bluetooth/BLE device | Owned-beacon inventory and randomized address behavior | Disable unneeded discoverability, use secure pairing, avoid identity assertions |
| New wired node | Switch port, LLDP, DHCP lease, 802.1X auth and MAC move | Disable unused ports, restrict access VLAN and management |
| Repeated password attempts | SSH/SMB/IdP logs, source rate, authorization | MFA, account lockout design, conditional access and endpoint hardening |
| DNS hijack symptoms | DHCP option 6, RA/RDNSS, gateway/resolver changes, certificate errors | Approved recursive resolvers, protective DNS, DHCP snooping and RA guard |

## Wireshark Evidence Matrix

These are **display filters**, not capture BPF expressions. A match is a starting point for analysis, never confirmation of a malicious event. Capture only from a physically visible radio/TAP/mirror interface; ordinary Ethernet promiscuous mode does not grant wireless coverage.

| Scenario | Display Filter | Validation |
|---|---|---|
| Wi-Fi deauthentication | \`wlan.fc.type_subtype == 0x0c\` | Correlate rate, channel, AP state, PMF and logs |
| Disassociation | \`wlan.fc.type_subtype == 0x0a\` | Could reflect routine roaming |
| AP beacons | \`wlan.fc.type_subtype == 0x08\` | Compare security information with known AP inventory |
| ARP traffic | \`arp\` | Check gateway-to-MAC consistency on owned LAN |
| DHCP traffic | \`dhcp || bootp\` | Compare server identity/options with authorized DHCP |
| DNS transactions | \`dns\` | Compare resolver address, question/answer and trusted logs |
| IPv6 router advertisements | \`icmpv6.type == 134\` | Compare legitimate router link-layer identity |
| VLAN tags | \`vlan\` | Tags may be removed by capture NIC, switch or driver |

For repeatable filter syntax, use the [Wireshark Master Filters](./wireshark-master-filters.md), [Field Cheat Sheet](./wireshark-cheatsheet.md) and [Advanced Capture Guide](./wireshark.md). Source references: [Wireshark WLAN fields](https://www.wireshark.org/docs/dfref/w/wlan.html), [ARP fields](https://www.wireshark.org/docs/dfref/a/arp.html) and [802.1Q fields](https://www.wireshark.org/docs/dfref/v/vlan.html).

### Offline TShark Lab

Use an **already collected, authorized synthetic capture**. This example does not contact a target.

```bash
tshark -r ./owned-lab.pcapng -Y 'wlan.fc.type_subtype == 0x0c' \
  -T fields -e frame.time -e wlan.bssid -e wlan.sa -e wlan.da
tshark -r ./owned-wired-lab.pcapng -Y 'arp || dns || dhcp'
sha256sum ./owned-lab.pcapng ./owned-wired-lab.pcapng
```

The files and commands are examples. For missing files, create them from a controlled lab or use an official training dataset with suitable permission.

## Field Assessment & Incident Procedure

1. **Define scope & consent:** list approved APs, stations, VLANs, radio channels, buildings, dates and retention limit.
2. **Establish baseline:** authorized BSSIDs, SSID/security/PMF, switchport inventory, expected DNS/gateway and normal login rate.
3. **Select sensors:** fixed-channel wireless receiver, managed-switch SPAN or rated TAP, plus AP/IdP/DNS logs. Measure blind spots.
4. **Observe before intervening:** note anomalous frames and timing, verify sender claims are spoofable, correlate host/controller evidence.
5. **Contain safely:** disable unauthorized switch ports through change control; quarantine untrusted clients; correct AP and resolver settings.
6. **Recover:** reset compromised credentials/sessions if warranted, update firmware, apply PMF/EAP-TLS/segmentation and validate monitoring.
7. **Report:** clearly separate observed behavior, suspected mechanism, attribution confidence and untested hypotheses.

## What Actually Blocks & What Merely Detects

- **PMF / 802.11w** protects certain robust Wi-Fi management frames *after association* when both sides negotiate it. WPA3 normally requires PMF; some mixed WPA2/WPA3 transition deployments permit clients without full protection. PMF does **not stop radio jamming**, all pre-association spoofing, rogue SSIDs or every denial-of-service mechanism.
- **WIDS** alerts on radio behavior; it does not create a protective RF shield. Automatic deauthentication-based "counterattacks" are not a recommended remedy.
- **VLAN/ACL controls** restrict reachable services **after network entry**; they do not eliminate RF-layer deauth or stop a genuine credential-phishing page by themselves.
- **TLS/certificate validation** protects application sessions against many MITM and DNS redirection attempts but cannot compensate for a user ignoring certificate errors or installing a malicious root CA.
- **DNSSEC** authenticates eligible DNS answers when a validator and properly signed chain are used; **DoH/DoT encrypt the client–resolver path**. They address distinct problems.

## Test Cases & Acceptance

| Test | Expected Observation | Acceptance |
|---|---|---|
| Authorized AP reboot | Some client disconnects in AP logs | Not misclassified as attack solely from frame count |
| Synthetic WIDS deauth event / provided PCAP | Rule alerts with correct timestamp/channel | No unwanted client disruption |
| Unauthorized DHCP server on **isolated** test VLAN | DHCP snooping / IDS observation | Production VLAN unaffected |
| Rogue device plugged into lab access port | NAC denies or quarantine VLAN assigned | No route to trusted management |
| Alternate resolver offered to test client | Alert on DHCP/DNS configuration change | Trusted policy preserved |
| BLE address rotates on owned beacon | Inventory retains uncertainty, no identity inference | Privacy-safe logging |

## Related Guides & Primary References

- [Wi-Fi Deauthentication & Disassociation](./wifi-deauthentication-detection.md)
- [MITM Detection & Prevention](./mitm-detection-prevention.md)
- [DNS Hijacking & Secure DNS](./dns-hijacking-secure-dns.md)
- [Segmentation, DMZ, ACLs & VLANs](./network-segmentation-dmz-acl-vlan.md)
- [LAN TAPs, SPAN & Packet Visibility](./network-taps-and-packet-visibility.md)
- [BLE Passive Sniffing & Privacy](./bluetooth-passive-scanning-sniffing.md)
- [Kismet + Wazuh Wireless IDS](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md)
- [CISA Network Segmentation Guidance](https://www.cisa.gov/sites/default/files/2025-01/joint-guidance-enhanced-visibility-hardening-guide-for-comms-infrastructure-508c_0.pdf)
- [IEEE 802.11 PMF Operational Notes (Cisco)](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/26-1/configuration-guide/wl-26-1-cg/configuring-802-11-w/802-11w-pmf.html)

---

[Documentation Index](./README.md) | [Incident Response](../IncidentResponse/README.md) | [Legal Notice](../LEGAL.md)
