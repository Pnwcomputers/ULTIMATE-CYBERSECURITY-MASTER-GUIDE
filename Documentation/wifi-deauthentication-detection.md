# Wi-Fi Deauthentication and Disassociation: Protocol Analysis and Defensive Detection

_Last reviewed: 2026-10-31 · IEEE 802.11 · Blue Team / wireless forensics_

> [!CAUTION]
> This guide covers **authorized, passive observation** and defensive analysis. Capture only where permitted; do not inject frames, disrupt client connectivity, collect credentials, or publish sensitive station identifiers. See [legal terms](../LEGAL.md), the [wireless field workflow](../Wardriving/field-workflow.md), and [data handling](../Wardriving/data-handling.md).

## Purpose

Learn to interpret 802.11 deauthentication and disassociation packets, separate legitimate network behavior from likely abuse, observe the frames using Wireshark/TShark or Kismet, and respond without inadvertently disrupting a network.

**Critical distinction:** The presence of a deauthentication packet is **not** proof of an attack. Neither its MAC address nor its reason code verifies the transmitter's true identity. Strong conclusions require channel-correct capture and corroboration with access-point (AP) and client logs.

## 1. How connection state works

~~~text
802.11 authentication (including SAE where appropriate)
       ↓
802.11 association or reassociation
       ↓
WPA/WPA2/WPA3 key establishment (e.g., EAPOL exchanges)
       ↓
Normal data and management traffic
       ↓
Disassociation and/or deauthentication when appropriate
~~~

- **Disassociation:** IEEE 802.11 management **subtype 10 (0x0a)**; ends association. Authentication state may remain.
- **Deauthentication:** IEEE 802.11 management **subtype 12 (0x0c)**; ends 802.11 authentication state. To rejoin, a station must complete the required authentication and association procedure.
- **EAPOL:** used in security key exchanges. It is **not** a deauthentication management frame.
- A local client Wi-Fi disconnect may occur **without** an over-the-air deauthentication packet. Channel hopping or packet loss can also hide packets from the sensor.
- 802.11v **BSS Transition Management** is different from a deauth frame; not every roam involves deauth.

### Legitimate uses and likely causes

| Scenario | What you might see | Corroboration |
| --- | --- | --- |
| Client shuts down or leaves network | Occasional client-initiated disconnect, or none on air | Client events |
| AP restarts, updates or radio reset | Several clients disconnect close together | Controller maintenance, boot and admin logs |
| Session idle timeout | AP-originated disconnect after inactivity | Idle/session policies |
| Roaming or steering | Reassociation, possibly cleanup of old connection | Old/new AP and roaming logs |
| Failed WPA handshake / 802.1X | Repeated retries and disconnects | Key negotiation, RADIUS, password and RF errors |
| Weak RF, driver or firmware problems | Connection losses, retries, timeouts | Client driver events, RF health, AP statistics |

**Do not assume** that high volume automatically means an attack: AP restart and configuration changes can disconnect many stations simultaneously.

## 2. How attackers misuse these frames

On networks or client associations **without negotiated Protected Management Frames (PMF)**, a transmitter can forge the apparent source MAC address of some management frames. An attacker can attempt to:

1. Cause repeated client disconnects (**denial of service**).
2. Disrupt several stations with broadcast-addressed or multiple targeted frames.
3. Induce reconnections as one step in a rogue AP / evil-twin attack.
4. Prompt a vulnerable connection to repeat observable authentication or EAPOL activity.

**A captured handshake is not equivalent to a recovered password.** Wi-Fi protocol-layer deauthentication is also **not** the same physical technique as RF noise jamming. No attack-generation instructions are needed to diagnose these behaviors.

## 3. Frame fields: what they prove (and do not prove)

| Field | Analyst's question | Caution |
| --- | --- | --- |
| Frame subtype | Is this **0x0c** deauth or **0x0a** disassoc? | Type alone cannot establish intent |
| Source (SA) and BSSID | Which device **claims** to have sent it? | Spoofable without appropriate protection |
| Destination (DA) | Individual target or group/broadcast recipient? | Broadcast is not automatically hostile |
| Reason code | What reason does the sender claim? | Not a verified cause or identity |
| Protected bit | Does the frame claim protected status? | Does not prove cryptographic validation or acceptance |
| Timestamp / frequency | Is behavior isolated or unusually repetitive? | Clock drift, channel hopping, and packet loss affect counts |
| Sequence, retry, RSSI | Do patterns differ from normal observations? | Suggestive only; not transmitter attribution |
| RSN capabilities | Is PMF offered or required? | AP advertisement is not proof that a given client negotiated PMF |
| Client and AP/controller logs | Did trusted endpoints accept or reject a disconnect? | Vary by vendor and must be time-aligned |

### Common reason codes (selected examples)

| Code | Broad meaning | Investigation tip |
| --- | --- | --- |
| 1 | Unspecified | Examine other evidence |
| 2 | Previous authentication no longer valid | Inspect session/security state |
| 3 | Sender leaving ESS/IBSS | Often normal; verify initiator |
| 4 | Disassociated due to inactivity | Check timeout policy |
| 5 | AP unable to handle associated stations | Check AP capacity/load |
| 6 | Class 2 frame from nonauthenticated station | Review protocol state |
| 7 | Class 3 frame from nonassociated station | Review association |
| 8 | Sender leaving BSS | Often normal; correlate roaming |
| 15 | Four-way handshake timeout | Check credentials, RF and security negotiation |
| 16 | Group-key handshake timeout | Inspect rekeying and compatibility |
| 23 | IEEE 802.1X authentication failed | Check RADIUS/EAP events |

This list is **not exhaustive**. Some descriptions explicitly concern disassociation. An invalid code can be caused by a bug; a valid code can be forged. The reason code is a claim, not an authentication mechanism.

## 4. PMF / IEEE 802.11w

Protected Management Frames (PMF) protect specified *robust* management frames—including deauthentication and disassociation—**once PMF has been negotiated and the relevant keys are established**.

- **Disabled:** unauthenticated forged disconnects are a realistic risk.
- **Capable/optional:** the AP supports PMF, but **individual client associations** may or may not use it.
- **Required:** protected association requires PMF-capable clients. Properly functioning clients reject unauthenticated spoofed robust-management disconnects after protection applies.
- **WPA3-Personal:** PMF is required for a normal WPA3-Personal association; mixed WPA2/WPA3 transition operation may include separately negotiated WPA2 connections with different protection.
- **Limits:** PMF is not a cure for jamming, RF disruption, all pre-association attacks, or every spoofable management-frame category.

Wireshark can reveal **advertised** RSN PMF capability fields (where present):

~~~wireshark
wlan.rsn.capabilities.mfpc == 1
wlan.rsn.capabilities.mfpr == 1
~~~

**MFPC** = capable; **MFPR** = required. Verify the station's *negotiated* PMF state using its association exchange and trusted AP/client information. Seeing an unprotected deauth that claims a PMF-required AP is suspicious **only in context**: the sensor may not have witnessed the actual association, and seeing a frame does not mean the client accepted it. Protected disconnect payloads might not reveal a plain-text reason code without decryption.

## 5. Capture prerequisites: avoid false negatives

To capture raw 802.11 management frames, use an **authorized monitor-mode Wi-Fi adapter**, supported chipset/driver, correct channel and band, plus adequate sensor placement. A typical **wired Ethernet capture, managed-mode laptop WLAN capture, port mirror, or VM virtual NIC does not contain the original over-the-air 802.11 management frames**. For Proxmox-based Snort/Wazuh monitoring, use an independent Wi-Fi sensor or AP/controller logs, then forward relevant *events* to the SIEM.

On Linux with an **extra, dedicated** compatible adapter, first verify:

~~~bash
iw dev
iw list
~~~

Confirm that **monitor** appears as a supported interface mode. The following example may disconnect an adapter's existing association and assumes a working **wlan1** radio and an authorized 2.4 GHz **channel 6** test AP. Replace names/channel for the actual hardware and legal regulatory domain.

~~~bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
sudo iw dev wlan1 set channel 6

# Passive, 120-second, fixed-channel capture:
sudo dumpcap -i wlan1 -a duration:120 -w authorized-wifi.pcapng

# Restore the dedicated adapter afterward, if needed:
sudo ip link set wlan1 down
sudo iw dev wlan1 set type managed
sudo ip link set wlan1 up
~~~

Some drivers/network managers require a different workflow. See [Wireshark WLAN capture setup](https://wiki.wireshark.org/CaptureSetup/WLAN). On Windows, Npcap/raw 802.11 support depends on driver and adapter; ordinary capture usually excludes management frames. A fixed-channel sensor is preferable to channel hopping when comparing event rates.

**Evidence:** record UTC start/stop, observer position, channel/frequency, adapter/driver, BSSID and PMF settings; preserve original capture and compute integrity hash:

~~~bash
sha256sum authorized-wifi.pcapng
~~~

## 6. Wireshark display filters

Paste **one expression at a time** in the Wireshark display filter bar:

~~~wireshark
wlan.fc.type_subtype == 0x0c
~~~

Deauthentication frames (subtype 12).

~~~wireshark
wlan.fc.type_subtype == 0x0a
~~~

Disassociation frames (subtype 10).

~~~wireshark
wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a
~~~

Both disconnect types.

~~~wireshark
(wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a) && wlan.bssid == aa:bb:cc:dd:ee:ff
~~~

Limit the scope to a **placeholder example BSSID**; replace with the authorized AP.

~~~wireshark
(wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a) && wlan.fc.protected == 0
~~~

Unprotected disconnect frames. **Not an attack verdict.**

~~~wireshark
eapol
~~~

Observe WPA key negotiation for relevant connection context; EAPOL alone is not evidence of a deauth attack.

**Review sequence:** timestamp → subtype → source/destination/BSSID → reason (if decodable) → protected flag → nearby authentication/association/EAPOL → AP/client logs → baseline. Use Wireshark's time sorting and **Statistics → I/O Graphs** to visualize bursts. If an unprotected frame is suspicious, verify that the *receiving* device actually disconnected, instead of relying on the claimed sender address.

### Read an existing PCAP with TShark (passive)

~~~bash
tshark -r authorized-wifi.pcapng \
  -Y 'wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a' \
  -T fields -E header=y \
  -e frame.time_epoch \
  -e wlan.fc.type_subtype \
  -e wlan.sa -e wlan.da -e wlan.bssid \
  -e wlan.fixed.reason_code -e wlan.fc.protected
~~~

Output is tab-separated field data. Empty reason codes on protected frames can be expected. Fields are verified in the [official Wireshark IEEE 802.11 field reference](https://www.wireshark.org/docs/dfref/w/wlan.html).

## 7. Kismet as a fixed wireless IDS sensor

Kismet supports passive wireless alerting with a suitable monitor-capable radio. For **detection**, configure stationary/fixed-channel observation and review the alert view and relevant PCAP/KismetDB logs. **Do not conflate this with** the inventory-oriented **wardrive overlay** in the [Kismet wardriving guide](../Wardriving/kismet.md).

| Kismet alert | What to do |
| --- | --- |
| **DEAUTHFLOOD** | Examine burst rate, recipients, sensor coverage, and AP event log |
| **BCASTDISCON** | Investigate group-directed disconnect behavior; verify maintenance/firmware |
| **DISASSOCTRAFFIC** | Compare station activity against association timeline; missed frames can create false positives |
| **NOCLIENTMFP** | Identify client advertising no PMF support; verify association and policy |
| **DISCONCODEINVALID** | Treat cautiously; current Kismet config may disable it as noisy/deprecated |

Check the [official Kismet alert documentation](https://www.kismetwireless.net/docs/readme/alerts/alerts/) and [current upstream alert configuration](https://github.com/kismetwireless/kismet/blob/master/conf/kismet_alerts.conf) for available alerts and defaults. **Kismet rate limits and packet deduplication can affect observed alert counts**; don't change settings indiscriminately on production sensors.

For SIEM integration, export Kismet alert metadata or AP/controller security events using the **version-supported** logging/API integration rather than guessing fixed event schemas. Normalize fields such as timestamp, sensor, channel, BSSID, claimed source, destination scope, event type, PMF state and confidence.

## 8. Distinguishing valid disconnects from attacks

There is no perfect packet-only authenticity test for **unprotected** Wi-Fi management frames; legitimate-looking MAC/reason values are spoofable. Use this evidence-driven procedure:

1. **Verify visibility:** monitor-mode frames, correct channel, synchronized clocks, capture coverage, and dropped-packet count.
2. **Classify frame:** deauth vs disassoc, DA/SA/BSSID, broadcast vs unicast, reason where visible, protected bit.
3. **Establish baseline:** expected disconnect rate for this site, AP, time and client population. **No universal frames/second threshold** proves an attack.
4. **Verify PMF:** beacon/association capabilities **plus negotiated per-client protection** and AP/client enforcement records.
5. **Correlate independent logs:** legitimate admin actions, AP restart, client shutdown, roaming, security/authentication failures, firmware glitches or RF interference.
6. **Investigate compound signs:** persistent bursts targeting several clients, no corresponding trusted AP actions, simultaneous rogue SSID/BSSID, repeated forced reconnects, client rejection of invalid frames, or multi-sensor anomalies.
7. **Record a confidence level:** normal/expected; likely misconfiguration/RF; suspicious; or confirmed (corroborated).

### Examples (illustrative, not real incidents)

| Observations | Working interpretation |
| --- | --- |
| One disconnect and matching AP idle-timeout log | **Likely legitimate** |
| Repeated reason 15 and AP/client key-handshake failures | **Likely RF, credential, or security-negotiation issue** |
| Many unprotected disconnects and sudden multi-client disruption; no AP admin action | **Suspicious**; investigate PMF and multiple sources |
| Claimed AP deauth rejected by a PMF-protected client, corroborated by client/AP security event | **Strong evidence of spoofing attempt** |
| Invalid reason codes during channel-hopping collection | **Inconclusive**; rerun fixed-channel, check device firmware |

Avoid equating arbitrary OUI, signal strength, sequence numbers, or any one disconnect code with the physical attacker's identity. Use separate observers only as supporting evidence.

## 9. Response and hardening

- Preserve original PCAP and AP/client logs, timestamps, hashes, and case notes; do not share neighboring stations' identifiers.
- Consider **PMF required** for compatible WPA2/WPA3 deployments; test IoT and legacy-client compatibility before changing production policy.
- Use WPA3 where clients support it; review WPA2/WPA3 transition-mode decisions and explicit PMF configuration.
- Update wireless AP/controller and client firmware; audit security policies and rogue networks.
- Use a fixed-channel wireless IDS for critical networks; align sensor alerts to Wazuh/SIEM with suppression for planned restarts.
- Do not “fight back” with deauth injection against suspected attackers or nearby networks.

## 10. Reproducible, non-disruptive lab

1. Set up an owned AP and owned client on a documented channel and PMF configuration.
2. Start fixed-channel passive capture and timestamp-aligned AP/client logs.
3. Toggle client Wi-Fi normally, then perform an approved AP administrative disconnect or restart.
4. Inspect actual frame subtypes, reasons, advertised/negotiated PMF, and client state; record when **no air frame appears**.
5. Repeat with compatible PMF-required settings to compare ordinary management-frame behavior **without frame forgery**.
6. Build a case report with evidence and alternative explanations; hash original logs and redact before publication.

## Troubleshooting

| Symptom | Likely issue |
| --- | --- |
| No 802.11 management frames | Managed/Ethernet capture, wrong channel/band, unsupported monitor-mode driver |
| Disconnect count unusually low | Channel hopping, sensor drop, deduplication, lack of observed transmission |
| Encrypted disconnect, missing reason | PMF protection can hide payload until decrypted |
| AP advertises PMF but clients still vulnerable | PMF optional vs actually negotiated |
| WIDS alert during legitimate reboot | Correlate change window, AP uptime and all-station effects |
| Proxmox/Ubuntu Snort sees no deauth | Wired IDS sensor has no Wi-Fi management layer; use Wi-Fi sensor or controller events |

## Related guides and authoritative references

**In this repository:**
- [Wardriving / passive survey principles](../Wardriving/README.md)
- [Kismet on Linux](../Wardriving/kismet.md)
- [Wireshark filters](./wireshark.md)
- [Wireless intrusion response](../IncidentResponse/network_intrusion.md)
- [Incident Response index](../IncidentResponse/README.md)
- [Wireless testing hardware](./WiFiMarauder_Guide.md)
- [Data and evidence handling](../Wardriving/data-handling.md)

**Upstream references:**
- [Wireshark IEEE 802.11 field reference](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [Wireshark monitor-mode setup](https://wiki.wireshark.org/CaptureSetup/WLAN)
- [Kismet wireless alerts](https://www.kismetwireless.net/docs/readme/alerts/alerts/)
- [Kismet maintained default alert configuration](https://github.com/kismetwireless/kismet/blob/master/conf/kismet_alerts.conf)

_Reviewed against available upstream documentation 2026-10-31. No claim is made that example capture commands were run on a particular adapter._

---

[Back to Documentation](./README.md) | [Wardriving](../Wardriving/README.md) | [Incident Response](../IncidentResponse/README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
