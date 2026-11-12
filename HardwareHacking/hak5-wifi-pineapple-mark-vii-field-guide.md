# Hak5 WiFi Pineapple Mark VII — Authorized Wireless Assessment Field Guide

## Purpose & Constraints
The WiFi Pineapple Mark VII is a dedicated Wi-Fi security assessment platform. This guide focuses on passive discovery, authorized AP inventory, controlled test SSIDs, wireless policy checks, and defensive detection validation. Wireless transmissions can affect systems outside the intended site: obtain written authorization for channels, bands, SSIDs, location, and active features. **Do not use rogue-AP impersonation, credential capture, deauthentication, or traffic interception against third parties.**

## Preflight
1. Confirm the exact Mark VII hardware, power supply, firmware, and supported radio capabilities.
2. Back up settings and evidence; use official Hak5 firmware and follow the model-specific upgrade procedure.
3. Create a dedicated management password and restrict management access to the assessment operator.
4. Record local regulatory domain, permitted channels, client-owned SSIDs/BSSIDs, approved time window, and a stop contact.
5. Use a separate lab AP and client; never assume a signal is in scope because it is visible.
6. Synchronize device clock and define an evidence storage and retention plan.

## Core Concepts
- **SSID:** network name; not a unique identifier.
- **BSSID:** radio identifier for an AP; a multi-radio or multi-AP network may have many.
- **Channel/band:** affects visibility and which radios can observe the network.
- **Passive discovery:** observing management traffic without deliberately interacting with client devices.
- **Active assessment:** any probing, AP broadcasting, association testing, or disruption; requires additional authorization.
- **Encryption posture:** distinguish open, WPA2-Personal, WPA3-Personal, and enterprise authentication from what the tool actually observes. Do not infer a full security configuration from SSID alone.

## Lab 1 — Passive AP Inventory
**Goal:** inventory the lab's APs and compare with approved infrastructure.

1. Open the Mark VII's management interface using the official setup workflow.
2. Configure only approved scan bands/channels; use passive discovery where supported.
3. Start a short survey and record time, channel, SSID, BSSID, signal strength, and observed security indicators.
4. Compare against a client-supplied authorized AP inventory.
5. Mark unmatched devices **unverified**, not automatically malicious. Verify against controller records and physical inventory.
6. Export or manually record results using the supported firmware interface; avoid storing client identifiers in public repositories.

## Lab 2 — Encryption & Configuration Audit
1. Configure two lab SSIDs with known settings (for example, WPA2-Personal and WPA3-Personal if supported by the lab AP).
2. Survey both; note advertised capabilities and any transition mode.
3. Compare observed advertisements with AP/controller configuration.
4. Document any open or deprecated configuration only after independent verification.
5. Recommend configuration changes appropriate to client device compatibility and operational constraints.

## Lab 3 — Rogue AP Detection Exercise
1. Obtain approval for a unique synthetic SSID such as `PNWC-ROGUE-LAB-01` and a separate lab AP.
2. Configure the lab AP to broadcast the unique SSID; **do not clone a real organization's SSID**.
3. Use the Mark VII for observation and a separate WIDS/Kismet/nzyme sensor for detection.
4. Confirm the new BSSID/SSID is identified and an alert reaches the monitoring system.
5. Stop the lab AP, verify disappearance, and correlate sensor/controller logs.

## Lab 4 — Wireless Coverage & Channel Survey
At preapproved locations, record signal levels and channel occupancy over consistent intervals. Compare measurements against the client's AP plan; do not treat raw signal strength as throughput or a complete interference diagnosis. Note antenna orientation, device placement, scan duration, and environmental conditions.

## Lab 5 — Client Isolation Validation
Use **two client-owned lab stations** on a dedicated test SSID. Configure client isolation in the AP/controller, then test only approved connectivity between those two stations using basic reachability checks. The Pineapple can document the wireless environment, but is not required to act as a packet interception point. Verify results at the clients and controller, not solely from wireless advertisements.

## Lab 6 — Wireless Monitoring & SIEM Correlation
1. Generate a harmless, unique test SSID on a lab AP.
2. Capture its appearance/disappearance using the Pineapple and an independent Kismet or nzyme sensor.
3. Forward authorized WIDS alerts to Wazuh using the sensor's supported integration.
4. Correlate timestamps, sensor IDs, BSSID, channel, and alert classifications.
5. Tune false-positive handling and retain a screenshot/export demonstrating detection.
6. Remove the test SSID and verify the alert lifecycle.

## Active Features — Authorization Gate
The platform's active modules and features may advertise networks or interact with wireless clients. They are intentionally **not enabled by default** in these labs. For any active exercise, specify the exact feature, target lab SSID/BSSID, operator, allowed time, potential service impact, monitoring plan, and stop conditions; test first in an RF-controlled environment. Never run broad active tests merely because a device is in range.

## Troubleshooting
| Symptom | Investigate |
|---|---|
| No APs discovered | Radio/band support, channel plan, antenna, scanning mode, regulatory constraints |
| Missing expected SSID | Hidden/low-duty advertisements, band mismatch, distance, scan duration |
| Unexpected results | Multiple BSSIDs, mesh nodes, randomized client MACs, stale observations |
| Management unavailable | Power, approved management interface, cabling, firmware-specific setup |
| SIEM alert absent | Sensor capture, integration, clock sync, parser/rule mapping |

## Evidence & Reporting
For each observation retain test ID, authorization, site, firmware, time/time zone, channel, observed SSID/BSSID (redacted as needed), scan configuration, independent validation, and recommendation. Distinguish observation from inference; do not label every unknown AP an attack. Restore AP settings, stop test broadcasts, securely archive evidence, and obtain client sign-off.

## Cross-References
- [Wireless Surveying & Wardriving](../Wardriving/README.md)
- [Kismet](../Wardriving/kismet.md)
- [Kismet + Wazuh Wireless Lab](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md)
- [nzyme + Wazuh](../IncidentResponse/IDS%26IPS/nzyme-wazuh-integration.md)
- [Assessment Service Blueprint](../PlayBooks/assessment-service-integration-map.md)
- [Official Hak5 Documentation](https://docs.hak5.org/)
