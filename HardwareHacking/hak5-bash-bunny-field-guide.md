# Hak5 Bash Bunny — Authorized USB Assessment Field Guide

## Purpose & Scope
The Bash Bunny is a programmable USB assessment device capable of presenting different USB device classes to a host. Use it to validate USB device policy, endpoint visibility, physical access controls, and safe automation on **owned or expressly authorized** systems. Capabilities vary by hardware generation, firmware, and host OS. Do not assume every example works unchanged on all versions.

**Rules of engagement:** document client, target asset IDs, operator, approved time window, permitted USB classes, expected impact, data handling, emergency contact, and rollback. Never deploy on unattended third-party devices. Do not collect credentials, browser secrets, tokens, or client documents.

## Preparation
1. Identify exact Bash Bunny model and installed firmware; compare with the matching official Hak5 documentation before updating.
2. Back up existing payloads, configuration, and test evidence. Obtain firmware only from the official source.
3. Use a disposable Windows/Linux VM or dedicated workstation with snapshots; ensure USB passthrough is assigned to the intended VM.
4. Create a synthetic test user, sample documents, and a designated evidence directory. Record clock/time zone.
5. Confirm physical switch positions, power requirements, and the device's setup/storage mode using the model-specific manual. Do not confuse arming/setup with payload execution.
6. Start with a non-destructive payload that only types a unique marker into an already-open text editor.

## Architecture & Operational Concepts
USB composite devices may expose HID keyboard, USB storage, serial, or USB networking functions, depending on firmware and payload configuration. The host enumerates each interface separately; Windows Device Manager, Linux journal/udev, EDR, and device-control policy can therefore show different events. Network emulation is not equivalent to connecting to a trusted corporate network; the host may route traffic differently depending on interface priority and policy.

Bash Bunny payloads commonly use a shell-based workflow with device-specific helper commands such as `ATTACKMODE`, `QUACK`, and LED indicators. **Verify exact syntax for your firmware before deployment**. Avoid importing unreviewed community payloads or running them as administrator.

## Lab 1 — USB Enumeration & Device Control
**Objective:** determine whether an unauthorized USB composite device is permitted and logged.

1. Capture baseline Device Manager/USB device inventory or `lsusb` and `journalctl -k` on Linux.
2. Enable endpoint device-control auditing or a blocking policy for a dedicated test device class.
3. Connect the Bash Bunny using a harmless, firmware-verified mode, first without keyboard emulation.
4. Record vendor/product IDs, interface classes, timestamps, allow/block decisions, and endpoint alerts.
5. Repeat with the approved HID test mode; do not issue privileged commands.
6. Restore the baseline policy and unplug the device.

**Expected evidence:** policy outcome for each class, host logs, screenshots, and any alert correlation. **Finding:** a policy gap exists only if the observed outcome violates the client's written requirements.

## Lab 2 — Synthetic Keyboard Marker
**Objective:** measure whether a newly connected HID can type into an unlocked workstation.

1. Open a text editor manually on the lab host and place the cursor in a blank document.
2. Prepare a payload that waits for host enumeration and types `PNWC-USB-TEST-2026` only.
3. Execute once while an operator observes. Stop if focus changes.
4. Record whether characters appeared, keyboard layout, delay required, and device-control alerting.
5. Save the harmless text as evidence; remove the device.

**Do not** automate shell launch, UAC prompts, credentials, or security-setting changes. An unlocked workstation accepting a keyboard is not, by itself, a vulnerability; assess it against the agreed physical access threat model.

## Lab 3 — USB Network Interface Policy
**Objective:** check whether an unexpected USB Ethernet/RNDIS/ECM interface is created or blocked.

1. Isolate the lab host from production networks and capture its baseline interfaces and routes.
2. Use only the device's documented USB-networking mode; avoid DHCP or routing changes outside the lab.
3. On Windows, inspect `Get-NetAdapter` and `Get-NetRoute`; on Linux, inspect `ip -br link` and `ip route`.
4. Record any new interface, metric, DNS change, firewall profile change, and EDR alert.
5. Disconnect the device and confirm routes and DNS return to baseline.

**Pass criteria:** behavior matches documented device-control/network-adapter policy; unexpected default-route or DNS changes require investigation. No traffic interception or credential capture is necessary.

## Lab 4 — Removable Storage Restrictions
Use a dedicated test host with a policy that blocks new removable storage. Present a supported, harmless storage mode, attempt to write only a synthetic file, and record allow/block/audit outcomes. Do not enumerate or copy client files. Differentiate storage-class policy from HID-class policy.

## Troubleshooting
| Symptom | Check |
|---|---|
| No enumeration | USB cable/port, power, physical switch, host USB passthrough |
| Unexpected interface | Model/firmware, composite-mode selection, OS driver support |
| Marker typed incorrectly | Keyboard locale, host focus, timing, special-character encoding |
| No endpoint alert | Sensor health, policy scope, event ingestion delay, device-class coverage |
| Networking affects lab host | Disconnect, restore routes/DNS, revert VM snapshot |

## Reporting & Cleanup
Record test ID, firmware, payload hash, host asset ID, operator, timestamps, observed interfaces, logs, policy expected/actual, impact, and remediation. Delete synthetic test data, restore policies, verify connectivity, and securely handle logs. Recommendations may include USB class allowlisting, EDR correlation, workstation locking, and user training.

## Further Reading
- [Hak5 Documentation](https://docs.hak5.org/)
- [Hardware Hacking Index](./README.md)
- [Assessment Service Blueprint](../PlayBooks/assessment-service-integration-map.md)
- [Endpoint Visibility](../IncidentResponse/Endpoint-Visibility/README.md)
