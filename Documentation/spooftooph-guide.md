# Spooftooph: Bluetooth Identity Spoofing Risks & Defensive Validation

_Reference review: 2026-11-21. No Bluetooth identity spoofing or RF testing was performed._

> [!CAUTION]
> **Authorized & isolated lab only.** Spooftooph can change a compatible adapter's Bluetooth identity fields. Never impersonate a real user's device, bypass trust decisions, interfere with pairing or track nearby devices. This guide is for defensive analysis and synthetic fixtures. See [Legal Notice](../LEGAL.md).

## Purpose & Architecture

[Spooftooph](https://www.kali.org/tools/spooftooph/) is a historical Linux utility for changing or cloning supported Bluetooth **device name, class and address**. The relevant security question is whether a relying system mistakenly treats these **mutable identifiers** as proof of a trusted device.

Changing display identity does **not** automatically clone an authenticated pairing relationship, cryptographic keys, link-layer capabilities or a user's permissions. Ability to change a Bluetooth controller address varies by **chipset, firmware and kernel/driver**.

## Concepts & Limits

| Field | What It Identifies | Can It Prove Trust? |
|---|---|---|
| Human-readable device name | Advertised label | No: it may be changed or copied |
| Class of device | Broad legacy device category | No: metadata, not authentication |
| Bluetooth device address | Device-address field (classic/static/randomized contexts differ) | No: address alone is not a secret |
| Pairing keys / bonding data | Cryptographic relationship | Require explicit secure protocol |
| LE private/random address | Privacy-address mechanism | Changes may be intentional, not hostile |

Bluetooth Classic and BLE differ substantially; do not assume a Classic spoofing tool controls BLE privacy-address rotation or follows all current controllers.

## Nonintrusive Lab Preflight

Only use a dedicated, resettable Bluetooth adapter, separated from personal devices.

```bash
lsusb -nn
bluetoothctl list
bluetoothctl show
spooftooph -h 2>&1 | head -n 45
```

These commands inspect configuration or help. They do **not** spoof, transmit a modified identity or establish that the hardware is compatible. Review the installed package and source before execution; older drivers and tools can be incompatible with modern BlueZ stacks.

## Safe Validation Scenario

| Step | Activity | Evidence |
|---|---|---|
| 1 | Create two **owned** lab identities, documented as fictional | Asset IDs and test authorization |
| 2 | Check how your application records Bluetooth identity | Application log and UI screenshot |
| 3 | Review whether trust derives only from name or address | Code/config analysis |
| 4 | Verify authenticated bonding/authorization is required | Pairing-flow test using the normal OS UI |
| 5 | Simulate duplicate names in a **non-RF unit-test fixture** | App rejects unauthenticated duplication |
| 6 | Record remediations and regressions | Signed configuration/coding findings |

No over-the-air impersonation sequence is necessary to prove that address-only trust is insecure.

## Detection & Remediation

| Symptom | Better Control |
|---|---|
| "Trusted" device based only on displayed name | Verify cryptographic identity/bond |
| Duplicate addresses appear | Correlate physical-layer uncertainty & pairing state, avoid attribution overclaim |
| Unexpected re-pairing | Require user interaction and authenticated pairing |
| Privacy address rotation appears suspicious | Identify BLE resolvable/private address behavior |
| Software caches the first matching device | Bind authorization to authenticated session and unique device credential |

## Compatibility & Troubleshooting

Some controllers support name changes but not address changes. Newer Bluetooth implementations may block actions available in legacy builds. Older spoofing code may require privileged APIs or outdated `hciconfig` assumptions; **do not weaken host security settings** just to make a demo work.

## Related Guides & Sources

- [Bluetooth/BLE & Radio Adapter Comparison](./bluetooth-radio-adapter-guide.md)
- [BlueMaho Historical Toolkit](./bluemaho-guide.md)
- [Kali Spooftooph Tool Reference](https://www.kali.org/tools/spooftooph/)
- [BlueZ](https://github.com/bluez/bluez) and [Linux Bluetooth Security](https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/)

---

[Documentation Index](./README.md) | [Wireless Tool Index](./wireless-toolkit-reference.md) | [Legal Notice](../LEGAL.md)
