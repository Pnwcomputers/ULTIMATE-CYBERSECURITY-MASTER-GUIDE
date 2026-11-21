# Wifite2 & Wifite3: Wireless Audit Automation & Safe Tool Selection

_Upstream repository guidance reviewed: 2026-11-21. No scans or attacks were executed._

> [!CAUTION]
> **Authorized use only.** Wifite automates potentially disruptive Wi-Fi security tests and can invoke tools that transmit management frames or attempt WPS PIN recovery. Never point automation at open-ended or unapproved radio environments. See [Legal Notice](../LEGAL.md).

## Version / Project Distinctions

The upstream [Wifite2](https://github.com/derv82/wifite2) README now points readers to [Wifite3](https://github.com/derv82/wifit3) and recommends the [kimocoder/Wifite2 branch](https://github.com/kimocoder/wifite2) for supported Wifite2 use. **Do not imply they are the same program or support the same hardware.** Older Wifite1 is a separate historical project.

| Tool | Driver / Control Model | Host Compatibility | Caveat |
|---|---|---|---|
| [Wifite1](https://github.com/derv82/wifite) | Legacy Linux tools | Older Kali-era Linux | Legacy reference only |
| [Wifite2 (original)](https://github.com/derv82/wifite2) | Wraps Aircrack, Reaver/Bully, HCX and other tools | Linux-oriented | Original repo points to newer/forked work |
| [Wifite2 (community-maintained)](https://github.com/kimocoder/wifite2) | Package/tool-dependent Linux automation | Check project docs | Installed tools/options may differ |
| [Wifite3](https://github.com/derv82/wifit3) | Own supported USB drivers in userspace | Linux/Windows for listed adapters | **Restricted supported-hardware matrix** |

## Audit Modules & Dependencies

| Feature Family | Common Dependency | Key Risk |
|---|---|---|
| Radio/channel inventory | Supported 802.11 adapter, capture stack | Scope and channel hopping gaps |
| WPA/WPA2 PSK audit | Aircrack-ng/HCX/Hashcat, format/version dependent | Not universally applicable to WPA3-SAE |
| WPS PIN analysis | Reaver/Bully/Pixiewps when supported | Lockouts, disruptive or intrusive attempts |
| Legacy WEP | Aircrack-ng suite | Insecure deprecated protocol |
| Session handling | Processes, capture files & local temp dirs | Sensitive PCAP and recovered-secret leakage |

Never assume Wifite's automated "target selection" respects client boundaries on its own. Any active mode requires preapproval for exact BSSID, channels, protocols and stop conditions.

## Safe Preflight & Orientation

```bash
# No wireless transmission, no tool execution against an AP:
lsusb -nn
iw dev
uname -r
command -v wifite || true
wifite --help 2>&1 | head -n 45
```

Only use `wifite --help` with an installed vetted build; help behavior is not identical across forks. In a VM, USB passthrough is essential. A guest-visible `eth0` bridge is not a Wi-Fi monitor radio.

## Lab Process & Risk Gates

| Gate | Required Evidence |
|---|---|
| RF permission | Named operator, AP owner, permitted source & times |
| Radio ID | Model/revision, chipset, VID:PID, driver |
| Mode selection | Confirm candidate is passive/active by source review |
| Third-party visibility | Make exclusion controls and physical isolation explicit |
| Output handling | Save synthetic captures only, no real credentials |
| Restore | Return card to managed mode and confirm connectivity |

For ordinary network inventory, prefer [Kismet](../Wardriving/kismet.md) or a bounded [Aircrack-ng capture workflow](./Aircrack-ng_Commands.md). For WPS resilience, first inspect AP settings and firmware; do not use brute-force automation as a substitute for configuration evidence.

## Troubleshooting & Defensive Checks

| Problem | Explanation / Response |
|---|---|
| Tool launches wrong version | Confirm executable path, package and fork |
| No monitor interface | Driver, firmware or hardware support, not necessarily app bug |
| External tools missing | Match dependencies to selected Wifite release |
| Unexpected disconnections | Stop active workflow and restore services |
| WPA3 not recovering PSK | WPA3 SAE is **not** generic WPA2-PBKDF2 offline workflow |
| WPS found but not vulnerable | Feature present ≠ exploitable weak PRNG or enabled PIN method |

## Related Guides & Sources

- [Wi-Fi Adapter Matrix](./wifi-adapter-selection-guide.md)
- [Aircrack-ng](./Aircrack-ng_Commands.md) | [HCXTools](./hcxtoolshashcat.md) | [Pixiewps](./pixiewps-guide.md)
- [Fern GUI](./fern-wifi-cracker-guide.md)
- [Original Wifite2](https://github.com/derv82/wifite2), [Wifite2 fork](https://github.com/kimocoder/wifite2) & [Wifite3](https://github.com/derv82/wifit3)

---

[Documentation Index](./README.md) | [Wardriving](../Wardriving/README.md) | [Legal Notice](../LEGAL.md)
