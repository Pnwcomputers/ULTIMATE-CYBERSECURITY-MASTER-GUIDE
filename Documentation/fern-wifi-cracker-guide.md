# Fern WiFi Cracker: GUI Wireless Auditing & Risk Assessment

_Upstream and Kali package references reviewed: 2026-11-21. No active wireless testing was performed._

> [!CAUTION]
> **Authorized use only.** Fern includes disruptive WEP/WPA/WPS and credential features. Only perform tests on a dedicated, isolated AP with written approval. Do not scan or transmit against neighbors' networks. See [Legal Notice](../LEGAL.md).

## Purpose & Project Status

[Fern WiFi Cracker](https://github.com/savio-code/fern-wifi-cracker) is a Python/Qt graphical frontend for traditional wireless security audits. Kali [packages Fern](https://www.kali.org/tools/fern-wifi-cracker/), but its upstream README also mentions legacy BackTrack, WEP and outdated dependencies. **Package availability does not mean every workflow is modern, safe or supported.**

Use it to understand GUI workflow selection and assess an **owned** legacy lab, not as a universal replacement for [Kismet](../Wardriving/kismet.md) or the [Aircrack-ng suite](./Aircrack-ng_Commands.md).

## Components & Limitations

| Component | Role | Caution |
|---|---|---|
| Qt GUI | Inventory, device selection & task coordination | GUI actions can start active tests |
| Aircrack-ng dependency | 802.11 capture & legacy security testing | Adapter monitor/injection support varies |
| Reaver / WPS integration | Legacy WPS PIN vulnerability analysis | Active radio work can cause lockouts or disruption |
| WEP analysis | Demonstrates insecure retired encryption | WEP should be replaced, not maintained |
| Credential/MITM extensions | Historical offensive features | **Not appropriate** for ordinary inventory or troubleshooting |

## Safe Installation Review

On an isolated Kali VM with a compatible USB Wi-Fi adapter, inspect the [Kali package details](https://www.kali.org/tools/fern-wifi-cracker/) and project source before installation. Do not run unreviewed auto-updaters as root.

```bash
apt-cache policy fern-wifi-cracker
python3 --version
lsusb -nn
iw dev
```

Fern needs a graphical session and supporting packages. If the GUI refuses to start, inspect the Python/Qt versions and logs before applying old tutorials or changing system-wide Python libraries.

## Authorized Lab Workflow

| Phase | Method | Evidence |
|---|---|---|
| Scope | Label a disposable AP and channel | Approved BSSID, test owner & schedule |
| Adapter preflight | Confirm Linux driver / radio capability | Chipset, USB ID & version |
| Passive baseline | Use a trusted monitor-capable receiver / Kismet | Captured beacons and security capabilities |
| Fern GUI evaluation | Review categories and defaults **without initiating an attack** | Screenshot of tool choices & dependencies |
| Config audit | Inspect AP config for WPS, legacy WEP, WPA2-only, PMF | Owner-approved configuration export |
| Remediation | Disable WPS PIN, use WPA3-SAE if supported, enforce strong PSK | Before/after AP settings |
| Retest | Capture new advertised capabilities | Packet evidence & caveats |

## Troubleshooting

| Symptom | First Check |
|---|---|
| No adapters in GUI | USB pass-through, compatible driver, monitor capability |
| Qt launch error | Current Python/Qt packages; upstream age |
| AP does not appear | Channel selection, 2.4/5 GHz band support & country rules |
| Active options look easy | Treat as separate high-risk authorization scope |
| WEP or WPS "success" | Verify **only** against owned lab, never extrapolate to production |

## Related Programs & Sources

- [Aircrack-ng Commands](./Aircrack-ng_Commands.md)
- [Wireless Adapter Selection](./wifi-adapter-selection-guide.md)
- [Wifite2/Wifite3](./wifite-guide.md) — automation and support differences
- [Pixiewps](./pixiewps-guide.md) — weak WPS entropy conditions
- [Kali Fern Package](https://www.kali.org/tools/fern-wifi-cracker/)
- [Original Fern Project](https://github.com/savio-code/fern-wifi-cracker)

---

[Documentation Index](./README.md) | [Wardriving](../Wardriving/README.md) | [Legal Notice](../LEGAL.md)
