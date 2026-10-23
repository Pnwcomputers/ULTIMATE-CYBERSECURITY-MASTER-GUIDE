# Wardriving Data Handling, Privacy, Exports and WiGLE

_Last reviewed: 2026-10-22_

> [!CAUTION]
> Treat **BSSID, SSID, time and GPS coordinates as potentially identifying location data**, and identify exactly what an outside service will receive before uploading. See [LEGAL.md](../LEGAL.md).

## Purpose

Preserve useful authorized wireless-survey results without accidentally exposing private client locations, operator movements, organization network names or credentials.

## Inventory of possible records

| Data | Why it matters | Handling recommendation |
| --- | --- | --- |
| SSID | Human-readable AP name, potentially names people/organizations | Minimize public inclusion when needed |
| BSSID / device MAC | Uniquely identifies an AP radio or observed device; MACs can be randomized | Restrict access, consider redaction |
| Latitude / longitude | *Receiver's observation point*, **not proof of AP's precise physical location** | Enforce authorized boundary and sharing rules |
| Timestamp, route | Can reveal survey patterns and operator movements | Keep session metadata separate |
| Frequency, channel, RSSI, security mode | Supports engineering / audit interpretation | Retain with context and precision limits |
| Phone / app identifiers, BLE devices | May relate to nearby personal devices | Avoid logging or publishing beyond need |
| KismetDB, PCAP-NG | Potentially contains more than a device inventory, including raw packet content | Stronger access restrictions and retention review |
| WiGLE token, Wi-Fi PSK | Credentials with account/network access | Store in secret managers, **never commit to GitHub** |

## Recommended retention workflow

1. Create a scope ID and document permission and allowed sharing destinations.
2. Keep **unaltered originals** in controlled storage; work on verified copies.
3. Create a SHA-256 checksum of each original so modifications to the archived copy can later be detected:

```bash
sha256sum your-authorized-survey.csv > your-authorized-survey.csv.sha256
sha256sum -c your-authorized-survey.csv.sha256
```

4. Analyze with tools that do not accidentally synchronize an entire private folder.
5. Normalize format/headers **only on a copy**; do not remove the original raw evidence.
6. Remove out-of-scope coordinates and identifiers *from the export copy*; document redactions.
7. If client policy permits uploading to WiGLE / WDGWars, record the destination, user/account, export filename, date and service receipt.
8. Delete working and shared copies when the approved retention period expires. Follow the client’s actual retention requirements.

## WiGLE and other community databases

[WiGLE](https://wigle.net/) accepts supported GPS-tagged survey formats such as WiGLE CSV. **Creating a valid CSV does not authorize its publication.** Check that the exported record represents approved collection and does not contain out-of-scope locations.

### Tool-specific notes

- **SigRoam dedicated scanner on Scout Lite:** saves a WiGLE-compatible CSV on **Scout Lite's card**. Its after-STOP upload uses credentials + authorized Wi-Fi import from the board card. [Setup](./sigroam-scout-lite.md).
- **ESP32 Marauder:** own WiGLE/WDGWars direct upload and SD credentials; its upload workflow is separate from SigRoam. [Marauder](./esp32-marauder.md).
- **Biscuit:** app controls session, GPS source and export; don't assume a compatible Biscuit firmware writes Scout Lite/Mini onboard card logs. [Biscuit](./biscuit.md).
- **AWOK Dual C5:** devices lack onboard microSD; save through the actual controlling app/workflow. [AWOK](./awok-dual-c5-biscuit.md).
- **Wardrive Go:** app offers local collection and user-triggered upload. Android and iOS have **different** Wi-Fi data-source models. [Guide](./wardrive-go.md).
- **Kismet:** `wiglecsv` requires valid GPS; wardrive overlay enables it, but can also leave richer Kismet logs enabled unless you explicitly restrict `log_types`. [Guide](./kismet.md).

## CSV validation checklist

- Does the CSV parse in a strict CSV reader and include a recognized WiGLE-compatible header?
- Are timestamps in a documented time zone, with plausible chronology?
- Do coordinates fall within the actual authorized survey boundary?
- Are absent/invalid GPS fixes omitted or clearly flagged instead of replaced by `0,0`?
- Do GHz bands match channels / frequencies and supported capture hardware?
- Are repeated sightings expected or are duplicate file uploads being counted?
- Is an SSID marked hidden/blank handled correctly instead of invented?
- Is the file intentionally public, internal, or restricted?

## Credential hygiene

- Don't commit `wigle_api_token.txt`, `home_psk.txt`, API keys, WiGLE files with sensitive locations, or screenshots of credentials.
- Use a dedicated low-privilege upload profile/network if available.
- Revoke/rotate a token if accidentally published. Removing it from a new Git commit does not necessarily erase its Git history.
- Do not put customer survey exports in a public repository or bug report.

## Sources and related guides

- [Kismet WiGLE CSV logging](https://www.kismetwireless.net/docs/readme/logging/wiglecsv/)
- [Kismet unified logs](https://www.kismetwireless.net/docs/readme/logging/kismetdb/)
- [WiGLE](https://wigle.net/)
- [Field procedure](./field-workflow.md) · [OPSEC](../OPSEC/README.md) · [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md)

---

[Back to Wardriving](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
