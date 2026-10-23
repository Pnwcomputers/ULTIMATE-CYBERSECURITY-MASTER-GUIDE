# Wardriving Field Procedure and Acceptance Checklist

_Last reviewed: 2026-10-22_

> [!CAUTION]
> Collect only within approved scope and applicable law. A passenger, not the driver, operates devices during a moving survey. Review the [legal notice](../LEGAL.md).

## Purpose

Use a defensible and repeatable method for authorized wireless inventory collection across any supported tool. This workflow intentionally separates **operator safety**, **survey quality**, **evidence integrity**, and **publication**.

## 1. Plan and authorize

- Record client/owner approval, scope (sites, routes and boundaries), time window, objective, expected radio bands, authorized device identifiers and whether Bluetooth/cellular collection is included.
- Define the minimum data required; identify private residences, sensitive facilities and out-of-scope locations to exclude, mask or flag.
- Decide whether the target workflow is receive-only. Some general-purpose firmware's wardrive modes can transmit; test/consult firmware before saying it is passive.
- Determine whether logs must stay local. **Do not enable third-party sync/upload by default.**
- Select approved transport route and safe mounting; never obstruct the driver's view or controls.

## 2. Prepare equipment

1. Record board model, revision, firmware build, Flipper/app/OS version, GPS source, storage location and antenna.
2. Check power, cables, antenna attachment, microSD health and free space.
3. Take copies of existing logs before flashing or changing settings.
4. Test with an AP you own: verify expected SSID/BSSID, channel, band and security type.
5. Acquire an outdoor GNSS fix. Record location accuracy when available; don't invent coordinates to fill gaps.
6. Verify the platform's **actual destination**: board SD, Flipper SD, phone session database or Linux KismetDB.
7. Confirm any firmware change/rollback and inspect device regulatory settings.

## 3. Start and collect

1. Create a survey ID, start timestamp and operator log.
2. Start recording while stationary; verify that at least one authorized observation has a valid timestamp and (where required) GPS fix.
3. Follow a safe planned route. For cars, use a passenger or pull over before reading or operating devices.
4. Note tunnels, urban canyons, poor GPS fixes, low battery, power resets, antenna interruptions and apparent gaps in sampling.
5. Do not treat RSSI as exact distance or a single unseen AP as evidence it does not exist.

## 4. Stop and preserve

1. Use the platform's explicit **STOP / end session** action. Merely closing a UI may not stop the scanner.
2. Let all buffered files/database writes finish. Don't pull SD cards or power during saves or uploads.
3. Make a read-only original archive; analyze a working copy.
4. Validate CSV headers, timestamps, channel/frequency ranges, latitude/longitude, record counts, truncation and duplicate uploads.
5. If capturing PCAP or KismetDB, restrict access: raw frames may carry more information than an AP inventory.
6. Decide separately whether an export/upload is permitted; keep track of recipient and upload status.

## 5. Acceptance tests

| ID | Verification | Pass condition |
| --- | --- | --- |
| A01 | Hardware and power | No reset/disconnect during bench collection |
| A02 | Expected owned AP | BSSID/SSID, radio band and channel match test environment |
| A03 | GPS | Outdoor fix with plausible location |
| A04 | Start and stop | Both operations confirmed in tool or logs |
| A05 | File creation | Expected SD/phone/KismetDB location has a new record |
| A06 | Integrity | Data parses; samples have reasonable time, location and signal fields |
| A07 | Offline run | Data survives disconnected operation and reboot |
| A08 | Recovery | Known firmware fallback or restore path documented |
| A09 | Authorized sharing | No upload unless expressly approved |

Record Pass/Fail/Not Applicable individually; **an untested result is not a pass**.

## Deployment record template

```text
Survey ID:
Date/time zone:
Operator:
Authorization / collection boundary:
Tool + hardware revision + antenna:
Firmware/app/OS versions:
GPS source / initial fix:
Radio bands / collection types:
Log source path / output format:
Survey start / stop:
Rows / unique BSSIDs:
Gaps, anomalies, resets:
Archive location / checksum:
Upload authorized? destination and result:
Evidence reviewed / redactions:
Acceptance tests:
Follow-up / disposition:
```

## See also

- [Tool selection](./README.md)
- [Handling GPS-tagged logs and WiGLE](./data-handling.md)
- [Network audit playbook](../PlayBooks/NetworkAuditPlayBook.md)
- [OPSEC](../OPSEC/README.md)

---

[Back to Wardriving](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
