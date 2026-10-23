# Kismet: Linux Wireless Surveys and Wardrive Mode

_Last reviewed: 2026-10-22_

> [!CAUTION]
> Kismet can collect more detail than a basic wireless inventory. Use only permitted interfaces and survey areas, secure logs, and avoid retaining unnecessary packet content. [Legal notice](../LEGAL.md).

## Purpose

[Kismet](https://www.kismetwireless.net/) is a powerful open-source wireless detector, monitoring and logging system. For a **lightweight AP/BLE mapping run**, Kismet provides an official `wardrive` **configuration overlay**. It is *not* a separate executable and is deliberately different from Kismet's full monitoring/IDS capture.

## Requirements

- Linux device (laptop, Raspberry Pi or portable cyberdeck) capable of running a current Kismet release.
- At least one **Kismet-supported capture interface**, with drivers that really provide the needed mode/bands. A Wi-Fi USB adapter with monitor mode is typical.
- Optional compatible BLE source.
- GPS that Kismet can actually read (often through `gpsd`). A WiGLE CSV will contain no records without GPS.
- Adequate power and secured disk location for logs.
- Permission to operate within the proposed area.

For installation choose the maintained [Kismet Linux install guidance](https://www.kismetwireless.net/docs/readme/installing/linux/) for the *exact distribution* (including interface capabilities, `kismet` group permissions and package availability). Do not blindly assume `apt install kismet` supplies a modern version on every distro.

## 1. Identify interfaces and GPS

On a Linux host:

```bash
ip -brief link
iw dev
command -v kismet
kismet --version
```

Check supported data sources in [Kismet's datasources documentation](https://www.kismetwireless.net/docs/readme/datasources/). Some adapters can't stay associated to your internet network while collecting in monitor mode; plan a separate backhaul if remote access is required.

A common local `gpsd` configuration for the **Kismet override** (often `/etc/kismet/kismet_site.conf`, depending on installation) is:

```ini
gps=gpsd:host=localhost,port=2947
```

Configure gpsd to read the *actual GNSS receiver* according to the OS. Confirm it is reporting current plausible coordinates before logging. Other sources include Kismet's own serial-NMEA and TCP GPS interfaces. `localhost:2947` refers to your **local gpsd service**, not a GPS receiver magically present on the machine.

## 2. Run a short authorized test

Substitute `wlan1` for **your actual supported capture interface**. This is an example, not a universal interface name:

```bash
kismet -c wlan1 -t authorized-test --override wardrive
```

The official Kismet documentation uses `--override wardrive`; it loads the shipped `kismet_wardrive.conf` overlay. The tool should announce wardrive mode and reduced logging. Open Kismet's locally reported web UI address to inspect device/AP counts and GPS fix. Use a known test AP, then stop cleanly using normal Kismet shutdown.

Do not test by scanning neighbors' networks and treating those captures as clients' assets. Reception of broadcasts and authorization for professional assessment/reporting are separate concepts.

## 3. Decide which logs to retain

The default overlay **adds** WiGLE-compatible CSV without necessarily disabling every other configured log type:

```ini
log_types+=wiglecsv
```

For a **WiGLE-only** survey with minimal retention, set an explicit `log_types=wiglecsv` in an appropriate, verified configuration override for the same session, rather than using the additive `+=` form. Confirm effective configuration and output after starting Kismet. To retain packets or device history for separately approved analysis, use `kismet` / `pcapng` as needed and apply stricter evidence controls.

| Format | Content | Typical purpose |
| --- | --- | --- |
| `wiglecsv` | Simplified location-tagged AP/BLE rows, no raw packet payloads | Minimal mapping/sharing |
| `kismet` / KismetDB | Unified SQLite device, GPS and potentially packet/historical data | Evidence, detailed offline analysis |
| `pcapng` | Packet capture with datasource/context | More detailed authorized protocol review |

**Important:** Kismet only emits WiGLE CSV records when GPS is valid. A connected GPS with no usable fix can leave an otherwise active-looking wardrive CSV empty.

## 4. Collect and verify

1. Start in a stationary authorized test location and wait for the GPS fix.
2. Confirm owned AP identifiers, channels and the appropriate source adapter.
3. Follow the approved route without manipulating the laptop or phone while driving.
4. Shut down Kismet; check log sizes and parse the resulting files.
5. Archive an unmodified original and produce a client-safe export.
6. Only share/upload after approval and redaction of out-of-scope coordinates.

## 5. Common failures

| Symptom | Checks |
| --- | --- |
| Kismet sees no Wi-Fi | Actual interface/driver monitor support, rfkill, source permissions |
| No 5 GHz results | Adapter capabilities, regdomain, channels and hopping interval |
| No position / blank WiGLE CSV | gpsd running? receiver device/path? correct time? valid outdoor fix? |
| Only KismetDB but no CSV | Was `--override wardrive` loaded? effective `log_types`? |
| Unexpected packet-rich logs | `log_types+=wiglecsv` adds, does not replace other defaults |
| Service cannot write files | Kismet user permissions, configured log prefix and disk space |
| Host slows under heavy density | Try wardrive mode, restrict interfaces and logs, compare CPU/RAM/IO |

## Source documentation

- [Wardrive overlay](https://www.kismetwireless.net/docs/readme/configuring/wardrive/)
- [gpsd GPS configuration](https://www.kismetwireless.net/docs/readme/gps/gps_gpsd/)
- [GPS coordinate semantics](https://www.kismetwireless.net/docs/readme/gps/gps_intro/)
- [WiGLE CSV logging](https://www.kismetwireless.net/docs/readme/logging/wiglecsv/)
- [Logging configuration](https://www.kismetwireless.net/docs/readme/logging/logging/)
- [KismetDB](https://www.kismetwireless.net/docs/readme/logging/kismetdb/)

## See also

[Field workflow](./field-workflow.md) · [Data handling](./data-handling.md) · [SDR](../SDR/README.md) · [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md)

---

[Back to Wardriving](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
