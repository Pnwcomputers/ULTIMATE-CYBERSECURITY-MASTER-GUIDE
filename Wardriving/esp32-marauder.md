# ESP32 Marauder: Wardriving with GPS and WiGLE

_Last reviewed: 2026-10-22_

> [!CAUTION]
> **Authorized wireless observation only for this workflow.** Marauder has transmit-capable testing features (including disruptive modes) that are **not required** to make an AP inventory. Do not turn those on during a standard wardrive. See [LEGAL.md](../LEGAL.md).

## Purpose and architecture

[ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) is firmware for supported ESP32 hardware. Features differ by **chip, board revision, display, serial build, connected GNSS and microSD**. Classic ESP32 boards do **not** universally support 5 GHz; ESP32-C5 builds on suitable boards can cover 2.4 and 5 GHz. The Flipper Zero can act as its controller with suitable external Marauder hardware and a compatible companion app.

**Do not confuse Marauder with SigRoam:** on a Scout Lite, factory Marauder and dedicated SigRoam scanner firmware are alternate board images, and auto-upload after STOP is a SigRoam-specific workflow.

## Hardware requirements

- Marauder-compatible ESP32 board; for Flipper use a physically compatible GPIO module and firmware build.
- Compatible GNSS/GPS receiver **wired and configured for the exact board**. PINGEQUA Scout Lite integrates its own Quectel L86 GPS.
- Writable SD card where applicable; serial-Flipper builds may put `wardrive_` logs on the **Flipper** SD instead of the board SD.
- Power and antenna connections appropriate to the actual hardware.
- For manual recovery, backup, correct bootloader connection and **board-specific** vendor flashing instructions.

## Prepare and inspect

1. Identify the exact hardware target and current Marauder build; preserve a backup of saved scans/settings.
2. Read the [Marauder GPS Modification](https://github.com/justcallmekoko/ESP32Marauder/wiki/gps-modification) page for a generic board, or the [Scout Lite guide](https://github.com/pingequalab/scout-lite) for integrated GPS. Do **not** blindly copy GPS GPIO wiring from a different target.
3. Insert/verify SD card where applicable and establish GPS fix outdoors.
4. If using Flipper + Scout Lite, confirm the Flipper's serial log device is off when it competes for pins 13/14, and use the compatible Flipper Marauder companion.
5. Confirm storage destination and test with a known AP you own.

## Start a Wi-Fi AP wardrive

On current touchscreen Marauder targets, use **WiFi → Sniffers → Wardrive**. The official CLI documents:

```text
wardrive
```

Stop a CLI session with:

```text
stopscan
```

The optional `wardrive -s` mode logs **stations / client devices**, not just APs; it has different privacy implications and is intentionally **not** part of the baseline AP survey. On touchscreen targets, tapping may take multiple attempts to stop because of scan timing. Confirm collection has stopped before unmounting media.

Marauder writes GPS-tagged rows only when a valid fix is available; a display may still show detected networks when the GPS cannot lock. Expect filenames prefixed with `wardrive_` on the board SD, or in applicable serial firmware variants on Flipper SD.

> [!NOTE]
> In Marauder releases with geofence support (v1.17.0 onward), compatible GPS/SD targets can configure logging boundaries via **Device → Geofences**. A geofence filters logged positions and is not a guarantee of legal/physical boundaries or GNSS accuracy.

## Uploading completed files

The [official Direct Upload guide](https://github.com/justcallmekoko/ESP32Marauder/wiki/wardriving-direct-upload) documents the SD-root files:

| Credential file | Contents |
| --- | --- |
| `wigle_api_name.txt` | WiGLE API Name |
| `wigle_api_token.txt` | WiGLE API Token |
| `wdg_key.txt` | WDGWars key, **only if using that service** |

Current documented firmware imports the files on boot and removes them. Never assume this has occurred without checking. Marauder can connect via AP scan + **Join WiFi** / `join` CLI, and upload prior wardrive logs using its own interface. **A Marauder scan does not inherit SigRoam's `home_ssid.txt` + `home_psk.txt` after-STOP setup.** Manual removal of the SD and upload of an explicitly approved CSV is also an option.

## Acceptance tests

- Board matches firmware build; device starts and GPS has a plausible outdoor fix.
- Authorized test AP and (if hardware supports it) 5 GHz test AP are observed.
- `wardrive_` file exists on verified **actual** storage; CSV parses.
- Start/stop and offline reboot do not lose the file.
- Optional upload is authorized, uses the intended account and records a clear success/error.

## Troubleshooting

| Symptom | What to inspect |
| --- | --- |
| Many detections but empty log | GNSS fix; logging only occurs after valid GPS |
| No 5 GHz observations | Chip/firmware support, correct antenna, AP channel, dwell time |
| No log on board SD | Check whether a **serial Flipper build** logged on the Flipper card |
| GNSS missing | Board-specific UART/GPS wiring, antenna and outdoor fix |
| App cannot control board | GPIO seating, Log Device conflict, port baud and matching Marauder companion |
| No WiGLE upload | Service approval, Wi-Fi join, imported credentials, limits and response |
| Flash failure | Exact target image/bootloader/USB port; **never** use a generic C5 binary without target compatibility |

## Official references

- [Marauder source](https://github.com/justcallmekoko/ESP32Marauder)
- [Marauder Wardrive wiki](https://github.com/justcallmekoko/ESP32Marauder/wiki/Wardrive)
- [Direct Upload](https://github.com/justcallmekoko/ESP32Marauder/wiki/wardriving-direct-upload)
- [GPS modification](https://github.com/justcallmekoko/ESP32Marauder/wiki/gps-modification)
- [Scout Lite flasher](https://flash.pingequa.com/devices/scout-lite)

## See also

[SigRoam](./sigroam-scout-lite.md) · [Field workflow](./field-workflow.md) · [Data handling](./data-handling.md) · [Flipper Zero](../Documentation/flipper_zero_guide.md)

---

[Back to Wardriving](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
