# SigRoam + Flipper Zero + PINGEQUA Scout Lite

_Last reviewed: 2026-10-22_

**Setup, configuration, testing, deployment, and recovery guide**  
**Updated:** 2026-10-22  
**Scope:** Authorized wireless surveying and GPS-tagged inventory collection.

> **Use policy:** Survey only networks and locations where you have permission to operate. Treat collected BSSIDs, SSIDs, and precise locations as sensitive information. SigRoam's dedicated survey capture is passive, but uploading results uses an ordinary Wi-Fi connection. Some Marauder wardrive implementations may transmit probe/beacon traffic; verify the installed firmware's actual behavior before claiming a fully passive survey.

## 1. System overview

| Component | Function |
|---|---|
| Flipper Zero | User interface and survey controller |
| SigRoam `.fap` | Flipper application: dashboard, GPS/session status, upload controls |
| PINGEQUA Scout Lite | ESP32-C5 dual-band 2.4/5 GHz scanner with Quectel L86 GPS |
| Scout Lite firmware | Either factory ESP32 Marauder or optional dedicated SigRoam scanner |
| Scout Lite microSD | Stores WiGLE-compatible CSV survey logs |
| Flipper microSD | Stores the `.fap` application, **not** Scout Lite's survey CSV |
| WiGLE account (optional) | Upload destination for approved survey records |

The ESP32-C5 has one Wi-Fi radio; 2.4 GHz and 5 GHz observations are not simultaneous dual-radio captures. The GPS receiver is wired to Scout Lite, and a separate NMEA output can be exposed to the Flipper on GPIO 15/16.

## 2. Equipment and prerequisites

- [ ] Flipper Zero with charged battery and microSD card
- [ ] PINGEQUA Scout Lite and included dual-band SMA antenna
- [ ] Separate **FAT32-formatted microSD card for Scout Lite**
- [ ] USB-C **data** cable and desktop computer
- [ ] Chrome, Edge, or compatible desktop Firefox for browser flashing
- [ ] Compatible Flipper firmware and matching SigRoam `.fap` release
- [ ] Optional: WiGLE API Name and API Token
- [ ] Optional: known, authorized Wi-Fi network for after-stop uploads

**Before changing anything:** record the Flipper firmware version, Scout Lite firmware version, installed SigRoam version, and whether the current board is running Marauder. Keep a backup of existing logs and configuration.

## 3. Select a deployment mode

### Mode A — Complete SigRoam workflow (recommended for dedicated surveys)

- Install dedicated **SigRoam scanner firmware** on Scout Lite.
- Install the compatible **SigRoam `.fap`** on Flipper Zero.
- Survey Wi-Fi/BLE with GPS; CSV files remain on Scout Lite's microSD.
- Configure optional automatic WiGLE upload after a successful survey STOP; retry from the Upload screen if necessary.

### Mode B — Keep factory ESP32 Marauder

- Leave Scout Lite's factory Marauder firmware intact.
- Use the Marauder Flipper companion app, or a compatible SigRoam dashboard.
- Marauder saves its own WiGLE CSV on Scout Lite microSD.
- Use Marauder's own direct-upload workflow or manually transfer the CSV. **Do not expect SigRoam's after-stop auto-upload to work with Marauder firmware.**

## 4. Prepare the hardware

1. Power off the Flipper Zero.
2. Attach the supplied dual-band antenna to Scout Lite's SMA connector **before operating the radio**.
3. Format the Scout Lite microSD as FAT32, then insert it into the Scout Lite slot.
4. Align Scout Lite carefully with the Flipper GPIO header; do not force the connector.
5. Check that there are no bent or offset pins.
6. Power on the Flipper. The Scout Lite uses the Flipper GPIO interface and serial communication on pins 13/14.
7. Do not attempt to power the scanner from Flipper GPIO pin 9 (3.3 V).

## 5. Install or update the Flipper app

1. Check your Flipper firmware version under the device settings.
2. Open the official installer: https://flash.pingequa.com/devices/flipper-sigroam
3. Select the **firmware type that matches your Flipper firmware**; the `.fap` API compatibility matters more than simply picking the highest version number.
4. Connect Flipper Zero to your computer with a USB-C data cable and follow the installer prompts.
5. Alternatively, download a compatible `.fap` from https://github.com/pingequalab/sigroam-wardriving/releases/latest and copy it to `SD Card/apps/GPIO/` on the Flipper.
6. Remove obsolete duplicate SigRoam `.fap` files so only the intended version appears.
7. On Flipper Zero set **Settings → System → Log Device → Off** to release GPIO serial pins 13/14.
8. Open **Apps → GPIO → SigRoam Wardriving**.

**Version note (verify at installation):** The SigRoam browser installer documented v0.7 with distinct builds for Momentum/Official 1.4.3 (API 87.1) and Official 1.5.1/Unleashed/RogueMaster (API 88.2). Release compatibility may change. Never ignore an API mismatch warning.

## 6. Flash dedicated SigRoam firmware to Scout Lite (Mode A)

> Flashing the Scout Lite is **not** required for Mode B. The Flipper `.fap` and ESP32-C5 scanner image are not interchangeable.

1. Stop any running survey and power down.
2. Disconnect Scout Lite from the Flipper GPIO header.
3. Open https://flash.pingequa.com/devices/scout-lite on a supported desktop browser.
4. Select the **SigRoam** firmware type and verify the displayed release and device target.
5. Hold the Scout Lite **BOOT** button while connecting USB-C (or use RESET while BOOT is held if already connected).
6. Release BOOT, click **Connect**, and select the Scout Lite serial port.
7. Follow the flasher's erase/write/verify instructions and wait for completion.
8. Disconnect USB-C, reconnect the board to the powered-off Flipper, and boot.
9. Open SigRoam and use **Probe firmware** to confirm communication and the detected scanner.

**Advanced manual flashing:** Some SigRoam 0.6 instructions specify `sigroam_lite.bin` at address `0x20000`. Do **not** assume that address is valid for later releases or for Marauder: use the flash layout documented for the exact binary. Prefer the vendor web flasher.

## 7. Configure GPS and serial communications

1. Set **Settings → System → Log Device → Off** on the Flipper.
2. Launch SigRoam and open **Probe firmware**. Confirm the scanner responds.
3. Open the dashboard and its **GPS** view. Move to an outdoor area with an unobstructed sky and allow time for the first fix.
4. Check that GPS coordinates, fix state, and satellites are plausible before accepting a survey as geographically valid.
5. Optional, if using the Flipper's **native GPS app** with Momentum: configure **MNTM → Protocols → GPIO Pins → NMEA GPS UART → Extra 15,16**. This remap is not required for Scout Lite to tag its own wardrive logs.
6. In SigRoam **Settings**, adjust available sound, vibration, backlight, stealth/LED, and new-network alert preferences. Keep the default serial baud unless the firmware documentation specifies otherwise.

## 8. Configure WiGLE uploads (Mode A only)

Create a WiGLE account and obtain the **API Name** and **API Token** from your account. On a trusted computer, create these four plain-text files at the **root of Scout Lite's microSD**:

| File | Content |
|---|---|
| `wigle_api_name.txt` | WiGLE API Name only |
| `wigle_api_token.txt` | WiGLE API Token only |
| `home_ssid.txt` | SSID of the authorized upload Wi-Fi |
| `home_psk.txt` | Password for that Wi-Fi; empty for an open network |

Use UTF-8/plain text, with no labels, quotes, or extra whitespace. Ensure the names do not silently end in `.txt.txt`.

1. Safely eject the Scout Lite microSD and reinsert it in Scout Lite.
2. Restart the Scout Lite scanner.
3. Dedicated SigRoam firmware imports these files into internal settings at boot and then overwrites/removes the source files.
4. Verify that the four files disappeared. If they remain, **do not assume import succeeded**.
5. Keep WiGLE tokens and Wi-Fi credentials out of screenshots, Git repositories, shared logs, and public documentation.
6. Complete a short survey, press **STOP**, and check upload status when the configured Wi-Fi is reachable.
7. If offline or unsuccessful, use the SigRoam **Upload** page to retry later. The scanner does not interrupt an active survey for uploads and does not necessarily retry automatically when Wi-Fi later appears.

**Privacy:** Uploading GPS-tagged observations to WiGLE may publish information about networks and locations. Confirm your organization's sharing policy and WiGLE privacy settings before uploading. For internal-only assessments, keep CSVs local instead.

## 9. Configure Marauder uploads (Mode B only)

Marauder uses its **own** upload process. The documented credentials files are `wigle_api_name.txt` and `wigle_api_token.txt` on the Scout Lite card. Use Marauder's AP scan / **Join WiFi** and upload menu to connect and send files, or copy the CSV off the card and upload manually at https://wigle.net/ . Do not use SigRoam's four-file automatic-upload instructions as proof that Marauder will import those same settings.

## 10. Bench acceptance test

Use a network you own or are explicitly permitted to inventory. Record actual outcomes rather than marking tests as passed in advance.

| ID | Test | Pass criterion | Result |
|---|---|---|---|
| T01 | Hardware boot | Flipper and Scout Lite power on normally | ☐ Pass ☐ Fail |
| T02 | Serial handshake | **Probe firmware** detects scanner | ☐ Pass ☐ Fail |
| T03 | App navigation | Dashboard, GPS, Session and Upload screens open | ☐ Pass ☐ Fail |
| T04 | Wi-Fi observation | Known authorized 2.4 GHz AP appears | ☐ Pass ☐ Fail |
| T05 | 5 GHz observation | Known authorized 5 GHz AP appears, if available | ☐ Pass ☐ Fail |
| T06 | GPS | Outdoor GPS fix and plausible coordinates | ☐ Pass ☐ Fail |
| T07 | Start/stop | Dashboard OK starts and then stops survey | ☐ Pass ☐ Fail |
| T08 | Storage | New CSV exists on **Scout Lite** microSD | ☐ Pass ☐ Fail |
| T09 | Data quality | CSV header/columns parse; records have plausible timestamps, channels, signal, and GPS | ☐ Pass ☐ Fail |
| T10 | Upload (optional) | Completed session upload is acknowledged, or an actionable error is shown | ☐ Pass ☐ Fail ☐ N/A |
| T11 | Offline recovery | Survey CSV remains available after offline stop/restart | ☐ Pass ☐ Fail |
| T12 | Reboot recovery | Device returns to operational state after restart | ☐ Pass ☐ Fail |

**Important controls:** In the documented dashboard, press **OK** on `Dash` to start and **OK again** to stop. **Back** leaves the screen but does **not** stop scanning. Do not remove the microSD or disconnect power while data is being written or uploaded.

## 11. Field deployment checklist

### Before leaving

- [ ] Confirm permission, survey boundaries, and data-handling policy.
- [ ] Charge Flipper; inspect GPIO connection and antenna.
- [ ] Confirm Scout Lite FAT32 card has adequate free space.
- [ ] Check the installed firmware/app pairing and serial handshake.
- [ ] Confirm GPS can fix outdoors.
- [ ] Set WiGLE upload off/unconfigured if data must stay private.
- [ ] Record deployment ID, operator, firmware versions, and expected route.

### During the survey

1. Mount the Scout Lite securely and keep its antenna unobstructed.
2. Wait for a valid GPS fix in an open-sky location.
3. Open **Apps → GPIO → SigRoam Wardriving → Dashboard**.
4. Press **OK** on `Dash` to start the survey.
5. Monitor AP counts, 2.4/5 GHz observations, GPS fix, and session/storage indicators.
6. Travel safely; do not operate the Flipper while driving. Use a passenger or stop in a safe location to inspect the screen.
7. Stay within the authorized collection area.
8. Press **OK** to **STOP**, then wait for the session to finish saving.

### After the survey

- [ ] Confirm the session stopped and data was saved.
- [ ] Confirm the CSV exists on Scout Lite microSD.
- [ ] Copy the original CSV to an access-controlled archive.
- [ ] Verify record counts and sample GPS values.
- [ ] Upload only if authorized; verify acknowledgment and retain error codes.
- [ ] Record completion status, firmware versions, GPS issues, and anomalies.
- [ ] Remove or redact sensitive fields before sharing reports publicly.

## 12. Troubleshooting

| Symptom | Likely cause / action |
|---|---|
| SigRoam missing from Apps | Verify `.fap` is in `apps/GPIO/` on **Flipper** microSD; confirm API compatibility |
| API mismatch | Install the release asset built for the Flipper's actual firmware/API |
| Probe firmware times out | Turn **Log Device Off**; check board seating, power, serial pins 13/14 and compatible baud |
| GPS never fixes | Move outdoors, allow acquisition time, check antenna orientation and hardware |
| No CSV created | Check **Scout Lite** card, FAT32 formatting, free space, scan start/stop and firmware mode |
| WiGLE setup files remain after boot | Recheck filenames, card readability, exact firmware mode and import support |
| Upload fails | Check credentials, Wi-Fi SSID/password, coverage, WiGLE service response and account limits |
| HTTP 429 | WiGLE rate/daily file limit; retain files and retry when permitted |
| Scanner disconnects during survey | Check GPIO seating, power source, USB/OTG transitions; restart and inspect log integrity |
| No 5 GHz records | Verify test AP exists, firmware supports 5 GHz, and enough channel-hopping time elapsed |
| Marauder cannot auto-upload after STOP | Expected: that automatic workflow is specific to dedicated SigRoam scanner firmware |
| Browser cannot see Scout Lite | Use supported desktop browser, data cable, BOOT download mode and correct serial port |

## 13. Recovery and rollback

1. Stop scanning and back up the Scout Lite card's CSV files.
2. Power off the Flipper and detach Scout Lite.
3. Open https://flash.pingequa.com/devices/scout-lite .
4. Enter BOOT download mode and select the **correct target and firmware**.
5. Reflash dedicated SigRoam or restore the supported **Marauder** option.
6. Reboot, remount the board, and repeat T01–T09 before field reuse.
7. If changing between firmware families, review their different flash layouts, CSV formats, upload behavior, and credential import process. Never write a `.fap` to the ESP32-C5.

## 14. Deployment record template

```text
Deployment ID:
Date / operator:
Authorization / survey area:
Flipper firmware + API:
SigRoam FAP version:
Scout Lite scanner firmware:
Scout Lite card capacity / free space:
GPS fix confirmed (Y/N):
Serial probe passed (Y/N):
Survey start / stop time:
CSV filenames and record count:
WiGLE upload permitted (Y/N):
Upload result / HTTP status:
Data archive location:
Outstanding issues:
Final acceptance: PASS / FAIL
```

## 15. Official references

- SigRoam application and release notes: https://github.com/pingequalab/sigroam-wardriving
- SigRoam latest releases: https://github.com/pingequalab/sigroam-wardriving/releases/latest
- SigRoam Flipper installer: https://flash.pingequa.com/devices/flipper-sigroam
- Scout Lite firmware web flasher: https://flash.pingequa.com/devices/scout-lite
- Scout Lite hardware guide: https://github.com/pingequalab/scout-lite
- PINGEQUA hardware wiki: https://www.pingequa.com/pages/wiki
- WiGLE: https://wigle.net/

> **Documentation note:** Vendor product pages and older GitHub snapshots describe earlier SigRoam releases and sometimes say dedicated firmware is not yet available. Prefer the **current installer, release assets, and their compatibility notes** over older static product copy. Revalidate firmware/API pairings before every rollout.

## See also

- [Wardriving overview](./README.md) — workflows and comparison.
- [ESP32 Marauder](./esp32-marauder.md) — factory Scout Lite alternative and different upload behavior.
- [Field workflow](./field-workflow.md) — permissions, acceptance and reporting.
- [Data handling](./data-handling.md) — GPS, WiGLE and sharing practices.
- [Flipper Zero guide](../Documentation/flipper_zero_guide.md) — general Flipper usage.

---
[Back to Wardriving](./README.md) | [Master Index](../README.md) | [Start Here](../START_HERE.md) | [Legal Notice](../LEGAL.md)
