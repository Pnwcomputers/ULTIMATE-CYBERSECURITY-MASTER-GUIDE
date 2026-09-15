# HACKRF RF SPECTRUM & WIRELESS SECURITY AUDIT PLAYBOOK
## Field Surveys, Signal Analysis, Device Audits & Controlled Bench Testing

**Version:** 1.1  
**Last Updated:** September 15, 2026  
**Owner:** Pacific Northwest Computers  
**Suggested repository location:** `PlayBooks/HackRFAuditPlayBook.md`  
**Primary platform:** HackRF One with a Linux host; optional PortaPack with Mayhem

---

## 🎯 Purpose

Provide a repeatable procedure for surveying radio activity, investigating interference, analyzing owned wireless devices, and documenting RF security findings with HackRF. Follow the same engagement-oriented format as the [Wireless & Network Security Audit Playbook](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/PlayBooks/NetworkAuditPlayBook.md): preparation, testing, evidence, analysis, and reporting.

## ⚙️ Function

Start with a receive-only survey, narrow interesting signals to focused recordings, correlate observations with authorized devices, and use suitable decoders or companion radios where required. Perform transmitter and receiver security tests only within an approved, isolated bench setup.

## 🏆 Goal

Produce a defensible RF inventory, reproducible measurements, confirmed findings, and practical remediation. Distinguish measured facts from signal-class guesses and untested security hypotheses.

## 📋 When to Use

- Troubleshooting intermittent wireless connectivity or suspected interference.
- Establishing an RF baseline for an office, home lab, or client facility.
- Auditing owned sensors, wireless peripherals, remotes, and telemetry devices.
- Measuring relative RF leakage outside a designated area.
- Checking whether known devices emit unexpected or identifying information.
- Comparing equipment before and after repair, relocation, or configuration changes.
- Investigating proprietary protocols and testing an isolated development receiver.
- Performing portable surveys using HackRF with PortaPack.

**Scope note:** This is a broad practical playbook, not a claim that one SDR can decode every protocol. All field command examples are receive-only. Frequencies are measurement examples, not permission to transmit or declarations of local spectrum allocation. Command syntax was checked against upstream documentation/source; no HackRF hardware was available to execute these procedures during authoring.

---

## TABLE OF CONTENTS

1. [Capabilities & Limits](#section-1-capabilities--limits)
2. [Pre-Engagement Checklist](#section-2-pre-engagement-checklist)
3. [Equipment, Software & Validation](#section-3-equipment-software--validation)
4. [Spectrum Discovery & Baseline Surveys](#section-4-spectrum-discovery--baseline-surveys)
5. [Focused IQ Capture & Signal Analysis](#section-5-focused-iq-capture--signal-analysis)
6. [Protocol & Device Audit Procedures](#section-6-protocol--device-audit-procedures)
7. [Interference, Leakage & Monitoring](#section-7-interference-leakage--monitoring)
8. [Controlled Bench Security Tests](#section-8-controlled-bench-security-tests)
9. [PortaPack / Mayhem Field Workflow](#section-9-portapack--mayhem-field-workflow)
10. [Documentation & Evidence](#section-10-documentation--evidence)
11. [Analysis, Remediation & Reporting](#section-11-analysis-remediation--reporting)
12. [Troubleshooting & Quick Reference](#section-12-troubleshooting--quick-reference)
13. [References & Document Control](#section-13-references--document-control)
14. [Repository Cross-Reference & Consistency Review](#section-14-repository-cross-reference--consistency-review)

---

## SECTION 1: CAPABILITIES & LIMITS

### 1.1 Understand the Hardware

HackRF One covers **1 MHz–6 GHz**, provides **8-bit I/Q sampling**, and operates **half duplex**: one device receives or transmits at a time. Its supported sample-rate range is 2–20 MS/s, but Great Scott Gadgets recommends avoiding rates below 8 MS/s because of converter and filtering limitations. Start at 8 MS/s and filter/decimate in software when a lower processing rate is required. [HackRF One specifications](https://hackrf.readthedocs.io/en/latest/hackrf_one.html), [sampling guidance](https://hackrf.readthedocs.io/en/latest/sampling_rate.html).

| Property | Practical audit consequence |
|---|---|
| Maximum 20 MS/s complex sampling | At most approximately 20 MHz nominal instantaneous span; useful bandwidth also depends on filters and edge response. |
| Sweeping retunes across a larger band | A wide sweep does not watch every frequency continuously. Brief or hopping signals can be missed. |
| 8-bit converter | Strong nearby transmitters can mask weaker signals or create misleading artifacts. |
| Half duplex | Use a second receiver or DUT logs to observe a response during a bench transmission. |
| Uncalibrated receive chain | Treat displayed levels as relative unless the complete measurement chain has been calibrated. |
| Raw IQ output | A recording is not a PCAP, a decoded message, or evidence that encryption has been broken. |
| Upper specified frequency of 6 GHz | Does not cover the full 6 GHz Wi-Fi band or 60 GHz radios. |
| Lower specified frequency of 1 MHz | Does not directly cover 125/134 kHz LF RFID. |

**Protect the input:** The specified maximum input is **−5 dBm**. Use attenuation and margin; never connect a transmitter directly to the input without calculating the power reaching it. Disabling the amplifier does not replace this protection. [Input-power guidance](https://hackrf.readthedocs.io/en/latest/hackrf_one.html).

### 1.2 Audit Capability Matrix

| Audit | HackRF role | Additional requirement / boundary |
|---|---|---|
| Broad RF discovery | Sweep and waterfall | Appropriate antennas and repeated observation. |
| Channel activity / congestion | Relative power and sampled occupancy | Not equivalent to protocol airtime or channel utilization counters. |
| Interference investigation | Capture anomalies and compare operating states | Correlate with endpoint logs; rule out receiver overload. |
| RF leakage survey | Compare reception at documented locations | Measurements do not establish maximum eavesdropping distance. |
| Sub-GHz sensor inventory | Capture OOK/ASK/FSK activity | Supported decoder, such as rtl_433, or custom analysis. |
| Proprietary protocol analysis | IQ and pulse/bit examination | GNU Radio or URH; protocol-specific validation. |
| Wi-Fi audit | 2.4/5 GHz energy survey | Monitor-mode Wi-Fi adapter for SSIDs, frames, WPA configuration, and retries. |
| Bluetooth / BLE audit | Observe 2.4 GHz activity | BLE sniffer or appropriate controller for advertising, hopping, pairing, and GATT. |
| Zigbee / Thread / 802.15.4 | Observe candidate channel activity | Compatible 802.15.4 sniffer for packet and network analysis. |
| LoRa / LoRaWAN | Observe chirps and capture channels | Compatible decoder/gateway and keys for authorized payload analysis. |
| Z-Wave | Observe configured regional band | Z-Wave diagnostic hardware and controller logs for security assessment. |
| NFC / HF RFID | Specialized near-field research around 13.56 MHz | Suitable coupler/front end; dedicated reader for practical protocol audits. |
| UHF RFID | Spectral observation / research | Dedicated reader or specialized receive setup; strong reader carrier is a challenge. |
| GNSS interference investigation | Examine RF conditions near an authorized receiver | GNSS receiver metrics; RF energy alone does not prove spoofing. |
| Cellular / DECT | Spectrum and selected research captures | Protocol-specific tools; carrier spectrum and traffic have separate restrictions. |
| Broadcast / telemetry reception | Receive and analyze supported waveforms | Appropriate demodulator and lawful content scope. |
| Antenna / filter comparison | Relative A/B measurement | Not a VNA, calibrated power meter, or certified EMC test. |
| Replay / input validation | Signal generation in isolated development bench | Approved DUT, verified containment, receiver observation, protocol expertise. |

### 1.3 Follow the Evidence Ladder

1. **Detected:** Energy appeared at a frequency and time.
2. **Characterized:** Bandwidth, timing, and a plausible modulation were measured.
3. **Decoded:** A decoder produced consistent, validated frames.
4. **Attributed:** Controlled device actions or records connect those frames to an asset.
5. **Security-tested:** A defined control was exercised and its outcome observed.

Do not skip from “detected at 433 MHz” to “vulnerable alarm,” or from “repeated bits” to “replay works.”

---

## SECTION 2: PRE-ENGAGEMENT CHECKLIST

### 2.1 Scope & Authorization

- [ ] Identify sites, owned devices, bands, collection locations, and testing windows.
- [ ] Define whether the assessment permits spectrum-only observations, payload decoding, or bench transmission.
- [ ] Identify third-party signals likely to fall inside the receive passband.
- [ ] Establish handling rules for incidental audio, identifiers, location data, and payloads.
- [ ] Record the emergency contact, stop conditions, and business-critical devices.
- [ ] Agree on reporting, retention, access controls, and deletion dates.
- [ ] For active work, document the isolated setup, DUT state, permitted inputs, and recovery process.

A client can authorize testing their equipment; that does not independently authorize transmission on a frequency or interception of third-party communications. In the US, intentional interference with authorized radio services is prohibited; “testing at my business” is not a general exception. Keep resilience testing in an appropriately controlled conducted/shielded lab, with regulatory requirements addressed. [FCC jammer enforcement](https://www.fcc.gov/general/jammer-enforcement).

### 2.2 Define the Questions Before Scanning

| Question | Required evidence |
|---|---|
| What changed since the last visit? | Comparable baseline and current surveys using matched settings. |
| Is equipment causing interference? | Repeatable device on/off correlation plus affected-system metrics. |
| Can this sensor be identified outside the facility? | Attributed decoded identifiers and documented observation locations. |
| Is sensitive data broadcast without protection? | Validated plaintext fields from an authorized device; impact context. |
| Does the receiver reject stale commands? | Controlled bench test and receiver-side outcome logs. |
| Is an unknown emitter unauthorized? | Physical/device attribution and asset-owner confirmation. |

### 2.3 Plan Coverage

- [ ] Assign location IDs: `L01-reception`, `L02-workbench`, `L03-parking`.
- [ ] Include different operating periods and known problem times.
- [ ] Include device startup, normal operation, and idle states where relevant.
- [ ] Choose observation durations based on emission intervals, not a universal minimum.
- [ ] Record unobserved frequencies, physical areas, and time periods as limitations.

For a device expected to transmit every five minutes, a 30-second capture cannot support a conclusion that it is silent. Observe several expected cycles and record missed opportunities.

---

## SECTION 3: EQUIPMENT, SOFTWARE & VALIDATION

### 3.1 Field Kit

- HackRF One, known-good USB data cable, and reliable host power.
- Antennas appropriate to each measured band; record antenna model and polarization.
- 50-ohm termination, suitable attenuators, and band-pass filters.
- Directional antenna for localization; near-field probes for equipment noise comparisons.
- Enough storage for IQ and a means to protect client recordings.
- Optional PortaPack, supported firmware, and suitable microSD card.
- Companion Wi-Fi/BLE/802.15.4 radios where packet analysis is required.

For bench work, add a verified attenuated RF path, suitable load, shielded enclosure if required, and independent observation equipment. Check every component's frequency and power rating.

### 3.2 Host Software

Examples assume Bash on Debian/Kali/Ubuntu-family systems. Check package availability in your distribution first; optional GUI applications may need their upstream installation method.

```bash
sudo apt update
apt-cache policy hackrf gnuradio gqrx-sdr rtl-433 soapysdr-tools soapysdr-module-hackrf
sudo apt install hackrf
```

Optional packages, when available:

```bash
sudo apt install gnuradio gqrx-sdr rtl-433 soapysdr-tools soapysdr-module-hackrf
```

| Tool | Role | Notes |
|---|---|---|
| `hackrf_info` | Device identity and firmware | Save before an engagement. |
| `hackrf_sweep` | Swept spectrum CSV | Contains power bins, not raw IQ. |
| `hackrf_transfer` | Focused IQ recording | Native receive file uses signed 8-bit interleaved I/Q. |
| Gqrx | Interactive receive inspection | Verify source, rate, gain, and demodulation before capture. |
| SDRangel | Receive analysis and protocol plugins | Plugin/build availability varies. |
| GNU Radio | Filtering, decimation, demodulation | Preserve flowgraphs and dependency versions. |
| rtl_433 + SoapyHackRF | Supported sensor decoding | HackRF is supported through SoapySDR. |
| Universal Radio Hacker | Pulse/bit comparison and protocol analysis | Upstream repository was marked archived when reviewed; validate installation and dependencies. |
| Inspectrum | Offline waveform/pulse inspection | Confirm supported input format in your installed build. |
| Wireshark | Decoded protocol capture analysis | Does not directly decode arbitrary raw HackRF IQ. |
| PortaPack Mayhem | Portable capture and receive apps | Firmware, hardware, app, and recording-format dependent. |

Sources: [HackRF tools](https://hackrf.readthedocs.io/en/latest/hackrf_tools.html), [rtl_433](https://github.com/merbanan/rtl_433), [SoapyHackRF](https://github.com/pothosware/SoapyHackRF), [SDRangel](https://github.com/f4exb/sdrangel), [URH](https://github.com/jopohl/urh).

### Repository Setup References

Use [LinuxCheatSheet.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/LinuxCheatSheet.md) for the broader Debian/Ubuntu and WSL USB workflow, or [ArchLinux_CheatSheet.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/ArchLinux_CheatSheet.md) for Arch-family packaging. These are environment references; verify capture stability on the actual host before field use.

The repository's [tool installer](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Scripts/pnwc_install_tools.sh) includes HackRF in its APT and Pacman wireless/hardware functions. It does **not** establish the complete rtl_433/SoapyHackRF stack used in Section 6.1, and its DNF branches do not list the same RF packages. Verify dependencies individually rather than assuming installer completion means this playbook is ready.

For a portable Linux host, [uConsole CM4 setup](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/uConsole/CM4-SETUP.md) and [uConsole CM5 setup](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/uConsole/CM5-SETUP.md) discuss SDR-oriented OS options. Confirm current image compatibility, USB power, storage throughput, and the selected sample rate; these pages are not evidence that a particular HackRF capture configuration has been tested.

### 3.3 Create an Engagement Workspace

Run commands in the same shell so the `CASE_DIR` variable remains available. Replace the generic case name before collecting evidence.

```bash
export TZ=UTC
umask 077
CASE_DIR="$PWD/RF-Audit-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$CASE_DIR"/{01_Planning,02_Sweeps,03_IQ,04_Decoded,05_Screenshots,06_Logs,07_Analysis,08_Report}

hackrf_info > "$CASE_DIR/06_Logs/hackrf-info.txt" 2>&1
hackrf_sweep -h > "$CASE_DIR/06_Logs/hackrf-sweep-help.txt" 2>&1
hackrf_transfer -h > "$CASE_DIR/06_Logs/hackrf-transfer-help.txt" 2>&1
uname -a > "$CASE_DIR/06_Logs/host.txt"
date -u --iso-8601=seconds > "$CASE_DIR/06_Logs/session-start.txt"
```

Some help commands exit nonzero after printing usage. Inspect their saved output. If multiple HackRF devices are connected, use `-d SERIAL` with the intended device's serial number in each HackRF command.

### 3.4 Validate the Receive Chain

1. Inspect connectors and ensure the selected port is the antenna port.
2. Keep the RF amplifier and antenna power off initially.
3. Confirm a known authorized signal at the expected approximate frequency.
4. Replace the antenna with a 50-ohm termination and compare persistent artifacts.
5. Repeat with lower gain if the spectrum appears crowded or distorted.
6. Test a short IQ recording and check its size and transfer log.
7. Resolve USB permission errors using the package's udev rules; avoid running all GUI analysis as root.
8. Record firmware and host-library versions. Do not flash firmware as an automatic troubleshooting step during an engagement.

**Starting gains:** `-a 0 -l 16 -g 16`; antenna power `-p 0`. These are starting points, not calibrated measurement settings. Adjust IF/LNA and baseband/VGA carefully; reduce gain or add attenuation for strong signals. [Gain guidance](https://hackrf.readthedocs.io/en/latest/setting_gain.html).

---

## SECTION 4: SPECTRUM DISCOVERY & BASELINE SURVEYS

### 4.1 Broad Discovery

**Objective:** Identify candidate activity in relevant bands before selecting focused captures.

1. Review the asset inventory and expected operating bands.
2. Select the correct antenna and document its position.
3. Record idle conditions and normal business conditions separately.
4. Run repeated sweeps with fixed settings.
5. Inspect peaks, bursts, occupied regions, and changes between operating states.
6. Revisit interesting regions with narrower sweeps or continuous IQ capture.

**Important unit difference:** `hackrf_sweep -f` accepts **MHz ranges**; `hackrf_transfer -f` accepts **Hz**. Sweep `-w` is FFT bin width in Hz. [Sweep syntax](https://hackrf.readthedocs.io/en/latest/hackrf_tools.html).

```bash
# Example sub-GHz discovery range; repeat with antennas suited to your scope.
hackrf_sweep -f 300:1000 -w 100000 -N 100 \
  -a 0 -p 0 -l 16 -g 16 \
  -r "$CASE_DIR/02_Sweeps/L01-subghz-baseline.csv" \
  2> "$CASE_DIR/06_Logs/L01-subghz-baseline.log"
```

`-N 100` means 100 sweeps, not 100 seconds. Record actual elapsed time and valid completed sweeps. If the installed build lacks `-N`, use a timed run or stop manually and record the duration.

### 4.2 Focused Band Examples

Run these selectively for in-scope bands, sequentially on a single HackRF. Change filenames for each location/session to avoid overwriting evidence.

```bash
# 2.4 GHz shared-band survey
hackrf_sweep -f 2400:2484 -w 100000 -N 200 \
  -a 0 -p 0 -l 16 -g 16 \
  -r "$CASE_DIR/02_Sweeps/L01-2400-2484.csv" \
  2> "$CASE_DIR/06_Logs/L01-2400-2484.log"

# Example 5 GHz survey; this is a receive span, not a channel authorization map.
hackrf_sweep -f 5150:5895 -w 250000 -N 100 \
  -a 0 -p 0 -l 16 -g 16 \
  -r "$CASE_DIR/02_Sweeps/L01-5150-5895.csv" \
  2> "$CASE_DIR/06_Logs/L01-5150-5895.log"

# Focused area around a known owned 433.92 MHz device
hackrf_sweep -f 430:440 -w 10000 -N 200 \
  -a 0 -p 0 -l 16 -g 16 \
  -r "$CASE_DIR/02_Sweeps/L02-430-440.csv" \
  2> "$CASE_DIR/06_Logs/L02-430-440.log"
```

Other useful receive survey regions depend on the asset and region: around 315 MHz, 868 MHz, 902–928 MHz, or a vendor-specified channel. Verify the device's actual regional variant. A full 1 MHz–6 GHz sweep is possible, but usually less useful than selected ranges with suitable antennas and adequate observation time.

### 4.3 Interpret Sweep CSV Correctly

Format:

```text
date,time,hz_low,hz_high,hz_bin_width,num_samples,power_bin_0,power_bin_1,...
```

- A sweep consists of multiple frequency segments. Sort by timestamp and frequency when plotting; file order is not necessarily ascending frequency.
- Each power column represents a bin. Preserve the row's start/end frequencies and bin width.
- `num_samples` is not elapsed time or a packet count.
- Upstream gives all rows within one sweep a shared timestamp; those bins were not sampled simultaneously.
- Do not label raw sweep values as calibrated dBm or infer transmitter power from them.
- Hold gain, antenna, bandwidth, position, and processing constant for comparisons.

### 4.4 Occupancy & Baseline Comparisons

**Suggested analysis procedure:**

1. Choose a frequency grid shared by both datasets.
2. Estimate a per-bin baseline during representative quiet conditions.
3. Select and document a relative threshold, such as baseline plus 6 dB. This is an analyst setting, not a universal standard.
4. Count valid visits to each bin and visits exceeding its threshold.
5. Report `100 × above-threshold visits / valid visits` as **sampled occupancy**.
6. Include total visits, survey duration, repeatability, and gaps.
7. Plot median and peak levels alongside occupancy so one rare burst is not confused with sustained use.

If computing average physical power, convert dB values to linear power before averaging, then convert back. A median in dB is a different statistic and should be labeled as such.

**Limit:** Swept occupancy is biased by retuning and revisit timing. Use fixed-frequency observation when burst timing or true time occupancy matters. A Wi-Fi AP's airtime counter and a swept energy estimate measure different things.

**Deliverables:** Per-location CSVs, settings manifest, annotated waterfall, list of candidate frequencies, and explicit coverage gaps.

---

## SECTION 5: FOCUSED IQ CAPTURE & SIGNAL ANALYSIS

### 5.1 Capture a Known Owned Device

**Objective:** Record enough waveform detail to characterize a repeatable event.

1. Identify the nominal frequency using documentation and the survey.
2. Capture baseline idle behavior.
3. Have the operator perform one documented action at a time.
4. Record several repetitions, including an idle interval between actions.
5. Keep gain fixed and avoid clipping.
6. Preserve the original IQ and analyze a working copy.

Example: approximately 30 seconds of an owned 433.92 MHz device at 8 MS/s:

```bash
date -u --iso-8601=ns > "$CASE_DIR/06_Logs/sensor433-command-start.txt"
hackrf_transfer \
  -r "$CASE_DIR/03_IQ/sensor433-action01.cs8" \
  -f 433920000 -s 8000000 -b 1750000 \
  -n 240000000 -a 0 -p 0 -l 16 -g 16 \
  2> "$CASE_DIR/06_Logs/sensor433-action01.log"
date -u --iso-8601=ns > "$CASE_DIR/06_Logs/sensor433-command-end.txt"

sha256sum "$CASE_DIR/03_IQ/sensor433-action01.cs8" \
  > "$CASE_DIR/03_IQ/sensor433-action01.cs8.sha256"
```

Here the 1.75 MHz baseband filter is intentionally selected for a narrowband target; it does not provide an 8 MHz flat passband. Choose a wider filter when the target requires it. The start timestamp marks command invocation, not the exact first RF sample. USB startup delay and any gaps must be considered in event correlation. [Transfer source and flags](https://github.com/greatscottgadgets/hackrf/blob/master/host/hackrf-tools/src/hackrf_transfer.c).

### 5.2 Storage Planning

Raw HackRF files contain one signed byte for I and one for Q, interleaved. Each complex sample occupies two bytes.

| Sample rate | Approximate bytes/second | 30 seconds | 5 minutes |
|---|---:|---:|---:|
| 8 MS/s | 16 MB | 480 MB | 4.8 GB |
| 10 MS/s | 20 MB | 600 MB | 6 GB |
| 20 MS/s | 40 MB | 1.2 GB | 12 GB |

Values use decimal MB/GB and exclude metadata. Nominal duration is `file_bytes / (2 × sample_rate)`, assuming a continuous recording. Transfer failures can invalidate that assumption. Float32 complex working files require four times the storage of signed 8-bit IQ.

### 5.3 Import Without Corrupting Interpretation

For the example above, set:

| Import property | Value |
|---|---|
| Data type | Complex signed 8-bit interleaved IQ |
| Sample order | I, Q, I, Q |
| Sample rate | 8,000,000 samples/second |
| Center frequency | 433,920,000 Hz |
| Header | None |

Do not load signed bytes as unsigned RTL-SDR IQ. Do not assume a `.wav`, `.c16`, `.cs8`, or `.cu8` extension describes every recorder identically. Renaming does not convert sample types.

If a tool accepts only complex float32, explicitly convert signed int8 to normalized floating point, preserving I/Q order and documenting the scale. In GNU Radio, an interleaved signed-byte source must be converted to complex samples before complex-domain filtering or FFT processing.

**Repository companion:** [SDR fundamentals, Chapter 11](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/sdr.md#chapter-11-digital-signal-processing-in-python) includes separate NumPy loaders for HackRF signed-byte IQ, RTL-SDR unsigned-byte IQ, and GNU Radio complex64. Keep those formats distinct when moving between tools. [Sub-GHz guide](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/subghz.md) supplies capture and post-processing workflows; apply the sample-rate and gain corrections documented in Section 14 below.

### 5.4 Analysis Checklist

- [ ] Measure center-frequency offset and occupied bandwidth with stated settings.
- [ ] Inspect burst lengths, spacing, and repetitions.
- [ ] Determine candidate modulation: OOK/ASK, FSK, PSK, OFDM, chirp, or unknown.
- [ ] Estimate symbol timing from repeated structure; verify with multiple captures.
- [ ] Distinguish line coding and whitening from encryption.
- [ ] Locate candidate preamble, sync, length, identifier, payload, and integrity fields.
- [ ] Compare different known device actions and unchanged-state repetitions.
- [ ] Validate decoded values against controlled real-world changes.
- [ ] Confirm checksum/CRC behavior where understood.
- [ ] Preserve uncertain field labels as hypotheses.

**Offset tuning:** If a signal overlaps the SDR's center spike, retune slightly while keeping it inside the useful passband, then shift it digitally for demodulation. A real signal remains at the same absolute RF frequency; a center-related artifact follows the receiver tuning.

### 5.5 Metadata

Save sample rate, center frequency, datatype, antenna, gains, filter bandwidth, hardware identity, command, timestamps, location, and DUT action in a sidecar file. SigMF is a standardized option: signed 8-bit complex data uses `ci8`, with matching `.sigmf-data` and `.sigmf-meta` files. Use `core:datatype`, `core:sample_rate`, and capture fields such as `core:sample_start` and `core:frequency`; validate metadata against the chosen specification version. Do not imply hardware timestamp precision that the recording does not have. [SigMF specification](https://sigmf.org/).

---

## SECTION 6: PROTOCOL & DEVICE AUDIT PROCEDURES

### 6.1 Sub-GHz Sensors, Weather Stations & Telemetry

**Objective:** Inventory owned devices and determine what information their transmissions expose.

1. Confirm the device model, regional frequency, and expected reporting interval.
2. Capture idle and controlled changes: temperature, switch state, or another safe stimulus.
3. Use a supported rtl_433 decoder or analyze IQ manually.
4. Compare decoded IDs and measurements with the physical device.
5. Repeat at approved interior and exterior collection points.
6. Report only attributed devices; label unrelated decoded messages incidental.

HackRF requires a SoapySDR-enabled rtl_433 build and the SoapyHackRF module. Check discovery before decoding:

```bash
SoapySDRUtil --find="driver=hackrf"
SoapySDRUtil --probe="driver=hackrf"
rtl_433 -V
rtl_433 -h
```

An example direct receive workflow is:

```bash
rtl_433 -d 'driver=hackrf' -f 433920000 -s 8000000 \
  -F "json:$CASE_DIR/04_Decoded/sensors433.jsonl" \
  2> "$CASE_DIR/06_Logs/rtl433.log"
```

Stop with Ctrl+C after the planned observation period. At 8 MS/s, decoder CPU load and behavior must be checked on the actual build. Configure supported gain elements and antenna-power settings from the probe/help output and record them; the generic example does not establish a reproducible gain profile. If direct operation is unreliable, use a documented GNU Radio filtered/decimated conversion into a decoder-supported format. Do not silently fall back to an unsuitable low HackRF hardware sample rate. [rtl_433 support and options](https://github.com/merbanan/rtl_433).

**Findings to evaluate:** Stable identifying fields, sensitive plaintext telemetry, unexpected transmission intervals, or undocumented devices. An unencrypted outdoor temperature value is not automatically a high-severity issue.

**Repository companion:** [Sub-GHz guide](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/subghz.md) Sections 9–11 contain a device/protocol lookup matrix, protocol profiles, and a capture log. Use frequency/model entries to generate candidates, then verify the exact model, regional variant, and decoded behavior. Frequency alone is not protocol identification.

### 6.2 Owned Remotes, Buttons & Simple Controllers

**Objective:** Understand message structure and identify controls needing bench verification.

- Capture at least several repeats of each normal action.
- Compare fixed fields, changing counters, and different button values.
- Check behavior after an ordinary device restart when permitted.
- Separate transmitter repetitions within one action from independent user actions.
- Document whether the receiver acknowledges an event using its logs or another receiver.
- Escalate suspected freshness/authentication issues to Section 8.

**Interpretation:** Identical captures may be normal retransmissions. Changing payloads may be counters, whitening, or state; they do not prove cryptographic security. Do not test live door, gate, alarm, vehicle, or safety controls through replay.

**Cross-tool workflow:** Follow [Flipper Zero guide](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/flipper_zero_guide.md) or [Bruce firmware guide](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/bruce_firmware.md) for device-specific collection, then preserve their original records alongside HackRF IQ. A Flipper `.sub` file contains decoded fields or pulse timings; it is not interchangeable with signed complex HackRF samples. See the [official Sub-GHz file format](https://developer.flipper.net/flipperzero/doxygen/subghz_file_format.html). Re-record with HackRF when phase/amplitude information is needed. Bruce hardware features depend on the attached radio module and build.

### 6.3 Wi-Fi Spectrum & Coexistence Audit

**Objective:** Correlate RF conditions with Wi-Fi performance.

1. Collect 2.4 GHz and relevant 5 GHz sweep baselines.
2. Focus on affected channels during reported symptoms.
3. Record AP channel, configured width, client location, and workload.
4. Collect retries, signal/noise metrics, disconnects, and channel utilization from the Wi-Fi equipment.
5. Use a monitor-mode Wi-Fi adapter for beacon, authentication, and frame-level evidence.
6. Compare RF bursts with retries and disconnect timestamps.
7. Change one approved variable, such as AP location or channel, and retest.

**Limits:** HackRF does not become `wlan0mon` and cannot be passed to Aircrack-ng as a normal Wi-Fi interface. Specialized SDR decoders exist, but full Wi-Fi assessment is not a native HackRF function. A 20 MS/s nominal capture is not a general solution for 40/80/160 MHz channels. Spectrum shape does not establish an SSID, WPA mode, or rogue AP identity.

**Repository companions:** Use the [network audit playbook](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/PlayBooks/NetworkAuditPlayBook.md), [microcontroller wireless workflow](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/microcontroller_wifi_testing.md), and [Wireshark guide](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/wireshark.md) for network-side evidence. The [Nzyme WIDS guide](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/IDS%26IPS/nzyme_wids.md) supplies a separate Wi-Fi monitoring workflow: correlate its tap events with HackRF timestamps, but do not configure HackRF as a monitor-mode Wi-Fi tap. [Marauder guide](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/WiFiMarauder_Guide.md) describes companion hardware; validate band and firmware support for the exact board.

### 6.4 Bluetooth & BLE

**Objective:** Assess RF coexistence and pair signal observations with owned-device protocol evidence.

- Observe 2.4 GHz activity while the owned device advertises, connects, and transfers data.
- Use a compatible BLE sniffer/controller to identify advertising fields and address behavior.
- Correlate packet timestamps with RF observations.
- Use device configuration and packet tooling to assess pairing and exposed services.
- Document which PHYs and channels the companion tool actually supports.

A single narrow receive window does not continuously follow every Bluetooth hop. A failed HackRF decode is not evidence that advertising is absent or payloads are encrypted.

### 6.5 Zigbee, Thread & IEEE 802.15.4

**Objective:** Examine coexistence and investigate commissioning or operational failures.

1. Obtain the configured channel from the authorized coordinator/controller.
2. Record activity around that channel during idle, join, and normal traffic.
3. Capture frames with compatible 802.15.4 hardware.
4. Compare coordinator logs, packet timing, and RF events.
5. Review commissioning policy, device inventory, and key management through the proper platform tools.

Do not infer network keys, successful decryption, or a joining flaw from a waterfall. Zigbee and Thread can share the radio layer while using different upper-layer protocols.

### 6.6 LoRa / LoRaWAN & Other LPWAN Telemetry

**Objective:** Characterize owned transmissions and correlate them with gateway behavior.

- Confirm regional channel plan and actual device/gateway settings.
- Capture complete bursts with enough bandwidth for the configured waveform.
- Record candidate chirp bandwidth, timing, and repetition.
- Use a compatible decoder or gateway logs for frame-level validation.
- Audit join behavior and counters using authorized network-server records.
- Treat application decryption as a separate, key-dependent step.

A visible chirp is not proof of a valid LoRaWAN frame. Packet losses can originate in coverage, collisions, gateway configuration, or backend processing.

### 6.7 Z-Wave & Other Home/Building Automation

**Objective:** Separate RF reliability issues from controller/security configuration issues.

- Confirm the regional hardware variant and operating frequency.
- Capture activity during normal commands to an owned noncritical device.
- Compare controller route, retry, inclusion, and security-mode logs.
- Use a suitable protocol diagnostic tool for packet-level conclusions.
- Record RF observations separately from security configuration findings.

Do not apply the same frequency plan to every region or product generation.

### 6.8 Wireless Peripherals, Microphones & Audio Equipment

**Objective:** Identify unintended RF exposure or coexistence problems in owned equipment.

- Inventory intended modes, bands, and security features from vendor documentation.
- Use synthetic test audio or non-sensitive input during the audit.
- Observe idle versus active behavior and receiver muting/link loss.
- Where lawful and scoped, use a compatible demodulator to verify whether test content is recoverable.
- Pair any plaintext finding with an attributed source and a reproducible test.

Do not infer that all wireless keyboards, headsets, or microphones use the same protocol. Proprietary hopping links may need specialized hardware; absence of decoding is not proof of protection.

### 6.9 NFC, HF RFID & UHF RFID

**Objective:** Determine whether specialized RF investigation is warranted.

- LF tags around 125/134 kHz are below HackRF One's specified tuning range.
- HF/NFC around 13.56 MHz requires suitable near-field coupling; protocol timing and weak tag responses are additional challenges.
- UHF reader signals can overwhelm the receive chain; assess power and filtering before any capture.
- Use a dedicated reader/test instrument for access-control and tag-security assessment.

HackRF is useful as a research observation tool here, not a universal badge reader or cloning device.

**Repository companion:** [RFID/NFC bench guide](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/rfid.md) covers dedicated reader choices, coupling checks, protocol profiles, and credential logging. Use it when the task is a card/reader audit rather than RF spectrum observation. Its reader-specific commands are not HackRF commands.

### 6.10 GNSS Receiver Interference Investigation

**Objective:** Investigate RF conditions around an owned positioning receiver.

1. Collect receiver lock state, satellite counts, C/N0, antenna status, and failure timestamps.
2. Compare RF observations during healthy and degraded periods.
3. Check approved nearby electronics through controlled on/off comparisons.
4. Recheck apparent interference with attenuation/filtering and, ideally, another receiver.
5. Escalate confirmed external interference through the equipment/provider process.

GNSS signals can be below the apparent noise floor of a simple spectrum display. A clean-looking sweep does not prove reception should work; an anomaly does not establish spoofing. This field procedure includes no GNSS transmission or navigation-signal simulation.

**Repository companion:** [Space Security Part IV](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SpaceSecurity/PartIV.md) provides GNSS threat and mitigation context. Keep navigation-signal simulations separate from this receive-only field workflow. See Section 14 for the incorrect duplex labels in other Space Security pages.

### 6.11 Cellular, DECT & Other Managed Radio Systems

**Objective:** Document RF activity and correlate it with authorized system logs.

- Restrict field collection to the approved spectrum/measurement scope.
- Record band, approximate occupied width, time, location, and receiver settings.
- Obtain service failures and radio-quality metrics from the owned equipment or operator.
- Treat subscriber identification, private traffic decoding, and base-station emulation as separate specialized activities outside this playbook's field workflow.

HackRF's range does not imply sufficient bandwidth, duplex capability, or decoding support for every cellular generation or deployment.

### 6.12 Broadcast, Aviation/Marine Telemetry & Satellite Reception

**Objective:** Validate receive capability or analyze permitted public/owned transmissions.

- Use a suitable antenna, filter, and protocol-specific receive application.
- For FM/AM tests, document mode and demodulator bandwidth.
- For ADS-B, AIS, or satellite telemetry, validate decoder support and capture format first.
- Use known received data for sanity checks, not precision calibration unless the reference is suitable.
- Record reception gaps and antenna/view limitations.

These are receive-analysis workflows, not authorization to transmit navigation, aviation, maritime, emergency, or satellite signals. Software designed only for RTL-SDR cannot automatically consume HackRF data without a supported backend/conversion.

### 6.13 Proprietary 2.4 GHz Peripherals & nRF24-Class Devices

**Objective:** Investigate an owned peripheral's RF behavior without assuming it is Wi-Fi or BLE.

1. Identify its actual radio chipset and regional/device configuration.
2. Collect baseline and controlled synthetic input, such as non-sensitive test keystrokes or toy-controller movements with actuators disconnected.
3. Characterize channel activity and packet timing using HackRF.
4. Use a compatible protocol-specific receiver when hopping or packet framing prevents useful SDR decoding.
5. Correlate decoded test inputs with the owned receiver's logs; report unverified classifications separately.

The [Sub-GHz/2.4 GHz guide](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/subghz.md) compares CC1101 and nRF24L01+ roles. Neither should be treated as a universal radio for the other's bands. A radio chipset match does not prove that a device is vulnerable to a named peripheral attack.


---

## SECTION 7: INTERFERENCE, LEAKAGE & MONITORING

**Background references:** [SDR fundamentals, Chapters 4 and 17](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/sdr.md) discusses RF front ends and monitoring. [advanced SDR guide, Chapters 12–13](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/sdr_hacking.md) discusses unintentional emissions and EM side channels. Treat its research examples as starting points requiring validation, not evidence that an arbitrary display or cryptographic key can be recovered with HackRF.

### 7.1 Interference Investigation

**Objective:** Establish whether an RF source causes an observed problem.

1. Reproduce the problem while logging affected-device metrics.
2. Capture a fixed span during both healthy and failing periods.
3. Identify candidate emissions and their timing.
4. Reduce receiver gain or add attenuation; check whether apparent signals disappear as overload artifacts.
5. Have the owner switch one suspected noncritical device off/on using normal controls.
6. Repeat the sequence to test reproducibility.
7. Check another location or antenna orientation.
8. Report causal confidence and plausible alternative explanations.

**Example evidence:** Repeated bursts coincide with increased AP retries; the bursts and retries disappear during authorized power-off intervals and return after restart. This supports a stronger conclusion than “large peak near the Wi-Fi channel.”

### 7.2 Approximate Source Localization

- Use a directional antenna and fixed gain.
- Record bearings from several accessible positions.
- Compare attenuation needed to keep reception unsaturated as you approach.
- Verify changes with the suspected device's controlled activity.
- Account for reflections and polarization; the strongest indoor direction may be a reflection.

One HackRF is not a coherent antenna array. Bearings and received levels support approximate localization, not automatic triangulation or a guaranteed distance estimate.

### 7.3 RF Leakage / Boundary Survey

**Objective:** Measure how an attributed signal is received across a defined physical boundary.

1. Select an owned transmitter and repeatable normal operating event.
2. Measure at approved inside, doorway, perimeter, and public-access positions.
3. Preserve antenna height, orientation, gains, rate, and processing settings.
4. Record whether energy, frames, or meaningful content was recoverable at each point.
5. Compare after approved relocation, power configuration, or shielding changes.

**Report:** “The test sensor identifier was decoded at L03 under the documented setup.” Do not convert this into “cannot be intercepted beyond L03.” Different receivers, antennas, and conditions can change reception.

### 7.4 Equipment Noise / EMC Pre-Compliance Checks

- Compare device powered off, idle, and loaded states.
- Keep probe position and cable placement repeatable.
- Check power supplies, displays, USB cables, and switching equipment.
- Retest with known-good replacement cables or supplies where appropriate.
- Use attenuation and filtering to distinguish actual harmonics from receiver-generated products.

HackRF can support troubleshooting and relative pre-compliance comparisons. Formal emissions limits, calibrated field strength, receiver blocking, or sensitivity specifications require an appropriate measurement setup and test standard.

### 7.5 Antenna, Filter & Placement Comparisons

1. Use the same stable source and receive configuration.
2. Change only the component under comparison.
3. Repeat A/B/A to detect source or environmental drift.
4. Record desired-signal level, noise/background, and decode success where applicable.
5. Include insertion loss, cable changes, orientation, and uncertainty.

Do not use this method to claim antenna SWR, impedance, return loss, or absolute gain. Use a VNA or appropriate calibrated setup for those measurements.

### 7.6 Repeated Monitoring & Baseline Drift

- Run finite sweep sessions at agreed times with unique filenames.
- Keep metadata and antenna placement constant.
- Compare per-bin occupancy and relative levels with representative baselines.
- Require repeated anomalies or corroborating device logs before escalating.
- Trigger short, scoped IQ captures for investigation rather than retaining all raw RF indefinitely.
- Track disk usage, gaps, USB failures, and configuration changes.

Suggested monitoring output: **new activity**, **persistent increase**, **expected scheduled activity**, **measurement failure**, or **needs attribution**. Never automatically classify a new peak as an attacker or jammer.

### 7.7 Unintentional Information Leakage & EM Research Triage

**Objective:** Determine whether an owned device's emissions correlate with a controlled workload and warrant specialized investigation.

- Use non-sensitive test patterns and a fixed probe/antenna position.
- Compare powered-off, idle, and known active workloads across repeated runs.
- Confirm candidate emissions are not receiver artifacts or unrelated devices.
- Record repeatable correlations without claiming content reconstruction or key recovery.
- Escalate only with adequate bandwidth, triggering, alignment, and measurement equipment.

[Advanced SDR Chapters 12–13](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/sdr_hacking.md) provides TEMPEST/EM context. [Hardware Hacking Chapter 5](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/HardwareHacking/Chapter5.md) discusses trace acquisition, filtering, and alignment. Its power-trace setup and sampling assumptions are not automatically transferable to free-running HackRF IQ. A visible workload-dependent peak is evidence of correlation, not proof of exploitable data leakage.


---

## SECTION 8: CONTROLLED BENCH SECURITY TESTS

### 8.1 Bench Preconditions

These procedures apply to an owned development/test device with an inert output, not operational access, vehicle, alarm, medical, or safety equipment.

- [ ] Explicit active-test scope and a restorable DUT configuration.
- [ ] Verified conducted path or adequate RF containment.
- [ ] Appropriate attenuation, loads, filtering, and component ratings.
- [ ] Power reaching each receiver safely below its limit with margin.
- [ ] Independent observation: DUT logs, logic output, or another receiver.
- [ ] Finite test cases and stop conditions; no uncontrolled continuous transmission.
- [ ] Production accounts, keys, actuators, and live integrations removed.

Calculate the maximum credible receive input:

`P_rx = P_tx − attenuation − cable/path loss`

Include uncertainty, frequency-dependent output, possible amplifier settings, and attenuator power ratings. Do not assume a nominal low software gain guarantees a safe input. HackRF is half duplex, so a single device cannot transmit and simultaneously monitor the receiver's reply. [Hardware and power limits](https://hackrf.readthedocs.io/en/latest/hackrf_one.html).

### 8.2 Freshness / Replay-Resistance Assessment

**Objective:** Determine whether an isolated receiver rejects an already-used valid test message.

1. Establish normal behavior with a benign test action and record the receiver state.
2. Preserve the corresponding test waveform/message and its metadata.
3. Reintroduce that known test message once through the verified isolated path.
4. Observe actual receiver acceptance or rejection; RF transmission alone is not success.
5. Compare with a fresh legitimate test action to ensure the receiver remains functional.
6. Record the result and restore the initial state.

**Pass criterion:** The receiver rejects stale actions when freshness is a required security property and continues accepting legitimate new actions. A rejection without a valid positive control is inconclusive.

### 8.3 Message Integrity / Authentication

- Use a protocol-aware test harness to alter one non-actuating test field.
- Verify that malformed or unauthenticated messages are rejected and logged where expected.
- Include legitimate positive controls before and after the test.
- Distinguish checksum/CRC checks from cryptographic authentication.
- Record receiver state and recovery, not just the transmitted waveform.

A CRC detects accidental corruption; it does not by itself authenticate a sender.

### 8.4 State, Counter & Restart Behavior

- Exercise ordinary restart and reconnect behavior within the bench scope.
- Verify security state persists or is re-established as specified.
- Compare legitimate message handling across restarts.
- Test only documented benign states and preserve a recovery path.
- Record whether observations imply a control failure or an undocumented design decision needing vendor review.

### 8.5 Receiver Robustness

Use a finite, protocol-aware suite of benign malformed messages to test length handling, unsupported types, and recovery. Monitor crashes, rejected inputs, logs, and normal operation after each case. This is not an over-the-air flooding or jamming procedure.

### 8.6 Findings & Remediation

| Confirmed issue | Remediation direction |
|---|---|
| Stale command accepted | Authenticated freshness mechanism and durable replay state. |
| Unauthenticated control accepted | Cryptographic message authentication and secure key provisioning. |
| Sensitive telemetry exposed | Appropriate confidentiality plus authentication; reduce unnecessary fields. |
| Parser crash on malformed input | Bounds validation, robust parser handling, and recovery. |
| Unsafe state after link loss/restart | Explicit safe-state design and tested recovery behavior. |
| Excessive RF exposure | Placement/power review, antenna design, and secure protocol assumptions. |

No universal transmit command is provided: replay settings, timing, waveform format, containment, and acceptable receiver behavior must be established for the specific test system.

---

## SECTION 9: PORTAPACK / MAYHEM FIELD WORKFLOW

PortaPack adds portable controls, display, storage, and firmware applications; it does not remove HackRF's RF bandwidth, dynamic-range, or duplex limits. Feature names and recording formats depend on the installed firmware and hardware. Use the [official Mayhem project and wiki](https://github.com/portapack-mayhem/mayhem-firmware).

### 9.1 Preparation

- [ ] Record HackRF/PortaPack hardware revision and firmware version.
- [ ] Verify receive apps and SD-card resources on the actual device.
- [ ] Confirm clock/time behavior; annotate inaccurate timestamps.
- [ ] Verify storage capacity and a short recording before going onsite.
- [ ] Confirm amplifier and antenna-power settings.
- [ ] Review which menu actions receive versus transmit.

### 9.2 Field Procedure

1. Select a receive spectrum/search application available in your build.
2. Enter an in-scope band and conservative receive gains.
3. Log location, antenna orientation, frequency span, and observation time.
4. Narrow to an interesting signal and capture a short recording if supported.
5. Use receive-only protocol apps only where authorized and supported.
6. Record any decoder output as preliminary until correlated with the owned asset.
7. Photograph settings when the application cannot export them.
8. Copy evidence to the host and hash the originals before analysis.

Do not assume an app labeled “scanner” continuously covers all listed channels. Record dwell, step, and scan list when available.

### 9.3 Host Handoff

- Identify the exact recording format, sample rate, and metadata file.
- Check whether the app stores signed 8-bit, signed 16-bit, audio, or another format.
- Convert explicitly when needed; do not merely rename a file to `.cs8`.
- Reopen a known test capture to verify frequency, duration, and amplitude interpretation.
- For host-controlled use, select the firmware's USB/HackRF mode as documented and confirm `hackrf_info` can access it.

**Deliverables:** Original SD recordings and sidecars, firmware identity, screen photographs, location log, and documented conversions.

---

## SECTION 10: DOCUMENTATION & EVIDENCE

### 10.1 Activity Log Template

```text
Evidence ID:
UTC timestamp / timing uncertainty:
Tester / location ID:
Authorization scope / owned asset:
Question being tested:
Hardware model / serial / firmware:
Tool version / command or GUI profile:
Antenna / cable / filter / attenuation:
Center frequency or sweep range:
Sample rate / FFT bin width / baseband filter:
RF amp / LNA / VGA / antenna power:
Device action / operating state:
Start/end times / actual valid duration:
Dropped samples, errors, or missing coverage:
Observed result:
Interpretation / confidence / alternatives:
Files / hashes / screenshot references:
Next validation step:
```

**Align with existing repository logs:** Reuse the device-model, FCC ID, modulation, pulse-width, and protocol-field records from the [Sub-GHz capture matrix](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/subghz.md). Add the IQ datatype, input protection, gain-stage values, timing uncertainty, dropped-sample notes, and hashes required here. Link both logs with the same evidence ID instead of duplicating conflicting metadata.

### 10.2 Evidence Requirements by Activity

| Activity | Minimum evidence |
|---|---|
| Broad survey | Original CSV, tool log, antenna/settings, location, start/end times. |
| IQ analysis | Original IQ, datatype/rate/frequency, transfer log, action labels, hash. |
| Decoding | Decoder version/settings, output, IQ reference, asset correlation. |
| Interference | RF capture plus affected-system logs and controlled comparison. |
| Leakage | Map/location descriptions, matched settings, attributed reception result. |
| Bench test | Approved setup, power/containment record, test case, positive controls, DUT outcome. |
| Retest | Original finding reference and comparable new evidence. |

Screenshots should show frequency span, axes, gains, timestamp, and tool identity. A waterfall image alone is insufficient evidence for payload or authentication claims.

### 10.3 Hash Finalized Evidence

Hash files only after recording completes. Regenerate a final manifest after intentional evidence additions; retain prior versions when chain of custody requires them.

```bash
python3 - "$CASE_DIR" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest = root / 'evidence-sha256.txt'
with manifest.open('w', encoding='utf-8') as out:
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path == manifest:
            continue
        digest = hashlib.sha256()
        with path.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        out.write(f'{digest.hexdigest()}  {path.relative_to(root).as_posix()}\n')
PY
```

Keep originals unchanged and document any conversion, filtering, decimation, trimming, or redaction as a derived file. A hash supports integrity checking; it does not establish collection time, attribution, or a full chain of custody by itself.

### 10.4 Minimize Incidental Collection

An RF passband can contain multiple transmitters before their identities are known. Define scope before capture, minimize duration/bandwidth, restrict access to raw files, and sanitize report extracts. Filtering a decoded report does not remove incidental material from its underlying IQ file.

---

## SECTION 11: ANALYSIS, REMEDIATION & REPORTING

### 11.1 Classify Results

Use **confirmed**, **probable**, **unresolved**, or **not observed under tested conditions** for technical confidence. Keep confidence separate from severity.

| Observation | Appropriate treatment |
|---|---|
| Unknown RF peak | Inventory/anomaly item pending attribution. |
| Owned sensor exposes a stable ID | Privacy or tracking concern only where context supports impact. |
| Non-sensitive plaintext reading | Informational or contextual design issue. |
| Sensitive authorized data recovered | Confidentiality finding with demonstrated scope. |
| Bench receiver accepts stale authenticated action | Freshness/control finding based on demonstrated impact. |
| Reproducible RF-linked service failure | Availability/reliability finding with causal evidence. |
| No activity captured | Coverage-limited observation, not a universal assurance. |

Use CVSS only when a concrete technical vulnerability can be scored meaningfully; include the version/vector if used. Do not force spectrum anomalies into CVSS or assign a critical rating based solely on the presence of radio activity.

### 11.2 Finding Template

```text
Finding ID / title:
Affected asset and owner:
Category: confidentiality / integrity / availability / privacy / reliability
Severity and rationale:
Confidence and supporting evidence:

Observed behavior:
Expected behavior / security requirement:
Business impact:
Exact scope and physical conditions:
Reproduction steps:
Evidence IDs and hashes:
Positive/negative controls:
Alternative explanations tested:
Untested assumptions / measurement limitations:

Immediate remediation:
Long-term remediation:
Responsible owner / target date:
Retest method and acceptance criteria:
Retest result:
```

### 11.3 Final Report Structure

1. **Executive summary:** Questions answered, major findings, and business impact.
2. **Scope:** Sites, devices, bands, time windows, permitted test modes, and exclusions.
3. **Methodology:** Hardware, software, calibration status, locations, and capture strategy.
4. **RF inventory:** Attributed assets and separately listed unidentified activity.
5. **Findings:** Evidence, confidence, severity, and practical fixes.
6. **Limitations:** Sweep blind spots, receiver limitations, timing uncertainty, and unsupported protocols.
7. **Remediation plan:** Owners, priorities, and measurable acceptance criteria.
8. **Appendices:** Settings, sanitized results, hashes, tool versions, and source references.

### 11.4 Retest Checklist

- [ ] Use matched antenna, location, gains, and processing where comparison matters.
- [ ] Reproduce the original operating conditions.
- [ ] Repeat legitimate positive controls.
- [ ] Measure the specific acceptance criterion.
- [ ] Document configuration changes and remaining limitations.
- [ ] Confirm normal operation after testing.
- [ ] Apply agreed retention and deletion rules.

---

## SECTION 12: TROUBLESHOOTING & QUICK REFERENCE

### 12.1 Common Problems

| Symptom | Likely causes | Next check |
|---|---|---|
| HackRF not detected | USB cable/power, permissions, firmware mode | Data cable, direct USB port, udev, PortaPack USB mode. |
| Device busy | Another application owns the radio | Close other SDR applications before retrying. |
| Strong spike exactly at center | DC/LO-related artifact | Offset tuning and terminated-input comparison. |
| Many mirrored/unexpected peaks | Overload or images | Lower gain, attenuation, filtering, alternate tuning. |
| Weak/no expected signal | Wrong antenna/band, polarization, intermittent source | Known-source test and longer focused capture. |
| Sweep misses button press | Revisit gap | Continuous focused IQ; repeat controlled action. |
| Capture file too short | USB drop, disk issue, interrupted process | Transfer log, byte count, disk space, shorter capture. |
| Decoder produces nonsense | Wrong format/rate/modulation, bad SNR | Import metadata and known controlled reference. |
| rtl_433 cannot open HackRF | Missing Soapy module/build support | Soapy find/probe and rtl_433 help output. |
| Results differ between visits | Gain/antenna/location/time changes | Compare full settings before interpreting drift. |
| PortaPack file looks distorted | Incorrect IQ datatype or sample rate | Verify app format and documented conversion. |
| “Encrypted” conclusion from decode failure | Unsupported decoder or poor capture | Mark unresolved; inspect the protocol separately. |

### 12.2 Command Reminders

| Task | Command / pattern |
|---|---|
| Identify hardware | `hackrf_info` |
| Check sweep options | `hackrf_sweep -h` |
| Check capture options | `hackrf_transfer -h` |
| Select a HackRF | Add `-d SERIAL` to HackRF tool commands. |
| Sweep a band | `hackrf_sweep -f LOW_MHZ:HIGH_MHZ -w BIN_HZ -N COUNT -r FILE.csv` |
| Receive IQ | `hackrf_transfer -r FILE.cs8 -f CENTER_HZ -s RATE_HZ -n SAMPLES` |
| Conservative receive settings | `-a 0 -p 0 -l 16 -g 16` |
| Check Soapy backend | `SoapySDRUtil --probe="driver=hackrf"` |
| Hash one completed file | `sha256sum FILE` |

**Review every command before use.** In HackRF tools, `-p` controls antenna-port power. In other SDR programs, the same flag can mean frequency correction or something else. Flags are not interchangeable between tools.

### 12.3 Field Completion Checklist

- [ ] Scope and collection locations confirmed.
- [ ] Receive chain checked against a known source.
- [ ] Baseline and active-state observations collected.
- [ ] Interesting activity captured continuously where needed.
- [ ] Asset identity independently validated.
- [ ] Protocol conclusions supported by suitable tools.
- [ ] Overload, timing gaps, and alternative explanations considered.
- [ ] Original evidence preserved with metadata and hashes.
- [ ] Findings distinguish RF observations from demonstrated weaknesses.
- [ ] Remediation and retest criteria recorded.

---

## SECTION 13: REFERENCES & DOCUMENT CONTROL

### Primary References

- [Original PNWC Network Audit Playbook](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/PlayBooks/NetworkAuditPlayBook.md) — structural reference.
- [HackRF One documentation](https://hackrf.readthedocs.io/en/latest/hackrf_one.html) — hardware limits and input protection.
- [HackRF tools](https://hackrf.readthedocs.io/en/latest/hackrf_tools.html) — sweep syntax and CSV fields.
- [Sampling rate and baseband filters](https://hackrf.readthedocs.io/en/latest/sampling_rate.html) — low-rate limitations and decimation.
- [Receive gain controls](https://hackrf.readthedocs.io/en/latest/setting_gain.html) — gain stages and starting settings.
- [hackrf_transfer source](https://github.com/greatscottgadgets/hackrf/blob/master/host/hackrf-tools/src/hackrf_transfer.c) — capture options and sample representation.
- [rtl_433 project](https://github.com/merbanan/rtl_433) — supported sensors, SoapySDR input, and decoder options.
- [SoapyHackRF](https://github.com/pothosware/SoapyHackRF) — HackRF backend for SoapySDR.
- [SDRangel](https://github.com/f4exb/sdrangel) — receive analysis and channel plugins.
- [Universal Radio Hacker](https://github.com/jopohl/urh) — protocol analysis; check repository maintenance status.
- [PortaPack Mayhem](https://github.com/portapack-mayhem/mayhem-firmware) — firmware, hardware notes, and app documentation.
- [SigMF](https://sigmf.org/) — recording metadata and sample datatype conventions.
- [FCC jammer enforcement](https://www.fcc.gov/general/jammer-enforcement) — US restrictions on intentional interference.

### Document Control

- **Version:** 1.1
- **Created:** September 15, 2026
- **Next review:** December 2026, or after material hardware/software changes.
- **Validation:** Upstream documentation/source review and static example checks; hardware execution still required before operational adoption.
- **Maintenance:** Recheck command help, distribution packages, decoder compatibility, firmware formats, and regulatory context before field use.

### Related Files

- [PlayBooks index](README.md)
- [Wireless & Network Security Audit Playbook](NetworkAuditPlayBook.md)

## SECTION 14: REPOSITORY CROSS-REFERENCE & CONSISTENCY REVIEW

### 14.1 Review Scope

Reviewed the repository snapshot [986c00ce7710](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/986c00ce7710570f213381bfd067a8f3a19438eb) on September 15, 2026. The recursive tree returned **589 entries** without truncation. Searched repository text for HackRF/PortaPack and related SDR, decoder, and companion-radio terms, then inspected relevant sections and code examples. **23 text files contained direct HackRF/PortaPack mentions.** The companion list below also includes relevant files without those exact terms.

Extracted searchable text from all **20 PDFs**; no HackRF/PortaPack or selected SDR-term matches appeared. Two PDFs (`PDF/OSCP_Cheat_Sheet.pdf` and `PDF/ReactJs_Cheatsheet.pdf`) yielded negligible text and were not OCR-reviewed. Images and embedded screenshots were not exhaustively inspected. This is a targeted RF cross-reference and consistency review, not a full correctness audit of every repository topic.

No standalone `.iq`, `.cs8`, `.cu8`, `.c16`, `.sigmf-data`, `.sigmf-meta`, `.grc`, `.sub`, `.pcap`, or `.pcapng` files appeared in the reviewed tree. The useful RF material is primarily documentation, embedded examples, and setup scripts; no reusable HackRF capture corpus or standalone GNU Radio flowgraph was found. The exact current device firmware, installed tool versions, and live hardware behavior were not tested.

### 14.2 Companion Document Map

Links below follow `main` for convenient navigation. The reviewed snapshot above fixes the version used for the findings in this section.

| Repository document | How it supports this playbook |
|---|---|
| [SDR/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/README.md) | Section index and tool routing; start here for the existing RF library. |
| [SDR/sdr.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/sdr.md) | Foundations: hardware, antennas, GNU Radio, IQ loaders, protocols, and monitoring. |
| [SDR/subghz.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/subghz.md) | Practical capture workflows, protocol matrix, and laboratory logging. |
| [SDR/sdr_hacking.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/sdr_hacking.md) | Advanced signal reversal, receiver testing, LoRa, TEMPEST, and EM research context. |
| [SDR/rfid.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SDR/rfid.md) | Dedicated LF/HF RFID/NFC workflow; companion tools rather than direct HackRF capability. |
| [Documentation/flipper_zero_guide.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/flipper_zero_guide.md) | Flipper module operation and field-to-bench integration. |
| [Documentation/bruce_firmware.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/bruce_firmware.md) | Module-specific portable operations and independent SDR observation. |
| [Documentation/microcontroller_wifi_testing.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/microcontroller_wifi_testing.md) | Coordinated Flipper/CC1101, Wi-Fi, and network-side evidence workflow. |
| [Documentation/WiFiMarauder_Guide.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/WiFiMarauder_Guide.md) | Wi-Fi/Bluetooth companion hardware; exact capabilities depend on board/build. |
| [Documentation/wireshark.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/wireshark.md) | Packet-level analysis and BLE capture-tool references. |
| [IncidentResponse/IDS&IPS/nzyme_wids.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/IDS%26IPS/nzyme_wids.md) | Wi-Fi monitoring and alert correlation; separate monitor-mode radio required. |
| [Documentation/LinuxCheatSheet.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/LinuxCheatSheet.md) | Debian/Ubuntu tooling and WSL USB setup context. |
| [Documentation/ArchLinux_CheatSheet.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Documentation/ArchLinux_CheatSheet.md) | Arch-family tooling and RF package references. |
| [Scripts/pnwc_install_tools.sh](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Scripts/pnwc_install_tools.sh) | Existing wireless/hardware install functions; dependency gaps noted below. |
| [uConsole/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/uConsole/README.md) | Portable-host and OS overview. |
| [uConsole/CM4-SETUP.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/uConsole/CM4-SETUP.md) | CM4 host setup and SDR-oriented image reference. |
| [uConsole/CM5-SETUP.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/uConsole/CM5-SETUP.md) | CM5 host setup and SDR-oriented image reference. |
| [SpaceSecurity/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SpaceSecurity/README.md) | Space-security index and RF tool overview; duplex correction below. |
| [SpaceSecurity/PartI.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SpaceSecurity/PartI.md) | Foundational RF/space-security context; duplex correction below. |
| [SpaceSecurity/PartII.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SpaceSecurity/PartII.md) | Ground-link and IQ capture context; low-rate example requires review. |
| [SpaceSecurity/PartIV.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SpaceSecurity/PartIV.md) | GNSS threat/mitigation and terminal-security context. |
| [SpaceSecurity/Appendices.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SpaceSecurity/Appendices.md) | Supplementary spectrum/tool reference. |
| [HardwareHacking/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/HardwareHacking/README.md) | Hardware research and test-equipment routing. |
| [HardwareHacking/Chapter5.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/HardwareHacking/Chapter5.md) | Trace acquisition, filtering, alignment, and analysis context. |
| [PlayBooks/NetworkAuditPlayBook.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/PlayBooks/NetworkAuditPlayBook.md) | Engagement structure and complementary network assessment. |
| [SPECIALIZED_TOPICS_GUIDE.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/SPECIALIZED_TOPICS_GUIDE.md) | Broader RF material; read with the specific corrections below. |

### 14.3 Corrections & Compatibility Notes

These discrepancies were found in the reviewed source documents. This version of the playbook uses the corrected interpretation; the upstream repository files have not been edited as part of this deliverable.

| Source location | Issue found | Interpretation to use |
|---|---|---|
| [SpaceSecurity/README.md, near line 183](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SpaceSecurity/README.md#L183) | HackRF described as full duplex. | HackRF One is half duplex; it cannot receive and transmit simultaneously. |
| [SpaceSecurity/PartI.md, near line 165](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SpaceSecurity/PartI.md#L165) | The same full-duplex specification appears in the tool table. | Use half duplex consistently across the Space Security documentation. |
| [SPECIALIZED_TOPICS_GUIDE.md, near line 2091](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SPECIALIZED_TOPICS_GUIDE.md#L2091) | HackRF listed as 12-bit. | HackRF One samples I and Q with 8-bit resolution. |
| [SPECIALIZED_TOPICS_GUIDE.md, near line 2333](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SPECIALIZED_TOPICS_GUIDE.md#L2333) | One HackRF described as capable of simultaneous interference transmission and capture. | That simultaneous operation is inconsistent with the hardware. Do not carry this claim into any workflow. |
| [SDR/subghz.md, near line 236](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SDR/subghz.md#L236) | Capture/flowgraph guidance presents 2 MS/s as a clean default; several other guides repeat 2 MS/s examples. | The rate is supported, but upstream recommends avoiding rates below 8 MS/s. Use an appropriate filter and software decimation; reassess duration and storage after changes. |
| [SDR/subghz.md, near line 311](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SDR/subghz.md#L311) | GNU Radio example requests HackRF IF gain of 20 dB. | HackRF LNA/IF gain uses 8 dB steps. Use a supported value such as 16 or 24 dB and verify what the backend applies. |
| [SDR/subghz.md, near line 315](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SDR/subghz.md#L315) | Complex GNU Radio File Sink and raw hackrf_transfer files both use generic IQ names; unbuffered writes are described as guaranteed instant writes. | Record the actual datatype. Complex float32 is not signed int8. Disabling application buffering does not guarantee durable disk writes or lossless collection. |
| [SDR/sdr.md, near line 1249](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SDR/sdr.md#L1249) | Sweep values are printed as dBm without calibration. | Label relative reported power unless the complete measurement chain is calibrated. |
| [SDR/sdr.md, near line 1255](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SDR/sdr.md#L1255) | Wi-Fi example uses RtlSdr() at 2.4 GHz and labels an instantaneous power estimate as occupancy. | Typical RTL-SDR tuners do not reach 2.4 GHz. Use suitable hardware and the repeated/time-aware occupancy methodology in Section 4.4. |
| [SDR/subghz.md, near line 569](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SDR/subghz.md#L569) | Identical/different messages are treated as definitive fixed/rolling-code identification. | Repetitions, counters, state, coding, and cryptography need separate validation. Message equality alone does not prove receiver replay behavior. |
| [SDR/subghz.md, near line 430](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/SDR/subghz.md#L430) | Offline decoder example uses a .cu8 file while neighboring HackRF examples produce signed-byte IQ. | Do not rename signed IQ to unsigned IQ. Convert the format and preserve the real sample rate or use a verified supported input path. |
| [Scripts/pnwc_install_tools.sh, near line 649](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/986c00ce7710570f213381bfd067a8f3a19438eb/Scripts/pnwc_install_tools.sh#L649) | Wireless install function includes core SDR packages but not the complete decoder/backend chain used here. | Verify rtl_433, SoapySDR, SoapyHackRF, GUI tools, and supported modules separately; package coverage differs across distributions. |

Hardware corrections are grounded in [HackRF One specifications](https://hackrf.readthedocs.io/en/latest/hackrf_one.html), [sampling/filter guidance](https://hackrf.readthedocs.io/en/latest/sampling_rate.html), and [gain controls](https://hackrf.readthedocs.io/en/latest/setting_gain.html). These notes identify issues encountered while integrating the guide; they are not a claim that all other examples have been validated.

### 14.4 Additional Mentions & Navigation

Other direct mentions appear in the root `README.md`, `ENHANCED_MASTER_GUIDE.md`, `START_HERE.md`, `GLOSSARY.md`, `Homelab/README.md`, `Documentation/evil_m5.md`, and `AI/OpenClaw/agent_skill_config.md`. These are primarily navigation, hardware lists, comparisons, or agent-context entries, rather than independent HackRF audit procedures.

The existing `AUDIT_FINDINGS.md` records broader maintenance concerns, including SDR software compatibility. Use it as an issue-tracking reference, not as proof that an installed decoder works. No dedicated PortaPack/Mayhem operational guide was found; Section 9 supplies that workflow and links to upstream firmware documentation.

For repository integration, place this file at `PlayBooks/HackRFAuditPlayBook.md`. Add a link from `PlayBooks/README.md` and `SDR/README.md`, then optional reciprocal links from `SDR/sdr.md`, `SDR/subghz.md`, and `SDR/sdr_hacking.md`. Suggested description: **HackRF field audit playbook — spectrum surveys, IQ capture, interference analysis, protocol triage, evidence, and reporting.**

### 14.5 Revision History

| Version | Change |
|---|---|
| 1.0 | Initial standalone HackRF audit playbook. |
| 1.1 | Repository-wide reference discovery, contextual companion links, proprietary 2.4 GHz and EM-research triage, evidence-template alignment, installer caveats, and source-discrepancy register. |

## END OF PLAYBOOK