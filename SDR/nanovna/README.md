# 📶 NanoVNA Vector Network Analysis — Antennas, Feedlines & RF Measurement

<div align="center">

**Field manual for SEESII NanoVNA-H (HW3.7) and NanoVNA-H4 (V4.4) — antenna testing, impedance matching, cable fault location, and defensible RF measurement**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [SDR & RF Section](../README.md)*

![NanoVNA](https://img.shields.io/badge/Hardware-NanoVNA_H_%2F_H4-blue?style=for-the-badge&logo=raspberrypi)
![Range](https://img.shields.io/badge/Coverage-9kHz_--_1.5GHz-green?style=for-the-badge&logo=wifi)
![Focus](https://img.shields.io/badge/Focus-Antennas_%26_Feedlines-blueviolet?style=for-the-badge)
![Tooling](https://img.shields.io/badge/Tooling-Touchstone_Diff-orange?style=for-the-badge&logo=python)

</div>

---

## 🎯 Purpose

This README is the entry point for the NanoVNA subsection. It connects **twelve companion documents** plus a Python toolchain covering instrument setup, RF fundamentals, calibration, antenna testing and tuning, cable and filter measurement, worked examples, and measurement scope.

A vector network analyzer answers a different question than an SDR. An SDR tells you **what is on the air**; a VNA tells you **whether your own receive chain can hear it**. The antenna, feedline, connectors, and filters that every capture in the rest of this section depends on are exactly what this subsection measures.

## ⚙️ Function

Use this index to select a document, calibrate correctly at a known reference plane, test and tune an antenna, locate a feedline fault by distance, characterize a filter, and archive results in a form that can be compared months later.

## 🏆 Goal

Move from an RF symptom to a documented, defensible result: calibrate at a stated plane, measure the antenna system, distinguish an antenna fault from a feedline fault, make one controlled change at a time, and produce before/after evidence a customer can act on.

## 📋 When to Use

- Commissioning, tuning, or accepting any antenna installation.
- Validating the receive chain before blaming a capture on the SDR or the band.
- Locating a cable fault by distance instead of by tracing or climbing.
- Proving a feedline has degraded, rather than assuming it.
- Tuning a duplexer or cavity, or verifying a filter, attenuator, or dummy load.
- Building a baseline library for recurring site visits and service records.

> **Instrument protection:** Physically disconnect every transmitter before connecting a NanoVNA. Use a DC block on any system that might carry bias-tee voltage, and discharge static from outdoor antennas. The commonly cited maximum input is **+10 dBm** — one hundredth of a watt — and the receive path is unprotected. See [Safe Workflows](#safe-workflows).

---

## Table of Contents

- [Guides in This Subsection](#guides-in-this-subsection)
- [Choose a Starting Point](#choose-a-starting-point)
- [The 60-Second Version](#the-60-second-version)
- [Hardware and Coverage](#hardware-and-coverage)
- [Tooling](#tooling)
- [Safe Workflows](#safe-workflows)
- [Scope and Legal Boundaries](#scope-and-legal-boundaries)
- [Contributing](#contributing)
- [Resources](#resources)
- [Related Repository Material](#related-repository-material)
- [Subsection Inventory and Maintenance](#subsection-inventory-and-maintenance)

## Guides in This Subsection

| Guide | Level | Focus |
|---|---|---|
| **[Hardware, Controls, and Setup](01-hardware-and-setup.md)** | 🟢 Foundational | Model comparison, port mapping, menu tree, first power-on, accessory kit, and the failure modes that destroy the instrument. |
| **[RF Fundamentals and Display Formats](02-rf-fundamentals.md)** | 🟢 Foundational | Reflection coefficient, S-parameters, VSWR and return loss with the sign-convention trap, phase, group delay, and reading the Smith chart. |
| **[Calibration and the Reference Plane](03-calibration.md)** | 🟢 Foundational | SOLT procedure, what the calibration plane changes, feedline loss arithmetic, status indicators, slot strategy, and errors that look plausible. |
| **[Checking Antennas](04-antenna-testing.md)** | 🟡 Practical / Field | Safety sequence, sweep setup, establishing repeatability, and a decision tree from trace shape to physical cause. |
| **[Tuning Antennas](05-antenna-tuning.md)** | 🟡 Practical / Bench | Element trimming, ground-plane geometry as a matching technique, L-network design from measured impedance, transformers, stubs, and chokes. |
| **[Cables, Filters, and Other Measurements](06-cables-filters-other-uses.md)** | 🟡 Practical / Bench | Time-domain fault location and its real limits, velocity factor, cable loss, filters and duplexers, components, isolation, and shielding. |
| **[Field Quick Reference Card](07-quick-reference.md)** | 🟢 Reference / All Levels | Printable pre-flight checklist, conversion tables, every formula, velocity factors, band presets, and a troubleshooting flowchart. |
| **[PC Software, Export, and Firmware](08-pc-software-and-firmware.md)** | 🟡 Practical | NanoVNA-Saver, segmented sweeps, Touchstone export, serial automation, firmware updates, and DFU recovery. |
| **[Worked Tuning Examples by Band](09-worked-examples-by-band.md)** | 🟡 Practical / Bench | Thirteen complete examples from 40 m through 1090 MHz — setup, sweep, diagnosis, arithmetic, action, result. |
| **[Antenna Types and Special Cases](10-antenna-types-and-special-cases.md)** | 🟡 Practical / Bench | Handhelds, receive-only and SDR antennas, active antennas, 75 Ω systems, mobile and dual-band whips, end-feds, traps, Yagis, discones. |
| **[Field Worksheet and Practice Exercises](11-worksheet-and-exercises.md)** | 🟢 All Levels | A copy-per-job measurement record, plus eight bench exercises that teach the instrument using known loads. |
| **[Sources, Scope, and Verification Limits](12-sources-and-scope.md)** | 🟢 Reference | What is verified, what is convention, what is unverified, primary sources, and what these procedures do **not** establish. |

> **Included tooling:** [`tools/s1pdiff.py`](tools/README.md) analyses a Touchstone `.s1p` sweep and compares one against an archived baseline, with scriptable exit codes for unattended monitoring.

## Choose a Starting Point

| What you need to do | Start here | Follow with |
|---|---|---|
| Learn VNA measurement from the beginning | [01](01-hardware-and-setup.md) → [02](02-rf-fundamentals.md) → [03](03-calibration.md) | Exercises 1–5 in [11](11-worksheet-and-exercises.md) before touching a real antenna. |
| Test or accept an antenna installation | [04](04-antenna-testing.md) | [11](11-worksheet-and-exercises.md) to record the result as a baseline. |
| Tune an antenna to a target frequency | [05](05-antenna-tuning.md) | The matching band in [09](09-worked-examples-by-band.md). |
| Find a cable fault without climbing | [06](06-cables-filters-other-uses.md) | The distance-to-fault example in [04 §4.7](04-antenna-testing.md). |
| Validate an SDR or ADS-B receive chain | [10 §10.3](10-antenna-types-and-special-cases.md) | Filter and LNA measurement in [06](06-cables-filters-other-uses.md). |
| Work a job in the field, offline | [07](07-quick-reference.md) | [11](11-worksheet-and-exercises.md) as the record sheet. |
| Compare today's sweep to last year's | [tools/](tools/README.md) | The baseline-library workflow in [06 §6.10](06-cables-filters-other-uses.md). |
| Write measurements into a customer report | [12](12-sources-and-scope.md) | The suggested report language in §12.4. |

## The 60-Second Version

1. **Set the frequency span first.** A calibration is valid only across the span it was taken on.
2. **Calibrate with the exact cables and adapters you will measure through.** The calibration plane is wherever you put the standards, not the front panel.
3. **Never connect to anything transmitting, carrying DC, or holding static.** The front end is unprotected.
4. **Establish repeatability before believing anything.** If the trace moves when you move the coax, you are measuring your test setup.
5. **VSWR is not the goal.** A 50 Ω dummy load shows a perfect match and radiates nothing.
6. **Resonance low = element too long; resonance high = element too short.** Cut half of what the arithmetic says, then re-measure.
7. **Reactance and resistance are separate problems.** Cancelling reactance does not match an impedance.

## Hardware and Coverage

| Unit | Role | Limits to check on your own hardware |
|---|---|---|
| **NanoVNA-H (HW 3.7)** | Pocket field unit for quick checks and go/no-go verification | Screen size, sweep points, calibration slots, battery capacity, and connector type vary by batch. |
| **NanoVNA-H4 (V4.4)** | Bench and site unit; larger display, more points and storage | SD-card presence and selectable point counts are firmware and batch dependent. |

**Coverage is not uniform across the range.** The architecture uses harmonic extension above roughly 300 MHz:

| Range | Generation | Usable dynamic range | Verdict |
|---|---|---|---|
| 9–50 kHz | Fundamental | Poor | Marginal; many builds start at 50 kHz. |
| 50 kHz – 300 MHz | Fundamental (direct) | ~70 dB | Excellent |
| 300–900 MHz | 3rd harmonic | ~50 dB | Good |
| 900 MHz – 1.5 GHz | 5th harmonic | ~40 dB | Usable for reflection (S11) |
| Above 1.5 GHz | 7th/9th harmonic, firmware dependent | ~25–30 dB | Rough S11 only; do not trust S21 |

**Tuning range is not measurement capability.** These units cover HF, VHF, UHF, 433 MHz ISM, 868/915 MHz ISM and LoRa, GMRS/MURS, and 1090 MHz ADS-B well. They do **not** properly cover 2.4 GHz Wi-Fi/BLE, 5 GHz, or GPS L1 at 1575.42 MHz — see [09 §9.13](09-worked-examples-by-band.md#913--24-ghz-what-you-can-and-cannot-do) for exactly where the boundary falls.

> **Specifications above are unverified for these listings.** Point counts, slot counts, battery, SD card, the 9 kHz lower limit, and maximum input power vary by production batch and firmware. Run the checklist in [12 §12.2](12-sources-and-scope.md#122-first-session-verification-checklist) and correct the tables to match your units. This subsection is meant to be edited.

## Tooling

| Tool | Role | Notes |
|---|---|---|
| **[`tools/s1pdiff.py`](tools/README.md)** | Touchstone `.s1p` analyser and baseline comparator | Python 3.8+, standard library only. Text, JSON, Markdown, and CSV output; exit codes 0/1/2/3 for scripting. |
| **[NanoVNA-Saver](https://github.com/NanoVNA-Saver/nanovna-saver)** | PC capture, segmented sweeps, Touchstone export | Segmented sweeps give the resolution high-Q devices need. Verify calibration handling for your firmware combination. |
| **[scikit-rf](https://scikit-rf.org/)** | Python RF analysis library | Renormalization (including 50 ↔ 75 Ω), de-embedding, cascading, plotting. |
| **[DiSlord / NanoVNA-D](https://github.com/DiSlord/NanoVNA-D)** | Community firmware | **Separate H and H4 builds targeting different processors — not interchangeable.** |

Record the sweep span, point count, calibration plane, cables, adapters, and firmware version with every capture. An archived sweep without that metadata cannot be compared to anything later.

---

## Safe Workflows

### Before Connecting the Instrument

- [ ] Physically disconnect every transmitter. Not "PTT locked out" — disconnected.
- [ ] Check center-to-shield for DC; fit an inline DC block on any unknown or powered system.
- [ ] Short the coax center conductor to the shield for 2–3 seconds to discharge static.
- [ ] At co-sited transmitter locations, fit an attenuator and calibrate with it in place.
- [ ] Confirm SMA versus RP-SMA center contacts before mating.
- [ ] Support heavy coax and adapters so they do not strain the board-mounted connectors.

The receive path has no protection circuitry. An ISM band, a low-power device, or a receive-only installation does not by itself establish that a feedline is safe to connect.

### Measure and Analyze

1. Define the question, the target frequency, and the acceptance requirement before sweeping.
2. Set the span, then calibrate on that span at the plane you want the truth about.
3. Verify with the known load and confirm the correction indicator.
4. Establish repeatability before drawing any conclusion.
5. Separate observed trace shape, candidate cause, confirmed measurement, and demonstrated finding.
6. Change one variable at a time, and record each change.
7. Archive the sweep with its full metadata.

No dip means the wrong span, insufficient resolution, a disconnected element, or an antenna that is not resonant in that range. It does not by itself establish which.

### Before Any Physical Modification

- [ ] Confirm the antenna is yours or the owner has authorized the change.
- [ ] Confirm the measurement is repeatable and taken at a known plane.
- [ ] Prefer reversible adjustments — telescoping sections, adjustment screws, folded wire — over cutting.
- [ ] Cut half of what the arithmetic indicates, then re-measure.
- [ ] Record the starting dimension before changing it.
- [ ] Recheck after locking and weatherproofing; both change the result.

## Scope and Legal Boundaries

**These procedures characterize input impedance match at low test power.** That boundary matters when results reach a customer report.

| Question | What a VNA sweep establishes |
|---|---|
| Is the load close to 50 Ω at this plane? | **Yes** — this is the measurement. |
| Where is reactance zero? | **Yes**, at that plane; a feedline can transform it. |
| Over what range is the match acceptable? | **Yes.** |
| How much accepted power is radiated? | **No.** Accepted power can become heat. |
| What is the gain or radiation pattern? | **No.** Requires an antenna range or controlled comparison. |
| Will it survive at operating power? | **No.** A microwatt stimulus reveals nothing about arcing or heating. |
| Does it improve receive signal-to-noise? | **No.** Requires separate receiving tests. |

**Transmission is a separate activity from measurement.** Nothing in this subsection authorizes transmitting on any frequency. Sample frequencies are measurement examples, not spectrum allocations or operating permissions. Amateur, GMRS, marine, and aviation frequencies referenced here require the appropriate license or authorization to transmit on, and the instrument's own output is not a transmitter in any operational sense.

Mounting, grounding, bonding, lightning protection, and work at height are governed by applicable codes and site procedure, not by this documentation. See [LEGAL.md](../../LEGAL.md) for repository-wide terms. Materials are provided **as is**, without a guarantee of compatibility, accuracy, hardware safety, or suitability for an engagement.

---

## Contributing

Contributions should be reproducible, sourced, and suitable for education or authorized professional work.

**Welcome contributions:**

- Verified hardware specifications from actual units, with the firmware version recorded.
- Additional worked tuning examples following the setup → sweep → diagnosis → arithmetic → result format.
- Antenna classes not yet covered in [10](10-antenna-types-and-special-cases.md).
- Corrections to constants, conversion tables, or arithmetic — every worked example should re-derive.
- Tooling improvements, with tests added to `testdata/run_tests.sh`.

**Submission requirements:**

- State the unit, hardware revision, firmware version, calibration plane, and cable set for any measurement.
- Mark illustrative numbers as illustrative; mark measured numbers with the conditions that produced them.
- Cite primary sources for specifications and regulatory claims.
- Validate relative links and update the inventory table below when adding or renaming a file.
- Keep physical dimensions labeled as starting estimates rather than finished dimensions.

**Not accepted in this subsection:** procedures that require transmitting without authorization, instructions presented as guaranteed hardware specifications without verification, or measurement claims that overstate what a reflection sweep establishes.

## Resources

### Project and Firmware

- [NanoVNA project overview](https://nanovna.com/) — hardware revisions and model identity.
- [Measurement architecture](https://nanovna.com/?page_id=60) — harmonic extension and performance across the range.
- [Calibration reference](https://nanovna.com/?page_id=2) and [status indicators](https://nanovna.com/?page_id=46).
- [hugen79 / NanoVNA-H](https://github.com/hugen79/NanoVNA-H) — H and H4 developer repository.
- [DiSlord / NanoVNA-D](https://github.com/DiSlord/NanoVNA-D) — community firmware, separate H/H4 builds.
- [cho45 NanoVNA user guide](https://cho45.github.io/NanoVNA-manual/) — time-domain transform and windowing concepts.

### Software

- [NanoVNA-Saver](https://github.com/NanoVNA-Saver/nanovna-saver) — capture, segmented sweeps, Touchstone export.
- [scikit-rf](https://scikit-rf.org/) — Python RF analysis, renormalization, de-embedding.

### RF Reference

- [FCC Part 15](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15) and [Part 97](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-D/part-97).
- [ARRL amateur licensing information](https://www.arrl.org/getting-licensed).
- [Target Frequencies & Protocols MASTER LIST](../target_frequencies_protocols.md) — band and protocol reference for choosing a sweep span.

## Related Repository Material

| Resource | Relationship |
|---|---|
| [Main repository](../../README.md) | Top-level navigation. |
| [SDR & RF section index](../README.md) | Parent section: SDR, RF, NFC/RFID, Sub-GHz. |
| [SDR Fundamentals](../sdr.md) | Antenna and RF front-end theory that this subsection measures in practice. |
| [HackRF Spectrum Audits](../hackrf.md) | Survey work that depends on a validated receive chain. |
| [Target Frequencies & Protocols](../target_frequencies_protocols.md) | Band references for selecting sweep spans. |
| [HackRF Audit Playbook](../../PlayBooks/HackRFAuditPlayBook.md) | Engagement procedure; antenna verification fits its preparation phase. |
| [Space Security](../../SpaceSecurity/README.md) | Satellite reception — antenna and feedline quality dominate results. |
| [Hardware Hacking](../../HardwareHacking/README.md) | Embedded and PCB antenna work referenced in [10](10-antenna-types-and-special-cases.md). |
| [Repository terms](../../LEGAL.md) | Repository-wide terms and use requirements. |

## Subsection Inventory and Maintenance

| Item | Current inventory |
|---|---|
| Documents linked from this index | **12:** `01-hardware-and-setup.md` through `12-sources-and-scope.md`. |
| Markdown files in `SDR/nanovna/` | **13**, including this README. |
| Tooling | `tools/s1pdiff.py` with `tools/README.md`; fixtures and suite in `testdata/`. |
| Automated tests | **14** checks — both Touchstone formats, both unit conventions, four output formats, three verdict levels, error paths. |
| Coverage | HF through 1.5 GHz antenna, feedline, filter, and component measurement. Does not cover 2.4/5 GHz. |
| Verification status | Physics and arithmetic re-derivable; firmware behaviour is ecosystem convention; **hardware specifications unverified** — see [12](12-sources-and-scope.md). |
| Last reviewed | September 18, 2026. |
| Maintainer | [Pacific Northwest Computers / Pnwcomputers](https://github.com/Pnwcomputers). |

**Maintenance note:** Update counts when adding or removing files. Replace unverified hardware figures with measured values once units are confirmed, and date that verification. A document's presence in this index does not establish that every figure in it has been bench-validated.

---

<div align="center">

**Calibrate the plane. Measure the antenna. Document the evidence.**

[ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE) · [Pacific Northwest Computers](https://github.com/Pnwcomputers)

</div>
