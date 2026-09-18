<a id="top"></a>

# 📡 NanoVNA Field Guide — SEESII NanoVNA-H & NanoVNA-H4

<div align="center">

**Practical guides for vector network analysis, antenna testing and tuning, cable diagnostics, and RF measurement records**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [SDR & RF](../README.md)*

![NanoVNA](https://img.shields.io/badge/Hardware-NanoVNA--H_%26_H4-blue?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Antenna_%26_RF_Measurements-green?style=for-the-badge)

</div>

---

## 🎯 Purpose

Provide a practical reference for using the NanoVNA-H and NanoVNA-H4 to inspect antennas and passive RF systems.

## ⚙️ Function

Connect twelve chapters, worked examples, field worksheets, and a Touchstone comparison tool into a repeatable measurement workflow.

## 🏆 Goal

Move from a known calibration setup to a documented result, then make and verify controlled adjustments.

## 📋 When to Use

- Learning the analyzer, its controls, and RF display formats.
- Checking antenna match, resonance, feedlines, filters, and connectors.
- Tuning an antenna or comparing an installed system against a baseline.
- Exporting measurements and documenting their scope and limitations.

---

## 📋 Table of Contents

- [Guides in This Section](#guides-in-this-section)
- [Choose a Starting Point](#choose-a-starting-point)
- [The 60-second version](#the-60-second-version)
- [Frequency coverage reality check](#frequency-coverage-reality-check)
- [Accuracy expectations](#accuracy-expectations)
- [What this guide does not establish](#what-this-guide-does-not-establish)
- [Related Repository Material](#related-repository-material)
- [Section Inventory and Maintenance](#section-inventory-and-maintenance)

---

Working documentation for the two SEESII-branded NanoVNA units:

- **NanoVNA-H, hardware rev 3.7** — 2.8" resistive touchscreen
- **NanoVNA-H4, "V4.4"** — 4" touchscreen, more memory and sweep points

Both are the same measurement engine in different packages. Everything here
applies to both unless a section is explicitly marked for one model.

> **Before you trust a spec on any page:** Hardware details (point counts,
> calibration slots, battery, SD card, the 9 kHz lower limit, max input power)
> vary by batch and firmware and were **not** verifiable for these listings.
> Run the checklist in [12 §12.2](12-sources-and-scope.md#122-first-session-verification-checklist)
> on your actual units and correct the tables to match. This guide is meant to
> be edited.
>
> **All measurement numbers shown are worked illustrations**, not readings from
> your hardware. Dimensions are starting estimates, not finished dimensions.

---

<a id="contents"></a>

## Guides in This Section

| Guide | Focus |
|---|---|
| **[01 — Hardware, Controls, and Setup](01-hardware-and-setup.md)** | Model comparison, ports, controls, menu map, first power-on, accessories, what will destroy the unit |
| **[02 — RF Fundamentals](02-rf-fundamentals.md)** | What a sweep can and can't answer · S-parameters · VSWR, return loss and the sign-convention trap · phase, delay, the Smith chart |
| **[03 — Calibration](03-calibration.md)** | SOLT step by step, reference planes and why they change the answer, status indicators, save slots, drift, and the mistakes that produce confident wrong answers |
| **[04 — Antenna Testing](04-antenna-testing.md)** | The full how-to: safety, repeatability, sweep setup, diagnostic decision tree, common-mode current, feedline effects |
| **[05 — Antenna Tuning](05-antenna-tuning.md)** | Trimming elements, resonance vs. match, L-networks from Smith chart readings, stubs, transformers, chokes |
| **[06 — Cables, Filters, and Other Measurements](06-cables-filters-other-uses.md)** | TDR fault location and its real resolution limits, velocity factor, coax loss, filters and duplexers, components, shielding |
| **[07 — Quick Reference](07-quick-reference.md)** | Printable cheat sheet: conversion tables, formulas, band plans, troubleshooting flowchart |
| **[08 — PC Software and Firmware](08-pc-software-and-firmware.md)** | NanoVNA-Saver, Touchstone exports, serial automation, firmware and DFU recovery |
| **[09 — Worked Examples by Band](09-worked-examples-by-band.md)** | Thirteen worked tuning examples from 40 m to 1090 MHz, each setup → sweep → diagnosis → arithmetic → result |
| **[10 — Antenna Types and Special Cases](10-antenna-types-and-special-cases.md)** | Handhelds, SDR/receive-only, active antennas, 75 Ω, mobile, dual-band, end-fed, traps, Yagis, discones, the DC continuity trap |
| **[11 — Worksheet and Exercises](11-worksheet-and-exercises.md)** | Copy-per-job field worksheet, plus eight practice exercises using known loads |
| **[12 — Sources and Scope](12-sources-and-scope.md)** | What's verified vs. convention vs. unverified, primary sources, and what these procedures do **not** establish |
| **[Touchstone Analysis Tools](tools/README.md)** | `s1pdiff.py` — Touchstone analyser and baseline comparator, with tests |

---

<a id="two-ways-in"></a>

## Choose a Starting Point

**New to VNAs?** Read in order: 01 → 02 → 03, then work Exercises 1–5 in
[11](11-worksheet-and-exercises.md) before touching a real antenna. Then 04 → 05.

**Experienced, just need this instrument?** Skim
[07](07-quick-reference.md) for the cheat sheet, read
[03 §3.2](03-calibration.md#32-the-calibration-plane) on reference planes and
[01 §1.7](01-hardware-and-setup.md#17-things-that-will-destroy-your-nanovna) on
what kills the unit, then go to
[09](09-worked-examples-by-band.md) for the band you're working.

---

## The 60-second version

If you read nothing else:

1. **Set your frequency span first.** A calibration is only valid across the span
   it was performed on.
2. **Calibrate with the same cables and adapters you'll measure through.** The
   calibration plane is wherever you put the standards, not the front panel.
3. **Never connect the NanoVNA to anything transmitting, carrying DC, or holding
   a static charge.** The front end is unprotected and one hundredth of a watt
   destroys it.
4. **Establish repeatability before you believe anything.** If the trace moves
   when you move the coax, you are measuring your test setup, not the antenna.
5. **VSWR is not the goal.** A 50 Ω dummy load has a perfect VSWR and radiates
   nothing. VSWR tells you power is *entering* the antenna, not that it's
   leaving usefully.
6. **Resonance too low = element too long. Resonance too high = element too
   short.** Percent change in length ≈ inverse percent change in frequency.
   Cut half of what the math says.
7. **Reactance and resistance are separate problems.** Cancelling reactance does
   not match an impedance. Fix resonance first, then match.

---

## Frequency coverage reality check

The hardware is specified 9 kHz – 1.5 GHz, but coverage is not uniform — the
architecture uses harmonic extension above roughly 300 MHz:

| Range | How it's generated | Usable dynamic range | Verdict |
|---|---|---|---|
| 9–50 kHz | Fundamental | Poor | Marginal; expect noise. Many builds start at 50 kHz. |
| 50 kHz – 300 MHz | Fundamental (direct) | ~70 dB | Excellent |
| 300–900 MHz | 3rd harmonic | ~50 dB | Good |
| 900 MHz – 1.5 GHz | 5th harmonic | ~40 dB | Usable for reflection (S11) |
| Above 1.5 GHz | 7th/9th harmonic, firmware-dependent | ~25–30 dB | Rough S11 only, don't trust S21 |

**Practical consequence:** these units cover HF, VHF, UHF, 433 MHz ISM,
868/915 MHz ISM/LoRa, GMRS/MURS, 1090 MHz ADS-B and L-band edges well. They do
**not** properly cover 2.4 GHz Wi-Fi/BLE, 5 GHz, or GPS L1 at 1575.42 MHz. See
[09 §9.13](09-worked-examples-by-band.md#913--24-ghz-what-you-can-and-cannot-do)
for exactly what remains possible above 1.5 GHz and what doesn't.

Treat deep notches and anything near the top of the range with extra care, and
verify against a known device before reporting.

---

## Accuracy expectations

Properly calibrated with decent standards and good cables, below about 900 MHz,
a NanoVNA typically agrees with a bench VNA within a few percent on impedance
and a few tenths of a dB on return loss. Above 1 GHz the gap widens.

That is more than good enough for antenna work, cable diagnostics, and filter
tuning. It is not metrology.

**The largest error source is never the instrument** — it's the calibration kit,
the connectors, and the operator. See [03-calibration.md](03-calibration.md).

---

## What this guide does not establish

Worth knowing before anything here goes into a customer report: these procedures
characterize **input impedance match at low test power**. They say nothing about
radiated gain, radiation efficiency, pattern, power handling, receive
performance, or regulatory compliance.

[12 §12.4](12-sources-and-scope.md#124-scope-of-what-these-procedures-establish)
has the full scope statement and suggested report language.

---

## Related Repository Material

| Resource | Relationship |
|---|---|
| [SDR & RF section](../README.md) | Parent section and guide selection. |
| [SDR Fundamentals](../sdr.md) | Receivers, antennas, and signal-processing foundations. |
| [HackRF RF Spectrum and Wireless Security Audits](../hackrf.md) | Spectrum surveys and receive-chain validation. |
| [Target Frequencies & Protocols MASTER LIST](../target_frequencies_protocols.md) | Frequency references and hardware coverage. |
| [Sub-GHz RF Exploration](../subghz.md) | Related device and protocol workflows. |
| [HackRF Audit Playbook](../../PlayBooks/HackRFAuditPlayBook.md) | Broader field and bench engagement procedure. |
| [Hardware Hacking](../../HardwareHacking/README.md) | Embedded hardware investigation. |

## Section Inventory and Maintenance

| Item | Inventory |
|---|---|
| Learning chapters | **12**, covering setup through sources and scope. |
| Chapter sequence | Hardware → RF fundamentals → calibration → testing → tuning → other measurements → reference → software → examples → antenna types → exercises → sources. |
| Companion tools | [Touchstone sweep analysis and comparison](tools/README.md). |
| Measurement records | [Field worksheet and practice exercises](11-worksheet-and-exercises.md). |
| Source and verification policy | [Sources, scope, and verification limits](12-sources-and-scope.md). |
| Maintainer | [Pacific Northwest Computers / Pnwcomputers](https://github.com/Pnwcomputers). |

**Maintenance note:** Keep chapter links and the parent SDR index synchronized when adding or renaming files. Record model, firmware, reference plane, and setup with measurement results.

---

<div align="center">

**Calibrate the setup. Understand the measurement. Verify the result.**

[↑ Back to Top](#top) · [SDR & RF](../README.md) · [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)

</div>
