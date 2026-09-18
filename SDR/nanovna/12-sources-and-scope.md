<a id="top"></a>

# 📚 12 — Sources, Scope, and Verification Limits

<div align="center">

**Check the evidence behind the guide and identify what must be verified on the actual unit.**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [SDR & RF](../README.md)*

![NanoVNA](https://img.shields.io/badge/Hardware-NanoVNA--H_%26_H4-blue?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Sources_Scope_and_Verification_Limits-green?style=for-the-badge)
![Chapter](https://img.shields.io/badge/Chapter-12_of_12-orange?style=for-the-badge)

</div>

---

[← NanoVNA Index](README.md) · [SDR & RF](../README.md)

## 🎯 Purpose

Separate sourced information, conventions, and unverified device-specific details.

## ⚙️ Function

Provide verification checklists, primary references, and measurement-scope guidance.

## 🏆 Goal

State conclusions that match the evidence and limitations of the measurement.

## 📋 When to Use

- Confirming a hardware or firmware claim.
- Preparing a report or reviewing what the measurement can establish.

---

## 📋 Table of Contents

- [12.1 What's verified, what isn't](#121-whats-verified-what-isnt)
- [12.2 First-session verification checklist](#122-first-session-verification-checklist)
- [12.3 Primary sources](#123-primary-sources)
- [12.4 Scope of what these procedures establish](#124-scope-of-what-these-procedures-establish)

---

This guide is independently written practical documentation. **It is not a
SEESII factory manual**, and nobody who wrote it has had the specific units from
those two Amazon listings on a bench.

That distinction matters when you are billing work against these measurements,
so this page states plainly what is solid, what is convention, and what you have
to check yourself.

---

## 12.1 What's verified, what isn't

### Solid — physics and mathematics

The RF relationships, conversion tables, worked calculations, matching-network
designs, and diagnostic logic throughout this guide are standard transmission
line theory. They are checkable from first principles and do not depend on which
instrument you own:

- Γ, SWR, return loss, mismatch loss conversions ([02](02-rf-fundamentals.md))
- Impedance transformation and L-network design ([05](05-antenna-tuning.md))
- Quarter-wave transformers, stubs, hairpin conditions
- TDR resolution and ambiguity relationships ([06](06-cables-filters-other-uses.md))
- Velocity factor and cable length relationships

Every worked example's arithmetic can be re-derived. If you find one that
doesn't reproduce, the guide is wrong — fix it.

### Conventional — the H-family ecosystem

Menu labels, port naming, calibration sequence, display formats, and firmware
behaviour are documented by the upstream NanoVNA project and are consistent
across most H/H4 firmware. **They are not guaranteed identical in every seller's
firmware build.** If a function named here doesn't exist on your unit, consult
the documentation for the firmware version your unit actually reports.

### Unverified — your specific hardware

The following could **not** be confirmed for these listings and must be checked
on the actual units:

| Claim | Status |
|---|---|
| 9 kHz lower frequency limit | **Unverified.** Many upstream builds start at 50 kHz. |
| Sweep point counts (101 / 401) | Depends on hardware + firmware |
| Calibration slot counts (5 / 7) | Depends on hardware + firmware |
| Battery capacity and runtime | Varies by batch |
| microSD card presence | Varies by batch |
| USB connector type | Varies by batch |
| Included accessories and their accuracy | Varies by batch |
| Delivered firmware version | Varies by batch |
| **Maximum safe input power** | **No verified figure.** +10 dBm is the community convention — see [01 §1.7](01-hardware-and-setup.md#17-things-that-will-destroy-your-nanovna) |
| Screen size on the H | Listing did not state it; H family is normally ~2.8" |

The Amazon short links supplied
([H](https://a.co/d/0cH5nXVe), [H4](https://a.co/d/09Ejs4iQ)) could not be
retrieved during preparation, so nothing in this guide reflects the current
listing text beyond what was quoted in the request.

**The upstream project does document H v3.7 and H4 v4.4 as real hardware
revisions** — specifically as revisions using a replacement mixer after the
original part was discontinued. That corroborates the revision names in the
listing titles. It says nothing about what SEESII put in your box.

### Illustrative — every measurement number in this guide

**All measurement results shown are worked illustrations, not readings from your
hardware or your antennas.** They are internally consistent and realistic, and
the methods they demonstrate are sound. The specific numbers are not predictions
of what you will see.

Physical dimensions given are **starting estimates**, not finished dimensions.

---

## 12.2 First-session verification checklist

Do this once per unit and write the answers into the worksheet in
[11](11-worksheet-and-exercises.md).

```
□ CONFIG → VERSION — record board ID and firmware string verbatim
□ Count the calibration slots the menu actually offers
□ Check whether POINTS is selectable, and what values
□ Confirm lowest usable start frequency (try 9 kHz; note where it gets noisy)
□ Confirm highest stop frequency the firmware accepts
□ Note connector type (USB-C / micro-USB), SD slot presence
□ Inventory the supplied calibration standards; mark them
□ Verify the supplied load against a second known load if you have one
□ Run Exercise 1 and Exercise 7 from 11-worksheet-and-exercises.md
□ Correct the tables in 01-hardware-and-setup.md to match reality
```

That last line is the point. **This guide is meant to be edited.** The version
that's useful in two years is the one with your unit's real numbers in it and
your own field notes appended.

---

## 12.3 Primary sources

Upstream project and software references, checked **18 September 2026**:

| Resource | Covers |
|---|---|
| [NanoVNA project overview](https://nanovna.com/) | Hardware revisions, model identity |
| [Measurement architecture and accessories](https://nanovna.com/?page_id=60) | Harmonic extension, performance across the range |
| [Calibration](https://nanovna.com/?page_id=2) | Calibration sequence and save controls |
| [Screen and calibration-status indicators](https://nanovna.com/?page_id=46) | The `C` / `c` / `D R S T X` letters |
| [Measurement formats and controls](https://nanovna.com/?page_id=64) | Display formats, trace/channel handling |
| [hugen79 / NanoVNA-H](https://github.com/hugen79/NanoVNA-H) | H and H4 developer repository, hardware |
| [DiSlord / NanoVNA-D](https://github.com/DiSlord/NanoVNA-D) | Current community firmware, separate H/H4 builds |
| [cho45 NanoVNA user guide](https://cho45.github.io/NanoVNA-manual/) | Time-domain concepts, transform and windowing |
| [NanoVNA-Saver](https://github.com/NanoVNA-Saver/nanovna-saver) | PC software, segmented sweeps, Touchstone export |
| [scikit-rf](https://scikit-rf.org/) | Python RF library — renormalization, de-embedding |

**Firmware warning, repeated because it matters:** H and H4 target different
processors (STM32F072 vs STM32F303). Their firmware files are not
interchangeable. Do not choose firmware because the display looks similar, and
do not put NanoVNA V2 / SAA-2 firmware on either of these.
See [08 §8.5](08-pc-software-and-firmware.md#85-firmware).

---

## 12.4 Scope of what these procedures establish

Worth being precise about, especially in anything that goes to a customer.

**These procedures characterize an antenna's input match at low test power.**

They do **not** establish:

- **Transmit power handling.** A microwatt stimulus reveals nothing about
  what arcs, heats, or saturates at 100 W. Capacitor voltage ratings, core
  saturation, connector power ratings and thermal limits are all outside what a
  VNA can see.
- **Radiated gain or pattern.** Requires an antenna range or controlled
  comparative testing.
- **Radiation efficiency.** A matched antenna and an efficient antenna are
  different claims. Accepted power can become heat.
- **Receive performance.** Depends on pattern, noise environment, siting, and
  receiver behaviour at least as much as match.
- **Regulatory compliance.** Nothing here speaks to emissions, licensing, or
  authorization to transmit on any frequency. Sample frequencies used throughout
  are measurement examples, not transmission permissions.
- **Structural or installation safety.** Mounting, grounding, bonding, lightning
  protection, and work-at-height practices are governed by applicable codes and
  site procedures, not by this document.

### Suggested language for customer reports

> Measurements characterize the antenna system's input impedance match at the
> stated reference plane, using a vector network analyzer at low test power.
> Results establish match, resonance, and matching bandwidth. They do not
> establish radiated gain, radiation efficiency, pattern, or power handling,
> which require separate testing.

Pair that with the before/after sweeps and the `s1pdiff` verdict, and you have a
defensible technical report rather than an assertion.

---

[← Worksheet & exercises](11-worksheet-and-exercises.md) |
[Back to index](README.md)

---

<div align="center">

[↑ Back to Top](#top) · [NanoVNA Index](README.md) · [SDR & RF](../README.md)

</div>
