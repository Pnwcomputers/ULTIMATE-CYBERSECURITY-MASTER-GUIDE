<a id="top"></a>

# 🔌 06 — Cables, Filters, and Other Measurements

<div align="center">

**Apply the analyzer to feedlines, passive RF components, and repeatable service baselines.**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [SDR & RF](../README.md)*

![NanoVNA](https://img.shields.io/badge/Hardware-NanoVNA--H_%26_H4-blue?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Cables_Filters_and_Other_Measurements-green?style=for-the-badge)
![Chapter](https://img.shields.io/badge/Chapter-06_of_12-orange?style=for-the-badge)

</div>

---

[← NanoVNA Index](README.md) · [SDR & RF](../README.md)

## 🎯 Purpose

Extend NanoVNA measurements beyond antenna matching.

## ⚙️ Function

Cover cable delay and fault location, loss, filters, components, coupling, and baseline records.

## 🏆 Goal

Characterize the measured RF path with its setup and limitations documented.

## 📋 When to Use

- Checking coax, connectors, attenuators, or filters.
- Investigating a cable fault or building a baseline library.

---

## 📋 Table of Contents

- [6.1 TDR — Time Domain Reflectometry](#61-tdr--time-domain-reflectometry)
- [6.2 Measuring an unknown cable's velocity factor and length](#62-measuring-an-unknown-cables-velocity-factor-and-length)
- [6.3 Measuring cable loss](#63-measuring-cable-loss)
- [6.4 Filters, duplexers, and cavities](#64-filters-duplexers-and-cavities)
- [6.5 Measuring components](#65-measuring-components)
- [6.6 Antenna-to-antenna coupling and isolation](#66-antenna-to-antenna-coupling-and-isolation)
- [6.7 Shielding and enclosure effectiveness](#67-shielding-and-enclosure-effectiveness)
- [6.8 Checking connectors and adapters](#68-checking-connectors-and-adapters)
- [6.9 Verifying attenuators and dummy loads](#69-verifying-attenuators-and-dummy-loads)
- [6.10 Building a service baseline library](#610-building-a-service-baseline-library)

---

---

## 6.1 TDR — Time Domain Reflectometry

The NanoVNA measures in the frequency domain, then applies an inverse FFT to show
you the **time domain**: reflections plotted against distance.

This turns the instrument into a cable fault locator.

### Setup

```
STIMULUS → START → 0 (or lowest available)
STIMULUS → STOP  → as high as practical (500 MHz – 1.5 GHz)
CAL → full SOLT calibration on that span
DISPLAY → TRANSFORM → TRANSFORM ON
DISPLAY → TRANSFORM → LOW PASS IMPULSE   (or LOW PASS STEP)
DISPLAY → TRANSFORM → VELOCITY FACTOR → [your cable's VF]
```

**Wider frequency span = better distance resolution.** A 1.5 GHz sweep resolves
to roughly 10 cm; a 100 MHz sweep to about 1.5 m.

### Velocity factors

| Cable | VF |
|---|---|
| RG-58 (solid PE) | 0.66 |
| RG-59 (solid PE) | 0.66 |
| RG-213 / RG-8 (solid PE) | 0.66 |
| RG-316 | 0.695 |
| RG-174 | 0.66 |
| RG-6 (foam) | 0.83 |
| RG-8X (foam) | 0.82 |
| LMR-240 / LMR-400 | 0.84 – 0.85 |
| Belden 9913 / air-dielectric | 0.84 – 0.88 |
| Hardline (foam) | 0.88 |
| 450 Ω ladder line | 0.90 – 0.95 |
| Semi-rigid (PTFE) | 0.70 |

Wrong VF = proportionally wrong distance. If you don't know it, measure it
(§6.2).

> **Check which convention the field expects.** Some firmware and software want
> `0.66`, others want `66`. Enter it wrong and every distance is off by a factor
> of 100. Verify once against a cable of known length before trusting any fault
> distance.

### What TDR resolution you actually get

The transform is synthesized from the frequency sweep, so the sweep sets the
limits. For a sweep of bandwidth **B** with uniform step **Δf**:

```
Smallest resolvable separation:   Δd ≈ VF × c / (2B)
Maximum unambiguous distance:      d ≈ VF × c / (2Δf)
```

Worked, for RG-213 (VF 0.66) swept 1–301 MHz in 3 MHz steps:

```
B  = 300 MHz  →  Δd = 0.66 × 3e8 / 6e8  = 0.33 m   separation
Δf = 3 MHz    →  d  = 0.66 × 3e8 / 6e6  = 33 m     before wrap-around
```

Two consequences worth internalizing:

- **A narrow antenna-band sweep is useless for TDR.** A 4 MHz sweep around the
  2 m band gives roughly 25 m of resolution — it cannot distinguish a connector
  fault from the far end of the cable. Sweep wide.
- **Beyond the ambiguity distance the display wraps**, and a fault at 40 m on a
  33 m-ambiguity sweep can appear at 7 m. If the reported distance seems
  implausible, reduce Δf (finer steps or more points) and re-check.

Windowing broadens every event beyond the theoretical figure, and a long lossy
cable reduces useful reach further, so treat both formulas as optimistic bounds.

### If your display gives time rather than distance

```
one-way distance = VF × c × (round-trip time) / 2      c ≈ 299,792,458 m/s
```

Example: an 80 ns round trip on VF 0.66 coax → 0.66 × 3e8 × 80e−9 / 2 = **7.9 m**.

**If the display already gives corrected one-way distance, do not divide by two
again.** Confirm which one you are looking at using a cable of known length.

Note also that polarity interpretation depends on the transform mode: a real
low-pass **step** plot gives a positive step for an open and a negative step for
a short. Bandpass magnitude modes do not preserve that simple polarity reading.

### Reading TDR results

| Pattern | Meaning |
|---|---|
| Single positive spike at cable end | **Open circuit** — the normal result for an unterminated cable |
| Single negative spike at cable end | **Short circuit** |
| No significant spike | Properly terminated, or so lossy nothing comes back |
| Spike partway along | Discontinuity: bad connector, splice, crushed cable, water ingress |
| Positive spike mid-run | Impedance **higher** than the line (crimp failure, corrosion, stretched cable) |
| Negative spike mid-run | Impedance **lower** than the line (crushed cable, water bridging, staple through the jacket) |
| Multiple decaying spikes | Multiple reflections bouncing between two discontinuities |

### Practical use

- **Find a fault without climbing.** See the worked example in
  [04](04-antenna-testing.md) §4.7.
- **Verify cable length** on an unmarked reel.
- **Locate a buried or in-wall splice.**
- **Confirm a repair** — sweep before and after.

### LOW PASS IMPULSE vs LOW PASS STEP

- **IMPULSE** — sharp spikes at each discontinuity. Best for locating faults.
- **STEP** — shows impedance as a step profile along the cable. Better for
  understanding *what kind* of discontinuity it is and seeing gradual impedance
  variation.

Use IMPULSE to find it, STEP to characterize it.

---

## 6.2 Measuring an unknown cable's velocity factor and length

If you know either the length or the VF, you can find the other.

### Method — quarter-wave resonance

1. Leave the far end of the cable **open**.
2. Calibrate CH0 with the cable **not** attached.
3. Attach the cable, sweep from low frequency upward.
4. Find the **first SWR minimum / return-loss dip**. This is the quarter-wave
   resonance — at that frequency the open far end transforms to a short at the
   near end.
5. Apply:

```
L (m) = (75 × VF) / f₁(MHz)

or, solving for VF:

VF = (L(m) × f₁(MHz)) / 75
```

**Example:** an unknown coax shows its first dip at 24.6 MHz, and you measure it
physically at 2.00 m.
```
VF = (2.00 × 24.6) / 75 = 0.656  →  solid-PE dielectric, likely RG-58 or RG-213
```

**Example:** a known LMR-400 (VF 0.85) shows its first dip at 8.9 MHz.
```
L = (75 × 0.85) / 8.9 = 7.16 m
```

Subsequent dips appear at odd multiples (3×, 5×…) of f₁. Use a higher-order dip
for better precision on long cables.

---

## 6.3 Measuring cable loss

### Method 1 — Short the far end (one connection, most convenient)

1. Calibrate CH0 at the near end of the cable.
2. **Short** the far end.
3. Read **LOGMAG** (return loss) at your frequency of interest.
4. **One-way loss = measured return loss ÷ 2** (the signal traveled down and
   back).

Example: shorted 30 m of RG-58 reads −9.4 dB at 146 MHz → **4.7 dB one-way
loss.** Manufacturer spec for RG-58 at 150 MHz is roughly 4.5 dB/30 m — cable is
healthy.

### Method 2 — S21 through measurement (more accurate)

1. Calibrate CH0→CH1 with a THRU.
2. Insert the cable between CH0 and CH1.
3. Read S21 LOGMAG directly. That's the one-way loss.

Requires access to both ends.

### Typical loss reference (dB per 30 m / 100 ft)

| Cable | 10 MHz | 150 MHz | 450 MHz | 900 MHz |
|---|---|---|---|---|
| RG-174 | 3.5 | 11 | 20 | 30 |
| RG-58 | 1.3 | 4.5 | 8.5 | 13 |
| RG-8X | 1.0 | 3.4 | 6.3 | 9.5 |
| RG-213 | 0.6 | 2.2 | 4.2 | 6.5 |
| RG-6 (foam) | 0.6 | 2.2 | 4.0 | 5.9 |
| LMR-400 | 0.3 | 1.3 | 2.4 | 3.5 |

**A cable measuring more than about 1 dB worse than spec is degraded** — water
ingress, oxidized shield, or damaged dielectric. Replace it.

---

## 6.4 Filters, duplexers, and cavities

This is S21 territory — you need both ports.

### Setup

```
1. Set the span to cover passband + stopbands
2. Full 5-step calibration (OPEN, SHORT, LOAD, ISOLN, THRU)
3. DISPLAY → TRACE 0 → CH1 → LOGMAG      (insertion loss / rejection)
   DISPLAY → TRACE 1 → CH0 → SWR          (input match)
   DISPLAY → TRACE 2 → CH1 → PHASE or DELAY
4. Connect filter in: CH0 → filter → CH1
```

### What to measure

| Metric | Where to read it | Typical target |
|---|---|---|
| **Insertion loss** | S21 LOGMAG at center of passband | < 1 dB for a good LC filter, < 1.5 dB for a cavity |
| **−3 dB bandwidth** | Frequencies where S21 drops 3 dB from peak | Per design |
| **Stopband rejection** | S21 LOGMAG at the frequency you want killed | 40–90 dB |
| **Passband ripple** | Variation of S21 within the passband | < 0.5 dB |
| **Input return loss** | S11 / SWR in the passband | < −15 dB |
| **Group delay flatness** | S21 DELAY across the passband | Application-dependent |

### Dynamic range limit

The NanoVNA's noise floor limits how deep a rejection you can measure:

| Band | Realistic measurable rejection |
|---|---|
| < 300 MHz | ~70 dB |
| 300–900 MHz | ~50 dB |
| 900–1500 MHz | ~40 dB |

If a filter spec says 90 dB rejection, you will measure "about 70 dB" and see the
noise floor. That's the instrument, not the filter. **Shorten the test cables,
keep the ports separated, and avoid coiling CH0 and CH1 cables together** —
direct coupling between the cables sets a practical floor that's often worse than
the instrument's.

### Tuning a duplexer or cavity

1. Set up the S21 sweep across both the pass and reject frequencies.
2. Terminate the unused port of the duplexer in 50 Ω. **Always.** An unterminated
   port makes the measurement meaningless.
3. Adjust the tuning rod for maximum S21 at the pass frequency.
4. Adjust the notch/reject loop for maximum rejection at the reject frequency.
5. These interact — iterate.
6. Confirm the input match on S11 as well; a well-tuned cavity should show good
   return loss in its passband.

This is a job that traditionally required a service monitor. A NanoVNA-H4 does it
well enough for commercial repeater work at VHF/UHF.

---

## 6.5 Measuring components

### Inductors

1. Calibrate CH0 with the fixture in place (a short SMA-to-clip adapter,
   calibrated with standards at the clips if you can).
2. Connect the inductor from center to ground.
3. Set **FORMAT → REACTANCE** or read from the Smith chart.
4. The firmware displays an equivalent inductance in nH/µH at the marker
   frequency.
5. Sweep upward to find the **self-resonant frequency (SRF)** — where reactance
   crosses zero and goes capacitive. Above SRF the inductor behaves as a
   capacitor. This is genuinely useful and rarely on the datasheet.

### Capacitors

Same procedure. Look for the series resonance where the capacitor's ESL takes
over. Below SRF it's a capacitor, above it's an inductor.

### Crystals

1. Series-connect the crystal between CH0 and CH1.
2. Sweep a very narrow span around the marked frequency.
3. You'll see a sharp series-resonance peak and a nearby parallel-resonance
   notch.
4. **The H4 at 401 points is essentially required** for this — crystals have Q in
   the tens of thousands and a coarse sweep will step right over the peak. Use
   NanoVNA-Saver's segmented sweep for real resolution.

Uses: matching crystals for ladder filters, checking pull range, identifying
unmarked crystals.

### Splitters, combiners, diplexers, and duplexers

**Terminate every unused RF port in its specified impedance. Every time.**

A splitter output measured with the other outputs left open is not a measurement
of the splitter — the open ports reflect everything back into the junction and
the numbers are fiction. The same applies to the unused leg of a diplexer and
the unused port of a duplexer.

Measure each path separately, and **write down which port was driven and which
ports were terminated.** A splitter measurement without that note is not
reproducible and not worth archiving.

### Active devices and amplifiers

Do not connect an unknown powered amplifier to a NanoVNA as a casual experiment.
Doing it safely requires all of:

- a verified source level at the amplifier input
- proper DC bias arrangement and DC blocks on both ports
- output attenuation sized so the amplifier cannot exceed the VNA's input limit
- awareness that the H-family's harmonic-extended source is not spectrally clean
  above ~300 MHz, which complicates broadband active measurements

Get those wrong and you destroy the instrument in the time it takes to key the
supply. This is not beginner territory; the exercises in this guide are all
passive and unpowered for that reason.

### Ferrite characterization

Wind a few turns on a core, measure the impedance versus frequency. Tells you the
material's useful range — invaluable when you have a bin of unmarked toroids.

---

## 6.6 Antenna-to-antenna coupling and isolation

Put one antenna on CH0 and another on CH1 and sweep S21.

**Uses:**

- **Isolation between co-sited antennas** — how much does the transmit antenna
  couple into the receive antenna? Critical for duplex systems, and for figuring
  out why a receiver desenses when the transmitter keys.
- **Rough pattern checks** — rotate the antenna under test and watch S21 change.
  Not a proper anechoic-chamber pattern measurement, but it will reveal a
  front-to-back ratio, a null, or a defective element.
- **Relative gain comparison** — measure S21 with a reference antenna, swap in
  the test antenna without moving anything, compare. The difference is relative
  gain.

**Caveat:** this is not calibrated absolute gain. Multipath in any indoor
environment will dominate. Do it outdoors, elevated, with as much separation as
practical, and treat the numbers as comparative.

---

## 6.7 Shielding and enclosure effectiveness

A practical security/EMC application:

1. Place a small transmit antenna on CH0 inside the enclosure under test.
2. Place a receive antenna on CH1 outside.
3. Sweep S21 with the enclosure open — baseline.
4. Close the enclosure and sweep again.
5. The difference is the **shielding effectiveness** in dB at each frequency.

Useful for validating RF-shielded bags, equipment cabinets, screen rooms, and
enclosure seams. Also useful for finding *where* a shield leaks: move the receive
antenna along the seams and watch S21.

Limited by the NanoVNA's dynamic range, so it will characterize a 30 dB enclosure
well and tell you very little about a 100 dB one.

---

## 6.8 Checking connectors and adapters

Cheap adapters are frequently terrible above a few hundred MHz.

1. Full SOLT calibration at the end of a good cable.
2. Attach the adapter under test with the **LOAD** on its far side.
3. Sweep. A good adapter adds almost nothing — return loss should stay better
   than about −30 dB.
4. A bad adapter shows visible degradation climbing with frequency.

Do this once with a bag of adapters and you'll throw several away. Label the good
ones and keep them in the calibration-quality bag.

---

## 6.9 Verifying attenuators and dummy loads

**Attenuators:** S21 measurement. A 10 dB pad should read −10 dB flat across your
band. Check both the value *and* the flatness — cheap pads often roll off at UHF.

**Dummy loads:** S11 measurement. Sweep it across the full range. A good load
stays better than −25 dB everywhere. Many inexpensive "1 kW dummy loads" are
fine at HF and turn into something else entirely above 200 MHz. Worth knowing
before you trust one for a tuning session.

---

## 6.10 Building a service baseline library

The highest-leverage habit with this instrument:

For every antenna system you install or service, capture and archive:

- `.s1p` file of the full system as measured at the shack end
- `.s1p` of the antenna alone if accessible
- TDR trace of the feedline
- A note of the exact calibration slot/span used and the cable/adapter set

Name them consistently:
```
2026-09-18_sitename_2m-base_system-shackend.s1p
2026-09-18_sitename_2m-base_feedline-tdr.png
```

On the next visit, sweep and compare. A shifted resonance, a new TDR spike, or
2 dB more feedline loss is objective evidence of a change — which beats
speculation, and beats a customer's description of the symptom.

---

[← Antenna tuning](05-antenna-tuning.md) | [Next: Quick reference →](07-quick-reference.md)

---

<div align="center">

[↑ Back to Top](#top) · [NanoVNA Index](README.md) · [SDR & RF](../README.md)

</div>
