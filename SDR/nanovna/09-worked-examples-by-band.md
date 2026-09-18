<a id="top"></a>

# 🧪 09 — Worked Tuning Examples by Band

<div align="center">

**Follow worked examples from the initial sweep through diagnosis, adjustment, and documentation.**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [SDR & RF](../README.md)*

![NanoVNA](https://img.shields.io/badge/Hardware-NanoVNA--H_%26_H4-blue?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Worked_Tuning_Examples_by_Band-green?style=for-the-badge)
![Chapter](https://img.shields.io/badge/Chapter-09_of_12-orange?style=for-the-badge)

</div>

---

[← NanoVNA Index](README.md) · [SDR & RF](../README.md)

## 🎯 Purpose

Demonstrate the tuning process across representative antenna bands and configurations.

## ⚙️ Function

Use a consistent setup, sweep, diagnosis, calculation, adjustment, and result sequence.

## 🏆 Goal

Adapt the measurement method to your own antenna while recognizing illustrative data.

## 📋 When to Use

- Practicing with a band-specific example.
- Comparing a tuning problem with a documented scenario.

---

## 📋 Table of Contents

- [9.1 — 40 m wire dipole @ 7.150 MHz](#91--40-m-wire-dipole--7150-mhz)
- [9.2 — 20 m dipole: the choke changes the antenna](#92--20-m-dipole-the-choke-changes-the-antenna)
- [9.3 — CB / 11 m mobile whip @ 27.205 MHz](#93--cb--11-m-mobile-whip--27205-mhz)
- [9.4 — 6 m ground plane @ 52 MHz — fix the radials first](#94--6-m-ground-plane--52-mhz--fix-the-radials-first)
- [9.5 — 2 m quarter-wave vertical @ 146 MHz](#95--2-m-quarter-wave-vertical--146-mhz)
- [9.6 — Airband receive vertical, 118–137 MHz — a bandwidth problem](#96--airband-receive-vertical-118137-mhz--a-bandwidth-problem)
- [9.7 — GMRS mag mount @ 462/467 MHz — placement beats trimming](#97--gmrs-mag-mount--462467-mhz--placement-beats-trimming)
- [9.8 — 433.92 MHz helical in an enclosure — matching network](#98--43392-mhz-helical-in-an-enclosure--matching-network)
- [9.9 — 868 MHz PCB chip antenna — pi-network tuning](#99--868-mhz-pcb-chip-antenna--pi-network-tuning)
- [9.10 — 915 MHz Yagi driven element — hairpin match](#910--915-mhz-yagi-driven-element--hairpin-match)
- [9.11 — 1090 MHz ADS-B ground plane](#911--1090-mhz-ads-b-ground-plane)
- [9.12 — HF magnetic loop @ 14.2 MHz — high Q, two controls](#912--hf-magnetic-loop--142-mhz--high-q-two-controls)
- [9.13 — 2.4 GHz: what you can and cannot do](#913--24-ghz-what-you-can-and-cannot-do)
- [9.14 — Measurement log template](#914--measurement-log-template)

---

Every example below follows the same shape: **setup → initial sweep → diagnosis →
arithmetic → action → result.** The numbers are realistic and internally
consistent; your antenna will differ, but the method won't.

Two rules apply throughout:

1. **Cut half of what the math says**, re-measure, iterate.
2. **Measure in the final installed environment.** Bench readings on
   ground-plane-dependent antennas are fiction.

**Jump to:**
[40 m dipole](#91--40-m-wire-dipole--7150-mhz) ·
[20 m dipole + choke](#92--20-m-dipole-the-choke-changes-the-antenna) ·
[CB mobile whip](#93--cb--11-m-mobile-whip--27205-mhz) ·
[6 m ground plane](#94--6-m-ground-plane--52-mhz--fix-the-radials-first) ·
[2 m vertical](#95--2-m-quarter-wave-vertical--146-mhz) ·
[Airband RX](#96--airband-receive-vertical-118137-mhz--a-bandwidth-problem) ·
[GMRS mag mount](#97--gmrs-mag-mount--462467-mhz--placement-beats-trimming) ·
[433 MHz in enclosure](#98--43392-mhz-helical-in-an-enclosure--matching-network) ·
[868 MHz PCB antenna](#99--868-mhz-pcb-chip-antenna--pi-network-tuning) ·
[915 MHz Yagi hairpin](#910--915-mhz-yagi-driven-element--hairpin-match) ·
[1090 MHz ADS-B](#911--1090-mhz-ads-b-ground-plane) ·
[HF magnetic loop](#912--hf-magnetic-loop--142-mhz--high-q-two-controls) ·
[2.4 GHz reality check](#913--24-ghz-what-you-can-and-cannot-do) ·
[Log template](#914--measurement-log-template)

---

## 9.1 — 40 m wire dipole @ 7.150 MHz

**Setup:** 14 AWG wire inverted-V, apex 12 m, legs at ~35°, 1:1 current balun at
the feedpoint, 20 m of RG-213. Calibrated at the feedpoint connector, span
6.5–7.6 MHz, 101 points.

**Built to:** 468 / 7.15 = 65.45 ft = **19.95 m total**, 9.97 m per leg.

### Initial sweep

| | |
|---|---|
| Resonance (SWR min) | **6.985 MHz** |
| SWR at resonance | 1.42:1 |
| Z @ 7.150 MHz | **58 + j31 Ω** |
| SWR @ 7.150 MHz | 1.94:1 |

**Diagnosis:** Positive reactance at the target → element is electrically **too
long**. Resistance (58 Ω) is normal for an inverted-V at that height; no matching
network needed once it's resonant.

### Arithmetic

```
Δf% = (7.150 − 6.985) / 6.985 = +2.362%
Shorten total length by 2.362%:
  0.02362 × 19.95 m = 0.471 m total
  ÷ 2 legs           = 23.6 cm per leg
```

**Cut half first: 12 cm per leg.**

### Iteration 1 — after 12 cm/leg (total 19.71 m)

```
Predicted: 6.985 × (19.95 / 19.71) = 7.070 MHz
Measured:  7.068 MHz   ✓ model tracks
```

Remaining: (7.150 − 7.068)/7.068 = **+1.160%** → 0.229 m total → **11.4 cm per
leg.** This time cut the full amount.

### Final — total 19.49 m

| | |
|---|---|
| Resonance | **7.149 MHz** |
| SWR at resonance | 1.21:1 |
| Return loss | −20.4 dB |
| Z @ 7.150 MHz | 60.4 + j1.8 Ω |
| 2:1 SWR bandwidth | 6.98 – 7.32 MHz (340 kHz) |

Done. No matching network — 60 Ω into 50 Ω is 1.2:1 and not worth chasing.

> **Note the wire stretch.** Come back in three months and re-sweep. Copperweld
> and stranded copper both creep under tension; a 40 m dipole commonly drifts
> 20–40 kHz lower over the first season.

---

## 9.2 — 20 m dipole: the choke changes the antenna

**Setup:** flat-top dipole at 8 m (0.38λ), 10.07 m total per the formula.
**No choke initially.**

### Initial sweep — no choke

| | |
|---|---|
| Resonance | 14.05 MHz |
| SWR at resonance | 1.60:1 |
| Z @ 14.20 MHz | 44 + j12 Ω |

Looks tunable. But:

**The hand test:** grab the coax a metre back from the feedpoint and move it.
**The resonance shifts by 60 kHz and the SWR wanders between 1.5 and 2.1.**

That is common-mode current. The coax shield is radiating and is part of the
antenna. Any tuning done now is invalidated the moment the feedline route
changes.

### After installing a 1:1 current balun at the feedpoint

| | |
|---|---|
| Resonance | **13.92 MHz** (moved 130 kHz down) |
| SWR at resonance | 1.31:1 |
| Z @ 14.20 MHz | 49 + j21 Ω |
| Hand test | **No change when the coax is moved** ✓ |

The choke removed the shield from the radiating system, which shortened the
effective antenna's counterpoise and moved resonance. **This is the real
antenna.** Now tune it.

### Arithmetic

```
Δf% = (14.20 − 13.92) / 13.92 = +2.011%
0.02011 × 10.07 m = 0.203 m total  →  10.1 cm per leg
Cut 5 cm per leg first.
```

### Iteration 1 — after 5 cm/leg (total 9.97 m)

```
Predicted: 13.92 × (10.07 / 9.97) = 14.06 MHz
Measured:  14.06 MHz  ✓
```

Remaining: +0.996% → 9.9 cm total → **5 cm per leg.**

### Final — total 9.87 m

| | |
|---|---|
| Resonance | **14.19 MHz** |
| SWR at resonance | 1.12:1 |
| Z @ 14.20 MHz | 52.3 + j3.1 Ω |
| 2:1 SWR bandwidth | 13.88 – 14.56 MHz |
| Hand test | Stable ✓ |

**Lesson: choke first, then tune.** Tuning an antenna that includes its own
feedline produces a result that only works with that exact feedline length and
route.

---

## 9.3 — CB / 11 m mobile whip @ 27.205 MHz

**Setup:** 102" (2.59 m) stainless whip, **trunk-lip mount**, vehicle on the
ground, doors closed, measured at the end of the vehicle's coax with electrical
delay compensation applied. Span 25–29 MHz.

### Initial sweep

| | |
|---|---|
| Resonance | **26.62 MHz** |
| SWR @ 27.205 MHz | 2.80:1 |
| Z @ 27.205 MHz | **21 + j19 Ω** |

**Diagnosis — two separate problems:**

1. **+j19** → element too long
2. **R = 21 Ω** → low feedpoint resistance. Partly the nature of a quarter-wave
   over a vehicle; mostly the **trunk-lip mount's poor ground plane and marginal
   bonding.**

Fix resonance first.

### Arithmetic

```
Δf% = (27.205 − 26.62) / 26.62 = +2.197%
0.02197 × 2.59 m = 5.7 cm
Trim 3 cm first.
```

### Iteration 1 — 2.56 m

```
Predicted: 26.62 × (2.59 / 2.56) = 26.93 MHz
Measured:  26.94 MHz  ✓
```
Remaining: +0.985% → 2.5 cm. Trim it.

### Iteration 2 — 2.535 m

| | |
|---|---|
| Resonance | **27.21 MHz** ✓ |
| Z @ 27.205 MHz | **24 + j2 Ω** |
| SWR | 2.08:1 |

Resonant, still mismatched. Now fix the resistance.

### Option A — fix the ground plane (do this first)

Bonding braid from the mount base to the vehicle body, and moving the mount from
the trunk lip to the roof:

| | Trunk lip | Roof centre |
|---|---|---|
| R at resonance | 24 Ω | 34 Ω |
| SWR | 2.08:1 | 1.47:1 |

**That is usually the whole fix**, and it costs nothing but relocation. If the
roof isn't an option, continue.

### Option B — L-network at the feedpoint

Match **24 Ω → 50 Ω** at 27.205 MHz. R_low is the antenna, so series element on
the antenna side, shunt on the coax side:

```
Q        = √(50/24 − 1) = √1.0833 = 1.041
X_series = 1.041 × 24   = 25.0 Ω    (series, antenna side)
X_shunt  = 50 / 1.041   = 48.0 Ω    (shunt, coax side)

ω = 2π × 27.205e6 = 1.709e8

L = 25.0 / 1.709e8              = 146 nH   → use 150 nH, or ~7 turns on a T50-2
C = 1 / (1.709e8 × 48.0)        = 122 pF   → 100 pF fixed + 50 pF trimmer
```

Tune the trimmer while watching the Smith marker walk to centre.

### Final (roof mount + L-network)

| | |
|---|---|
| SWR @ 27.205 MHz | **1.15:1** |
| Z | 48.9 − j2.6 Ω |
| 2:1 SWR bandwidth | 26.74 – 27.68 MHz |

> Mobile whips are moderately high-Q. Expect the 2:1 bandwidth to be under
> 1 MHz. Tune for the centre of the range you actually use.

---

## 9.4 — 6 m ground plane @ 52 MHz — fix the radials first

**Setup:** quarter-wave vertical, 4 radials, mast-mounted at 6 m. Element cut to
71.3/52 = **1.371 m**. Radials initially **horizontal**.

### Initial sweep — horizontal radials

| | |
|---|---|
| Resonance | 51.4 MHz |
| SWR at resonance | 1.55:1 |
| Z @ 52 MHz | **36 + j6 Ω** |

**Diagnosis:** 36 Ω is the textbook feedpoint resistance of a quarter-wave over a
perfect ground plane. Horizontal radials give you exactly that. The antenna isn't
broken — the geometry is just producing the wrong resistance.

**Do not reach for an L-network.** Slope the radials.

### After sloping the four radials to 45° downward

| | |
|---|---|
| Resonance | **51.6 MHz** |
| SWR at resonance | 1.07:1 |
| Z @ 52 MHz | 47 + j5 Ω |

Sloping the radials raised the feedpoint resistance from 36 Ω toward 50 Ω. This
is the entire reason the classic droopy-radial ground plane looks the way it
does.

### Trim for resonance

```
Δf% = (52.0 − 51.6) / 51.6 = +0.775%
0.00775 × 1.371 m = 10.6 mm
Trim 10 mm.
```

### Final — element 1.361 m

| | |
|---|---|
| Resonance | **51.98 MHz** |
| SWR at resonance | 1.05:1 |
| Return loss | −32.1 dB |
| Z @ 52 MHz | 49.3 + j0.9 Ω |
| 2:1 SWR bandwidth | 49.6 – 54.7 MHz |

**Lesson: mechanical geometry is a matching technique.** Check the ground plane
before you design a network.

---

## 9.5 — 2 m quarter-wave vertical @ 146 MHz

**Setup:** brass rod on an SO-239 chassis mount with 4 sloped radials, on a
1.5 m mast. Cut deliberately long at **50 cm** (formula says 49.0 cm). Span
138–155 MHz, calibrated at the antenna connector.

### Initial sweep

| | |
|---|---|
| Resonance | **143.2 MHz** |
| SWR at resonance | 1.18:1 |
| Z @ 146 MHz | **44 + j11 Ω** |

Good resistance, wrong length.

### Arithmetic

```
Δf% = (146.0 − 143.2) / 143.2 = +1.955%
0.01955 × 50 cm = 9.8 mm
Trim 5 mm first.
```

### Iteration 1 — 49.5 cm

```
Predicted: 143.2 × (50.0 / 49.5) = 144.65 MHz
Measured:  144.7 MHz  ✓
```
Remaining: +0.898% → 4.4 mm. Trim 4 mm.

### Iteration 2 — 49.1 cm

```
Predicted: 144.7 × (49.5 / 49.1) = 145.88 MHz
Measured:  145.9 MHz
```
Close. Remaining 0.7 mm — file it off.

### Final — element 49.04 cm

| | |
|---|---|
| Resonance | **146.05 MHz** |
| SWR at resonance | 1.09:1 |
| Return loss | −27.2 dB |
| Z @ 146 MHz | 48.6 − j2.1 Ω |
| 2:1 SWR bandwidth | 138.9 – 153.4 MHz |

Covers the whole 2 m band plus MURS. Record the final element length for the next
build: **49.0 cm with 45° radials** — your empirical constant for this
construction, more useful than 71.3/f.

---

## 9.6 — Airband receive vertical, 118–137 MHz — a bandwidth problem

**Setup:** receive-only quarter-wave for an ADS-B/airband scanner. Target: 2:1 or
better across **118–137 MHz** (a 15% bandwidth).

**Attempt 1:** 8 mm brass rod, cut to 71.3/125 = **57.0 cm**.

| | |
|---|---|
| Resonance | 124.3 MHz |
| SWR at resonance | 1.14:1 |
| 2:1 SWR bandwidth | **117.5 – 132.0 MHz** ✗ |

Resonance is fine. **Bandwidth is the failure** — it doesn't reach 137 MHz.

**Trimming will not fix this.** Moving the centre up just loses the bottom end.
Bandwidth is set by the antenna's Q, and Q is set by the conductor's
length-to-diameter ratio.

### Attempt 2 — 16 mm aluminium tube, same 57.0 cm

| | |
|---|---|
| Resonance | **121.0 MHz** (fatter element resonates lower for the same length) |
| 2:1 SWR bandwidth | 112.4 – 134.5 MHz — **22.1 MHz wide** vs 14.5 MHz before |

The bandwidth problem is solved; now re-centre.

```
Δf% = (125 − 121) / 121 = +3.306%
0.03306 × 57.0 cm = 1.88 cm  →  trim to 55.1 cm
```

### Final — 16 mm tube at 55.1 cm

| | |
|---|---|
| Resonance | **124.9 MHz** |
| SWR at resonance | 1.11:1 |
| 2:1 SWR bandwidth | **115.8 – 139.2 MHz** ✓ |

**Lesson:** resonance is a length problem; bandwidth is a diameter problem. If
the sweep shows a correctly-centred but too-narrow response, you need a fatter
conductor, a cage element, or a folded element — not a trim.

---

## 9.7 — GMRS mag mount @ 462/467 MHz — placement beats trimming

**Setup:** 1/4-wave mag mount, needs to cover 462.550–467.725 MHz (repeater
inputs and outputs). Span 420–500 MHz.

### Initial — mounted on the trunk lid

| | |
|---|---|
| Resonance | **448 MHz** |
| SWR @ 465 MHz | 2.60:1 |
| Z @ 465 MHz | **33 + j22 Ω** |
| Hand test on coax | **SWR shifts noticeably** ✗ |

Two red flags: low resistance, and coax sensitivity. Both point at an inadequate
ground plane — the trunk lid is small, curved, and poorly bonded, so the coax
shield is carrying return current.

**Before touching the whip, move the mount.**

### Relocated to the centre of the roof

| | |
|---|---|
| Resonance | **455.5 MHz** |
| SWR @ 465 MHz | 1.90:1 |
| Z @ 465 MHz | **41 + j14 Ω** |
| Hand test | Stable ✓ |

Resistance came up, coax sensitivity gone. Now it's just a length problem.

### Arithmetic

```
Δf% = (465 − 455.5) / 455.5 = +2.086%
Whip length 15.8 cm
0.02086 × 15.8 cm = 3.3 mm
Trim 2 mm first.
```

### Iteration 1 — 15.6 cm

```
Predicted: 455.5 × (15.8 / 15.6) = 461.3 MHz
Measured:  461.2 MHz  ✓
```
Remaining: +0.802% → 1.25 mm. Trim 1.2 mm.

### Final — 15.48 cm

| | |
|---|---|
| Resonance | **464.9 MHz** |
| SWR at resonance | 1.14:1 |
| Z @ 465 MHz | 49.1 + j1.4 Ω |
| SWR @ 462.550 | 1.16:1 |
| SWR @ 467.725 | 1.18:1 |
| 2:1 SWR bandwidth | 441 – 489 MHz |

**Lesson:** the relocation moved resistance from 33 Ω to 41 Ω and eliminated the
common-mode problem. Trimming only handled the last 2%. Diagnose the mount before
you cut metal.

---

## 9.8 — 433.92 MHz helical in an enclosure — matching network

**Setup:** moulded helical ("rubber duck") on a small sensor board. The bench
measurement and the assembled-product measurement are very different animals.

### Bare antenna on the bench, on a test ground plane

| | |
|---|---|
| Resonance | 434.6 MHz |
| SWR @ 433.92 | 1.30:1 |

Looks great. Ship it, right?

### Assembled: PCB, battery, and ABS enclosure

| | |
|---|---|
| Resonance | **411 MHz** |
| SWR @ 433.92 | **3.40:1** |
| Z @ 433.92 | **31 + j29 Ω** |

The plastic enclosure's dielectric loading plus the battery's proximity dragged
resonance down 24 MHz (5.6%). This is completely normal and is why you must
measure the finished product.

**You cannot trim a moulded helical**, so match it instead. The board has an
unpopulated pi-network footprint at the feed — that's what it's for.

### Design the L-network from the measured impedance

Load: **Z_L = 31 + j29 Ω**, at ω = 2π × 433.92e6 = **2.726e9 rad/s**.

R_load (31 Ω) < 50 Ω, so: **series element at the antenna, shunt element at the
radio side.**

```
Q = √(50/31 − 1) = √0.6129 = 0.7829

Required TOTAL series reactance (choosing the inductive branch):
  X_total = +Q × R_load = +0.7829 × 31 = +24.27 Ω

The antenna already supplies +29 Ω, so the added series element must be:
  X_series = 24.27 − 29 = −4.73 Ω   →  capacitive

  C_series = 1 / (2.726e9 × 4.73) = 77.5 pF   →  use 75 pF

Shunt element (capacitive, to pair with the inductive series branch):
  X_shunt = 50 / 0.7829 = 63.87 Ω
  C_shunt = 1 / (2.726e9 × 63.87) = 5.74 pF  →  use 5.6 pF
```

### Populate the pi-footprint

```
  antenna ──┤ 75 pF ├──┬── to radio
                       │
                    5.6 pF
                       │
                      GND
```

### Result

| | |
|---|---|
| SWR @ 433.92 MHz | **1.11:1** |
| Z @ 433.92 | 50.9 − j5.2 Ω |
| 2:1 SWR bandwidth | 419 – 449 MHz |

> **Radiation efficiency caveat:** the matching network makes the antenna *accept*
> power. It does not undo the losses the enclosure introduced. A matched but
> detuned-by-plastic antenna still radiates less than a properly sized one. If
> range matters, respin the antenna, don't just match it.

---

## 9.9 — 868 MHz PCB chip antenna — pi-network tuning

**Setup:** chip antenna on a 4-layer board, measured at the feed pad through a
U.FL test point, **with the final enclosure closed**. ω = 2π × 868e6 = **5.454e9**.

### Initial

| | |
|---|---|
| Z @ 868 MHz | **18 − j40 Ω** |
| SWR | 4.7:1 |

**Diagnosis:** capacitive (−jX) → antenna is electrically **too short** for
868 MHz. Resistance is low, as chip antennas tend to be.

### Design

```
Step 1 — cancel the −j40 and transform 18 Ω → 50 Ω in one network.

Q = √(50/18 − 1) = √1.7778 = 1.3333

Required total series reactance:
  X_total = +Q × 18 = +24.0 Ω

Antenna supplies −40 Ω, so the series element must supply:
  X_series = 24.0 − (−40) = +64.0 Ω    →  inductive

  L_series = 64.0 / 5.454e9 = 11.73 nH   →  use 12 nH

Shunt element (capacitive):
  X_shunt = 50 / 1.3333 = 37.5 Ω
  C_shunt = 1 / (5.454e9 × 37.5) = 4.89 pF   →  use 4.7 pF
```

### Populate

```
  antenna ──┤ 12 nH ├──┬── to transceiver
                       │
                    4.7 pF
                       │
                      GND
```

### Result

| | |
|---|---|
| Z @ 868 MHz | 52.6 + j6.1 Ω |
| SWR @ 868 MHz | **1.15:1** |
| SWR @ 863 MHz | 1.19:1 |
| SWR @ 870 MHz | 1.14:1 |
| 2:1 SWR bandwidth | 849 – 891 MHz ✓ |

### Practical notes for this class of work

- Use **0402 or 0201 high-Q RF components**. A general-purpose 0603 inductor has
  self-resonance too low and Q too poor at 868 MHz.
- Component tolerance matters: ±5% on a 12 nH part is ±0.6 nH, which moves the
  match. Verify each build.
- **Keep the test pigtail short** and calibrate at its far end, or the pigtail's
  own phase rotation will corrupt the impedance reading and you'll design a
  network for the wrong load.
- Re-verify after any enclosure, battery, or display change.

---

## 9.10 — 915 MHz Yagi driven element — hairpin match

**Setup:** 3-element Yagi for 915 MHz. Parasitic elements set gain and
front-to-back — **do not touch them.** Only the driven element and its match get
adjusted. ω = 2π × 915e6 = **5.749e9**.

The design uses a **hairpin (beta) match**: the driven element is deliberately
made slightly short so it looks capacitive, and a shunt inductor across the
feedpoint transforms the low resistance up to 50 Ω.

### Initial

| | |
|---|---|
| Z @ 915 MHz | **22 − j28 Ω** |
| SWR | 2.9:1 |

### The hairpin condition

For a shunt inductor to transform R_s + jX_s up to exactly 50 Ω, the series
reactance must satisfy:

```
|X_s| = √( R_s × (50 − R_s) ) = √(22 × 28) = √616 = 24.8 Ω
```

Measured X_s is **−28 Ω**; we need **−24.8 Ω**. Slightly less capacitive means
slightly **longer** driven element.

```
Adjust driven element length until X = −24.8 Ω at 915 MHz.
(Watch the REACTANCE trace, not SWR — it's the direct readout.)
```

### After lengthening the driven element 1.5 mm per side

| | |
|---|---|
| Z @ 915 MHz | **22.1 − j24.9 Ω** ✓ |

### Calculate the hairpin

```
|Z|² = 22.1² + 24.9² = 488 + 620 = 1108
Y    = (22.1 + j24.9) / 1108 = 0.01995 + j0.02247 S

Conductance G = 0.01995 S  =  1 / 50.1 Ω   ✓ exactly what we need

Cancel the +j0.02247 S with a shunt inductor:
  1 / (ωL) = 0.02247   →   ωL = 44.5 Ω
  L = 44.5 / 5.749e9 = 7.74 nH
```

At 915 MHz, 7.7 nH is a **shorted two-wire hairpin roughly 7–8 mm long** with
3 mm conductor spacing — trim to fit while watching the Smith marker.

### Final

| | |
|---|---|
| Z @ 915 MHz | 49.4 + j2.1 Ω |
| SWR | **1.05:1** |
| Return loss | −32.4 dB |
| 2:1 SWR bandwidth | 889 – 944 MHz ✓ covers 902–928 |

> **Measure the Yagi at operating height and clear of obstructions.** Ground
> proximity within about 1λ will shift both the impedance and the pattern. A
> Yagi tuned on a workbench is tuned for a workbench.

---

## 9.11 — 1090 MHz ADS-B ground plane

**Setup:** quarter-wave vertical with 4 sloped radials, built from 1.5 mm copper
wire in an SO-239. Span 950–1250 MHz.

> **Instrument note:** 1090 MHz is in the NanoVNA's **5th-harmonic** region —
> about 40 dB of usable dynamic range. Keep test cables short, calibrate on a
> narrow span, and let the unit warm up. Readings below −35 dB S11 here
> are not trustworthy; that's fine, you don't need them.

**Built to:** 71.3/1090 = 6.54 cm. Cut long at **6.9 cm**.

### Initial sweep

| | |
|---|---|
| Resonance | **1032 MHz** |
| SWR at resonance | 1.24:1 |
| Z @ 1090 MHz | **39 + j18 Ω** |
| SWR @ 1090 MHz | 2.20:1 |

### Arithmetic

```
Δf% = (1090 − 1032) / 1032 = +5.62%
0.0562 × 6.9 cm = 3.9 mm
Trim 2 mm first.
```

### Iteration 1 — 6.7 cm

```
Predicted: 1032 × (6.9 / 6.7) = 1063 MHz
Measured:  1061 MHz  (close — harmonic-mode readings are noisier)
```
Remaining: +2.73% → 1.8 mm. Trim 1.7 mm.

### Final — element 6.53 cm

| | |
|---|---|
| Resonance | **1089 MHz** |
| SWR at resonance | 1.11:1 |
| Z @ 1090 MHz | 47.2 − j3.8 Ω |
| 2:1 SWR bandwidth | 1020 – 1165 MHz |

For a receive-only ADS-B antenna, that bandwidth is more than sufficient —
1090 MHz is a single narrow channel.

**Also worth checking:** sweep the filter/LNA in front of the receiver on S21.
Many cheap ADS-B LNAs have far less out-of-band rejection than advertised, and
that's usually the real cause of poor performance at a site near cellular or
paging transmitters — not the antenna.

---

## 9.12 — HF magnetic loop @ 14.2 MHz — high Q, two controls

**Setup:** 1 m diameter copper loop, vacuum variable capacitor, inductively
coupled feed loop. Extremely high Q.

### The trap: sweeping too wide

```
Span 1–30 MHz, 101 points = 290 kHz per point
Result: the trace looks completely flat. No dip anywhere.
```

The loop's response is **19 kHz wide.** A 290 kHz-per-point sweep steps right
over it. The antenna is fine; the measurement is wrong.

### Correct setup

```
STIMULUS → CENTER 14.200 MHz → SPAN 400 kHz
H4: CONFIG → POINTS → 401     →  1 kHz per point
Re-calibrate on this span.
```

Or use **NanoVNA-Saver with 20+ segments** for ~2000 effective points.

### Initial sweep

| | |
|---|---|
| Resonance | **14.118 MHz** |
| SWR at resonance | **3.60:1** |

### Two independent controls

| Control | What it sets |
|---|---|
| **Tuning capacitor** | Resonant **frequency** |
| **Coupling loop size/position** | **Match depth** (feedpoint resistance) |

Do not confuse them. Turning the cap to try to fix a bad SWR just moves the
resonance off frequency.

### Step 1 — capacitor for frequency

Adjust the vacuum cap until resonance sits at 14.201 MHz.

| | |
|---|---|
| Resonance | **14.201 MHz** ✓ |
| SWR at resonance | 3.40:1 ✗ |

Frequency correct, match still poor. The cap has done its job.

### Step 2 — coupling loop for match

Coupling loop was 1/6 of the main loop circumference. Enlarge to 1/5 and re-check
(this increases coupling, raising the transformed feedpoint resistance).

| Coupling loop | SWR at resonance |
|---|---|
| 1/6 circumference | 3.40:1 |
| 1/5.5 | 1.90:1 |
| **1/5** | **1.25:1** ✓ |
| 1/4.5 | 1.70:1 (overcoupled) |

Enlarging past the optimum overshoots — the match passes through 1:1 and comes
back out. Watch the Smith marker cross the centre and stop there.

### Final

| | |
|---|---|
| Resonance | 14.201 MHz |
| SWR at resonance | 1.25:1 |
| Z | 47 + j11 Ω |
| 2:1 SWR bandwidth | 14.192 – 14.211 MHz (**19 kHz**) |
| Loaded Q | ≈ 14201 / 19 ≈ **747** |

**Practical consequence:** this antenna must be retuned for almost any frequency
change. That narrow bandwidth is also why a mag loop is quiet on receive — it's a
tracking preselector as much as an antenna.

> **Never transmit into a mag loop while the NanoVNA is connected.** The voltage
> across the tuning capacitor of a loop under power reaches kilovolts.

---

## 9.13 — 2.4 GHz: what you can and cannot do

You will be tempted. Here's the honest boundary.

**With stock firmware (1.5 GHz ceiling):** nothing. 2.4 GHz is simply outside the
sweep range.

**With extended firmware (some builds reach 2.7–3 GHz):**

| Measurement | Viable? |
|---|---|
| Rough location of resonance on S11 | **Yes** — you can see *roughly* where a 2.4 GHz antenna is resonant |
| Relative before/after comparison | **Yes**, if nothing else in the setup changes |
| Trustworthy VSWR figure | **No** — 25–30 dB dynamic range, poor directivity |
| Accurate impedance for matching-network design | **No** — don't design a pi-network from these numbers |
| S21 / filter characterization | **No** |

**What this means in practice:** you can use an extended-firmware NanoVNA to
confirm a 2.4 GHz antenna is resonant somewhere near 2.45 GHz rather than
2.1 GHz, or to confirm a cable isn't open. You cannot use it to tune a Wi-Fi
antenna properly, and you certainly cannot characterize 5 GHz.

For real 2.4/5 GHz work you need a NanoVNA V2/V2 Plus4 (up to 4.4 GHz), a
LiteVNA 6 GHz, or a proper bench VNA.

**Do not** design a production matching network from harmonic-mode data above
1.5 GHz. The measurement will look plausible and be wrong.

---

## 9.14 — Measurement log template

Copy this for each antenna. Consistent records are what make the next visit fast.

```markdown
## Antenna Measurement Record

Date:                    Technician:
Site / Customer:
Antenna (make/model/type):
Mounting / height / ground plane:
Feedline (type, length, VF):
Connectors / adapters in path:

### Instrument
Unit:            NanoVNA-H (3.7)  /  NanoVNA-H4
Firmware:
Cal slot used:           Span:              MHz –           MHz
Points:                  Cal plane location:
Load verification:              dB   (target: better than −35 dB)

### Results
Target frequency:                MHz
Resonance (SWR min):             MHz
Min SWR:                 :1      Return loss:            dB
Z @ target:                  +j            Ω
2:1 SWR bandwidth:               –              MHz
1.5:1 SWR bandwidth:             –              MHz

### Checks
Common-mode (hand test):   stable / shifts
Choke installed:           yes / no
TDR distance to end:               m    (expected:          m)
Feedline one-way loss:             dB @          MHz

### Action taken

### Files archived
  .s1p:
  Screenshot:
  Baseline compared against:
```

---

[← PC software & firmware](08-pc-software-and-firmware.md) |
[Next: Antenna types & special cases →](10-antenna-types-and-special-cases.md) |
[Back to index](README.md)

---

<div align="center">

[↑ Back to Top](#top) · [NanoVNA Index](README.md) · [SDR & RF](../README.md)

</div>
