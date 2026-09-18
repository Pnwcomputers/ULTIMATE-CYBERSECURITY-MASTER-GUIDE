<a id="top"></a>

# 📡 04 — Antenna Testing and Diagnostics

<div align="center">

**Check an antenna methodically and separate antenna behavior from the measurement setup.**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [SDR & RF](../README.md)*

![NanoVNA](https://img.shields.io/badge/Hardware-NanoVNA--H_%26_H4-blue?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Antenna_Testing_and_Diagnostics-green?style=for-the-badge)
![Chapter](https://img.shields.io/badge/Chapter-04_of_12-orange?style=for-the-badge)

</div>

---

[← NanoVNA Index](README.md) · [SDR & RF](../README.md)

## 🎯 Purpose

Provide a repeatable antenna inspection and measurement procedure.

## ⚙️ Function

Combine preparation, sweep setup, reference-plane checks, diagnostic decisions, and examples.

## 🏆 Goal

Produce a documented baseline before deciding whether an antenna needs adjustment.

## 📋 When to Use

- Checking an installed antenna or investigating poor performance.
- Separating feedline, connector, and common-mode effects.

---

## 📋 Table of Contents

- [4.1 Before you connect anything](#41-before-you-connect-anything)
- [4.2 Standard antenna test procedure](#42-standard-antenna-test-procedure)
- [4.3 Reading the result — diagnostic decision tree](#43-reading-the-result--diagnostic-decision-tree)
- [4.4 Testing for common-mode current](#44-testing-for-common-mode-current)
- [4.5 Testing a coax run and an antenna separately](#45-testing-a-coax-run-and-an-antenna-separately)
- [4.6 Worked example: tuning a 915 MHz LoRa whip](#46-worked-example-tuning-a-915-mhz-lora-whip)
- [4.7 Worked example: diagnosing a "dead" 2 m base antenna](#47-worked-example-diagnosing-a-dead-2-m-base-antenna)
- [4.8 Quick go/no-go field check](#48-quick-gono-go-field-check)

---

---

## 4.1 Before you connect anything

### Safety sequence — every time, no exceptions

1. **Disconnect the antenna from any transmitter.** Physically unplug it. A
   powered radio with a stuck PTT, a repeater controller, or a co-sited
   transmitter will destroy the VNA instantly.
2. **Check for DC.** If the system has a bias-tee, mast-head preamp, DC-grounded
   monitoring, or you simply don't know its history — put a **DC block** inline
   on CH0. If you have a multimeter, check center-to-shield for DC voltage first.
3. **Discharge static.** Short the coax center conductor to the shield for 2–3
   seconds with a screwdriver blade or shorting cap. Outdoor antennas,
   particularly long wires and anything on a mast, accumulate substantial static
   charge.
4. **Check the RF environment.** If you're at a broadcast site, a repeater site,
   or next to a cell tower, the antenna under test is acting as a receiving
   antenna and may be delivering serious power into your VNA. Insert a 10 dB
   attenuator on CH0 (and remember to calibrate with it in place).
5. **Weather.** Don't measure an outdoor antenna during a thunderstorm. This is
   about you, not the instrument.

### Physical safety

Working at height, near power lines, on rooftops, or around tower-mounted
hardware carries risk that has nothing to do with RF. Follow whatever site
procedures apply. Nothing in this guide changes that.

---

## 4.2 Standard antenna test procedure

### Step 1 — Know your target

Write down before you start:

- **Center frequency** you're tuning for
- **Bandwidth** you need to cover
- **Acceptable VSWR** across that bandwidth (usually ≤ 2:1, sometimes ≤ 1.5:1)

### Step 2 — Set a sweep span

Start **wide enough to find the resonance even if it's badly off**, then narrow.

Rule of thumb: sweep **±20–30%** of target frequency on the first pass.

| Target | First-pass span | Refined span |
|---|---|---|
| 7.15 MHz (40 m) | 5 – 10 MHz | 6.8 – 7.5 MHz |
| 14.2 MHz (20 m) | 11 – 18 MHz | 13.9 – 14.5 MHz |
| 146 MHz (2 m) | 120 – 175 MHz | 140 – 152 MHz |
| 433.92 MHz (ISM) | 380 – 490 MHz | 420 – 450 MHz |
| 462 MHz (GMRS) | 400 – 520 MHz | 455 – 470 MHz |
| 915 MHz (ISM/LoRa) | 800 – 1050 MHz | 890 – 940 MHz |
| 1090 MHz (ADS-B) | 950 – 1250 MHz | 1050 – 1130 MHz |

### Step 3 — Calibrate on that span

Full procedure in [03-calibration.md](03-calibration.md). Calibrate at the point
where you'll attach the antenna.

Verify with the load. **Check for the `C` indicator.**

### Step 4 — Configure the display

For antenna work:

```
DISPLAY → TRACE → 0 → FORMAT → SWR       (CH0)
DISPLAY → TRACE → 1 → FORMAT → SMITH     (CH0)
DISPLAY → TRACE → 2 → FORMAT → LOGMAG    (CH0)
DISPLAY → TRACE → 3 → (turn off)
```

Set the SWR scale to something readable — `DISPLAY → SCALE → SCALE/DIV → 1`
gives you 1:1 through 9:1 across the screen.

### Step 5 — Connect the antenna

Mount it the way it will actually be used. This matters enormously:

- **Ground-plane dependent antennas** (mag-mounts, 1/4-wave whips, mobile
  antennas) must be on their real ground plane. Measuring a mag-mount antenna
  sitting on a workbench gives a meaningless answer.
- **Height above ground** changes a horizontal antenna's feedpoint impedance
  dramatically. A dipole at 3 m and the same dipole at 10 m are different
  antennas.
- **Nearby objects** — your body, metal shelving, a vehicle, a gutter — detune
  antennas, especially at UHF and above. Get clear.
- **Feedline dress** matters. Coax routed along the radiating element can carry
  common-mode current and become part of the antenna.

### Step 5a — Establish repeatability BEFORE you believe anything

This step is skipped constantly and it is the difference between measuring an
antenna and measuring your own test setup.

1. Take several sweeps with your hands away from everything. Do they overlay?
2. Now lightly reposition the **test lead** without moving the antenna. Sweep
   again.
3. Flex each connector gently while watching the trace.

| What you see | What it means |
|---|---|
| Sweeps overlay; small repeatable change when the lead moves | Normal fixture sensitivity. Proceed. |
| Resonance or SWR moves noticeably when the lead moves | **Common-mode current**, inadequate ground plane, or a bad connection. See §4.4. |
| Abrupt, discontinuous jumps while flexing a connector | **Mechanical fault.** Find it and fix it. |
| Never settles; wanders between sweeps | Loose connection, dying battery, or interference. |

**Fix unstable measurement conditions before you trim anything.** Every
adjustment you make while the setup is unstable is an adjustment made to noise,
and you will not be able to tell whether your change or the fixture produced the
result.

### Step 6 — Find the resonance

```
MARKER → SELECT MARKER → MARKER 1
MARKER → SEARCH → MINIMUM
```

This drops marker 1 onto the lowest SWR / deepest return loss point. Read the
frequency at the top of the screen.

Enable **`TRACKING`** under SEARCH and the marker will follow the minimum
automatically as you adjust the antenna — this is essential for iterative
trimming, because you can watch the resonance move in real time.

### Step 7 — Narrow the span and refine

```
MARKER → OPERATIONS → →CENTER      (centers the sweep on the marker)
STIMULUS → SPAN → [narrower value]
```

**Then re-calibrate on the new span.** Yes, again. Every time.

### Step 8 — Measure the bandwidth

Place **marker 2** and **marker 3** at the frequencies where SWR crosses your
threshold (2:1 or 1.5:1). The span between them is your usable bandwidth.

A useful record for any antenna:

| Parameter | Value |
|---|---|
| Resonant frequency (SWR minimum) | ______ MHz |
| Minimum SWR | ______ :1 |
| Return loss at resonance | ______ dB |
| Impedance at target frequency (R + jX) | ______ + j______ Ω |
| 2:1 SWR bandwidth (lower / upper edge) | ______ / ______ MHz |

### Step 9 — Save the result

- **H4:** save a screenshot and an `.s1p` file to the microSD
- **Either unit:** connect NanoVNA-Saver and export Touchstone `.s1p`
- At minimum, photograph the screen

Build a baseline library. Six months later when a customer says "it stopped
working," the comparison sweep is worth more than any amount of speculation.

---

## 4.3 Reading the result — diagnostic decision tree

### The trace is flat at 1.0:1 across the whole sweep

**You're looking at a dummy load, a dead short with a resistor, or an extremely
lossy feedline.** Real antennas are not flat. If you're sweeping an installed
system and see this, suspect:

- A terminated/50 Ω-loaded test point
- A very long, very lossy coax run (the loss swamps the antenna's reflection)
- Water-logged coax
- A failed lightning arrestor that's gone resistive

Check the Smith chart: a genuine dummy load sits as a tight dot at center. A
lossy line shows a trace that spirals toward center but wanders.

### The trace is pinned at maximum SWR across the whole sweep

**Open or short circuit.** Check:

- Is anything actually connected?
- Broken center conductor in the coax
- Connector soldering failure (very common on field-installed PL-259s)
- Snapped element
- Use TDR mode ([06](06-cables-filters-other-uses.md)) to find how far away
  the fault is

Look at the Smith chart: a hard **open** parks at far right, a hard **short**
parks at far left. That alone tells you which failure mode you have.

### There's a dip, but it's at the wrong frequency

This is the normal case and it's the whole point of the exercise.

| Observation | Cause | Action |
|---|---|---|
| Resonance **below** target | Antenna is electrically **too long** | **Shorten** the element |
| Resonance **above** target | Antenna is electrically **too short** | **Lengthen** the element |

Confirm with the Smith chart at your *target* frequency:

- Marker **above** the centerline (inductive, +jX) → too long
- Marker **below** the centerline (capacitive, −jX) → too short

Amount of correction: see [05-antenna-tuning.md](05-antenna-tuning.md) §5.2.

### There's a dip at the right frequency, but SWR is still high (2.5:1+)

The antenna is **resonant but not matched**. Reactance is near zero, but
resistance isn't 50 Ω.

Put a marker at resonance and read the Smith impedance:

- **R much less than 50 Ω** (e.g. 20 Ω) — typical of a quarter-wave vertical
  over a good ground plane (~36 Ω theoretical), a low dipole, or an antenna with
  a shortened/loaded element. Needs step-up matching.
- **R much more than 50 Ω** (e.g. 100 Ω) — typical of a folded dipole (~300 Ω),
  an end-fed element, or a high horizontal antenna.

Trimming the element **will not fix this.** You need a matching network — see
[05](05-antenna-tuning.md) §5.4.

### Multiple dips across the sweep

Could be legitimate (a multiband antenna, a trap vertical) or could be an
artifact:

- **Harmonically related dips** (e.g. 7 MHz, 21 MHz, 35 MHz) — normal odd-harmonic
  behavior of a wire antenna. Expected.
- **Irregular, closely-spaced dips** — often **common-mode current** on the
  feedline turning the coax shield into a resonant radiator. See §4.4.
- **Evenly spaced ripple across a wide sweep** — a **reflection from a
  discontinuity** in the feedline. The spacing tells you the distance:
  `distance (m) = (150 × VF) / Δf(MHz)`. A connector, a splice, or water ingress.

### Broad, shallow dip that never gets good

Usually **loss**. Something in the system is dissipating energy:

- Wet or degraded coax
- Corroded connector
- A resistive fault (the classic "rain-soaked PL-259")
- An antenna with a lossy loading coil

The Smith chart is diagnostic here: a lossy system's trace stays bunched near the
center without ever forming a proper loop. Low SWR *plus* a poorly defined Smith
loop is the signature of a lossy system, not a good antenna.

> **The counterintuitive rule:** a suspiciously good SWR on an old installation
> is more often a symptom of feedline loss than of a great antenna.

---

## 4.4 Testing for common-mode current

Common-mode current on the coax shield is the most under-diagnosed antenna
problem. It causes: unstable SWR readings, RF in the shack, unexpected pattern
distortion, and interference with nearby equipment.

### The hand test

1. Sweep the antenna, note the resonant frequency and SWR.
2. Grab the coax about a half-metre back from the feedpoint. Move it around.
3. Watch the trace.

**If the SWR or resonance shifts noticeably when you touch or move the coax, you
have common-mode current.** The shield is part of the radiating system.

### The choke test

1. Baseline sweep.
2. Add a common-mode choke (ferrite clamp-ons or a coiled-coax choke) at the
   feedpoint.
3. Sweep again.

If the resonance moves or the SWR changes materially, the choke was needed and
is now doing its job. Re-tune the antenna **with the choke in place**, because
the choke changed the antenna.

### Why it matters for your measurement

Without a choke, you may be measuring an antenna-plus-feedline system and then
"tuning" it. As soon as the installation changes — different coax route,
different length — the tuning is invalidated. **Choke first, then tune.**

---

## 4.5 Testing a coax run and an antenna separately

The most efficient diagnostic when something's wrong with an installed system:

### Part 1 — Coax alone

1. Disconnect the antenna at the top.
2. **Leave the far end open.**
3. Sweep from the shack end.
4. You should see a classic open-ended transmission line pattern: the Smith
   trace spinning around the outer edge, SWR pinned high.
5. Switch to **TDR** mode. Set the velocity factor for your cable. You should see
   a single reflection at the cable's physical length.
6. Now **short** the far end and repeat. You should see the mirror-image behavior
   and a TDR spike at the same distance.

**What this tells you:** whether the coax is electrically intact, its true
length, and whether there are any mid-run discontinuities.

**Measuring coax loss:** with the far end shorted, read the return loss on
LOGMAG at your frequency of interest. Divide by 2. That is the **one-way loss**
of the cable. Compare to the manufacturer's spec — if it's more than about 1 dB
worse, the cable is degraded.

### Part 2 — Antenna alone

Calibrate at the end of a short jumper, connect directly to the antenna, sweep.

### Part 3 — Compare

If the antenna alone is fine and the coax alone is fine but the system is bad,
the fault is at a connector, the arrestor, or a bulkhead pass-through.

---

## 4.6 Worked example: tuning a 915 MHz LoRa whip

Target: 915 MHz, want ≤ 1.5:1, ISM band 902–928 MHz.

**Setup:**
- Antenna: SMA whip on a small ground plane, mounted as it will be deployed
- Cal: OPEN/SHORT/LOAD at the end of a 15 cm RG-316 jumper, span 850–1000 MHz

**Initial sweep result:**
```
Marker 1 (minimum): 878.4 MHz, SWR 1.31:1, RL −17.6 dB
Marker 2 @ 915 MHz: SWR 2.42:1, Z = 41.3 + j27.8 Ω
```

**Diagnosis:** Resonance is 36.6 MHz low. At 915 MHz the impedance is
**inductive** (+j27.8) — confirms the element is electrically too long.

**Correction:**
```
Required frequency shift = 915 / 878.4 = 1.0417  → +4.17%
Required length change   = −4.17%
```

Whip is a quarter-wave at ~878 MHz. Theoretical quarter wave at 878.4 MHz with
VF ≈ 0.95:
```
λ/4 = (71.3 / 878.4) m = 8.12 cm
```
Trim 4.17% of 8.12 cm = **3.4 mm**.

**Practice:** trim **2 mm** first, re-sweep. Iterate. You can always remove more
metal; you cannot put it back.

**After 2 mm:**
```
Marker 1: 900.1 MHz, SWR 1.22:1
Marker 2 @ 915 MHz: SWR 1.58:1, Z = 44.8 + j9.1 Ω
```

Moving the right way. Trim another 1.5 mm.

**After a further 1.5 mm:**
```
Marker 1: 916.8 MHz, SWR 1.14:1, RL −23.8 dB
Marker 2 @ 915 MHz: SWR 1.16:1, Z = 48.2 − j3.4 Ω
2:1 SWR bandwidth: 881 – 954 MHz  ✓ covers 902–928 comfortably
```

Done. Record the sweep as the baseline.

---

## 4.7 Worked example: diagnosing a "dead" 2 m base antenna

Customer reports a base station that "stopped hearing anything."

**Test 1 — full system from the shack, 130–175 MHz:**
```
Trace pinned at SWR > 10:1 across the entire sweep.
Smith chart: trace parked at the far LEFT.
```

Far left = **short circuit**. Not an open, not a detuned antenna — a dead short
somewhere in the system.

**Test 2 — TDR:**
```
DISPLAY → TRANSFORM → LOW PASS IMPULSE
Set VELOCITY FACTOR to 0.66 (RG-213)
```
Reflection spike at **4.1 m**.

The coax run is 22 m. So the short is 4.1 m from the shack end — not at the
antenna, not at the connector on the radio.

**Physical check at 4.1 m:** that's right where the cable passes through the
exterior wall bulkhead and there's a lightning arrestor.

**Found:** water had entered the arrestor housing, corroded through, and bridged
center to shell.

Total diagnostic time: about ten minutes, no climbing.

**This is the highest-value use of a VNA in service work** — it turns "climb the
tower and start checking things" into "the fault is 4.1 metres from here."

---

## 4.8 Quick go/no-go field check

When you just need a thumbs up or down:

```
1. Recall the saved cal slot for that band
2. Discharge the coax, connect
3. Look at the SWR trace
4. MARKER → SEARCH → MINIMUM
5. Compare to baseline
```

Twenty seconds. If it matches baseline, move on. If it doesn't, escalate to the
full procedure in §4.2.

---

[← Calibration](03-calibration.md) | [Next: Antenna tuning →](05-antenna-tuning.md)

---

<div align="center">

[↑ Back to Top](#top) · [NanoVNA Index](README.md) · [SDR & RF](../README.md)

</div>
