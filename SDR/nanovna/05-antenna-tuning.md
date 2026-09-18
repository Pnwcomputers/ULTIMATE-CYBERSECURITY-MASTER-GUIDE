# 05 — Tuning Antennas

[← Back to index](README.md)

---

## 5.1 The two separate problems

Every antenna match problem is actually two problems, and you have to fix them in
this order:

### Problem 1 — Resonance (reactance)

The antenna presents **+jX or −jX** — it stores energy rather than radiating it.
Fixed by changing the **electrical length** of the radiating element, or by
adding a compensating reactance.

**Symptom:** Smith marker is off the horizontal centerline.

### Problem 2 — Match (resistance)

At resonance the antenna presents pure resistance, but not 50 Ω. A quarter-wave
vertical over a perfect ground is about 36 Ω. A half-wave dipole in free space is
about 73 Ω. A folded dipole is about 300 Ω.

**Symptom:** Smith marker is on the centerline but not at the center dot.

**Fix resonance first, then fix the match.** Doing it the other way around means
the matching network fights a moving target.

---

## 5.2 Fixing resonance: element trimming

### The scaling relationship

For a simple resonant element, frequency and length are inversely proportional:

```
f_new / f_old = L_old / L_new
```

Rearranged for practical use:

```
Percent length change = −(Percent frequency change)
```

**To raise resonant frequency by X%, shorten the element by X%.**
**To lower resonant frequency by X%, lengthen the element by X%.**

### Baseline length formulas

Two different families of constant circulate for this, and confusing them is a
common source of "my antenna came out wrong":

**Free-space wavelength** — pure physics, no antenna involved:

| Quantity | Metric | Imperial |
|---|---|---|
| Full wave λ | 299.79 / f(MHz) m | 984 / f(MHz) ft |
| Half wave λ/2 | 149.90 / f(MHz) m | 492 / f(MHz) ft |
| Quarter wave λ/4 | **74.95** / f(MHz) m | 246 / f(MHz) ft |

**Practical antenna lengths** — the empirical constants, roughly 5% shorter than
free space to account for end effect on ordinary wire and tubing:

| Antenna | Metric | Imperial |
|---|---|---|
| **Half-wave dipole** (total) | **142.65** / f(MHz) m | **468** / f(MHz) ft |
| **Quarter-wave vertical / whip** | **71.3** / f(MHz) m | **234** / f(MHz) ft |
| Quarter-wave radials | 74.95 / f(MHz) m | 246 / f(MHz) ft |
| 5/8-wave vertical | 178 / f(MHz) m | 585 / f(MHz) ft |

> Radials are conventionally cut close to the free-space figure while the driven
> element is cut to the shortened empirical one — that is not an inconsistency,
> it is why the two columns differ.

**These are starting points, not answers.** The real finished length depends on
conductor diameter, insulation, mounting height, ground-plane quality, enclosure
material, and nearby objects. Expect the empirical constant to be wrong by a few
percent in either direction; the NanoVNA exists precisely to tell you by how
much. Always **start long** and trim.

> **These length rules apply to simple radiators near their intended fundamental
> mode.** They do **not** transfer to loaded whips, trapped antennas, multiband
> verticals, helicals, or anything with a manufacturer's matching structure
> built in. On those, a "total length" formula is actively misleading — follow
> the designer's adjustment instructions and use the VNA to verify, not to
> derive. See [10-antenna-types-and-special-cases.md](10-antenna-types-and-special-cases.md).

### Reference lengths at common frequencies

Computed from the **practical** constants above (71.3 / 142.65). Start long.

| Frequency | λ/4 element | λ/2 dipole (total) |
|---|---|---|
| 7.15 MHz | 9.972 m / 392.6 in | 19.951 m / 785.5 in |
| 14.2 MHz | 5.021 m / 197.7 in | 10.046 m / 395.5 in |
| 28.5 MHz | 2.502 m / 98.5 in | 5.005 m / 197.1 in |
| 52.0 MHz | 1.371 m / 53.98 in | 2.743 m / 108.0 in |
| 146 MHz | 48.84 cm / 19.23 in | 97.71 cm / 38.47 in |
| 433.92 MHz | 16.43 cm / 6.47 in | 32.87 cm / 12.94 in |
| 462 MHz | 15.43 cm / 6.08 in | 30.88 cm / 12.16 in |
| 868 MHz | 8.21 cm / 3.23 in | 16.43 cm / 6.47 in |
| 915 MHz | 7.79 cm / 3.07 in | 15.59 cm / 6.14 in |
| 1090 MHz | 6.54 cm / 2.58 in | 13.09 cm / 5.15 in |

### The trimming procedure

1. **Sweep. Record resonance.**
2. **Compute the required percentage change.**
   ```
   Δ% = ((f_target − f_measured) / f_measured) × 100
   Length change = −Δ% of current length
   ```
3. **Cut HALF of what you calculated.** Always. Metal comes off easily and goes
   back on with difficulty.

   **Prefer reversible adjustments wherever the antenna offers one:** slide a
   telescoping section, turn the manufacturer's adjustment screw, move a clamp,
   or fold the wire end back on itself instead of cutting. Folded-back wire is
   not electrically identical to removed wire — it still couples — but it lets
   you find the right length before you commit, and then cut once.
4. **Re-sweep.** Confirm the resonance moved in the expected direction by
   roughly the expected amount. If it didn't, stop and figure out why before
   cutting more.
5. **Iterate**, halving each time, until you're inside tolerance.

### For a dipole specifically

The total length determines resonance, but you must **keep both legs equal** or
the feedpoint impedance and pattern become asymmetric.

```
Total length to remove = Δ% × total length
Remove from EACH leg   = (that total) / 2
```

Example: 20 m dipole, 10.20 m total, resonant at 13.85 MHz, target 14.20 MHz.
```
Δ% = (14.20 − 13.85)/13.85 = +2.53%  → shorten by 2.53%
Total to remove = 0.0253 × 10.20 m = 25.8 cm
Remove from each leg = 12.9 cm
Cut 6 cm per leg first, re-measure.
```

### For telescoping whips

Easiest case — no cutting. Collapse or extend in small increments while watching
a tracking marker. Once you find the right extension, mark it with a paint pen
or a wrap of tape so it can be reset in the field.

### When trimming is not the answer

Don't trim if:

- The Smith marker is already **on** the centerline (you have a match problem,
  not a resonance problem)
- The element is fixed-length (a commercial antenna, a PCB trace antenna)
- Resonance is off by more than about 15% — something else is wrong (wrong
  antenna, missing ground plane, wrong band segment, broken element)

---

## 5.3 The ground plane — the most common cause of a mysteriously wrong vertical

A quarter-wave vertical is only half an antenna. The ground plane is the other
half, and its condition determines both resonance and feedpoint resistance.

| Ground plane condition | Effect on feedpoint R | Typical value |
|---|---|---|
| Perfect infinite ground plane | Theoretical | ~36 Ω |
| 4 radials sloped 45° down | Raises R | ~50 Ω (this is why the classic ground-plane antenna works) |
| 4 radials horizontal | Near theoretical | ~36 Ω |
| Vehicle roof (good) | Near theoretical | ~35–40 Ω |
| Vehicle trunk lip / fender mount | Asymmetric, poor | 20–60 Ω, unpredictable |
| Small disc / no radials | Poor | Highly variable, often high R and reactive |
| Mag-mount on a bench | Meaningless | Anything |

**Practical implication:** if a vertical reads badly and trimming isn't fixing
it, the ground plane is the first suspect. Try:

- Adding radials (4 is the practical minimum; 8 is noticeably better; beyond 16
  gives diminishing returns for an elevated ground plane)
- **Sloping the radials downward** — this raises feedpoint resistance toward
  50 Ω and is often the entire fix
- Improving bonding to the vehicle body

---

## 5.4 Fixing the match: impedance transformation

Once the antenna is resonant (X ≈ 0) but R ≠ 50 Ω.

### First: cancelling reactance is not the same as matching

This trips people up constantly, so work it through once.

Suppose the NanoVNA reads **25 − j25 Ω** at 14.2 MHz. The obvious move is to
cancel that −j25 with a series inductor:

```
ω = 2π × 14.2e6 = 8.922e7 rad/s
L = 25 / 8.922e7 = 280 nH
```

Add it and the load becomes **25 + j0 Ω**. Reactance is gone. The Smith marker
is sitting exactly on the centerline. And the SWR is still **2:1**, because
25 Ω is not 50 Ω.

**Resonating an impedance and matching an impedance are two different
operations.** The Smith chart's job is to keep them separate in your head:
vertical position is reactance, horizontal position is resistance, and you need
both to reach the centre.

### The same example, matched properly

Use the L-network formula on that 25 Ω:

```
Q        = √(50/25 − 1) = 1
X_series = 1 × 25 = 25 Ω    → series L at the load side  = 280 nH
X_shunt  = 50 / 1  = 50 Ω    → shunt C at the input side  = 224 pF
```

Verify by admittance, which is how the Smith chart actually moves:

```
1 / (25 + j25) = (25 − j25)/1250 = 0.0200 − j0.0200 S
shunt C adds                     = +j0.0200 S
                          total  = 0.0200 + j0      S  =  50 Ω  ✓
```

Note what happened: the load's **own** −j25 got absorbed as part of the series
arm rather than being cancelled separately. One network did both jobs. That is
the normal case — design the L-network against the impedance you actually
measured, not against a pre-resonated version of it.

### Option A — L-network (most flexible)

Two reactive components. Handles both R transformation *and* residual reactance.

**Topology rule:** the **shunt** element goes on the side with the **higher**
resistance; the **series** element goes on the side with the **lower** resistance.

```
Q  = √( R_high / R_low − 1 )
X_series = Q × R_low
X_shunt  = R_high / Q

L = X / (2πf)
C = 1 / (2πf · X)
```

#### Worked example — matching a 20 Ω antenna to 50 Ω at 915 MHz

```
R_low = 20 Ω (antenna), R_high = 50 Ω (feedline)

Q = √(50/20 − 1) = √1.5 = 1.225

X_series = 1.225 × 20   = 24.5 Ω   → series element at the antenna side
X_shunt  = 50 / 1.225   = 40.8 Ω   → shunt element at the feedline side
```

Choose a lowpass configuration (series L, shunt C) — generally preferred because
it also attenuates harmonics:

```
L = 24.5 / (2π × 915e6) = 4.26 nH
C = 1 / (2π × 915e6 × 40.8) = 4.26 pF
```

So: **4.3 nH in series with the antenna, 4.3 pF shunt to ground on the feedline
side.**

#### Worked example — matching a 110 Ω antenna to 50 Ω at 146 MHz

```
R_low = 50 (feedline), R_high = 110 (antenna)

Q = √(110/50 − 1) = √1.2 = 1.095
X_series = 1.095 × 50  = 54.8 Ω   → series, on the feedline side
X_shunt  = 110 / 1.095 = 100.4 Ω  → shunt, on the antenna side

L = 54.8/(2π × 146e6)      = 59.7 nH
C = 1/(2π × 146e6 × 100.4) = 10.9 pF
```

#### Tuning the network on the VNA

1. Build the network with the calculated values (or with trimmers/variable caps).
2. Put a marker at your target frequency on the **Smith chart**.
3. Adjust the **series** element — the marker moves along a **constant-resistance
   circle**.
4. Adjust the **shunt** element — the marker moves along a **constant-conductance
   circle**.
5. Alternate between the two, walking the marker toward the center dot.

With trimmer caps and a slug-tuned inductor this takes about two minutes once
you've got a feel for which direction each control moves the marker. **This is
what the Smith chart is for.**

### Option B — Quarter-wave transformer

A quarter-wavelength of transmission line with a specific characteristic
impedance transforms one resistance to another:

```
Z_transformer = √( Z_source × Z_load )
```

**Example:** matching a 25 Ω antenna to 50 Ω:
```
Z = √(50 × 25) = 35.4 Ω
```
Two 75 Ω coax lines in parallel = 37.5 Ω — close enough in practice.

Length of the quarter-wave section:
```
L (m) = (75 × VF) / f(MHz)
```

At 146 MHz with RG-59 (VF 0.66): L = (75 × 0.66)/146 = **0.339 m**.

**Use the NanoVNA to verify the section:** sweep it open-ended and confirm the
first quarter-wave resonance falls at your target frequency, then trim.

Narrowband by nature — good for single-frequency applications, not for wide
coverage.

### Option C — Matching stub

A short length of open or shorted transmission line, connected in shunt at a
calculated distance from the load, cancels the reactance and transforms R.

Classic technique, genuinely useful at VHF/UHF where the stubs are physically
small. The NanoVNA makes this practical because you can measure the stub's
behavior directly rather than relying on calculation.

### Option D — Gamma, hairpin, delta, and beta matches

Mechanical matching arrangements used on Yagis and driven elements:

- **Gamma match** — a shunt rod alongside the driven element with a series
  capacitor. Adjust rod length and capacitance while watching the Smith chart.
  Two degrees of freedom, so it's exactly an L-network in mechanical form.
- **Hairpin / beta match** — a shunt inductor across a deliberately capacitive
  (slightly short) driven element. Adjust hairpin length.
- **Delta match** — tapped connection across the element.

All four are tuned the same way: put a marker at the target frequency on the
Smith chart, adjust one control, observe which way the marker moves, iterate.

### Option E — Transformers (baluns / ununs)

- **4:1 balun** — 200 Ω → 50 Ω, or 12.5 Ω → 50 Ω. Folded dipoles, some loops.
- **9:1 unun** — 450 Ω → 50 Ω. Random wire / end-fed antennas.
- **49:1 unun** — 2450 Ω → 50 Ω. End-fed half-wave antennas.
- **1:1 current balun** — no impedance transformation; provides common-mode
  choking and balanced feed for dipoles.

**Test any transformer on the NanoVNA** by terminating the secondary with a
resistor of the design value and sweeping the primary. A good 49:1 unun
terminated in 2.4 kΩ should show near-50 Ω across its rated range. This is a
great way to check whether a purchased transformer is actually doing what it
claims.

---

## 5.5 Common-mode chokes

A common-mode choke stops RF current flowing on the *outside* of the coax shield.
It is not an impedance match; it's a separate fix for a separate problem.

**Build options:**

| Type | Typical use |
|---|---|
| Coiled coax ("ugly balun"), 5–8 turns, 10–15 cm diameter | HF, cheap, effective over ~1 octave |
| Coax wound on a ferrite toroid (type 31 for HF, type 43 for VHF) | HF/VHF, compact, broadband |
| Snap-on ferrite clamps, 5–10 of them, at the feedpoint | Quick field fix, VHF/UHF |
| Commercial 1:1 current balun | Permanent installations |

**Testing a choke on the NanoVNA:** measure its common-mode impedance by
connecting the choke's shield path across CH0 and CH1 and sweeping S21. A good
choke shows deep attenuation (high common-mode impedance) across the band of
interest — you want at least several kΩ, which shows as strong S21 rejection.

**Always tune the antenna with the choke installed**, because installing the
choke changes the antenna's environment.

---

## 5.6 Wideband vs. narrowband: bandwidth is a design choice

If your antenna is resonant and matched but the **bandwidth is too narrow**:

| To increase bandwidth | Mechanism |
|---|---|
| Use fatter conductors (tubing instead of wire) | Lowers Q |
| Use a cage or multi-wire element | Effectively fatter conductor |
| Use a folded element | Broader response |
| Add deliberate resistive loading | Trades efficiency for bandwidth — a real trade, don't do it casually |
| Raise the antenna higher | Reduces ground interaction |

If the bandwidth is **too wide** and you're seeing low SWR everywhere, be
suspicious — as noted in [04](04-antenna-testing.md), that's usually loss, not
performance.

---

## 5.7 What an antenna tuner does and doesn't do

An antenna tuner (ATU / transmatch) sits **in the shack** and presents a 50 Ω
load to the transmitter. It does this by cancelling the reactance and
transforming the resistance it sees at the **shack end of the feedline**.

**What it fixes:** the transmitter's happiness. It stops the PA folding back.

**What it does not fix:** the actual mismatch at the antenna. Power still
reflects off the antenna, still travels back down the coax being attenuated,
still bounces off the tuner and goes back up. On a lossy line at UHF, a badly
mismatched antenna behind a tuner loses real power to feedline heating, and the
tuner cheerfully reports 1.0:1.

**Use a NanoVNA to decide whether you need a tuner or need to fix the antenna.**
Measure at the antenna. If the antenna itself is well matched, the tuner is
handling feedline effects and that's fine. If the antenna is 6:1 and the tuner is
making it look like 1.1:1, you're heating coax.

---

## 5.8 Tuning procedures by antenna type

### Dipole (wire, half-wave)

1. Hang it at final height with the final feedline route.
2. Install the choke/balun.
3. Sweep. Find resonance.
4. Trim both legs equally. Iterate.
5. Expect feedpoint R of 50–75 Ω depending on height. Below about 0.2λ high, R
   drops; above 0.5λ it settles near 70 Ω.

### Quarter-wave ground plane / vertical

1. Install radials first. Slope them downward ~45° to bring R toward 50 Ω.
2. Sweep. Trim the vertical element.
3. If R is stubbornly low, add or slope radials before reaching for a matching
   network.

### Mobile whip (HF, loaded)

1. Mount on the vehicle, in its final position, vehicle on the ground, doors
   closed.
2. These are high-Q — sweep a narrow span.
3. Adjust the whip tip length or the coil tap.
4. Expect low feedpoint R (5–25 Ω is common). A matching network or a coil tap
   adjustment is usually needed.
5. **Re-check on the vehicle in its real environment.** Bench readings are
   worthless for mobile antennas.

### Yagi

1. Tune the **driven element** only. Parasitic elements set the pattern and
   gain — don't touch them unless you're redesigning.
2. Use the gamma/hairpin match to bring the feedpoint to 50 Ω.
3. Sweep, adjust, iterate.
4. Do final tuning at operating height if possible; ground proximity detunes.

### PCB / chip antennas (LoRa, BLE, sub-GHz modules)

1. These are exquisitely sensitive to the ground plane, the enclosure, and nearby
   components. Measure the assembled product, not the bare board.
2. Most designs include a **pi-network footprint** (series + two shunt pads) near
   the antenna feed for exactly this purpose.
3. Solder a wire pigtail to the feed point carefully, or use a proper U.FL test
   point.
4. Populate the pi-network based on the Smith chart reading using the L-network
   math in §5.4.
5. Re-measure in the final enclosure. Plastic enclosures shift resonance
   downward — often by several percent.

### Magnetic loop

1. Extremely high Q — SWR bandwidth may be only a few kHz.
2. Use a very narrow sweep span, and use the **H4 at 401 points** or
   NanoVNA-Saver segmented sweeps. A 101-point sweep will simply miss it.
3. Tune with the variable capacitor while watching a tracking marker.
4. Adjust the coupling loop size/position to set the match depth.

### Random wire / end-fed

1. Expect very high, frequency-dependent impedance.
2. Match with a 9:1 or 49:1 unun and a good counterpoise.
3. Sweep with the unun installed — measuring the bare wire tells you little.
4. Verify the unun independently (see §5.4 Option E).

---

## 5.9 The tuning loop, condensed

```
┌─────────────────────────────────────────────┐
│ 1. Calibrate on target span                 │
│ 2. Sweep in the real installed environment  │
│ 3. Marker → SEARCH → MINIMUM + TRACKING     │
│ 4. Read Smith impedance at TARGET frequency │
│                                             │
│    Off centerline? → adjust LENGTH          │
│      above = too long, shorten              │
│      below = too short, lengthen            │
│                                             │
│    On centerline, wrong R? → MATCH it       │
│      L-network / transformer / stub         │
│                                             │
│ 5. Change ONE thing. Re-sweep.              │
│ 6. Repeat until inside tolerance.           │
│ 7. Save the final sweep as baseline.        │
└─────────────────────────────────────────────┘
```

**Change one variable at a time.** The temptation to adjust length and matching
simultaneously will cost you an hour.

---

[← Antenna testing](04-antenna-testing.md) | [Next: Cables, filters & other uses →](06-cables-filters-other-uses.md)
