# 03 — Calibration

[← Back to index](README.md)

---

## 3.1 Why calibration is not optional

An uncalibrated NanoVNA is a random number generator with a nice screen.

The raw measurement is corrupted by:

- **Directivity error** — the internal bridge leaks some forward signal into the
  reflection receiver
- **Source match error** — the source isn't exactly 50 Ω
- **Frequency response / tracking error** — the mixers and filters aren't flat
- **Cable and adapter effects** — every centimeter of coax adds phase rotation and
  loss

Calibration measures these errors using known standards and mathematically
removes them. The result is that the instrument reports what's happening **at the
calibration plane** — the exact physical point where you attached the standards.

That last point is the one people miss, and it's the most important idea in this
document.

---

## 3.2 The calibration plane

> **Whatever you attach the calibration standards to becomes the zero point of
> your measurement.**

```
   [VNA] ── adapter ── 1m test cable ── [STANDARDS GO HERE]
                                              ↑
                                     calibration plane
```

If you calibrate at the VNA's front-panel connector and then attach a 1 m cable
and an antenna, you are measuring **the cable plus the antenna** as a single
system. The phase rotation of that cable will spin your Smith chart trace and
completely change how you interpret it.

If instead you calibrate **at the far end of that cable**, you're measuring the
antenna alone, and the Smith chart reads true.

**Rule: calibrate at the point where you want the truth.**

For antenna work at the antenna's connector: calibrate with the standards screwed
into the end of the exact cable and adapters you will use.

For antenna work through an installed feedline you can't reach: calibrate at the
shack end, and understand you're measuring the whole system. See §3.8.

### Why the plane changes the answer, with numbers

A lossless line transforms impedance but preserves reflection *magnitude* — the
Smith point rotates, the SWR stays put. A **real, lossy** line also attenuates
the reflected wave on its way back, so the mismatch looks smaller than it is.

Worked example. Suppose the antenna itself is genuinely 3:1, on a feedline with
3 dB of one-way loss:

```
Antenna SWR 3:1                    →  |Γ| at the antenna = 0.500
Reflected wave crosses the cable twice → 6 dB round-trip attenuation
Amplitude factor = 10^(−6/20)      =  0.501
|Γ| seen at the radio end          =  0.500 × 0.501 = 0.251
SWR displayed at the radio end     = (1+0.251)/(1−0.251) = 1.67:1
```

**The feedline did not improve the antenna.** It hid more than half the
mismatch by converting it to heat in the coax. A tech who measures 1.67:1 at the
shack and declares the antenna healthy has been fooled by a bad cable — and the
worse the cable gets, the better the antenna looks.

This is the single most important reason to know which plane you are measuring
at, and it is why an old installation showing a suspiciously flat, low SWR
deserves a feedline loss check before congratulations.

### For a balanced antenna, the balun is part of the antenna

When you "calibrate at the feedpoint" of a dipole, keep its intended
current balun or choke on the antenna side of the plane unless you are
deliberately characterizing the balun by itself. Clipping an unbalanced
adapter straight across balanced wires creates a current path that does not
exist in the real installation, and you will measure something that is not
your antenna.

---

## 3.3 The standards

| Standard | What it is | Where it lands on the Smith chart |
|---|---|---|
| **OPEN** | An unterminated connector (often literally nothing, or a cap) | Far **right** |
| **SHORT** | Center pin bonded to shell | Far **left** |
| **LOAD** | A precision 50 Ω termination | Dead **center** |
| **ISOLN** | Isolation: nothing connected to CH1 (or a load on it) | — |
| **THRU** | CH0 connected directly to CH1 | — |

For **S11-only work (antennas), you need only OPEN, SHORT, and LOAD.** ISOLN and
THRU only correct the transmission path.

### About the bundled standards

The plastic-bodied SOLT kit that ships with these units is adequate below about
500 MHz and increasingly approximate above that. Its OPEN has undefined fringing
capacitance and its LOAD is typically a 1% chip resistor with parasitic
inductance.

If you need real accuracy at UHF, buy a metal-bodied cal kit with published
offset delay and capacitance coefficients. For antenna tuning at HF/VHF, the
bundled kit is fine.

**The LOAD is the standard that matters most.** If you replace only one item,
replace the load.

---

## 3.4 Standard S11 calibration procedure

Follow this exactly. Order matters less than completeness, but this order matches
the menu flow.

### Step 1 — Set the sweep range FIRST

```
STIMULUS → START → [enter start frequency]
STIMULUS → STOP  → [enter stop frequency]
```

Or use CENTER and SPAN.

> **A calibration is valid only across the span it was taken on.** Change START
> or STOP after calibrating and the correction is interpolated at best,
> meaningless at worst. Some firmware will flag this with a `C*` (interpolated)
> indicator.

**Set a span with headroom but not excess.** For a 2 m antenna targeting 146 MHz,
sweep 130–160 MHz, not 1 MHz–1.5 GHz. Tighter span = better resolution per point
= better calibration accuracy.

### Step 2 — Attach your test cable and adapters

Whatever you'll measure through, attach it now. The far end of it is your
calibration plane.

### Step 3 — Reset any old calibration

```
CAL → RESET
```

The calibration indicator should disappear.

### Step 4 — Run the standards

```
CAL → CALIBRATE
```

Then, attaching each standard to the calibration plane in turn and pressing the
corresponding menu item after it's seated:

1. Screw on **OPEN** → tap `OPEN` → wait for the sweep to complete
2. Remove, screw on **SHORT** → tap `SHORT` → wait
3. Remove, screw on **LOAD** → tap `LOAD` → wait
4. *(S21 work only)* Leave LOAD on CH0, put a load on CH1 → tap `ISOLN`
5. *(S21 work only)* Connect CH0 directly to CH1 with your through cable →
   tap `THRU`
6. Tap **`DONE`**

**Wait for each sweep to finish before removing the standard.** On a 401-point
H4 sweep this takes a couple of seconds. Pulling the standard mid-sweep corrupts
that calibration step silently.

### Step 5 — Save it

```
CAL → SAVE → [slot 0–4 on H, 0–6 on H4]
```

**If you don't save, it's gone on power-off.** Slot 0 is loaded automatically at
boot.

### Step 5a — Adding transmission calibration (S21 work only)

For filters and through measurements, keep **both** test leads in their final
measurement positions, finish the reflection steps at the CH0-side DUT plane,
then:

- **ISOLN** — terminate both DUT-plane cable ends in 50 Ω and capture isolation.
- **THRU** — join the two DUT-plane ends with your through connection and
  capture. Verify the through path then reads near 0 dB.

Two cautions that cost people a lot of time:

1. **Your through connector becomes the assumed "zero-length" standard.** A
   non-trivial adapter introduces residual phase and delay error that the
   calibration will silently attribute to the device under test. Precision
   fixture work needs known standard definitions or proper de-embedding.
2. **If you have only one 50 Ω load, published instructions disagree about how
   to do isolation.** Do not improvise. Either buy a second load, or follow your
   specific firmware's documented method, or skip isolation correction and stop
   claiming deep rejection figures. Isolation correction also becomes unstable
   near the noise floor, where it can do more harm than good.

### Step 6 — Verify

Put the LOAD back on. You should see:

- **SWR:** flat, ≤ 1.02:1 across the whole span
- **LOGMAG:** better than −35 dB across the span
- **Smith:** a tight dot at the center

Then put the OPEN back on:

- **Smith:** a dot pinned at the far right
- **SWR:** off the top of the scale

If the LOAD doesn't sit at center, something is wrong. Do not proceed. Check
connector seating, check that you didn't swap OPEN and SHORT, check for a bad
cable.

---

## 3.5 Calibration slot strategy

Slots are precious. Here's a layout that covers most real work:

### NanoVNA-H (5 slots)

| Slot | Span | Purpose |
|---|---|---|
| **0** | 1 MHz – 1500 MHz | Boot default, general survey, "what is this thing" |
| 1 | 1 – 55 MHz | HF |
| 2 | 130 – 180 MHz | VHF / 2 m / MURS / marine / airband edge |
| 3 | 400 – 480 MHz | UHF / 70 cm / GMRS / 433 ISM |
| 4 | 860 – 960 MHz | 868/915 ISM, LoRa, cellular LTE low band |

### NanoVNA-H4 (7 slots)

Same as above, plus:

| Slot | Span | Purpose |
|---|---|---|
| 5 | 1000 – 1300 MHz | ADS-B (1090), 23 cm |
| 6 | *scratch* | Whatever the current job needs |

Keep slot 6 (or 4 on the H) as a scratch slot you overwrite freely, so you're
never tempted to overwrite a good standing calibration mid-job.

> Saving a slot saves the **sweep range and display setup** along with the
> correction data. Recalling a slot restores everything. This makes slots
> function as complete "measurement presets."

---

## 3.6 Electrical delay / port extension

Sometimes you can't put standards at the point you care about — for example,
measuring an antenna at the top of a mast through a fixed feedline.

**Electrical delay** mathematically rotates the phase to shift the reference
plane down the line:

```
DISPLAY → SCALE → ELECTRICAL DELAY → [enter a value in ps or ns]
```

### How to use it

1. Calibrate at the VNA end.
2. Connect the cable, leave the far end **open** (or shorted).
3. Adjust ELECTRICAL DELAY until the Smith chart trace collapses to a **single
   stationary dot** at the far right (for open) or far left (for short) instead
   of spinning around the outer circle.
4. That delay value now represents the cable's electrical length. Leave it set.
5. Connect the antenna. The Smith chart now reads as if measured at the antenna.

**The shortcut:** with a marker on the trace,
`MARKER → OPERATIONS → →EDELAY` will auto-set the delay based on the marker.

### The limitation

Electrical delay corrects the **phase** but not the **loss** of the cable. A long
lossy run will still make the antenna look better-matched than it really is,
because the reflected signal is attenuated on the way back. Delay compensation
fixes the Smith chart geometry; it does not fix the magnitude.

For a true reading through a lossy line you need either (a) to physically measure
at the antenna, or (b) to measure the cable's one-way loss separately and add
2× that loss back to the return loss figure.

---

## 3.7 Drift and when to re-calibrate

Re-calibrate when:

- **You change the sweep span.** Non-negotiable.
- **You change any cable or adapter** in the path.
- **The ambient temperature changes significantly** — going from a warm truck to
  a cold rooftop will shift things, especially above 500 MHz.
- **The unit was just powered on from cold.** Let it warm 3–5 minutes.
- **You switched between USB power and battery.**
- **More than an hour or two has passed** in a precision session.
- **Anything looks weird.** Re-calibrating is 90 seconds. Chasing a phantom
  antenna fault for an hour is not.

A quick sanity check without a full re-cal: screw the LOAD back on. If it still
reads better than −35 dB and sits centered, your calibration is still good.

### Reading the calibration status indicator

On older firmware the letters at the screen edge mean:

| Indicator | Meaning |
|---|---|
| **`C`** (uppercase) | A saved calibration is applied |
| **`c`** (lowercase) | Correction is being **interpolated** because the sweep range changed — the numbers are approximate |
| `D` `R` `S` `T` `X` | Which individual correction terms are active (directivity, reflection tracking, source match, transmission tracking, isolation) |

**A lowercase `c` is a warning, not a status.** It means you are no longer
measuring on the span you calibrated. For rough hunting that is tolerable; for
any decision you are going to cut metal over, re-calibrate.

An S11-only antenna calibration legitimately shows fewer terms than a full
two-port calibration — missing transmission and isolation terms there is
expected, not a fault.

### What calibration cannot fix

Calibration removes *systematic, repeatable* errors in the measurement path.
It does nothing about:

- the antenna physically moving, or your hand near it
- ambient interference and nearby transmitters
- nonlinear or active devices
- random noise
- **loss.** Calibrating through very lossy cable removes systematic effects only
  within whatever measurement sensitivity remains. It cannot recover a
  reflection the cable already dissipated.

Also beware of subtracting the same cable twice: if you calibrated at the far end
of a cable, do **not** then also dial in electrical delay for it.

---

## 3.8 Measuring through an installed feedline

You often can't reach the antenna. Three approaches, best to worst:

### Option A — Calibrate at the antenna (best)

Climb, disconnect, calibrate at the antenna connector using a short jumper, and
measure. Gives the truth about the antenna. Requires access.

### Option B — Half-wave multiple feedline (elegant)

A transmission line that is an **electrical half-wavelength (or any multiple)**
at the measurement frequency repeats the load impedance at its input, regardless
of the line's characteristic impedance.

```
Electrical half-wave length (meters) = (150 × VF) / f(MHz)
```

So if your feedline happens to be an exact multiple of a half-wave at your
operating frequency, the shack-end reading equals the antenna-end reading
(minus cable loss). Useful for building deliberate test jumpers.

At 146 MHz with RG-58 (VF 0.66): half-wave = (150 × 0.66)/146 = **0.678 m**.

### Option C — Electrical delay compensation (practical)

As in §3.6. Good enough for tuning decisions; remember the loss caveat.

### Option D — Measure at the shack and accept it (honest)

You're measuring the **whole system**: antenna, feedline, connectors, arrestor,
grounding. For a go/no-go health check — "did something change since last time?"
— this is actually the right measurement. Save a baseline sweep when the system
is known good, and compare against it later. A deviation from baseline is
actionable data even if the absolute numbers include the feedline.

**This is the single most valuable use of a NanoVNA in a service context:**
baseline every installed antenna system, store the S1P files, and compare on
every site visit.

---

## 3.9 Calibration mistakes that produce confident wrong answers

| Mistake | Symptom | Fix |
|---|---|---|
| Changed span after calibrating | `C*` indicator, subtly wrong impedances | Re-calibrate on the new span |
| Forgot to press DONE | No correction applied at all | Watch for the `C` indicator |
| Forgot to SAVE | Calibration vanishes on reboot | `CAL → SAVE → slot` |
| Calibrated at the VNA, measured through a cable | Smith trace spins, impedance readings nonsense | Calibrate at the cable's far end |
| Loose connector during cal | Erratic, non-repeatable results | Re-torque everything, re-cal |
| Swapped OPEN and SHORT | Smith chart mirrored; readings inverted | Verify with the LOAD check |
| Cheap or damaged LOAD | Noise floor limited to ~−25 dB | Better load |
| Cal on battery, measure on USB | Small systematic shift | Keep the power source consistent |
| Cold instrument | Slow drift over the first minutes | Warm up before calibrating |
| RP-SMA adapter mixed in | Wildly wrong or no signal | Check every adapter's gender |
| Standards not fully seated | Everything slightly off, especially above 500 MHz | Consistent torque, every time |

---

## 3.10 Fast calibration routine (memorize this)

```
1. STIMULUS → set START / STOP
2. Attach test cable + adapters
3. CAL → RESET
4. CAL → CALIBRATE
5. OPEN  → tap OPEN  → wait
6. SHORT → tap SHORT → wait
7. LOAD  → tap LOAD  → wait
8. DONE
9. CAL → SAVE → slot n
10. Re-attach LOAD, verify −35 dB or better
```

Ninety seconds once it's muscle memory.

---

[← RF fundamentals](02-rf-fundamentals.md) | [Next: Antenna testing →](04-antenna-testing.md)
