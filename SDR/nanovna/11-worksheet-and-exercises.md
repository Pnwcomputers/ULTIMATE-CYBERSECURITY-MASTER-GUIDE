# 11 — Field Worksheet and Practice Exercises

[← Back to index](README.md)

Two things here: a **worksheet** to copy for every job, and a set of
**exercises** that teach the instrument using known loads rather than guesswork
on an antenna.

Work the exercises before the first customer job. Each one takes minutes and
each one inoculates you against a specific mistake that is otherwise expensive
to learn in the field.

---

## Part 1 — Measurement worksheet

Copy this section for each test. The metadata block is not bureaucracy: a sweep
without its calibration plane, cable set and antenna geometry recorded is not
comparable to anything, which means it cannot serve as a baseline, which was
most of the point of taking it.

### Identity

| Field | Entry |
|---|---|
| Date / time / timezone | |
| Operator | |
| Site / customer | |
| Job or ticket reference | |
| Analyzer model (H / H4) | |
| Hardware revision (`CONFIG → VERSION`) | |
| Firmware version | |
| Antenna / DUT make, model or design | |
| Intended frequency range | |
| System reference impedance | 50 Ω / 75 Ω / other |
| Goal / acceptance requirement | |

### Setup and calibration

| Field | Entry |
|---|---|
| **Reference plane — exact connector and location** | |
| Feedpoint test, or complete-system test? | |
| Test leads and adapters in the path | |
| Calibration standards used / identifying marks | |
| Calibration slot number and date | |
| Sweep start / stop / points | |
| Averaging or bandwidth settings, if available | |
| Electrical delay / transform settings | |
| **Known-load verification result** (dB) | target: better than −35 dB |
| Correction indicator present? (`C`, not `c`) | |
| Mounting height and orientation | |
| Radials / counterpoise / ground plane | |
| Balun or choke, and its location | |
| Coax type, length, velocity factor | |
| Nearby objects / vehicle state / enclosure state | |
| Battery-only or USB-connected? | |

### Baseline and final readings

| Measurement | Baseline | Final |
|---|---|---|
| SWR at low required edge | | |
| SWR at target | | |
| SWR at high required edge | | |
| Minimum SWR, and its frequency | | |
| S11 LOGMAG at target (dB) | | |
| R + jX at target | | |
| Zero-reactance frequency near target | | |
| Chosen SWR threshold | | |
| Lower threshold crossing | | |
| Upper threshold crossing | | |
| **Matching bandwidth** | | |
| Complete-system SWR at radio connection | | |
| Repeatability check (stable / shifts) | | |

### Checks

| Check | Result |
|---|---|
| Common-mode hand test | stable / shifts |
| Choke installed? | yes / no |
| TDR distance to far end (m) | measured: ______ expected: ______ |
| Feedline one-way loss (dB @ ____ MHz) | measured: ______ spec: ______ |
| Known load rechecked after testing | |

### Adjustment log

One row per change. **One change per row** — that is the whole discipline.

| Step | Single change made | Physical dimension / value | Resonance | SWR at target | R + jX at target | Notes |
|---|---|---|---|---|---|---|
| 0 | Baseline | | | | | |
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |
| 5 | Final secured assembly | | | | | |

### Files archived

- Baseline `.s1p`:
- Baseline screenshot:
- Final `.s1p`:
- Final screenshot:
- Additional band sweeps:
- TDR trace:
- Compared against baseline file:
- `s1pdiff` verdict:

### Conclusion

- Meets stated matching requirement? **yes / no / partially**
- Remaining faults or uncertainty:
- Properties **not** measured (gain, efficiency, pattern, power handling):
- Recommended follow-up:

---

## Part 2 — Stop and diagnose before trimming if…

A short list worth reading before every adjustment session. Any one of these
means the measurement is not yet trustworthy, and trimming against an
untrustworthy measurement wastes metal and time.

- The calibration load does not read correctly.
- The trace jumps when a connector is flexed.
- You cannot confidently identify which feature is the intended resonance.
- The result depends strongly on hand or cable position.
- You are measuring through unknown or highly lossy coax.
- A complex antenna has no documented adjustment method and you are guessing.
- The reading is not repeatable across consecutive sweeps.

**A good final result is repeatable, taken at a known plane, and useful across
the whole intended range.** A reproducible 1.4:1 across the band you actually
use beats a momentary 1.01:1 that only happens when you hold the coax a
particular way.

---

## Part 3 — Practice exercises

All exercises use passive, unpowered devices. Do them in order.

### Exercise 1 — The known standards

**Do:** Calibrate. Then measure the 50 Ω load, the open, and the short in turn,
looking at both SWR and the Smith chart.

**Expect:** Load at the centre, near 1:1. Open at the far right, high SWR. Short
at the far left, high SWR.

**The lesson:** *Reflection magnitude alone does not identify an impedance.* Open
and short both reflect essentially everything and read almost identical SWR, yet
they are opposite impedances. Phase is what distinguishes them — and phase is
what your SWR meter was throwing away.

---

### Exercise 2 — Resonance is not matching

**Do:** Measure a non-inductive 100 Ω RF resistor in a compact fixture, at a
frequency low enough that fixture parasitics are small.

**Expect:** Reactance near zero. SWR near **2:1**.

**The lesson:** A perfectly resistive, perfectly "resonant" load can still be
badly mismatched. Resistance and reactance are independent problems.
See [05 §5.4](05-antenna-tuning.md#54-fixing-the-match-impedance-transformation).

---

### Exercise 3 — Which way does length move resonance?

**Do:** Measure a telescoping whip on a fixed counterpoise. Record the
fundamental resonance. Extend it by a known amount. Re-measure with everything
else untouched.

**Expect:** Resonance moves **down** as the whip gets longer.

**The lesson:** Builds the reflex you need for every tuning job, and — more
importantly — shows you the *magnitude* of the effect on your own hardware, so
your first real trim is an informed guess rather than a wild one.

---

### Exercise 4 — The reference plane is real

**Do:**
1. Calibrate at the VNA connector. Measure a stable mismatched load (a 100 Ω
   resistor, or an antenna) directly. Record the Smith point and SWR.
2. Without recalibrating, insert a known low-loss cable and measure the same load
   through it. Record again.
3. Now recalibrate at the **far end** of that cable and measure the load a third
   time.

**Expect:** Step 2 shows a dramatically rotated Smith point with roughly
unchanged SWR. Step 3 returns the Smith point close to where step 1 had it.

**The lesson:** The cable transformed the *displayed impedance* without changing
the mismatch much. Calibrating at the load plane removes that transformation.
This is the single most common source of "my impedance readings make no sense."

---

### Exercise 5 — How attenuation fakes a good match

**Do:** Measure a mismatched load directly. Then insert a known matched
attenuator (6 or 10 dB) ahead of it, keeping the original input-plane
calibration, and measure again.

**Expect:** The measured SWR improves markedly. A 10 dB pad in front of a 3:1
load will read close to 1.1:1.

**The lesson:** **A better-looking SWR does not mean more useful power reaches
the load.** This is exactly what a long, lossy, degraded feedline does to your
measurements — and why the flattest antenna on an old installation is often the
one with the worst coax. Pair this with the arithmetic in
[03 §3.2](03-calibration.md#why-the-plane-changes-the-answer-with-numbers).

---

### Exercise 6 — Find the resolution limit yourself

**Do:** Take any antenna with a reasonably sharp resonance. Sweep it at the
widest span your unit offers and find the dip. Then narrow the span in stages,
recalibrating each time, and watch the dip.

**Expect:** At wide spans the dip is shallow, ragged, or invisible. As the span
narrows, its true depth and shape emerge.

**The lesson:** `Resolution = Span / (Points − 1)`. A feature narrower than one
point spacing will be missed entirely, and no amount of marker interpolation
recovers data that was never sampled. Now you know where that boundary sits on
*your* instrument.

---

### Exercise 7 — Verify the TDR distance scale

**Do:** Take a coax of accurately known length. Leave the far end open, set up
TDR per [06 §6.1](06-cables-filters-other-uses.md#61-tdr--time-domain-reflectometry),
enter the correct velocity factor, and read the distance to the end.

**Expect:** The reported distance matches the physical length.

**If it doesn't:** You have learned which convention your firmware wants —
`0.66` versus `66` — or whether it reports one-way distance or round-trip time,
before a customer's fault depended on it. Also try the far end shorted and note
the polarity difference.

**The lesson:** Calibrate your understanding of the tool against a known answer
*before* using it to find an unknown one.

---

### Exercise 8 — Build your first baseline pair

**Do:** Pick any antenna. Sweep it, export `.s1p`, and archive it with full
worksheet metadata. Change something small and reversible — move the coax, add a
ferrite, tilt a radial. Sweep and export again. Then:

```bash
python3 tools/s1pdiff.py diff baseline.s1p modified.s1p --at <your target MHz>
```

**Expect:** The tool quantifies a change you made deliberately and know the size
of.

**The lesson:** This is the entire service workflow in miniature — baseline,
change, compare, evidence. Do it once on a change you control, so you trust the
output when the change is a customer's mystery fault.
See [tools/README.md](tools/README.md).

---

[← Antenna types & special cases](10-antenna-types-and-special-cases.md) |
[Next: Sources & scope →](12-sources-and-scope.md)
