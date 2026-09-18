# 02 — RF Fundamentals: What Every Display Format Means

[← Back to index](README.md)

---

## 2.1 The core idea: reflection

Send a signal down a 50 Ω transmission line into a load. If the load is exactly
50 Ω resistive, **all** the energy is absorbed and nothing comes back. If the
load is anything else — 25 Ω, 100 Ω, an open, a short, or something reactive —
part of the wave is **reflected** back toward the source.

The **reflection coefficient**, Γ (gamma), describes that returning wave as a
complex number:

```
Γ = (Z_load − Z_0) / (Z_load + Z_0)        where Z_0 = 50 Ω
```

Γ has a **magnitude** (how much comes back, 0 to 1) and a **phase** (the timing
relationship, which encodes whether the mismatch is inductive, capacitive, too
high, or too low).

Every reflection-side format on the NanoVNA — SWR, LOGMAG, Smith chart, phase,
resistance, reactance — is just a different way of drawing that same complex Γ.
They are not separate measurements. They are the same number in different
clothes.

---

## 2.1a What a reflection sweep does and does not answer

Before any of the display formats mean anything, be clear about the scope of the
measurement. An antenna has several independent properties, and one S11 sweep
addresses only some of them:

| Property | The question | Does an S11 sweep answer it? |
|---|---|---|
| **Input match** | How close is the presented load to 50 Ω? | **Yes** — at the calibration plane |
| **Resonance** | Where is input reactance ≈ zero? | **Yes** — at that plane; feedline can transform it |
| **Matching bandwidth** | Over what range does SWR meet the limit? | **Yes** |
| **Radiation efficiency** | How much accepted power becomes radiation? | **No** |
| **Gain and pattern** | Where does the energy go, how concentrated? | **No** |
| **Power handling** | Will it heat or arc at operating power? | **No** |
| **Receive performance** | Does it improve useful signal-to-noise? | **No** — needs separate receiving tests |

Everything in the right-hand column that says **No** is a property people
routinely try to infer from an SWR number, and cannot. A 50 Ω dummy load shows
a near-perfect match and radiates nothing. Conversely, an antenna with an
imperfect match can be an excellent receiving antenna.

Keep this table in mind when reporting results to a customer. "SWR is 1.2:1" is
a true and useful statement about the input match. It is not a statement that
the antenna works.

---

## 2.2 S-parameters

**S11** — reflection at port 1. Measured on **CH0**. "How much of what I sent
into this thing came back at me?"

**S21** — transmission from port 1 to port 2. Measured **CH0 → CH1**. "How much
of what I sent in at one end arrived at the other end?"

The NanoVNA measures only S11 and S21. It does not measure S22 or S12 — to get
those, physically reverse the device under test and sweep again.

| Parameter | Use it for |
|---|---|
| **S11** | Antennas, antenna systems, cable faults, filter input match, any one-port device |
| **S21** | Filters, duplexers, attenuators, cable loss, amplifier gain, coupling between two antennas, shielding effectiveness |

---

## 2.3 LOGMAG — return loss and insertion loss

**LOGMAG** displays magnitude in dB.

### On CH0 (S11), LOGMAG is the reflection magnitude in dB

Two quantities get muddled constantly, including in a lot of published material.
They are not the same thing and they have opposite signs:

```
S11 LOGMAG (dB) = 20 · log₁₀(|Γ|)      ← what the screen shows. NEGATIVE.
Return loss (dB) = −20 · log₁₀(|Γ|)     ← the conventional figure. POSITIVE.

S11 LOGMAG = −(return loss)
```

**On the NanoVNA's LOGMAG trace, more negative is better.** Return loss quoted
as a positive number is the same information with the sign flipped, and there
*larger* is better. Say "−20 dB S11" or "20 dB return loss" — never "−20 dB
return loss", which is the sign convention of neither.

| Screen (S11 LOGMAG) | As return loss | Meaning |
|---|---|---|
| −30 dB | 30 dB | Essentially nothing reflected. Excellent. |
| −20 dB | 20 dB | 1% of power reflected. Very good. |
| −14 dB | 14 dB | 4% reflected. VSWR 1.5:1. Good. |
| −9.5 dB | 9.5 dB | 11% reflected. VSWR 2:1. Fine for most transmitters. |
| −6 dB | 6 dB | 25% reflected. VSWR 3:1. Poor. |
| 0 dB | 0 dB | Everything reflected. Open, short, or nothing connected. |

**This matters operationally, not just pedantically.** `MARKER → SEARCH →
MINIMUM` finds the best match on an **SWR or LOGMAG** trace. If your firmware or
PC software plots *positive* return loss instead, the best match is a
**MAXIMUM** and a minimum-search will walk to the worst point in the sweep.
Check which convention your display is using before trusting a search result.

LOGMAG is the **more sensitive** display for tuning. On an SWR trace, the
difference between 1.1:1 and 1.3:1 is visually tiny. On LOGMAG it is −26 dB
versus −18 dB — 8 dB of clearly visible movement. **Tune on LOGMAG, report on
SWR.**

### On CH1 (S21), LOGMAG = insertion loss / gain

- **0 dB** → perfect pass-through
- **−3 dB** → half the power lost (this is the classic filter "corner")
- **−60 dB** → deep stopband rejection
- **positive dB** → gain (an amplifier — but see the power warning in
  [06](06-cables-filters-other-uses.md) before you connect one)

---

## 2.4 SWR / VSWR

**Voltage Standing Wave Ratio** is the ratio of maximum to minimum voltage along
the transmission line caused by the interference of forward and reflected waves.

```
VSWR = (1 + |Γ|) / (1 − |Γ|)
```

It runs from 1.0:1 (perfect) to infinity (total reflection). It's the traditional
number because it's what analog cross-needle meters read, and it's what
transmitter specs are written against.

### Conversion table — print this

| VSWR | S11 LOGMAG (screen) | Return loss | \|Γ\| | Power reflected | Mismatch loss |
|---|---|---|---|---|---|
| 1.00:1 | −∞ | ∞ | 0.000 | 0.0% | 0.00 dB |
| 1.05:1 | −32.3 dB | 32.3 dB | 0.024 | 0.06% | 0.00 dB |
| 1.10:1 | −26.4 dB | 26.4 dB | 0.048 | 0.23% | 0.01 dB |
| 1.20:1 | −20.8 dB | 20.8 dB | 0.091 | 0.83% | 0.04 dB |
| 1.30:1 | −17.7 dB | 17.7 dB | 0.130 | 1.7% | 0.07 dB |
| 1.50:1 | −14.0 dB | 14.0 dB | 0.200 | 4.0% | 0.18 dB |
| 1.70:1 | −11.7 dB | 11.7 dB | 0.259 | 6.7% | 0.30 dB |
| 2.00:1 | −9.54 dB | 9.54 dB | 0.333 | 11.1% | 0.51 dB |
| 2.50:1 | −7.36 dB | 7.36 dB | 0.429 | 18.4% | 0.88 dB |
| 3.00:1 | −6.02 dB | 6.02 dB | 0.500 | 25.0% | 1.25 dB |
| 4.00:1 | −4.44 dB | 4.44 dB | 0.600 | 36.0% | 1.94 dB |
| 5.00:1 | −3.52 dB | 3.52 dB | 0.667 | 44.4% | 2.55 dB |
| 10.0:1 | −1.74 dB | 1.74 dB | 0.818 | 66.9% | 4.81 dB |

Mismatch loss is `−10 · log₁₀(1 − |Γ|²)` — the share of incident power not
accepted at the reference plane. Accepted power is not automatically *radiated*
power; it can equally become heat.

### The thing nobody tells you about VSWR

Look at the mismatch loss column. **A 2:1 VSWR costs you half a dB.** That is
inaudible, invisible, and irrelevant to link performance.

So why does anyone care?

1. **Transmitter protection.** Solid-state PAs fold back power above ~1.5:1 to
   2:1 to protect the output devices. That's a *transmitter* limitation, not a
   physics limitation.
2. **Feedline loss multiplication.** Reflected power travels back down the coax
   and gets attenuated twice. On a lossy line at UHF, this matters.
3. **It's a diagnostic proxy.** A sudden VSWR change on a known-good installation
   means something physically changed — water in the coax, a corroded connector,
   ice, a broken element.

**What VSWR is not:** a measure of radiation efficiency. A 50 Ω resistor has
a perfect 1.0:1 VSWR across all frequencies and radiates nothing. A rusty coat
hanger can show 1.5:1 and radiate poorly. This is exactly why the Smith chart
matters — it tells you the *character* of the impedance, which is what lets you
distinguish a real antenna from a lossy one.

---

## 2.5 The Smith chart

This is the single most useful display on the instrument and the one most people
ignore. Ten minutes of understanding it will save you hours.

### The layout

```
                    INDUCTIVE (+jX)
                  ┌─────────────────┐
                 ╱                   ╲
   SHORT       ╱                       ╲      OPEN
  Z = 0    ───┤          ● 50Ω          ├───  Z = ∞
  Γ = −1      ╲        (center)        ╱      Γ = +1
               ╲                      ╱
                 └──────────────────┘
                   CAPACITIVE (−jX)
```

- **Center point** = 50 + j0 Ω. Perfect match. This is where you want to be.
- **Far left** = short circuit (0 Ω)
- **Far right** = open circuit (∞ Ω)
- **Outer circle** = |Γ| = 1, pure reactance, zero resistance — total reflection
- **Upper half** = inductive reactance (+jX)
- **Lower half** = capacitive reactance (−jX)
- **Horizontal centerline** = pure resistance, no reactance — this is the
  **resonance line**

### Reading it in practice

Touch a marker onto the Smith trace. The NanoVNA reports the impedance at that
point as **R + jX** at the top of the screen, e.g. `43.2Ω −12.4pF` or
`58.1Ω 22.3nH`. (The firmware converts reactance into an equivalent capacitance
or inductance at that frequency, which is genuinely helpful when you're
designing a matching network.)

### The four diagnoses

| Marker position | Impedance | What it means | Fix |
|---|---|---|---|
| **Center** | ~50 + j0 | Matched and resonant | Nothing |
| **On centerline, left of center** | e.g. 25 + j0 | Resonant but too low R | Impedance transformation needed (element too close to ground, too many radials, folded element wrong) |
| **On centerline, right of center** | e.g. 110 + j0 | Resonant but too high R | Transformation needed (element too high above ground, end-fed characteristics) |
| **Above centerline** | e.g. 45 + j30 | **Inductive — element is too LONG** | Shorten it, or add series capacitance |
| **Below centerline** | e.g. 45 − j30 | **Capacitive — element is too SHORT** | Lengthen it, or add series inductance |

That table is the entire basis of antenna tuning. Everything in
[05-antenna-tuning.md](05-antenna-tuning.md) elaborates on it.

### The loop trick

When you sweep an antenna across a wide span, the Smith trace draws a path. A
**tight loop that crosses the centerline** is a resonant antenna. The frequency
where it crosses the centerline is the resonant frequency. How close that
crossing is to the center dot tells you the quality of the match.

A trace that **hugs the outer edge** without ever heading toward center is an
antenna that isn't resonant anywhere in that span — or isn't connected.

A trace that **spirals inward toward center** across the whole sweep, without a
distinct loop, often indicates a **lossy** system — you're seeing coax loss, not
antenna performance. This is the classic "my antenna has great SWR" trap on a
long run of old RG-58 at UHF.

---

## 2.6 Phase

**PHASE** displays the phase angle of S11 or S21, from −180° to +180°.

On **S11**, phase tells you the electrical distance to the discontinuity. As you
sweep upward in frequency, the phase rotates; the *rate* of rotation is
proportional to how far away the reflection is. A fast-wrapping phase trace means
a distant reflection (long cable). A slow one means the discontinuity is near the
calibration plane.

On **S21**, phase tells you the phase shift through a device. This is how you
match cable lengths for phased arrays, stacked Yagis, and antenna diversity
systems: sweep each cable, compare phase at the operating frequency, trim until
they agree.

> **Phase wrapping:** the display jumps from +180° to −180°. That's a display
> artifact, not a discontinuity in the device.

---

## 2.7 Group delay

**DELAY** shows group delay — the derivative of phase with respect to frequency,
expressed in seconds (usually ns or ps).

Physically: how long a signal envelope takes to get through the device.

Uses:

- **Cable length measurement.** Delay × velocity of propagation = length.
- **Filter group-delay flatness.** A filter with wildly varying group delay
  across its passband will smear wideband modulation. Relevant for anything
  carrying data.
- **Reference plane setting.** The ELECTRICAL DELAY control under
  **DISPLAY → SCALE** lets you mathematically "remove" a length of cable from the
  measurement — see [03-calibration.md](03-calibration.md).

---

## 2.8 The remaining formats

| Format | Shows | When you'd use it |
|---|---|---|
| **LINEAR** | \|Γ\| as 0–1 linear | Rarely; occasionally for reflection coefficient math |
| **POLAR** | Γ on a polar plot | Alternative to Smith for people who think in Γ rather than Z |
| **REAL** | Real part of **Γ** (dimensionless) | Advanced / scripted analysis |
| **IMAG** | Imaginary part of **Γ** (dimensionless) | Advanced / scripted analysis |
| **RESISTANCE** | R component of **Z**, in ohms | **Very useful** — plot R alone while tuning a matching network |
| **REACTANCE** | X component of **Z**, in ohms | **Very useful** — the zero-crossing of X *is* the resonant frequency |

> **REAL is not RESISTANCE, and IMAG is not REACTANCE.** REAL/IMAG are the
> components of the reflection coefficient and carry no units.
> RESISTANCE/REACTANCE are the components of impedance in ohms, obtained through
> `Z = Z₀ (1 + Γ)/(1 − Γ)`. Mixing them up produces numbers that look plausible
> and are meaningless. Note also that near an open circuit the denominator
> `1 − Γ` becomes very small, so tiny measurement errors there produce enormous
> swings in computed impedance — treat impedance readings near the Smith chart's
> right-hand rim with suspicion.

### The reactance zero-crossing trick

Set trace 0 to **REACTANCE** on CH0. Sweep your antenna. The frequency where the
trace crosses **zero going from negative to positive** is the true series
resonance of the antenna.

This is a more precise resonance indicator than the SWR minimum, because the SWR
minimum can be pulled off resonance by the resistance mismatch. Use the reactance
zero-crossing to determine *length*, and the resistance value at that point to
determine *what matching you need*.

---

## 2.9 Sweep points and resolution

Your frequency resolution per data point is:

```
Resolution = Span / (Points − 1)
```

| Span | 101 points | 401 points (H4) |
|---|---|---|
| 1.5 GHz full sweep | **15 MHz/point** | 3.75 MHz/point |
| 100 MHz | 1 MHz/point | 250 kHz/point |
| 10 MHz | 100 kHz/point | 25 kHz/point |
| 2 MHz | 20 kHz/point | 5 kHz/point |

**A 15 MHz-per-point sweep will walk straight past a narrow notch.** If you're
hunting for a resonance, sweep wide first to find the general area, then narrow
the span around it and re-calibrate.

For high-Q devices — crystal filters, cavity resonators, small magnetic loops —
101 points across even a few hundred kHz can miss the peak entirely. Use the H4
at 401 points, or use NanoVNA-Saver's segmented sweep for effectively thousands
of points (see [08](08-pc-software-and-firmware.md)).

---

## 2.10 Reading the status bar

Across the top of the screen you'll see something like:

```
CH0 LOGMAG 10dB/  1  -18.4dB  433.920MHz
                  ↑    ↑          ↑
            marker#  value    frequency
```

And along the bottom: `START 400.000MHz` … `STOP 470.000MHz`, plus indicators:

- **`C`** or **`Cal`** — calibration correction is active. If this is missing,
  **your numbers are meaningless.**
- **`D`** or a slot number — which calibration slot is loaded
- Battery icon
- **`*`** — sweep in progress

**Always check for the calibration indicator before trusting a reading.** The
most common source of bad data is an uncalibrated sweep.

---

[← Hardware & setup](01-hardware-and-setup.md) | [Next: Calibration →](03-calibration.md)
