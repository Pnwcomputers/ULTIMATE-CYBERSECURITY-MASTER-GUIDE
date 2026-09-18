# 07 — Quick Reference Card

[← Back to index](README.md)

Print this. Tape it inside the case lid.

---

## Pre-flight (every measurement)

```
□ Radio physically DISCONNECTED
□ DC block inline (unknown systems)
□ Coax center shorted to shield for 3 s
□ Sweep span set
□ Calibrated on THIS span
□ "C" indicator visible on screen
□ LOAD check: −35 dB or better
```

**Max input: +10 dBm (community figure, no verified spec). That is 1/100 W.
Any transmitter, any power, destroys the front end.**

---

## The 90-second calibration

```
1.  STIMULUS → START / STOP
2.  Attach test cable + adapters
3.  CAL → RESET
4.  CAL → CALIBRATE
5.  OPEN  → tap OPEN  → wait for sweep
6.  SHORT → tap SHORT → wait
7.  LOAD  → tap LOAD  → wait
8.  DONE
9.  CAL → SAVE → slot n
10. Verify with LOAD
```

---

## VSWR ↔ reflection ↔ reflected power

**Sign convention:** the screen's S11 LOGMAG is **negative** (more negative =
better). Return loss quoted positively is the same number flipped (larger =
better). `S11 LOGMAG = −(return loss)`. Never say "−20 dB return loss."

| VSWR | S11 LOGMAG | Return loss | Refl. power | Mismatch loss |
|---|---|---|---|---|
| 1.0 | −∞ | ∞ | 0% | 0.00 dB |
| 1.1 | −26.4 | 26.4 | 0.2% | 0.01 dB |
| 1.2 | −20.8 | 20.8 | 0.8% | 0.04 dB |
| 1.3 | −17.7 | 17.7 | 1.7% | 0.07 dB |
| 1.5 | −14.0 | 14.0 | 4.0% | 0.18 dB |
| 2.0 | −9.5 | 9.5 | 11.1% | 0.51 dB |
| 2.5 | −7.4 | 7.4 | 18.4% | 0.88 dB |
| 3.0 | −6.0 | 6.0 | 25.0% | 1.25 dB |
| 5.0 | −3.5 | 3.5 | 44.4% | 2.55 dB |
| 10.0 | −1.7 | 1.7 | 66.9% | 4.81 dB |

> `SEARCH → MINIMUM` finds the best match on **SWR or LOGMAG**. If your display
> plots positive return loss, the best match is a **MAXIMUM**.

---

## Smith chart — instant diagnosis

```
         INDUCTIVE  (+jX)  →  TOO LONG, shorten
       ┌────────────────────┐
      ╱                      ╲
SHORT│          ● 50Ω         │OPEN
 0Ω   ╲       (center)       ╱  ∞Ω
       └────────────────────┘
         CAPACITIVE (−jX)  →  TOO SHORT, lengthen

  Left of center on centerline  → R < 50Ω, needs step-up
  Right of center on centerline → R > 50Ω, needs step-down
```

---

## Key formulas

```
Γ          = (Z − 50) / (Z + 50)
Z          = 50 · (1 + Γ) / (1 − Γ)
|Γ|        = (SWR − 1) / (SWR + 1)
VSWR       = (1 + |Γ|) / (1 − |Γ|)
S11 LOGMAG =  20 · log₁₀(|Γ|)      dB   (negative on screen)
Return loss= −20 · log₁₀(|Γ|)      dB   (positive by convention)
Refl. power= |Γ|²
Mismatch loss = −10 · log₁₀(1 − |Γ|²)  dB

FREE SPACE                      PRACTICAL (≈5% end effect)
λ   (m) = 299.79 / f(MHz)       dipole λ/2 (m)  = 142.65 / f(MHz)  total
λ/2 (m) = 149.90 / f(MHz)       dipole λ/2 (ft) = 468    / f(MHz)  total
λ/4 (m) =  74.95 / f(MHz)       λ/4 element (m) =  71.3  / f(MHz)
λ/4 (ft)= 246    / f(MHz)       λ/4 element (ft)= 234    / f(MHz)
                                (radials: use the free-space figure)

Coax λ/4 (m)  = (75 × VF) / f(MHz)
Coax λ/2 (m)  = (150 × VF) / f(MHz)
VF            = (L(m) × f₁(MHz)) / 75     from first open-stub dip

Length trim:  shorten by X%  →  frequency rises X%.  Cut HALF, re-measure.

L-network:    Q  = √(R_high/R_low − 1)
              X_series = Q × R_low        (low-R side)
              X_shunt  = R_high / Q       (high-R side)
              L = X / (2πf)    C = 1 / (2πf·X)

λ/4 transformer:  Z = √(Z_source × Z_load)
Hairpin match condition:  |X_s| = √(R_s × (50 − R_s))

Ripple spacing → distance:  d(m) = (150 × VF) / Δf(MHz)
Cable loss (shorted far end) = (return loss in dB) / 2
Sweep resolution = Span / (Points − 1)

TDR, sweep bandwidth B and step Δf, c = 299,792,458 m/s:
  resolvable separation   Δd ≈ VF × c / (2B)
  ambiguity distance       d ≈ VF × c / (2Δf)
  distance from round trip   = VF × c × t / 2
```

---

## Velocity factors

| Cable | VF | | Cable | VF |
|---|---|---|---|---|
| RG-58 / RG-213 / RG-59 | 0.66 | | RG-8X (foam) | 0.82 |
| RG-174 | 0.66 | | RG-6 (foam) | 0.83 |
| RG-316 | 0.695 | | LMR-240/400 | 0.84–0.85 |
| Semi-rigid PTFE | 0.70 | | Hardline | 0.88 |
| | | | Ladder line | 0.90–0.95 |

---

## Band presets

λ/4 uses the practical constant (71.3/f). **Start long.**

| Service | Frequency | λ/4 element | Discovery sweep | Detail sweep |
|---|---|---|---|---|
| 80 m | 3.75 MHz | 19.01 m | 3.0–4.5 MHz | 3.4–4.1 MHz |
| 40 m | 7.15 MHz | 9.972 m | 6–9 MHz | 6.8–7.5 MHz |
| 20 m | 14.2 MHz | 5.021 m | 12–16 MHz | 13.9–14.5 MHz |
| CB | 27.2 MHz | 2.621 m | 25–30 MHz | 26.5–28.0 MHz |
| 10 m | 28.5 MHz | 2.502 m | 25–32 MHz | 27.5–29.8 MHz |
| 6 m | 52 MHz | 1.371 m | 45–60 MHz | 50–54 MHz |
| Airband | 125 MHz | 57.04 cm | 100–150 MHz | 118–137 MHz |
| 2 m | 146 MHz | 48.84 cm | 130–170 MHz | 140–152 MHz |
| MURS | 152 MHz | 46.91 cm | 130–170 MHz | 150–155 MHz |
| Marine VHF | 157 MHz | 45.41 cm | 130–180 MHz | 155–163 MHz |
| 433 ISM | 433.92 MHz | 16.43 cm | 400–470 MHz | 420–450 MHz |
| 70 cm | 435 MHz | 16.39 cm | 400–470 MHz | 420–450 MHz |
| GMRS/FRS | ~464.5 MHz | 15.35 cm | 400–520 MHz | 455–470 MHz |
| 868 ISM | 868 MHz | 8.21 cm | 800–950 MHz | 863–870 MHz |
| 915 ISM / LoRa | 915 MHz | 7.79 cm | 850–1000 MHz | 902–928 MHz |
| ADS-B | 1090 MHz | 6.54 cm | 1000–1150 MHz | 1070–1110 MHz |

> Sweep spans are measurement suggestions, **not band-allocation statements**.
> Recalibrate after narrowing.

---

## Troubleshooting flowchart

```
Sweep looks wrong
│
├─ No "C" indicator? ──────────────→ Calibrate
│
├─ Flat 1.0:1 everywhere? ─────────→ Dummy load, or lossy/waterlogged coax
│                                     Check Smith: tight dot = load
│
├─ Pinned at max SWR everywhere? ──→ Open or short
│     ├─ Smith at far RIGHT ───────→ OPEN: broken conductor / nothing connected
│     └─ Smith at far LEFT ────────→ SHORT: crushed coax / failed arrestor
│     └─ Run TDR to locate the fault
│
├─ Dip at wrong frequency? ────────→ Trim length
│     ├─ Dip too LOW  ─────────────→ Element too long → shorten
│     └─ Dip too HIGH ─────────────→ Element too short → lengthen
│
├─ Dip right, SWR still high? ─────→ Match problem, not length
│     └─ Read R on Smith, build L-network
│
├─ SWR changes when you touch
│  the coax? ──────────────────────→ Common-mode current → add choke, retune
│
├─ Broad shallow dip, never good? ─→ Loss: wet coax, corroded connector
│
├─ Evenly spaced ripple? ──────────→ Mid-run discontinuity
│                                     d(m) = (150 × VF) / Δf(MHz)
│
├─ Erratic / non-repeatable? ──────→ Loose connector, dying battery,
│                                     or bad calibration → re-torque, re-cal
│
├─ Reads as a short on a DMM? ─────→ May be a NORMAL DC-grounded design.
│                                     Judge by RF sweep, not continuity.
│
└─ Stuck at exactly 1.5:1? ────────→ Is it a 75 Ω antenna? That IS its correct
                                      match on a 50 Ω instrument. Don't "fix" it.
```

---

## Stop and diagnose before trimming if…

```
✗ The calibration load does not read correctly
✗ The trace jumps when a connector is flexed
✗ You cannot identify which dip is the intended resonance
✗ The result changes with hand or cable position
✗ You are measuring through unknown or lossy coax
✗ A complex antenna has no documented adjustment method
```

---

## Display format quick pick

| I want to… | Use |
|---|---|
| Report a number to a customer | **SWR** |
| Tune precisely | **LOGMAG** (more visible resolution) |
| Understand *why* it's mismatched | **SMITH** |
| Find true resonance | **REACTANCE** (zero crossing) |
| See what matching R I need | **RESISTANCE** |
| Measure a filter | **CH1 LOGMAG** |
| Match cable lengths | **CH1 PHASE** |
| Find a cable fault | **TRANSFORM → LOW PASS IMPULSE** |

---

## Marker operations

```
MARKER → SEARCH → MINIMUM      drop marker on the SWR/RL minimum
MARKER → SEARCH → TRACKING     marker follows the minimum live (use while tuning)
MARKER → SEARCH → MAXIMUM      peak finding (S21 filter passband)
MARKER → OPERATIONS → →CENTER  recenter the sweep on the marker
MARKER → OPERATIONS → →SPAN    set span from two markers
MARKER → OPERATIONS → →EDELAY  auto-set electrical delay from marker
MARKER → SELECT → DELTA        show differences between markers
```

---

## Dynamic range by band

| Range | Usable range | Notes |
|---|---|---|
| 9–50 kHz | Poor | Noisy |
| 50 kHz – 300 MHz | ~70 dB | Fundamental — best performance |
| 300–900 MHz | ~50 dB | 3rd harmonic |
| 900 MHz – 1.5 GHz | ~40 dB | 5th harmonic |
| Above 1.5 GHz | ~25–30 dB | Firmware-dependent, S11 only, don't trust S21 |

**These units do not usefully cover 2.4 GHz Wi-Fi/BLE or 5 GHz.**

---

## Things that kill the instrument

```
✗ Transmitting into it (any power)
✗ DC on the feedline
✗ Static from an outdoor antenna
✗ Nearby high-power transmitter coupling in
✗ Over-torquing the SMA connectors
✗ RP-SMA forced onto standard SMA
```

---

[← Cables & filters](06-cables-filters-other-uses.md) | [Next: PC software & firmware →](08-pc-software-and-firmware.md)

More: [worked examples](09-worked-examples-by-band.md) · [special antenna types](10-antenna-types-and-special-cases.md) · [worksheet](11-worksheet-and-exercises.md)
