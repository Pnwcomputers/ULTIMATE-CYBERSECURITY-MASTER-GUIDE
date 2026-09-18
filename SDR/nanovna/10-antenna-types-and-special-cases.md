<a id="top"></a>

# 📻 10 — Antenna Types and Special Cases

<div align="center">

**Recognize when the standard antenna-testing procedure needs a different fixture or interpretation.**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [SDR & RF](../README.md)*

![NanoVNA](https://img.shields.io/badge/Hardware-NanoVNA--H_%26_H4-blue?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Antenna_Types_and_Special_Cases-green?style=for-the-badge)
![Chapter](https://img.shields.io/badge/Chapter-10_of_12-orange?style=for-the-badge)

</div>

---

[← NanoVNA Index](README.md) · [SDR & RF](../README.md)

## 🎯 Purpose

Explain antenna designs and installations that require additional measurement context.

## ⚙️ Function

Cover handhelds, receive-only and active antennas, 75-ohm systems, mobile and multiband designs.

## 🏆 Goal

Choose a procedure appropriate to the complete antenna system being measured.

## 📋 When to Use

- Working with end-fed, trapped, multiband, or broadband antennas.
- Interpreting a handheld, active antenna, or DC continuity result.

---

## 📋 Table of Contents

- [10.1 — Handheld antennas and rubber ducks](#101--handheld-antennas-and-rubber-ducks)
- [10.2 — Telescoping whips and higher-order modes](#102--telescoping-whips-and-higher-order-modes)
- [10.3 — Receive-only and SDR antennas](#103--receive-only-and-sdr-antennas)
- [10.4 — Active antennas and mast-head amplifiers](#104--active-antennas-and-mast-head-amplifiers)
- [10.5 — 75-ohm antennas on a 50-ohm instrument](#105--75-ohm-antennas-on-a-50-ohm-instrument)
- [10.6 — Mobile antennas: the three-frequency test](#106--mobile-antennas-the-three-frequency-test)
- [10.7 — Dual-band mobile whips](#107--dual-band-mobile-whips)
- [10.8 — End-fed half-wave antennas](#108--end-fed-half-wave-antennas)
- [10.9 — Random wire antennas and 9:1 ununs](#109--random-wire-antennas-and-91-ununs)
- [10.10 — Fan dipoles and trapped antennas](#1010--fan-dipoles-and-trapped-antennas)
- [10.11 — Yagis: what SWR does not tell you](#1011--yagis-what-swr-does-not-tell-you)
- [10.12 — Discones and other broadband receiving antennas](#1012--discones-and-other-broadband-receiving-antennas)
- [10.13 — The DC continuity trap](#1013--the-dc-continuity-trap)

---

The procedures in [04](04-antenna-testing.md) and [05](05-antenna-tuning.md)
assume a simple radiator you can measure and trim. Plenty of real antennas
aren't that. This file covers the ones where the standard method needs
modifying — or where following it blindly produces a confident wrong answer.

**Jump to:**
[Handhelds & rubber ducks](#101--handheld-antennas-and-rubber-ducks) ·
[Telescoping whips](#102--telescoping-whips-and-higher-order-modes) ·
[Receive-only & SDR](#103--receive-only-and-sdr-antennas) ·
[Active antennas](#104--active-antennas-and-mast-head-amplifiers) ·
[75 Ω / TV](#105--75-ohm-antennas-on-a-50-ohm-instrument) ·
[Mobile: 3-frequency test](#106--mobile-antennas-the-three-frequency-test) ·
[Dual-band whips](#107--dual-band-mobile-whips) ·
[End-fed half-wave](#108--end-fed-half-wave-antennas) ·
[Random wire & 9:1](#109--random-wire-antennas-and-91-ununs) ·
[Fan dipoles & traps](#1010--fan-dipoles-and-trapped-antennas) ·
[Yagis](#1011--yagis-what-swr-does-not-tell-you) ·
[Discones](#1012--discones-and-other-broadband-receiving-antennas) ·
[DC continuity](#1013--the-dc-continuity-trap)

---

## 10.1 — Handheld antennas and rubber ducks

**The problem:** a handheld antenna uses the radio's chassis — and often the
operator's hand and body — as its counterpoise. Screw one directly onto a
NanoVNA and you are measuring that antenna against *the NanoVNA's body*, in
*your* hand, which is not its operating condition and not repeatable between
sessions.

This is not a small effect. The same duck can read 1.4:1 on the radio and 3:1 on
the analyzer, and neither number is wrong — they are measurements of two
different antenna systems.

**What to do instead — build a fixture:**

1. Make a fixed conductive counterpoise that approximates the intended ground
   structure: a metal plate, a box the size of the radio, or a defined
   counterpoise wire.
2. Mount every antenna the same way on that same fixture.
3. Keep test-lead routing and your own body position constant between sweeps.
4. Save before/after data.

**What the result is good for:** comparing antennas *against each other* within
that fixture. Antenna A reading 8 dB better return loss than antenna B on the
same fixture is real, useful information.

**What it is not good for:** stating an absolute SWR for the antenna. Verify
final performance on the intended radio.

> If you add a counterpoise wire to improve the reading, you have changed the
> antenna system. Record that. Do not report the resulting SWR as a property of
> the bare antenna — that is how spec sheets end up lying.

---

## 10.2 — Telescoping whips and higher-order modes

A telescoping whip is the easiest thing in the world to tune — no cutting, just
slide and watch a tracking marker — with one trap.

**A whip has multiple resonances.** At a given extension it is a quarter wave at
one frequency, three-quarter wave at roughly three times that, and so on. A
sweep will show several dips and they are not equivalent.

**A low-SWR higher-order mode does not have the same radiation pattern as the
fundamental.** A 3/4-wave mode typically has a pattern with significant
high-angle lobes and a null where you wanted your main lobe. You can get a
beautiful 1.1:1 match on a mode that radiates in the wrong direction.

**Procedure:**

1. Fix the counterpoise and leave it alone.
2. Extend in marked increments — a paint pen mark per section is worth the
   thirty seconds.
3. Sweep wide enough to see *all* the dips, then identify which one is the
   fundamental. The fundamental is the lowest-frequency dip, and its element
   length should be near λ/4 by the table in [05](05-antenna-tuning.md#52-fixing-resonance-element-trimming).
4. Tune the mode you actually want.
5. Mark the final extension so it can be reset in the field.

---

## 10.3 — Receive-only and SDR antennas

Relevant to ADS-B, scanners, weather satellites, and general SDR work.

**For a passive receive antenna**, the method is the same as any other antenna:
disconnect the SDR, connect the calibrated fixture, sweep S11.

> **Never connect the NanoVNA's CH0 output directly to an SDR input.** The VNA
> source is small but SDR front ends are sensitive, and some SDRs put bias-tee
> voltage on their input, which flows the other way and kills the VNA bridge.
> Disconnect the receiver. Both devices survive.

**Match matters less here than people assume.** Receive performance is set by
pattern, losses, noise pickup, siting, and receiver behaviour — a 2:1 match on
a receive antenna costs half a dB, which is nothing next to a 10 dB siting
difference or an overloading front end.

**A useful workflow for SDR projects:**

1. Check the **passive antenna's** matching across the target range.
2. Measure the **feedline loss** separately ([06](06-cables-filters-other-uses.md) §6.3).
3. Measure any **filter's** S21 and S11 separately.
4. Reconnect the receiver and compare **actual reception** under controlled
   conditions.

Step 4 is the one that answers the real question. Steps 1–3 tell you where to
look when step 4 disappoints.

> Poor ADS-B or scanner performance near cell sites, paging transmitters, or
> broadcast is far more often **front-end overload** than antenna mismatch.
> Sweep the filter/LNA chain on S21 before touching the antenna.

---

## 10.4 — Active antennas and mast-head amplifiers

**Identify the power arrangement before connecting anything.**

An active antenna's connector is an **amplifier output**, not the radiator's
feedpoint. Measuring it tells you about the amplifier's output match — which is
usually a deliberate 50 Ω and tells you nothing about the antenna element.

Worse, these systems are normally powered through the coax by a bias tee. That
DC will destroy the NanoVNA's bridge.

**Rules:**

- **DC block inline, always**, on anything that might be powered.
- Check center-to-shield for DC with a multimeter first.
- Understand that a good reading on an active antenna's port is not a
  measurement of the antenna.
- To measure the actual radiator you must get behind the amplifier, which
  usually means disassembly.

---

## 10.5 — 75-ohm antennas on a 50-ohm instrument

Broadcast TV, some receive-only installations, satellite and CATV hardware are
75 Ω systems. The NanoVNA references **50 Ω**.

**An ideal, perfect 75 Ω resistive load reads 1.5:1 SWR on this instrument.**
That is the instrument being correct, not the antenna being faulty.

```
Γ = (75 − 50)/(75 + 50) = 25/125 = 0.20   →   SWR = 1.5:1
```

**Do not retune a sound 75 Ω antenna to force 1:1 on a 50 Ω display.** You would
be detuning a working antenna to satisfy the wrong reference impedance.

**What to do:**

- Read **impedance (R + jX)** rather than SWR, and judge it against 75 Ω.
- Or export the `.s1p` and renormalize to 75 Ω in software. NanoVNA-Saver and
  scikit-rf both do this correctly.
- Resonance still reads correctly regardless of reference impedance — the
  reactance zero-crossing is where it is.
- If you use a 50/75 Ω matching pad or transformer, it becomes part of the
  measurement and must be characterized or calibrated out.

Quick reference for judging 75 Ω loads on a 50 Ω display:

| True load (75 Ω system) | Reads on 50 Ω display |
|---|---|
| 75 Ω (perfect) | 1.50:1 |
| 60 Ω | 1.25:1 |
| 90 Ω | 1.80:1 |
| 50 Ω | 1.00:1 — *worse* in a 75 Ω system, VSWR 1.5:1 there |

---

## 10.6 — Mobile antennas: the three-frequency test

Mobile installs get measured at the radio end, on the vehicle, in operating
condition: **doors and hatch closed, vehicle on the ground, antenna in its real
mounting position.** A mobile antenna measured on a bench is a different antenna.

Sweep the full range, then read three points: low edge, target centre, high edge.

| Shape around the intended fundamental | Typical interpretation |
|---|---|
| SWR improves as frequency **increases** | Resonance is above the range → radiator too **short** |
| SWR improves as frequency **decreases** | Resonance is below the range → radiator too **long** |
| Low in the centre, similar at both edges | Roughly centred — good |
| High and irregular everywhere | **Stop.** Check mount, bonding, coax and connectors before touching length |

> **Confirm with the full sweep and the reactance trace.** Reading only the three
> endpoints can miss a second resonance sitting between them, or a distorted
> curve that isn't what you think it is. The three-frequency check is a summary,
> not a substitute for looking at the trace.

**Adjustment order for mobile whips:**

1. Use the **designed** adjustment first — tuning screw, whip slide, removable
   tip.
2. For loaded antennas, follow the manufacturer's instructions. **Do not trim a
   loading coil or move its turns** unless the design explicitly permits it.
3. Mark the starting position before changing anything.
4. Change one thing, retighten, **step away from the vehicle**, sweep.
5. Recheck after locking the adjustment and weatherproofing — both change the
   result.

**Never change coax length to fix a bad mount.** It will move the shack-end
number and fix nothing. (Deliberately designed transmission-line matching
sections are a separate, legitimate engineering case — that is not what this
warning is about.)

Mag mounts: the RF return path includes capacitive coupling through the magnet's
insulating pad to the vehicle body. A DC continuity test across that does **not**
describe the RF path. See §10.13.

---

## 10.7 — Dual-band mobile whips

The two bands interact. One adjustment will frequently improve one and degrade
the other.

**Method:** build a table and fill in **both** bands after **every** change.

| Step | Change made | VHF resonance | VHF SWR | UHF resonance | UHF SWR |
|---|---|---|---|---|---|
| 0 | baseline | | | | |
| 1 | | | | | |
| 2 | | | | | |

Tune to your **actual operating requirements**, not to an aesthetic ideal. In
particular, do not assume the two minima should land at an exact integer ratio —
the designed loading structure deliberately breaks that relationship, and
chasing it will make both bands worse.

If one band is simply not reachable without wrecking the other, that is a real
finding. Report it rather than grinding at it.

---

## 10.8 — End-fed half-wave antennas

Measure on the **50 Ω input of the intended transformer**, with its specified
counterpoise and choke arrangement installed. Measuring the bare wire tells you
almost nothing useful.

**Procedure:**

1. Start with the design's suggested wire length and mounting.
2. Sweep the lowest intended resonance and each higher band **separately** —
   these are multiband antennas and a single wide sweep will confuse you.
3. Identify which feature corresponds to which mode before adjusting anything.
4. Make a **small** wire-length adjustment.
5. **Recheck every intended band.** A change that fixes 40 m may ruin 20 m.
6. If one band stays poor while others are fine, the problem is usually the
   transformer, its compensation, or layout — not wire length. Stop cutting and
   investigate.

**About the 49:1 transformer:** its ideal high-side load is 2450 Ω, but a real
end-fed's impedance is strongly frequency-dependent and nowhere near a constant
2450 Ω. You can test the transformer in isolation by terminating it with a
2.4 kΩ non-inductive resistor and sweeping the 50 Ω side — that reveals gross
matching problems.

> **Good SWR through a transformer does not prove the transformer is
> efficient.** A lossy core produces beautiful SWR by dissipating power. Core
> loss, heating, and power handling need separate evaluation; the NanoVNA's
> microwatt stimulus will never reveal a core that saturates at 100 W.

The counterpoise and coax shield are part of this antenna system. If moving the
coax shifts the trace noticeably, fix that dependence before judging wire length.

---

## 10.9 — Random wire antennas and 9:1 ununs

**A 9:1 unun does not make a random wire a resonant 50 Ω antenna.** It
transforms a high, wildly frequency-dependent impedance down to something a
tuner can usually handle. That is all it promises.

Do not go hunting for a magic wire length that gives low SWR everywhere. It does
not exist, and lengths that appear to achieve it are usually revealing loss
rather than performance.

**What to do instead:**

1. Measure the complete intended system, including its return path/counterpoise.
2. Record, band by band, what impedance the system actually presents.
3. Determine whether your tuner can reach a match there — and at what cost in
   feedline loss, given the SWR on the line between tuner and antenna.
4. Document which bands are usable and what tuner settings they need. That
   document is the deliverable.

Avoid wire lengths near a half-wave (or multiple) at an intended operating
frequency — the impedance there goes very high and matching becomes difficult
and lossy.

---

## 10.10 — Fan dipoles and trapped antennas

**Elements and traps interact.** This is the defining property of these antennas
and the reason a simple length formula does not apply.

**Fan dipoles** — use the manufacturer's sequence where one exists. For a
home-built fan, a workable approach is:

1. Tune the **longest** (lowest-frequency) element first, with the others
   present.
2. Work upward to the shorter elements.
3. Make **another full pass** — adjusting the short elements will have moved the
   long one.
4. Expect two or three passes before it settles.

Element spacing matters. Elements too close together couple strongly and fight
each other; fan them out.

**Trapped antennas** — a trap is a parallel LC that acts as an insulator at its
design frequency and as loading below it. Consequences:

- Total-length formulas do not apply across bands.
- A **failed or detuned trap** produces symptoms that look exactly like an
  element-length problem: resonance in the wrong place on one band only.
- If behaviour is unexpected on one band while others are fine, **inspect the
  trap** before adjusting element lengths.

You can check a trap in isolation: sweep it as a two-port (S21) notch and
confirm the notch falls at the design frequency. A trap that has taken on water
or lost a capacitor will show a shifted or absent notch.

---

## 10.11 — Yagis: what SWR does not tell you

**Input SWR reports the driven element and its matching structure. Nothing
else.**

A Yagi with correct SWR can have wrong director lengths, wrong spacing, poor
gain, a ruined front-to-back ratio, and a pattern pointing somewhere unhelpful.
The reflector and directors are parasitic — they influence feedpoint impedance,
but you cannot infer their correctness from the match.

**Procedure:**

1. Build element lengths and spacings to the design. Measure them with a tape,
   not with the VNA.
2. Place the antenna clear of unintended conductors and at a realistic height —
   ground within about 1λ shifts both impedance and pattern.
3. Adjust **only** the driven element and its designed match (gamma, hairpin,
   beta, delta). See [05](05-antenna-tuning.md#54-fixing-the-match-impedance-transformation)
   Option D, and the worked hairpin example in
   [09](09-worked-examples-by-band.md#910--915-mhz-yagi-driven-element--hairpin-match).
4. Recheck SWR across the required range.
5. Evaluate gain and pattern **separately** — an antenna range, or a controlled
   comparative test against a reference antenna.

> **Do not trim directors because it moves the SWR minimum favourably.** You
> will trade away the gain and front-to-back ratio you built the Yagi for, in
> exchange for a number that was never measuring them.

---

## 10.12 — Discones and other broadband receiving antennas

A discone is designed for broad frequency coverage, not deep resonance. **Do not
expect one sharp dip**, and do not treat its absence as a fault.

**What to evaluate:** matching consistency across the intended range. A discone
performing correctly shows a moderate, reasonably flat match over a wide span —
often 2:1 or a bit better across several octaves.

**What to be suspicious of:** a discone showing an *excellent* match everywhere,
particularly through an old feedline. That is the loss signature described in
[04](04-antenna-testing.md#broad-shallow-dip-that-never-gets-good), not
performance.

The low-frequency limit is set by the cone dimensions. Below it, the match
degrades rapidly — that is normal and is where the antenna simply stops working.

---

## 10.13 — The DC continuity trap

A multimeter across an antenna feedline is a useful test for **finding a broken
conductor**. It is close to useless for deciding whether an antenna is good.

| DC reading | Could legitimately mean |
|---|---|
| **Short** (near 0 Ω) | A DC-grounded antenna, a shunt-fed design, a matching coil, a gamma match, a lightning arrestor — **all normal** |
| **Open** | A capacitively-coupled design, a series-fed element, a blocking capacitor — **also normal** |
| Either | An actual fault |

The DC test cannot distinguish "a coil that is a short at DC and a high
impedance at 146 MHz" from "a screwdriver across the connector."

**An RF sweep can.** A real short reads as a short across the entire sweep and
parks at the far left of the Smith chart everywhere. A designed DC-grounded
antenna shows frequency-dependent impedance and a proper resonance.

Use DC continuity to confirm a *suspected* break. Use the VNA to decide whether
the antenna works.

---

[← Worked examples](09-worked-examples-by-band.md) |
[Next: Worksheet & exercises →](11-worksheet-and-exercises.md)

---

<div align="center">

[↑ Back to Top](#top) · [NanoVNA Index](README.md) · [SDR & RF](../README.md)

</div>
