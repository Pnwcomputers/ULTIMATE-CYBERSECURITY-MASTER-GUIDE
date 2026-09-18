# 01 — Hardware, Controls, and Setup

[← Back to index](README.md)

> **Read this before believing any spec on this page.** The tables below
> describe the NanoVNA-H and H4 families as the upstream project documents
> them. They are **not** a verified inventory of what SEESII shipped you. Point
> counts, calibration-slot counts, battery capacity, SD-card presence, the
> 9 kHz lower limit, connector type and the bundled accessories all vary by
> batch and by installed firmware. Several older upstream builds start at
> 50 kHz, not 9 kHz.
>
> **Confirm on your actual units** via `CONFIG → VERSION` and by counting the
> slots and point options the menus actually offer, then correct these tables
> to match. Write the real numbers in the worksheet in
> [11-worksheet-and-exercises.md](11-worksheet-and-exercises.md).

---

## 1.1 What these instruments actually are

A NanoVNA is a **two-port vector network analyzer**. It generates a signal,
sweeps it across a frequency range, and measures both the **magnitude and phase**
of:

- the signal that bounces *back* from the device under test (reflection → **S11**)
- the signal that passes *through* the device under test (transmission → **S21**)

"Vector" means it captures phase, not just amplitude. That's the difference
between a NanoVNA and a cheap SWR meter: an SWR meter tells you *how bad* the
mismatch is; a VNA tells you **what kind** of mismatch it is, and therefore how
to fix it.

Internally both units use:

- **Si5351A** clock generator as the RF source (fundamental to ~300 MHz, odd
  harmonics above that)
- **SA612/SA602-class mixers** for down-conversion to audio IF
- **STM32F072 (H) / STM32F303 (H4)** MCU doing the DSP on the audio IF
- A resistive directional bridge on CH0 for reflection measurement

Output power is roughly **−13 dBm** (about 50 µW). This is why the NanoVNA is
safe for antennas but is also why it is *not* a spectrum analyzer or a signal
generator for anything meaningful.

---

## 1.2 Model comparison

| | **NanoVNA-H (HW 3.7)** | **NanoVNA-H4 (V4.4)** |
|---|---|---|
| Display | 2.8" resistive touch, 320×240 | 4.0" resistive touch, 480×320 |
| MCU | STM32F072 | STM32F303 (more RAM/flash) |
| Sweep points | 101 | 101 / 201 / 301 / 401 selectable |
| Calibration slots | 5 (0–4) | 7 (0–6) |
| Battery | ~400–450 mAh (~2 h) | ~1900–2000 mAh (~4–5 h) |
| microSD slot | No | Yes (on most units — screenshots, S1P/S2P) |
| Frequency range | 9 kHz – 1.5 GHz | 9 kHz – 1.5 GHz |
| Connectors | 2× SMA female (CH0, CH1) | 2× SMA female (CH0, CH1) |
| USB | Micro-USB or USB-C depending on batch | Usually USB-C |
| Size / pocketability | Genuinely pocketable | Bag-sized |

**Which to grab for what:**

- **H (3.7)** — the field unit. Goes in a jacket pocket, runs a quick VSWR check
  at the top of a ladder, gets tossed in a truck bin. 101 points is plenty when
  you're sweeping a narrow band.
- **H4** — the bench/site unit. 401 points means you can sweep 9 kHz – 1.5 GHz
  in one shot with meaningful resolution, the bigger screen makes the Smith
  chart actually readable, and the SD card means you can log S1P files at a
  customer site without a laptop.

> The version strings in the retail listings ("HW3.7", "Latest V4.4") refer to
> the PCB revision and the factory firmware build. Verify what your specific unit
> reports under **CONFIG → VERSION** before doing anything firmware-related.

---

## 1.3 Ports and what connects where

```
   ┌──────────────────────────────┐
   │                              │
   │        NanoVNA screen        │
   │                              │
   └──┬────────────────────────┬──┘
      │                        │
    [CH0]                    [CH1]
    PORT 1                   PORT 2
   TX / S11                  RX / S21
  Reflection                Transmission
```

- **CH0 / PORT 1 / "S11"** — This is both the transmitter *and* the reflection
  receiver. **Everything you measure with one connection goes here.** Antennas,
  cables under test, filters when you only want return loss.
- **CH1 / PORT 2 / "S21"** — Receive only. The far end of a through measurement:
  filters, attenuators, amplifiers, cable loss, coupling between two antennas.

For antenna work, **you will use CH0 almost exclusively.**

### Connector care

The SMA connectors on a NanoVNA are the weakest mechanical point on the
instrument. They are soldered to the PCB and they will eventually tear loose if
you crank torque on them.

- Fit a **short SMA male-to-female "sacrificial" adapter** or a 6-inch pigtail
  on each port and leave it there permanently. Wear it out instead of the board.
- Tighten **finger-tight plus a light nip** with a 5/16" wrench. About 0.5–0.6 N·m.
  Never hold the body of the VNA and twist the cable.
- Always rotate the **nut**, never the cable body.

---

## 1.4 Controls

### NanoVNA-H (3.7)

- **Multifunction jog switch** (left side):
  - Push in → open/select menu
  - Up / down → move between menu items, or move the active marker when no menu
    is open
- **Touchscreen** — resistive, needs a stylus or fingernail, not a fingertip pad
- **Power slide switch** (side)

### NanoVNA-H4

- Same jog switch behavior
- Larger touch target area — the touchscreen is the primary interface here
- **microSD** slot on the edge

### Touch calibration

If taps land in the wrong place — which they will out of the box:

```
CONFIG → TOUCH CAL → tap the upper-left cross, then the lower-right cross
CONFIG → TOUCH TEST → scribble to verify tracking
CONFIG → SAVE CONFIG   ← do not skip this, or it resets on reboot
```

---

## 1.5 Menu map

Press the jog switch or tap the right edge of the screen to open the top-level
menu. Structure on current DiSlord-based firmware:

```
DISPLAY
├── TRACE           0 / 1 / 2 / 3       (enable, disable, pick active)
├── FORMAT          LOGMAG · PHASE · DELAY · SMITH · SWR · POLAR
│                   LINEAR · REAL · IMAG · RESISTANCE · REACTANCE
├── SCALE           SCALE/DIV · REFERENCE POSITION · ELECTRICAL DELAY
├── CHANNEL         CH0 REFLECT · CH1 THROUGH
└── TRANSFORM       (TDR: LOW PASS IMPULSE/STEP · BANDPASS · VELOCITY FACTOR)

MARKER
├── SELECT MARKER   1 / 2 / 3 / 4 · ALL OFF · DELTA
├── SEARCH          MAXIMUM · MINIMUM · SEARCH LEFT · SEARCH RIGHT · TRACKING
└── OPERATIONS      →START · →STOP · →CENTER · →SPAN · →EDELAY

STIMULUS
├── START · STOP · CENTER · SPAN
├── CW FREQ         (single-frequency mode)
└── PAUSE SWEEP

CAL
├── CALIBRATE       OPEN · SHORT · LOAD · ISOLN · THRU · DONE
├── RESET
├── CORRECTION      (on/off toggle — shows as "C" indicator)
└── SAVE            slot 0–4 (H) / 0–6 (H4)

SAVE / RECALL       recall a stored calibration + setup

CONFIG
├── TOUCH CAL · TOUCH TEST
├── SAVE CONFIG
├── VERSION
├── POINTS          (H4: 101/201/301/401)
└── DFU             ← firmware update mode
```

### The four default traces

Out of the box you get:

| Trace | Channel | Format | Colour |
|---|---|---|---|
| 0 | CH0 | LOGMAG (return loss) | yellow |
| 1 | CH0 | SMITH | green |
| 2 | CH1 | LOGMAG (insertion loss) | blue |
| 3 | CH1 | PHASE | red |

For antenna work, a far more useful layout is:

| Trace | Channel | Format |
|---|---|---|
| 0 | CH0 | **SWR** |
| 1 | CH0 | **SMITH** |
| 2 | CH0 | **LOGMAG** (return loss) |
| 3 | off | — |

Turning off trace 3 and CH1 declutters the screen considerably on the 2.8" H.

---

## 1.6 What's in the box, and what you should add

### Usually included

- SOLT calibration kit: **OPEN**, **SHORT**, **50 Ω LOAD** (three SMA male caps)
- One or two SMA male-to-male coax jumpers
- USB cable
- Sometimes an SMA-to-BNC or SMA-to-N adapter

### What you should buy immediately

| Item | Why |
|---|---|
| **SMA male-to-female sacrificial adapters ×4** | Save the board-mounted connectors |
| **Decent test cables** (RG-316 or semi-rigid, 15–30 cm) | The bundled jumpers are often marginal above 500 MHz |
| **Adapter kit**: SMA↔N, SMA↔BNC, SMA↔UHF (PL-259/SO-239), SMA↔TNC, SMA↔RP-SMA | You will need all of these |
| **DC block, inline, SMA** | Protects against DC on a feedline. Cheap insurance. |
| **6 dB and 10 dB SMA attenuators** | Protection + improves source match for tricky loads |
| **Better cal kit** (metal-bodied, spec'd standards) | The bundled plastic standards are the accuracy ceiling |
| **5/16" torque wrench or small open-end** | Repeatable connector torque |
| **Hard case with foam** | The screen is the other fragile part |

> **RP-SMA warning:** Wi-Fi, LoRa, and many ISM antennas use **reverse-polarity
> SMA**. The threads mate with standard SMA but the center pin/socket genders are
> swapped. Forcing an RP-SMA antenna onto a standard SMA port can bend or crush
> the VNA's center contact. Keep dedicated RP-SMA↔SMA adapters and label them.

---

## 1.7 Things that will destroy your NanoVNA

This is the most important section in this guide. The CH0 bridge and the CH1
mixer are **directly exposed** to the SMA connectors. There is no protection
circuitry.

| Hazard | What happens | Prevention |
|---|---|---|
| **Transmitting into it** | Instant destruction of the bridge/mixer. Even 1 W kills it. | Physically disconnect the radio. Not "PTT locked out" — *disconnected.* |
| **DC on the feedline** | Destroys the bridge. Common with bias-tees, phantom-powered preamps, DC-grounded antennas connected to something. | Inline DC block on CH0 whenever measuring an unknown installed system. |
| **Static discharge from an outdoor antenna** | Blows the bridge. A long wire or tower-mounted antenna can hold kilovolts. | Short the coax center to the shield for a few seconds before connecting. Use a lightning arrestor / DC-grounded antenna where possible. |
| **Nearby high-power transmitter** | A co-sited repeater or broadcast site can push far more than +10 dBm into a connected antenna. | Attenuator on CH0, or don't measure live at hot sites. |
| **Over-torquing SMA** | Rips the connector pad off the PCB | Sacrificial adapters, light torque |
| **Charging while measuring on a grounded PC** | Not destructive, but ground loops add noise to low-level readings | Run on battery for precision work |

**The commonly cited limit for this hardware family is +10 dBm (10 mW).** Treat
that as a hard wall — but treat it as a *community* figure, not a specification
SEESII published for your unit. No verified maximum input power is available for
these particular listings.

The practical consequence is the same either way, and it is not a number you
should ever be near: **a VNA's tiny output does not make its inputs tolerant of
anything.** +10 dBm is one hundredth of a watt. Any transmitter, at any power,
on any band, destroys the front end. If you find yourself calculating whether
some source is under the limit, you are already in the wrong posture — add an
attenuator or disconnect the source.

### The static discharge habit

Before connecting any outdoor or long-run coax to the NanoVNA:

1. Take the PL-259/N connector.
2. Briefly bridge center pin to shell with a screwdriver blade or a shorting cap.
3. Hold for 2–3 seconds.
4. Connect.

Do this every single time. It costs three seconds and saves the instrument.

---

## 1.8 First power-on checklist

1. Slide the power switch on. Let it boot.
2. **CONFIG → VERSION** — note the firmware string and board type. Write it down.
3. **CONFIG → TOUCH CAL**, then **TOUCH TEST**, then **SAVE CONFIG**.
4. **(H4 only) CONFIG → POINTS → 401.**
5. Charge fully via USB before the first real session. The battery gauge is
   crude; a full charge gives it a reference.
6. Run a **sanity calibration** on a narrow, familiar span (see
   [03-calibration.md](03-calibration.md)) and verify:
   - OPEN standard lands on the **far right** of the Smith chart
   - SHORT standard lands on the **far left**
   - LOAD standard sits at the **center**, with return loss better than −30 dB
   If those three don't happen, your standards, your cable, or your procedure is
   wrong — stop and fix it before measuring anything real.
7. **CAL → SAVE → slot 0** with a broad general-purpose calibration. Slot 0 is
   what loads automatically at boot.

---

## 1.9 Battery and power notes

- Both units use a single Li-ion cell with onboard charging. Charging draws
  around 500 mA; a laptop USB port is fine.
- The **H (3.7)** at ~450 mAh gives roughly two hours of continuous sweeping.
  Carry a power bank if you're doing a site survey.
- The **H4** at ~2 Ah is good for a working session.
- **Measurements drift while the unit warms up.** Give it 3–5 minutes from cold
  before calibrating if you want repeatable numbers, especially above 500 MHz.
- A nearly-flat battery can cause the Si5351 output level to sag, which shows up
  as noisy or shifted readings. If results look strange, charge it and
  re-calibrate.

---

[Next: RF fundamentals →](02-rf-fundamentals.md)
