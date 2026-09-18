# 08 — PC Software, Data Export, and Firmware

[← Back to index](README.md)

---

## 8.1 Why bother with PC software

The NanoVNA's on-device interface is fine for field work and quick checks. For
anything you need to keep, compare, or analyze, connect it to a computer:

- **Far more sweep points** via segmented sweeps — thousands instead of 101/401
- **Persistent records** — Touchstone `.s1p`/`.s2p` files you can archive and diff
- **Better calibration** — multi-standard, saved to disk, reusable
- **Readable charts** — proper Smith charts, multiple simultaneous traces,
  overlay comparisons
- **Scriptability** — the serial protocol is plain text over USB CDC, which makes
  automated sweeps trivial

---

## 8.2 NanoVNA-Saver

The standard companion application. Cross-platform Python (Windows, Linux, macOS).

**Source:** `https://github.com/NanoVNA-Saver/nanovna-saver`

### Setup

1. Connect the NanoVNA by USB. It enumerates as a **USB CDC serial device**
   (`COMx` on Windows, `/dev/ttyACM0` on Linux).
2. On Linux, add yourself to the `dialout` group:
   ```bash
   sudo usermod -aG dialout $USER
   # log out and back in
   ```
3. Launch NanoVNA-Saver, pick the port, click **Connect to device**.

### The segmented sweep — the killer feature

The hardware does 101 points per sweep. Saver breaks a wide span into N segments,
sweeps each one separately, and stitches them together.

```
Segments: 10  →  1010 effective points
Segments: 50  →  5050 effective points
```

This is what makes high-Q measurements possible — crystals, magnetic loops,
narrow cavity filters. Set segments high, accept a slower sweep, get real
resolution.

### Calibration in Saver

Saver runs its own calibration, independent of the device's internal slots, and
stores it on disk. It supports calibration-standard definitions (offset delay,
loss, and fringing capacitance coefficients) if you have a characterized cal kit
— which meaningfully improves accuracy above 500 MHz.

Calibrate in Saver **after** setting the segment count and span you'll use.

### Exporting data

`File → Export → Touchstone` produces:

- **`.s1p`** — one-port (S11) data. Frequency, real, imaginary. This is what you
  archive for antennas.
- **`.s2p`** — two-port data. For filters and anything you measured through.

These are plain-text industry-standard files. They open in Saver, in other RF
tools, and parse trivially in Python.

### Reading a Touchstone file in Python

```python
# Minimal .s1p reader — no dependencies beyond the stdlib
import cmath

def read_s1p(path):
    """Yield (freq_hz, gamma_complex) from a Touchstone 1-port file."""
    scale = 1e9          # default GHz
    fmt   = "RI"
    z0    = 50.0
    with open(path) as f:
        for line in f:
            line = line.split("!")[0].strip()
            if not line:
                continue
            if line.startswith("#"):
                tok = line[1:].upper().split()
                units = {"HZ": 1, "KHZ": 1e3, "MHZ": 1e6, "GHZ": 1e9}
                for t in tok:
                    if t in units:
                        scale = units[t]
                    if t in ("RI", "MA", "DB"):
                        fmt = t
                    if t.replace(".", "").isdigit():
                        z0 = float(t)
                continue
            parts = line.split()
            f_hz = float(parts[0]) * scale
            a, b = float(parts[1]), float(parts[2])
            if fmt == "RI":
                g = complex(a, b)
            elif fmt == "MA":
                g = cmath.rect(a, cmath.pi * b / 180.0)
            else:  # DB
                g = cmath.rect(10 ** (a / 20.0), cmath.pi * b / 180.0)
            yield f_hz, g


def metrics(gamma, z0=50.0):
    m = abs(gamma)
    vswr = float("inf") if m >= 1 else (1 + m) / (1 - m)
    rl   = float("inf") if m == 0 else -20 * (m and __import__("math").log10(m))
    z    = z0 * (1 + gamma) / (1 - gamma) if gamma != 1 else complex(float("inf"))
    return vswr, rl, z


if __name__ == "__main__":
    import sys
    best = None
    for f_hz, g in read_s1p(sys.argv[1]):
        vswr, rl, z = metrics(g)
        if best is None or vswr < best[1]:
            best = (f_hz, vswr, rl, z)
    f_hz, vswr, rl, z = best
    print(f"Resonance : {f_hz/1e6:.3f} MHz")
    print(f"VSWR      : {vswr:.3f}:1")
    print(f"Return loss: {-rl:.2f} dB")
    print(f"Impedance : {z.real:.1f} {'+' if z.imag >= 0 else '-'} j{abs(z.imag):.1f} ohm")
```

With `scikit-rf` installed (`pip install scikit-rf`) this becomes a two-liner and
you get plotting, de-embedding, and cascade analysis for free — worth it if
you're doing this regularly.

### Automating baseline comparisons

The natural workflow for service records: sweep a site, export `.s1p`, and diff
against the stored baseline.

```python
# Compare two sweeps and flag meaningful drift
def compare(baseline_path, current_path, tol_db=2.0):
    base = dict(read_s1p(baseline_path))
    curr = dict(read_s1p(current_path))
    import math
    flags = []
    for f in sorted(set(base) & set(curr)):
        rl_b = -20 * math.log10(max(abs(base[f]), 1e-12))
        rl_c = -20 * math.log10(max(abs(curr[f]), 1e-12))
        if abs(rl_b - rl_c) > tol_db:
            flags.append((f / 1e6, rl_b, rl_c))
    return flags
```

Anything that flags is a physical change in the antenna system since the
baseline: water, corrosion, a loosened connector, a moved element.

---

## 8.3 Other software

| Tool | Platform | Notes |
|---|---|---|
| **NanoVNA-Saver** | Win/Linux/macOS | The default choice. Actively maintained. |
| **NanoVNA-App** (OneOfEleven) | Windows | Polished UI, nice charts. Less actively developed. |
| **NanoVNA-QT / nanovna-v2 tools** | Cross-platform | Originally for the V2 series; some compatibility |
| **scikit-rf** | Python library | Post-processing, de-embedding, cascading, plotting |
| **Direct serial** | Anything | See §8.4 |

---

## 8.4 The serial command interface

The NanoVNA exposes a plain-text shell over USB CDC at any baud rate (it's USB,
the rate is ignored). This makes scripted automation straightforward.

```bash
# Linux: find the device
ls /dev/ttyACM*

# Talk to it
screen /dev/ttyACM0 115200
```

Common commands (firmware-dependent — type `help` to see the list on your unit):

```
help                      list available commands
info                      firmware / board info
scan <start> <stop> <pts> sweep and return data
sweep <start> <stop> <pts> set sweep parameters
data 0                    dump S11 as real/imag pairs
data 1                    dump S21
frequencies               dump the frequency list
marker                    marker state
cal                       calibration state
pause / resume            stop/start sweeping
capture                   dump a framebuffer screenshot
reset                     reboot
```

### Minimal Python automation

```python
import serial, time

def sweep(port, start_hz, stop_hz, points=101):
    with serial.Serial(port, 115200, timeout=3) as s:
        def cmd(c):
            s.write((c + "\r").encode())
            time.sleep(0.1)
            return s.read_until(b"ch> ").decode()

        cmd("pause")
        cmd(f"sweep {start_hz} {stop_hz} {points}")
        time.sleep(1.5)
        freqs = cmd("frequencies")
        s11   = cmd("data 0")
        cmd("resume")
        return freqs, s11
```

Useful for: scheduled unattended sweeps of a fixed installation, automated
production testing of antennas, or logging an antenna's behavior over a weather
cycle to prove water ingress.

---

## 8.5 Firmware

### Check what you have first

```
CONFIG → VERSION
```

Note the **board identifier** and the **firmware version string**. Write them
down before doing anything else.

### Why you might update

The community firmware (DiSlord's fork is the de facto standard for the H and H4)
adds over the older factory builds:

- More sweep points and selectable point counts
- Additional calibration slots
- Improved TDR/transform functions
- Better marker search and tracking
- Extended frequency range on some builds
- Bug fixes and speed improvements

### Why you might not

If the unit does what you need, updating firmware is risk for no benefit. Factory
firmware on a current SEESII H4 is already reasonably capable.

### The one rule that matters

> **Flash only firmware built for your exact board.** NanoVNA-H and NanoVNA-H4
> are different hardware with different MCUs. Within the H family, 3.x board
> revisions differ. Loading the wrong binary at best does nothing, at worst
> requires recovery.

### DFU update procedure

1. **Verify the board type** (`CONFIG → VERSION`).
2. Download the matching `.dfu` or `.bin` from the firmware author's release
   page. Verify the checksum if one is published.
3. Put the device into DFU mode, either:
   - `CONFIG → DFU → RESET AND ENTER DFU`, or
   - Power off, jumper the BOOT0 pad to VDD (inside the case), power on
4. Connect USB. The device enumerates as **STM32 BOOTLOADER** / DfuSe.
5. Flash with **STM32CubeProgrammer**, **DfuSe Demo**, or `dfu-util`:
   ```bash
   dfu-util -a 0 -s 0x08000000:leave -D nanovna-h4-firmware.bin
   ```
6. Power cycle.
7. **Re-do touch calibration and all SOLT calibrations.** Firmware updates
   invalidate stored calibration data.

### Recovery from a bad flash

The STM32 bootloader lives in ROM and cannot be erased by a user flash operation.
Even a completely failed firmware write can be recovered by entering DFU with the
hardware BOOT0 jumper and re-flashing. You have to physically damage the chip to
truly brick these units.

If the device won't enter DFU via the menu (because the firmware is broken), open
the case and use the BOOT0 pad. On most NanoVNA-H/H4 boards it's a labeled test
point near the MCU.

---

## 8.6 Suggested workflow for service work

```
FIELD (NanoVNA standalone)
 └─ recall band cal slot
 └─ discharge, connect, sweep
 └─ H4: save .s1p + screenshot to microSD
 └─ H: photograph screen, or connect laptop

BENCH / OFFICE (NanoVNA-Saver)
 └─ segmented sweep for detail work
 └─ export .s1p with consistent naming
 └─ archive alongside the site record
 └─ diff against previous baseline

REPORTING
 └─ Saver chart export → customer report
 └─ VSWR, resonance, bandwidth, TDR distance-to-fault
 └─ before/after comparison for any remediation
```

A before-and-after sweep attached to an invoice is the most persuasive
documentation you can give a customer for RF work — it turns "I fixed it" into
evidence.

---

[← Quick reference](07-quick-reference.md) | [Next: Worked examples →](09-worked-examples-by-band.md) | [Back to index](README.md)
