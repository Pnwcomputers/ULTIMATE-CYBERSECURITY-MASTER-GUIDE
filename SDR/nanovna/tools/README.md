<a id="top"></a>

# 🧰 s1pdiff — Touchstone Sweep Analysis and Baseline Comparison

<div align="center">

**Command-line analysis and comparison of one-port NanoVNA sweep records**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../../README.md) · [SDR & RF](../../README.md)*

![NanoVNA](https://img.shields.io/badge/Hardware-NanoVNA--H_%26_H4-blue?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Touchstone_Analysis-green?style=for-the-badge)

</div>

---

[← NanoVNA Index](../README.md)

## 🎯 Purpose

Provide a command-line companion for reviewing archived NanoVNA S11 sweeps.

## ⚙️ Function

Analyze individual Touchstone files or compare a current sweep with a baseline and export the result.

## 🏆 Goal

Report measurement changes with the input data and comparison assumptions available for review.

## 📋 When to Use

- Analyzing an exported .s1p file.
- Comparing repeat measurements and producing a report or machine-readable output.

---

## 📋 Table of Contents

- [What it's for](#what-its-for)
- [Install](#install)
- [Usage](#usage)
- [Exit codes](#exit-codes)
- [Options](#options)
- [File format support](#file-format-support)
- [Interpretation caveats](#interpretation-caveats)
- [Tests](#tests)
- [Naming convention for archived sweeps](#naming-convention-for-archived-sweeps)

---

A standalone command-line tool for NanoVNA `.s1p` files. Python 3.8+, **standard
library only** — no numpy, no scikit-rf, nothing to install.

Companion to [the NanoVNA field guide](../README.md); see
[06 §6.10](../06-cables-filters-other-uses.md#610-building-a-service-baseline-library)
for the workflow it's built around.

---

## What it's for

You sweep an antenna system, export `.s1p`, and archive it. Months later you
sweep the same system and want an objective answer to **"has anything changed?"**

`s1pdiff` gives you that answer, the numbers behind it, and an exit code you can
act on in a script.

---

## Install

```bash
chmod +x tools/s1pdiff.py
```

That's it. Optionally put it on your PATH:

```bash
sudo ln -s "$(pwd)/tools/s1pdiff.py" /usr/local/bin/s1pdiff
```

---

## Usage

### Analyse one sweep

```bash
s1pdiff.py analyze antenna.s1p
s1pdiff.py analyze antenna.s1p --band 144 148 --at 146
```

Reports resonance (parabolically interpolated, so it beats your point spacing),
the reactance zero-crossing separately, SWR bandwidth, worst-case SWR, and — with
`--at` — the impedance at an exact frequency plus whether the element reads
electrically long or short.

```
Resonance     : 146.0000 MHz  (VSWR 1.042:1, RL 33.80 dB)
X = 0 crossing: 146.0000 MHz (-0.0000 MHz from SWR minimum)
2:1 bandwidth: 140.0000 - 152.0000 MHz  (12.0000 MHz)  [CLIPPED by sweep edge]

At 146.0000 MHz:
  VSWR        : 1.042:1
  Impedance   : 48.00 + j0.00 ohm
  Character   : resonant (X ~ 0)
```

### Compare against a baseline

```bash
s1pdiff.py diff baseline.s1p current.s1p
s1pdiff.py diff baseline.s1p current.s1p --band 902 928 --warn-db 1.5 --fail-db 3
```

### Machine-readable output

```bash
s1pdiff.py diff base.s1p curr.s1p --format json
s1pdiff.py diff base.s1p curr.s1p --format csv  --out sweep.csv
s1pdiff.py analyze ant.s1p        --format markdown --out report.md
```

The **markdown** output is meant to paste straight into a customer report.

---

## Exit codes

| Code | Meaning |
|---|---|
| **0** | OK — within tolerance |
| **1** | WARN — past `--warn-db`, resonance shift past `--res-warn-pct`, or SWR limit newly exceeded |
| **2** | FAIL — past `--fail-db` |
| **3** | ERROR — bad input, no frequency overlap, unreadable file |

So it drops into a site-visit script or a cron job:

```bash
s1pdiff.py diff baselines/site7_2m.s1p today.s1p --format json \
    --out reports/site7_$(date +%F).json \
  || mail -s "Antenna drift: site 7" jon@pnwcomputers.com < reports/site7_$(date +%F).json
```

---

## Options

| Option | Default | Does |
|---|---|---|
| `--band LO HI` | full file | Restrict analysis to a frequency window (MHz) |
| `--at MHZ` | — | Report VSWR and impedance at one exact frequency |
| `--swr-limit S` | 2.0 | VSWR threshold used for bandwidth figures |
| `--format` | text | `text` · `json` · `markdown` · `csv` |
| `--out FILE` | stdout | Write output to a file |
| `--quiet` | off | Suppress output, rely on exit code |
| `--tol-db DB` | 1.0 | Per-point deviation counted in the segment report |
| `--warn-db DB` | 2.0 | Deviation that triggers WARN |
| `--fail-db DB` | 4.0 | Deviation that triggers FAIL |
| `--res-warn-pct PCT` | 0.5 | Resonance shift that triggers WARN |
| `--rl-ceiling-db DB` | 20.0 | Return loss better than this counts as "well matched" — see below |

### Why `--rl-ceiling-db` exists

Inside a deep null, dB figures swing wildly for physically trivial differences.
A 1.03:1 match reads 36 dB return loss; a 1.04:1 match reads 34 dB. Differencing
those raw would flag 2 dB of "drift" on an antenna that did not meaningfully
change, and every well-matched antenna in your library would throw spurious
warnings.

So both sweeps have their return loss **clamped at the ceiling before
differencing**. Anything better than 20 dB (VSWR 1.22) is simply "well matched"
and contributes zero deviation. Real degradation — 25 dB collapsing to 12 dB —
still registers at full size.

Raise it if you genuinely care about distinctions above 20 dB return loss;
lower it to make the tool less twitchy on marginal installations.

---

## File format support

Touchstone 1.0 one-port files:

- **Formats:** `RI` (real/imaginary), `MA` (magnitude/angle), `DB` (dB/angle)
- **Units:** Hz, kHz, MHz, GHz
- **Reference impedance** read from the option line (`R 50`, `R 75`, …)
- Comments (`!`), blank lines, and Touchstone 2.0 `[Keyword]` lines ignored
- Out-of-order frequency points sorted automatically

Handles NanoVNA-Saver's `# Hz S RI R 50` convention and the H4's on-device SD
card exports.

> **75 Ω systems:** the tool honours the `R` value in the file's option line, so
> a correctly-written 75 Ω `.s1p` is analysed against 75 Ω. If your software
> exports 75 Ω data with a `R 50` header, the SWR figures will be wrong — see
> [10 §10.5](../10-antenna-types-and-special-cases.md#105--75-ohm-antennas-on-a-50-ohm-instrument).

---

## Interpretation caveats

The tool sees only the S11 data it was given. It has no way to know:

- **Where the calibration plane was.** A sweep taken at the shack end of a lossy
  feedline has that loss baked in, and the tool will happily report a flattering
  match.
- **Whether the two sweeps are comparable.** A comparison is only meaningful if
  the calibration plane, cables, adapters, and antenna geometry match the
  baseline run. Record them — that's what the worksheet in
  [11](../11-worksheet-and-exercises.md) is for.
- **Anything about gain, efficiency, pattern, or power handling.** See
  [12 §12.4](../12-sources-and-scope.md#124-scope-of-what-these-procedures-establish).

Resonance is reported two ways — minimum-VSWR frequency *and* reactance
zero-crossing — because they are not always the same frequency, and the gap
between them is itself diagnostic.

---

## Tests

```bash
bash testdata/run_tests.sh
```

14 checks covering both Touchstone formats, both unit conventions, all four
output formats, the three verdict levels, and the error paths. The fixtures in
`testdata/` are synthetic sweeps generated by `testdata/gen.py` from a
series-RLC antenna model — regenerate or extend them freely.

---

## Naming convention for archived sweeps

```
2026-09-18_sitename_2m-base_system-shackend.s1p
2026-09-18_sitename_2m-base_antenna-feedpoint.s1p
2026-09-18_sitename_2m-base_feedline-tdr.png
```

Date first sorts chronologically. Site, antenna, and **measurement plane** in the
name means you never have to guess later which sweep is comparable to which.

---

<div align="center">

[↑ Back to Top](#top) · [NanoVNA Index](../README.md) · [SDR & RF](../../README.md)

</div>
