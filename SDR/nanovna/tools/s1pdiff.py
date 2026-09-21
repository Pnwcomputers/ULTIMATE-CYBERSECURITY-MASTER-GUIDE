#!/usr/bin/env python3
"""
s1pdiff.py — Touchstone .s1p analyser and baseline comparator for NanoVNA data.

Standalone. Python 3.8+. Standard library only — no numpy, no scikit-rf.

WHAT IT IS FOR
--------------
You sweep an antenna system, export an .s1p, and archive it. Months later you
sweep the same system and want an objective answer to "has anything changed?"
This tool gives you that answer and an exit code you can act on.

USAGE
-----
  Analyse one sweep:
      s1pdiff.py analyze antenna.s1p
      s1pdiff.py analyze antenna.s1p --band 144 148 --at 146

  Compare against a baseline:
      s1pdiff.py diff baseline.s1p current.s1p
      s1pdiff.py diff baseline.s1p current.s1p --band 902 928 --warn-db 1.5 --fail-db 3

  Machine-readable output:
      s1pdiff.py diff base.s1p curr.s1p --format json
      s1pdiff.py analyze ant.s1p --format markdown --out report.md

EXIT CODES
----------
  0  OK        — within tolerance
  1  WARN      — deviation past --warn-db or SWR limit exceeded
  2  FAIL      — deviation past --fail-db
  3  ERROR     — bad input, no frequency overlap, unreadable file

So this drops straight into a cron job or a site-visit script:

      s1pdiff.py diff baselines/site7_2m.s1p today.s1p --format json \
          --out reports/site7_$(date +%F).json || mail -s "Antenna drift: site 7" ...

NOTES ON INTERPRETATION
-----------------------
  * Everything here is computed from the S11 data as presented. If the sweep was
    taken at the shack end of a lossy feedline, that loss is baked into the
    numbers and the tool has no way to know.
  * A comparison is only meaningful if the calibration plane, cables, adapters
    and antenna geometry are the same as the baseline. Record them alongside the
    file.
  * Resonance is reported as the minimum-VSWR frequency (parabolically
    interpolated between sample points) AND, separately, as the reactance
    zero-crossing. They are not always the same frequency; the difference is
    itself diagnostic.
"""

from __future__ import annotations

import argparse
import cmath
import csv
import json
import math
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Sequence, Tuple

__version__ = "1.0.0"

EXIT_OK, EXIT_WARN, EXIT_FAIL, EXIT_ERROR = 0, 1, 2, 3

_UNIT_SCALE = {"HZ": 1.0, "KHZ": 1e3, "MHZ": 1e6, "GHZ": 1e9}


# ----------------------------------------------------------------------------
# Touchstone parsing
# ----------------------------------------------------------------------------

class TouchstoneError(Exception):
    pass


@dataclass
class Sweep:
    """A one-port sweep: frequencies in Hz, reflection coefficients, ref. impedance."""
    path: str
    freqs: List[float] = field(default_factory=list)
    gammas: List[complex] = field(default_factory=list)
    z0: float = 50.0

    def __len__(self) -> int:
        return len(self.freqs)

    @property
    def f_min(self) -> float:
        return self.freqs[0]

    @property
    def f_max(self) -> float:
        return self.freqs[-1]


def read_s1p(path: str) -> Sweep:
    """Parse a Touchstone 1.0 one-port file.

    Handles RI / MA / DB data formats and Hz/kHz/MHz/GHz units. Ignores comment
    lines, blank lines, and Touchstone 2.0 [Keyword] lines. Tolerates the
    NanoVNA/NanoVNA-Saver convention of '# Hz S RI R 50'.
    """
    scale = 1e9          # Touchstone default is GHz
    fmt = "MA"           # Touchstone default is MA
    z0 = 50.0
    freqs: List[float] = []
    gammas: List[complex] = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        raise TouchstoneError(f"cannot read {path}: {exc}") from exc

    for lineno, raw in enumerate(lines, 1):
        line = raw.split("!", 1)[0].strip()
        if not line or line.startswith("["):
            continue

        if line.startswith("#"):
            toks = line[1:].upper().split()
            i = 0
            while i < len(toks):
                t = toks[i]
                if t in _UNIT_SCALE:
                    scale = _UNIT_SCALE[t]
                elif t in ("RI", "MA", "DB"):
                    fmt = t
                elif t == "R":
                    try:
                        z0 = float(toks[i + 1])
                        i += 1
                    except (ValueError, IndexError):
                        raise TouchstoneError(f"{path}:{lineno}: invalid reference impedance")
                    if not math.isfinite(z0) or z0 <= 0:
                        raise TouchstoneError(f"{path}:{lineno}: reference impedance must be finite and positive")
                i += 1
            continue

        parts = line.replace(",", " ").split()
        if len(parts) != 3:
            raise TouchstoneError(f"{path}:{lineno}: expected one frequency and two S11 values")
        try:
            f_hz = float(parts[0]) * scale
            a = float(parts[1])
            b = float(parts[2])
        except ValueError:
            raise TouchstoneError(f"{path}:{lineno}: cannot parse data line: {line!r}")

        if not all(math.isfinite(v) for v in (f_hz, a, b)) or f_hz < 0:
            raise TouchstoneError(f"{path}:{lineno}: measurements must be finite with nonnegative frequency")
        if fmt == "MA" and a < 0:
            raise TouchstoneError(f"{path}:{lineno}: magnitude cannot be negative")
        try:
            if fmt == "RI":
                g = complex(a, b)
            elif fmt == "MA":
                g = cmath.rect(a, math.radians(b))
            else:  # DB
                g = cmath.rect(10.0 ** (a / 20.0), math.radians(b))
        except (OverflowError, ValueError) as exc:
            raise TouchstoneError(f"{path}:{lineno}: invalid reflection coefficient") from exc
        if not all(math.isfinite(v) for v in (g.real, g.imag, abs(g))):
            raise TouchstoneError(f"{path}:{lineno}: nonfinite reflection coefficient")

        freqs.append(f_hz)
        gammas.append(g)

    if not freqs:
        raise TouchstoneError(f"{path}: no data points found")
    if len(set(freqs)) != len(freqs):
        raise TouchstoneError(f"{path}: duplicate frequencies")
    if any(b < a for a, b in zip(freqs, freqs[1:])):
        pairs = sorted(zip(freqs, gammas))
        freqs = [p[0] for p in pairs]
        gammas = [p[1] for p in pairs]

    return Sweep(path=path, freqs=freqs, gammas=gammas, z0=z0)


# ----------------------------------------------------------------------------
# RF maths
# ----------------------------------------------------------------------------

def gamma_mag(g: complex) -> float:
    return abs(g)


def vswr(g: complex) -> float:
    m = abs(g)
    if m >= 1.0:
        return float("inf")
    return (1.0 + m) / (1.0 - m)


def return_loss_db(g: complex) -> float:
    """Return loss as a POSITIVE dB figure. Larger = better match."""
    m = abs(g)
    if m <= 1e-12:
        return float("inf")
    return -20.0 * math.log10(min(m, 1.0))


def impedance(g: complex, z0: float = 50.0) -> complex:
    denom = 1.0 - g
    if abs(denom) < 1e-15:
        return complex(float("inf"), 0.0)
    return z0 * (1.0 + g) / denom


def vswr_to_gamma(s: float) -> float:
    return (s - 1.0) / (s + 1.0)


# ----------------------------------------------------------------------------
# Sweep manipulation
# ----------------------------------------------------------------------------

def slice_band(sw: Sweep, f_lo: Optional[float], f_hi: Optional[float]) -> Sweep:
    """Return a new Sweep restricted to [f_lo, f_hi] in Hz. None = unbounded."""
    lo = -math.inf if f_lo is None else f_lo
    hi = math.inf if f_hi is None else f_hi
    fs, gs = [], []
    for f, g in zip(sw.freqs, sw.gammas):
        if lo <= f <= hi:
            fs.append(f)
            gs.append(g)
    if not fs:
        raise TouchstoneError(
            f"{sw.path}: no points inside {lo/1e6:.3f}-{hi/1e6:.3f} MHz "
            f"(file covers {sw.f_min/1e6:.3f}-{sw.f_max/1e6:.3f} MHz)"
        )
    return Sweep(path=sw.path, freqs=fs, gammas=gs, z0=sw.z0)


def interp_gamma(sw: Sweep, f_target: float) -> Optional[complex]:
    """Linear interpolation of the complex reflection coefficient."""
    fs = sw.freqs
    if f_target < fs[0] or f_target > fs[-1]:
        return None
    lo, hi = 0, len(fs) - 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if fs[mid] <= f_target:
            lo = mid
        else:
            hi = mid
    f0, f1 = fs[lo], fs[hi]
    if f1 == f0:
        return sw.gammas[lo]
    t = (f_target - f0) / (f1 - f0)
    g0, g1 = sw.gammas[lo], sw.gammas[hi]
    return complex(
        g0.real + t * (g1.real - g0.real),
        g0.imag + t * (g1.imag - g0.imag),
    )


def resample(sw: Sweep, grid: Sequence[float]) -> Sweep:
    fs, gs = [], []
    for f in grid:
        g = interp_gamma(sw, f)
        if g is not None:
            fs.append(f)
            gs.append(g)
    if not fs:
        raise TouchstoneError(f"{sw.path}: resample produced no points")
    return Sweep(path=sw.path, freqs=fs, gammas=gs, z0=sw.z0)


# ----------------------------------------------------------------------------
# Feature extraction
# ----------------------------------------------------------------------------

def find_resonance(sw: Sweep) -> Tuple[float, float, float]:
    """Minimum-|Gamma| point, refined by parabolic fit.

    Returns (frequency_hz, vswr_at_min, return_loss_db_at_min).
    """
    mags = [abs(g) for g in sw.gammas]
    i = min(range(len(mags)), key=lambda k: mags[k])
    f_res = sw.freqs[i]

    if 0 < i < len(mags) - 1:
        y0, y1, y2 = mags[i - 1], mags[i], mags[i + 1]
        denom = y0 - 2.0 * y1 + y2
        if abs(denom) > 1e-18:
            offset = 0.5 * (y0 - y2) / denom
            if -1.0 < offset < 1.0:
                step_lo = sw.freqs[i] - sw.freqs[i - 1]
                step_hi = sw.freqs[i + 1] - sw.freqs[i]
                step = step_hi if offset >= 0 else step_lo
                f_res = sw.freqs[i] + offset * step

    g = interp_gamma(sw, f_res)
    if g is None:
        g = sw.gammas[i]
    return f_res, vswr(g), return_loss_db(g)


def find_reactance_zero(sw: Sweep) -> Optional[float]:
    """Frequency of the first negative->positive reactance crossing (series resonance)."""
    xs = [impedance(g, sw.z0).imag for g in sw.gammas]
    for i in range(len(xs) - 1):
        x0, x1 = xs[i], xs[i + 1]
        if math.isinf(x0) or math.isinf(x1) or math.isnan(x0) or math.isnan(x1):
            continue
        if x0 < 0.0 <= x1:
            if x1 == x0:
                return sw.freqs[i]
            t = -x0 / (x1 - x0)
            return sw.freqs[i] + t * (sw.freqs[i + 1] - sw.freqs[i])
    return None


def find_bandwidth(sw: Sweep, limit: float = 2.0) -> Optional[Tuple[float, float]]:
    """Contiguous span around the SWR minimum where VSWR <= limit.

    Returns (f_low_hz, f_high_hz), or None if the minimum never gets under the
    limit. Edges are linearly interpolated in VSWR. If the passband runs off the
    end of the sweep, that end is reported as the sweep edge (see caller note).
    """
    swrs = [vswr(g) for g in sw.gammas]
    i = min(range(len(swrs)), key=lambda k: swrs[k])
    if swrs[i] > limit:
        return None

    def cross(a_idx: int, b_idx: int) -> float:
        ya, yb = swrs[a_idx], swrs[b_idx]
        fa, fb = sw.freqs[a_idx], sw.freqs[b_idx]
        if math.isinf(ya) or math.isinf(yb) or yb == ya:
            return fb
        t = (limit - ya) / (yb - ya)
        t = max(0.0, min(1.0, t))
        return fa + t * (fb - fa)

    lo_i = i
    while lo_i > 0 and swrs[lo_i - 1] <= limit:
        lo_i -= 1
    f_lo = sw.freqs[0] if lo_i == 0 else cross(lo_i, lo_i - 1)

    hi_i = i
    n = len(swrs)
    while hi_i < n - 1 and swrs[hi_i + 1] <= limit:
        hi_i += 1
    f_hi = sw.freqs[-1] if hi_i == n - 1 else cross(hi_i, hi_i + 1)

    return f_lo, f_hi


@dataclass
class Summary:
    path: str
    z0: float
    points: int
    f_start_mhz: float
    f_stop_mhz: float
    resonance_mhz: float
    resonance_vswr: float
    resonance_rl_db: float
    reactance_zero_mhz: Optional[float]
    bw2_low_mhz: Optional[float]
    bw2_high_mhz: Optional[float]
    bw2_width_mhz: Optional[float]
    bw2_clipped: bool
    at_freq_mhz: Optional[float] = None
    at_vswr: Optional[float] = None
    at_rl_db: Optional[float] = None
    at_r_ohm: Optional[float] = None
    at_x_ohm: Optional[float] = None
    worst_vswr: float = 0.0
    worst_vswr_mhz: float = 0.0


def summarise(sw: Sweep, at_hz: Optional[float] = None,
              swr_limit: float = 2.0) -> Summary:
    f_res, v_res, rl_res = find_resonance(sw)
    xz = find_reactance_zero(sw)
    bw = find_bandwidth(sw, swr_limit)

    clipped = False
    if bw is not None:
        clipped = (abs(bw[0] - sw.f_min) < 1e-9) or (abs(bw[1] - sw.f_max) < 1e-9)

    swrs = [vswr(g) for g in sw.gammas]
    wi = max(range(len(swrs)), key=lambda k: swrs[k])

    s = Summary(
        path=sw.path,
        z0=sw.z0,
        points=len(sw),
        f_start_mhz=sw.f_min / 1e6,
        f_stop_mhz=sw.f_max / 1e6,
        resonance_mhz=f_res / 1e6,
        resonance_vswr=v_res,
        resonance_rl_db=rl_res,
        reactance_zero_mhz=(xz / 1e6) if xz is not None else None,
        bw2_low_mhz=(bw[0] / 1e6) if bw else None,
        bw2_high_mhz=(bw[1] / 1e6) if bw else None,
        bw2_width_mhz=((bw[1] - bw[0]) / 1e6) if bw else None,
        bw2_clipped=clipped,
        worst_vswr=swrs[wi],
        worst_vswr_mhz=sw.freqs[wi] / 1e6,
    )

    if at_hz is not None:
        g = interp_gamma(sw, at_hz)
        if g is not None:
            z = impedance(g, sw.z0)
            s.at_freq_mhz = at_hz / 1e6
            s.at_vswr = vswr(g)
            s.at_rl_db = return_loss_db(g)
            s.at_r_ohm = z.real
            s.at_x_ohm = z.imag
    return s


# ----------------------------------------------------------------------------
# Comparison
# ----------------------------------------------------------------------------

@dataclass
class Segment:
    f_low_mhz: float
    f_high_mhz: float
    max_delta_db: float
    at_mhz: float


@dataclass
class DiffResult:
    baseline: Summary
    current: Summary
    overlap_low_mhz: float
    overlap_high_mhz: float
    compared_points: int
    resonance_shift_mhz: float
    resonance_shift_pct: float
    vswr_delta: float
    max_rl_delta_db: float
    max_rl_delta_mhz: float
    mean_abs_rl_delta_db: float
    rms_rl_delta_db: float
    points_over_tol: int
    pct_over_tol: float
    tol_db: float
    warn_db: float
    fail_db: float
    rl_ceiling_db: float
    segments: List[Segment]
    verdict: str
    reasons: List[str]


def diff_sweeps(base: Sweep, curr: Sweep, tol_db: float, warn_db: float,
                fail_db: float, at_hz: Optional[float], swr_limit: float,
                res_warn_pct: float, rl_ceiling_db: float = 20.0) -> DiffResult:
    lo = max(base.f_min, curr.f_min)
    hi = min(base.f_max, curr.f_max)
    if hi <= lo:
        raise TouchstoneError(
            "no frequency overlap between the two sweeps "
            f"({base.f_min/1e6:.3f}-{base.f_max/1e6:.3f} MHz vs "
            f"{curr.f_min/1e6:.3f}-{curr.f_max/1e6:.3f} MHz)"
        )

    grid = [f for f in base.freqs if lo <= f <= hi]
    if len(grid) < 3:
        grid = [lo + (hi - lo) * k / 200.0 for k in range(201)]

    b = resample(base, grid)
    c = resample(curr, grid)

    b_sum = summarise(b, at_hz, swr_limit)
    c_sum = summarise(c, at_hz, swr_limit)

    # Return loss is clamped at a ceiling before differencing. Inside a deep
    # null, dB figures swing wildly for physically trivial differences: a
    # 1.03:1 match reads 36 dB and a 1.04:1 match reads 34 dB, and flagging
    # that 2 dB as "drift" is noise. Anything better than the ceiling is
    # simply "well matched" and contributes no deviation. Real degradation --
    # 25 dB collapsing to 12 dB -- still registers in full.
    def clamped_rl(g: complex) -> float:
        rl = return_loss_db(g)
        if math.isinf(rl):
            return rl_ceiling_db
        return min(rl, rl_ceiling_db)

    deltas: List[float] = []
    for gb, gc in zip(b.gammas, c.gammas):
        deltas.append(clamped_rl(gc) - clamped_rl(gb))

    abs_d = [abs(d) for d in deltas]
    wi = max(range(len(abs_d)), key=lambda k: abs_d[k])
    max_d = deltas[wi]
    max_f = b.freqs[wi] / 1e6
    mean_abs = sum(abs_d) / len(abs_d)
    rms = math.sqrt(sum(d * d for d in deltas) / len(deltas))
    over = sum(1 for d in abs_d if d > tol_db)

    segments: List[Segment] = []
    in_seg = False
    seg_start = 0
    for idx, d in enumerate(abs_d):
        if d > tol_db and not in_seg:
            in_seg, seg_start = True, idx
        elif d <= tol_db and in_seg:
            segments.append(_make_segment(b.freqs, deltas, seg_start, idx - 1))
            in_seg = False
    if in_seg:
        segments.append(_make_segment(b.freqs, deltas, seg_start, len(abs_d) - 1))
    segments.sort(key=lambda s: abs(s.max_delta_db), reverse=True)
    segments = segments[:5]

    shift_hz = (c_sum.resonance_mhz - b_sum.resonance_mhz) * 1e6
    shift_pct = (shift_hz / (b_sum.resonance_mhz * 1e6) * 100.0
                 if b_sum.resonance_mhz else 0.0)

    verdict = "OK"
    reasons: List[str] = []

    if max(abs_d) > fail_db:
        verdict = "FAIL"
        reasons.append(f"return loss moved {max_d:+.2f} dB at {max_f:.3f} MHz "
                       f"(fail threshold {fail_db:.1f} dB)")
    elif max(abs_d) > warn_db:
        verdict = "WARN"
        reasons.append(f"return loss moved {max_d:+.2f} dB at {max_f:.3f} MHz "
                       f"(warn threshold {warn_db:.1f} dB)")

    if abs(shift_pct) > res_warn_pct:
        reasons.append(f"resonance shifted {shift_hz/1e6:+.3f} MHz "
                       f"({shift_pct:+.2f}%, threshold ±{res_warn_pct:.2f}%)")
        if verdict == "OK":
            verdict = "WARN"

    if c_sum.resonance_vswr > swr_limit >= b_sum.resonance_vswr:
        reasons.append(f"best VSWR is now {c_sum.resonance_vswr:.2f}:1, "
                       f"was {b_sum.resonance_vswr:.2f}:1 "
                       f"(limit {swr_limit:.2f}:1)")
        if verdict == "OK":
            verdict = "WARN"

    if not reasons:
        reasons.append("within tolerance on all checks")

    return DiffResult(
        baseline=b_sum, current=c_sum,
        overlap_low_mhz=lo / 1e6, overlap_high_mhz=hi / 1e6,
        compared_points=len(grid),
        resonance_shift_mhz=shift_hz / 1e6,
        resonance_shift_pct=shift_pct,
        vswr_delta=c_sum.resonance_vswr - b_sum.resonance_vswr,
        max_rl_delta_db=max_d, max_rl_delta_mhz=max_f,
        mean_abs_rl_delta_db=mean_abs, rms_rl_delta_db=rms,
        points_over_tol=over, pct_over_tol=100.0 * over / len(abs_d),
        tol_db=tol_db, warn_db=warn_db, fail_db=fail_db,
        rl_ceiling_db=rl_ceiling_db,
        segments=segments, verdict=verdict, reasons=reasons,
    )


def _make_segment(freqs: Sequence[float], deltas: Sequence[float],
                  i0: int, i1: int) -> Segment:
    best = i0
    for k in range(i0, i1 + 1):
        if abs(deltas[k]) > abs(deltas[best]):
            best = k
    return Segment(
        f_low_mhz=freqs[i0] / 1e6,
        f_high_mhz=freqs[i1] / 1e6,
        max_delta_db=deltas[best],
        at_mhz=freqs[best] / 1e6,
    )


# ----------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------

def _fmt(v: Optional[float], spec: str = ".3f", dash: str = "—") -> str:
    if v is None or (isinstance(v, float) and (math.isnan(v) or math.isinf(v))):
        return dash
    return format(v, spec)


def render_summary_text(s: Summary, swr_limit: float) -> str:
    L = []
    L.append(f"File          : {s.path}")
    L.append(f"Reference Z0  : {s.z0:.1f} ohm")
    L.append(f"Points        : {s.points}")
    L.append(f"Span          : {s.f_start_mhz:.4f} - {s.f_stop_mhz:.4f} MHz")
    L.append("")
    L.append(f"Resonance     : {s.resonance_mhz:.4f} MHz  "
             f"(VSWR {_fmt(s.resonance_vswr, '.3f')}:1, "
             f"RL {_fmt(s.resonance_rl_db, '.2f')} dB)")
    if s.reactance_zero_mhz is not None:
        drift = s.reactance_zero_mhz - s.resonance_mhz
        L.append(f"X = 0 crossing: {s.reactance_zero_mhz:.4f} MHz "
                 f"({drift:+.4f} MHz from SWR minimum)")
    else:
        L.append("X = 0 crossing: not found in this span")

    if s.bw2_width_mhz is not None:
        clip = "  [CLIPPED by sweep edge]" if s.bw2_clipped else ""
        L.append(f"{swr_limit:g}:1 bandwidth: {s.bw2_low_mhz:.4f} - "
                 f"{s.bw2_high_mhz:.4f} MHz  "
                 f"({s.bw2_width_mhz:.4f} MHz){clip}")
    else:
        L.append(f"{swr_limit:g}:1 bandwidth: none — VSWR never drops below "
                 f"{swr_limit:g}:1 in this span")

    L.append(f"Worst VSWR    : {_fmt(s.worst_vswr, '.2f')}:1 "
             f"at {s.worst_vswr_mhz:.4f} MHz")

    if s.at_freq_mhz is not None:
        sign = "+" if (s.at_x_ohm or 0) >= 0 else "-"
        L.append("")
        L.append(f"At {s.at_freq_mhz:.4f} MHz:")
        L.append(f"  VSWR        : {_fmt(s.at_vswr, '.3f')}:1")
        L.append(f"  Return loss : {_fmt(s.at_rl_db, '.2f')} dB")
        L.append(f"  Impedance   : {_fmt(s.at_r_ohm, '.2f')} "
                 f"{sign} j{_fmt(abs(s.at_x_ohm or 0.0), '.2f')} ohm")
        if s.at_x_ohm is not None:
            if s.at_x_ohm > 1.0:
                L.append("  Character   : inductive — element electrically LONG")
            elif s.at_x_ohm < -1.0:
                L.append("  Character   : capacitive — element electrically SHORT")
            else:
                L.append("  Character   : resonant (X ~ 0)")
    return "\n".join(L)


def render_diff_text(d: DiffResult, swr_limit: float) -> str:
    bar = "=" * 68
    L = [bar, f"  S1P COMPARISON — verdict: {d.verdict}", bar, ""]
    L.append(f"Baseline : {d.baseline.path}")
    L.append(f"Current  : {d.current.path}")
    L.append(f"Overlap  : {d.overlap_low_mhz:.4f} - {d.overlap_high_mhz:.4f} MHz "
             f"({d.compared_points} points compared)")
    L.append("")
    L.append("KEY FIGURES")
    L.append("-" * 68)
    L.append(f"{'':22s} {'baseline':>14s} {'current':>14s} {'delta':>14s}")
    L.append(f"{'Resonance (MHz)':22s} "
             f"{d.baseline.resonance_mhz:>14.4f} "
             f"{d.current.resonance_mhz:>14.4f} "
             f"{d.resonance_shift_mhz:>+14.4f}")
    L.append(f"{'  as percent':22s} {'':>14s} {'':>14s} "
             f"{d.resonance_shift_pct:>+13.3f}%")
    L.append(f"{'VSWR at resonance':22s} "
             f"{_fmt(d.baseline.resonance_vswr, '.3f'):>14s} "
             f"{_fmt(d.current.resonance_vswr, '.3f'):>14s} "
             f"{d.vswr_delta:>+14.3f}")
    L.append(f"{'RL at resonance (dB)':22s} "
             f"{_fmt(d.baseline.resonance_rl_db, '.2f'):>14s} "
             f"{_fmt(d.current.resonance_rl_db, '.2f'):>14s} "
             f"{'':>14s}")
    _bclip = ">" if d.baseline.bw2_clipped else ""
    _cclip = ">" if d.current.bw2_clipped else ""
    L.append(f"{f'{swr_limit:g}:1 BW (MHz)':22s} "
             f"{_bclip + _fmt(d.baseline.bw2_width_mhz, '.4f'):>14s} "
             f"{_cclip + _fmt(d.current.bw2_width_mhz, '.4f'):>14s} "
             f"{'':>14s}")
    if d.baseline.bw2_clipped or d.current.bw2_clipped:
        L.append(f"{'':22s} ('>' = ran off the edge of the sweep; "
                 f"true bandwidth is wider)")
    L.append("")
    L.append("RETURN-LOSS DEVIATION ACROSS THE BAND")
    L.append("-" * 68)
    L.append(f"  (return loss clamped at {d.rl_ceiling_db:.1f} dB before "
             f"differencing --")
    L.append(f"   better than that is just 'well matched' either way)")
    L.append(f"  Largest deviation : {d.max_rl_delta_db:+.2f} dB "
             f"at {d.max_rl_delta_mhz:.4f} MHz")
    L.append(f"  Mean |deviation|  : {d.mean_abs_rl_delta_db:.2f} dB")
    L.append(f"  RMS deviation     : {d.rms_rl_delta_db:.2f} dB")
    L.append(f"  Points over {d.tol_db:.1f} dB : {d.points_over_tol} "
             f"of {d.compared_points} ({d.pct_over_tol:.1f}%)")

    if d.segments:
        L.append("")
        L.append(f"  Segments exceeding {d.tol_db:.1f} dB (worst first):")
        for s in d.segments:
            L.append(f"    {s.f_low_mhz:10.4f} - {s.f_high_mhz:10.4f} MHz   "
                     f"peak {s.max_delta_db:+7.2f} dB at {s.at_mhz:.4f} MHz")

    if d.baseline.at_freq_mhz is not None:
        b, c = d.baseline, d.current
        L.append("")
        L.append(f"AT {b.at_freq_mhz:.4f} MHz")
        L.append("-" * 68)
        L.append(f"  VSWR      : {_fmt(b.at_vswr,'.3f')}:1  ->  "
                 f"{_fmt(c.at_vswr,'.3f')}:1")
        bs = "+" if (b.at_x_ohm or 0) >= 0 else "-"
        cs = "+" if (c.at_x_ohm or 0) >= 0 else "-"
        L.append(f"  Impedance : {_fmt(b.at_r_ohm,'.1f')} {bs} "
                 f"j{_fmt(abs(b.at_x_ohm or 0),'.1f')}  ->  "
                 f"{_fmt(c.at_r_ohm,'.1f')} {cs} "
                 f"j{_fmt(abs(c.at_x_ohm or 0),'.1f')} ohm")

    L.append("")
    L.append("VERDICT")
    L.append("-" * 68)
    for r in d.reasons:
        L.append(f"  [{d.verdict}] {r}")

    if d.verdict != "OK":
        L.append("")
        L.append("  Likely physical causes to check, in order:")
        if d.resonance_shift_mhz < 0:
            L.append("    - Resonance DOWN: water in the coax or connector, ice,")
            L.append("      added conductor near the element, corrosion adding")
            L.append("      series inductance, element loosened and lengthened.")
        elif d.resonance_shift_mhz > 0:
            L.append("    - Resonance UP: element shortened or broken, radial or")
            L.append("      counterpoise lost, ground-plane bond degraded.")
        L.append("    - Flat loss increase with no resonance shift: feedline")
        L.append("      degradation. Run a TDR sweep and a shorted-end loss check.")
        L.append("    - Before concluding anything: confirm the calibration plane,")
        L.append("      cables and adapters match the baseline run.")

    L.append("")
    L.append(bar)
    return "\n".join(L)


def render_diff_markdown(d: DiffResult, swr_limit: float) -> str:
    L = [f"# S11 baseline comparison — **{d.verdict}**", ""]
    L.append(f"- **Baseline:** `{d.baseline.path}`")
    L.append(f"- **Current:** `{d.current.path}`")
    L.append(f"- **Overlap:** {d.overlap_low_mhz:.4f} – {d.overlap_high_mhz:.4f} MHz "
             f"({d.compared_points} points)")
    L.append("")
    L.append("## Key figures")
    L.append("")
    L.append("| Metric | Baseline | Current | Delta |")
    L.append("|---|---:|---:|---:|")
    L.append(f"| Resonance (MHz) | {d.baseline.resonance_mhz:.4f} | "
             f"{d.current.resonance_mhz:.4f} | {d.resonance_shift_mhz:+.4f} "
             f"({d.resonance_shift_pct:+.2f}%) |")
    L.append(f"| VSWR at resonance | {_fmt(d.baseline.resonance_vswr,'.3f')}:1 | "
             f"{_fmt(d.current.resonance_vswr,'.3f')}:1 | {d.vswr_delta:+.3f} |")
    L.append(f"| RL at resonance (dB) | {_fmt(d.baseline.resonance_rl_db,'.2f')} | "
             f"{_fmt(d.current.resonance_rl_db,'.2f')} | |")
    _bc = "&gt;" if d.baseline.bw2_clipped else ""
    _cc = "&gt;" if d.current.bw2_clipped else ""
    L.append(f"| {swr_limit:g}:1 bandwidth (MHz) | "
             f"{_bc}{_fmt(d.baseline.bw2_width_mhz,'.4f')} | "
             f"{_cc}{_fmt(d.current.bw2_width_mhz,'.4f')} | |")
    if d.baseline.bw2_clipped or d.current.bw2_clipped:
        L.append("")
        L.append("> `>` on a bandwidth figure means it ran off the edge of "
                 "the sweep — the true bandwidth is wider than shown.")
    L.append("")
    L.append("## Return-loss deviation")
    L.append("")
    L.append(f"- Largest deviation: **{d.max_rl_delta_db:+.2f} dB** "
             f"at {d.max_rl_delta_mhz:.4f} MHz")
    L.append(f"- Mean |deviation|: {d.mean_abs_rl_delta_db:.2f} dB · "
             f"RMS {d.rms_rl_delta_db:.2f} dB")
    L.append(f"- Points beyond {d.tol_db:.1f} dB: {d.points_over_tol} / "
             f"{d.compared_points} ({d.pct_over_tol:.1f}%)")
    if d.segments:
        L.append("")
        L.append("| Segment (MHz) | Peak deviation | At (MHz) |")
        L.append("|---|---:|---:|")
        for s in d.segments:
            L.append(f"| {s.f_low_mhz:.4f} – {s.f_high_mhz:.4f} | "
                     f"{s.max_delta_db:+.2f} dB | {s.at_mhz:.4f} |")
    L.append("")
    L.append("## Verdict")
    L.append("")
    for r in d.reasons:
        L.append(f"- **{d.verdict}** — {r}")
    L.append("")
    L.append("> Comparison is only valid if the calibration plane, cables, "
             "adapters and antenna geometry match the baseline run.")
    return "\n".join(L)


def render_csv(sw_b: Sweep, sw_c: Optional[Sweep], out) -> None:
    w = csv.writer(out)
    if sw_c is None:
        w.writerow(["freq_mhz", "vswr", "return_loss_db", "r_ohm", "x_ohm",
                    "gamma_re", "gamma_im"])
        for f, g in zip(sw_b.freqs, sw_b.gammas):
            z = impedance(g, sw_b.z0)
            w.writerow([f"{f/1e6:.6f}", f"{vswr(g):.4f}",
                        f"{return_loss_db(g):.3f}", f"{z.real:.3f}",
                        f"{z.imag:.3f}", f"{g.real:.6f}", f"{g.imag:.6f}"])
    else:
        w.writerow(["freq_mhz", "vswr_base", "vswr_curr", "rl_base_db",
                    "rl_curr_db", "rl_delta_db", "r_base", "x_base",
                    "r_curr", "x_curr"])
        for f, gb, gc in zip(sw_b.freqs, sw_b.gammas, sw_c.gammas):
            zb, zc = impedance(gb, sw_b.z0), impedance(gc, sw_c.z0)
            rb, rc = return_loss_db(gb), return_loss_db(gc)
            delta = 0.0 if (math.isinf(rb) or math.isinf(rc)) else rc - rb
            w.writerow([f"{f/1e6:.6f}", f"{vswr(gb):.4f}", f"{vswr(gc):.4f}",
                        f"{rb:.3f}", f"{rc:.3f}", f"{delta:+.3f}",
                        f"{zb.real:.3f}", f"{zb.imag:.3f}",
                        f"{zc.real:.3f}", f"{zc.imag:.3f}"])


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def _band_to_hz(band: Optional[Sequence[float]]) -> Tuple[Optional[float], Optional[float]]:
    if not band:
        return None, None
    return band[0] * 1e6, band[1] * 1e6


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="s1pdiff.py",
        description="Analyse a NanoVNA .s1p sweep, or compare one against a baseline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 0 OK, 1 WARN, 2 FAIL, 3 ERROR.",
    )
    p.add_argument("--version", action="version",
                   version=f"s1pdiff.py {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--band", nargs=2, type=float, metavar=("START_MHZ", "STOP_MHZ"),
                        help="restrict analysis to this frequency window")
        sp.add_argument("--at", type=float, metavar="MHZ",
                        help="report VSWR and impedance at this exact frequency")
        sp.add_argument("--swr-limit", type=float, default=2.0, metavar="S",
                        help="VSWR threshold for bandwidth (default 2.0)")
        sp.add_argument("--format", choices=("text", "json", "markdown", "csv"),
                        default="text", help="output format (default text)")
        sp.add_argument("--out", metavar="FILE", help="write output to FILE")
        sp.add_argument("--quiet", action="store_true",
                        help="suppress output; rely on the exit code")

    a = sub.add_parser("analyze", aliases=["analyse"],
                       help="summarise a single .s1p file")
    a.add_argument("file")
    common(a)

    d = sub.add_parser("diff", help="compare a current sweep against a baseline")
    d.add_argument("baseline")
    d.add_argument("current")
    common(d)
    d.add_argument("--tol-db", type=float, default=1.0, metavar="DB",
                   help="per-point return-loss tolerance for segment "
                        "reporting (default 1.0)")
    d.add_argument("--warn-db", type=float, default=2.0, metavar="DB",
                   help="return-loss deviation that triggers WARN (default 2.0)")
    d.add_argument("--fail-db", type=float, default=4.0, metavar="DB",
                   help="return-loss deviation that triggers FAIL (default 4.0)")
    d.add_argument("--res-warn-pct", type=float, default=0.5, metavar="PCT",
                   help="resonance shift that triggers WARN, in percent "
                        "(default 0.5)")
    d.add_argument("--rl-ceiling-db", type=float, default=20.0, metavar="DB",
                   help="return loss better than this counts as simply "
                        "'well matched'; deviations above it are ignored, so "
                        "deep-null jitter does not read as drift "
                        "(default 20.0, i.e. VSWR 1.22)")
    return p


def json_safe(value):
    """Represent unbounded RF results (e.g. open-circuit VSWR) as JSON null."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    f_lo, f_hi = _band_to_hz(args.band)
    at_hz = args.at * 1e6 if args.at is not None else None

    try:
        for name, value in vars(args).items():
            values = value if isinstance(value, list) else [value]
            if any(isinstance(v, float) and not math.isfinite(v) for v in values):
                raise TouchstoneError(f"{name}: numeric options must be finite")
        if args.swr_limit <= 1:
            raise TouchstoneError("SWR limit must be greater than 1")
        if args.band and not 0 <= args.band[0] < args.band[1]:
            raise TouchstoneError("band must have nonnegative start below stop")
        if args.at is not None and args.at < 0:
            raise TouchstoneError("frequency must be nonnegative")
        if args.cmd == "diff":
            if args.tol_db < 0 or not 0 <= args.warn_db <= args.fail_db:
                raise TouchstoneError("require nonnegative tolerance and 0 <= warning <= failure threshold")
            if args.res_warn_pct < 0 or args.rl_ceiling_db <= 0:
                raise TouchstoneError("invalid resonance threshold or return-loss ceiling")
        if args.cmd in ("analyze", "analyse"):
            sw = read_s1p(args.file)
            if args.band:
                sw = slice_band(sw, f_lo, f_hi)
            s = summarise(sw, at_hz, args.swr_limit)

            if args.format == "json":
                text = json.dumps(json_safe(asdict(s)), indent=2, allow_nan=False)
            elif args.format == "markdown":
                text = "# Sweep summary\n\n```\n" + \
                       render_summary_text(s, args.swr_limit) + "\n```\n"
            elif args.format == "csv":
                import io
                buf = io.StringIO()
                render_csv(sw, None, buf)
                text = buf.getvalue()
            else:
                text = render_summary_text(s, args.swr_limit)

            _emit(text, args)
            return EXIT_OK

        # diff
        base = read_s1p(args.baseline)
        curr = read_s1p(args.current)
        if args.band:
            base = slice_band(base, f_lo, f_hi)
            curr = slice_band(curr, f_lo, f_hi)

        result = diff_sweeps(base, curr, args.tol_db, args.warn_db,
                             args.fail_db, at_hz, args.swr_limit,
                             args.res_warn_pct, args.rl_ceiling_db)

        if args.format == "json":
            text = json.dumps(json_safe(asdict(result)), indent=2, allow_nan=False)
        elif args.format == "markdown":
            text = render_diff_markdown(result, args.swr_limit)
        elif args.format == "csv":
            import io
            lo = max(base.f_min, curr.f_min)
            hi = min(base.f_max, curr.f_max)
            grid = [f for f in base.freqs if lo <= f <= hi]
            buf = io.StringIO()
            render_csv(resample(base, grid), resample(curr, grid), buf)
            text = buf.getvalue()
        else:
            text = render_diff_text(result, args.swr_limit)

        _emit(text, args)
        return {"OK": EXIT_OK, "WARN": EXIT_WARN, "FAIL": EXIT_FAIL}[result.verdict]

    except TouchstoneError as exc:
        print(f"s1pdiff: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR


def _emit(text: str, args) -> None:
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        if not args.quiet:
            print(f"written: {args.out}")
    elif not args.quiet:
        print(text)


if __name__ == "__main__":
    sys.exit(main())
