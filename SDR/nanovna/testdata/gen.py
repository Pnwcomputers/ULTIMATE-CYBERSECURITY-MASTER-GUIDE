import math, cmath

def series_rlc(f_mhz, f0_mhz, R, X0):
    """Simple series-resonant antenna model: X = X0*(f/f0 - f0/f)."""
    X = X0 * (f_mhz / f0_mhz - f0_mhz / f_mhz)
    return complex(R, X)

def write(path, f0, R, X0, fstart, fstop, n=201, fmt="RI", unit="Hz"):
    scale = {"Hz": 1.0, "MHz": 1e6}[unit]
    with open(path, "w") as fh:
        fh.write("! Synthetic NanoVNA-style sweep for s1pdiff self-test\n")
        fh.write(f"# {unit} S {fmt} R 50\n")
        for k in range(n):
            f = fstart + (fstop - fstart) * k / (n - 1)
            Z = series_rlc(f, f0, R, X0)
            g = (Z - 50) / (Z + 50)
            fval = f * 1e6 / scale
            if fmt == "RI":
                fh.write(f"{fval:.6f} {g.real:.9f} {g.imag:.9f}\n")
            else:  # MA
                fh.write(f"{fval:.6f} {abs(g):.9f} {math.degrees(cmath.phase(g)):.6f}\n")

# Healthy 2 m vertical: resonant 146.00 MHz, R = 48 ohm
write("base_2m.s1p",  146.00, 48.0, 250.0, 140.0, 152.0)
# Byte-identical conditions, separate file -> must report OK
write("same_2m.s1p",  146.00, 48.0, 250.0, 140.0, 152.0)
# Water ingress: resonance pulled down to 144.60, R up to 62 (loss)
write("wet_2m.s1p",   144.60, 62.0, 250.0, 140.0, 152.0)
# Tiny drift only: 146.05 MHz, R 48.5 -> should stay OK at default thresholds
write("drift_2m.s1p", 146.05, 48.5, 250.0, 140.0, 152.0)
# MA-format + MHz units, same antenna as base -> parser cross-check
write("base_2m_ma.s1p", 146.00, 48.0, 250.0, 140.0, 152.0, fmt="MA", unit="MHz")
# Non-overlapping band -> error path
write("uhf_70cm.s1p", 435.00, 45.0, 700.0, 420.0, 450.0)
# 915 LoRa whip, resonant low at 878 -> analyze --at exercise
write("lora_915.s1p", 878.40, 44.0, 900.0, 850.0, 1000.0)
print("generated")
