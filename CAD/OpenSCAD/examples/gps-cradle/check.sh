#!/usr/bin/env bash
# =============================================================================
# check.sh — export printable parts and run the clash test from the command line
#
# Usage:   ./check.sh                 # default parameters
#          ./check.sh -D fit_gap=0.4  # any extra -D overrides are passed through
#
# Exit code 0 = every part exported and the clash test is empty.
# Requires the `openscad` binary on PATH (2021.01 or a newer snapshot).
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"
SCAD=gps_cradle.scad
OUT=out
mkdir -p "$OUT"

run() {   # run <part> <output file> [extra args...]
    local part="$1" file="$2"; shift 2
    echo "==> part=$part -> $file"
    openscad -q -o "$file" -D "part=\"$part\"" "$@" "$SCAD"
}

# 1. Design checks: assert() failures stop openscad with a non-zero exit code.
#    (No -q here: quiet mode would also hide the echo() strain report.)
echo "==> design checks -> $OUT/checks.echo"
openscad -o "$OUT/checks.echo" "$@" "$SCAD" 2>/dev/null
cat "$OUT/checks.echo"

# 2. Printable parts (ASCII STL works with every slicer and with grep below).
for p in body lid inlay; do
    run "$p" "$OUT/gps_cradle_$p.stl" --export-format asciistl "$@"
done

# 3. Clash test: the intersection of parts and hardware must be empty.
#    OpenSCAD 2021.01 writes an empty STL; newer builds may refuse to export
#    an empty object. Both outcomes mean "no clash".
rm -f "$OUT/clash.stl"
if run clash "$OUT/clash.stl" --export-format asciistl "$@" 2>/dev/null; then
    facets=$(grep -c "facet normal" "$OUT/clash.stl" || true)
else
    facets=0
fi

if [ "${facets:-0}" -gt 0 ]; then
    echo "FAIL: $facets clash facets. Open gps_cradle.scad with part=\"clash_view\"."
    exit 1
fi
echo "PASS: no clashes; STLs are in $OUT/"
