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
    openscad --hardwarnings -o "$file" -D "part=\"$part\"" "$@" "$SCAD"
}

# 1. Design checks: assert() failures stop openscad with a non-zero exit code.
#    (No -q here: quiet mode would also hide the echo() strain report.)
echo "==> design checks -> $OUT/checks.echo"
openscad --hardwarnings -o "$OUT/checks.echo" "$@" "$SCAD"
cat "$OUT/checks.echo"

# 2. Printable parts (ASCII STL works with every slicer and with grep below).
for p in body lid inlay; do
    run "$p" "$OUT/gps_cradle_$p.stl" --export-format asciistl "$@"
done

# 3. Clash test: accept an empty ASCII STL or OpenSCAD's explicit empty result.
clash_file="$OUT/clash.stl"
clash_log="$OUT/clash.log"
rm -f "$clash_file"
if LC_ALL=C openscad --hardwarnings -o "$clash_file" \
        --export-format asciistl -D 'part="clash"' "$@" "$SCAD" >"$clash_log" 2>&1; then
    if [[ ! -s "$clash_file" ]] ||
        ! grep -q '^solid[[:space:]]' "$clash_file" ||
        ! grep -q '^endsolid[[:space:]]' "$clash_file"; then
        echo "FAIL: no valid ASCII STL was produced for the clash check. See $clash_log." >&2
        exit 1
    fi
    if grep -q 'facet normal' "$clash_file"; then
        echo 'FAIL: clash facets found. Open gps_cradle.scad with part="clash_view".' >&2
        exit 1
    fi
elif [[ -e "$clash_file" ]] ||
    ! grep -Fxq 'Current top level object is empty.' "$clash_log" ||
    grep -Eq '^(ERROR|WARNING):' "$clash_log"; then
    cat "$clash_log" >&2
    echo "FAIL: clash check could not complete." >&2
    exit 1
fi
echo "PASS: no clashes; STLs are in $OUT/"
