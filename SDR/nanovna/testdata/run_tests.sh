#!/usr/bin/env bash
# Regression suite for s1pdiff.py. Run from the guide root: bash testdata/run_tests.sh
cd "$(dirname "$0")/.." || exit 1
T=testdata; P="python3 tools/s1pdiff.py"; pass=0; fail=0

check() { # name expected_exit command...
  local name="$1" want="$2"; shift 2
  "$@" >/dev/null 2>&1; local got=$?
  if [ "$got" = "$want" ]; then echo "  PASS  $name"; pass=$((pass+1))
  else echo "  FAIL  $name (expected exit $want, got $got)"; fail=$((fail+1)); fi
}

echo "s1pdiff regression suite"
check "analyze RI/Hz"            0 $P analyze $T/base_2m.s1p --quiet
check "analyze MA/MHz"           0 $P analyze $T/base_2m_ma.s1p --quiet
check "analyze --at off-band"    0 $P analyze $T/lora_915.s1p --at 915 --quiet
check "diff identical"           0 $P diff $T/base_2m.s1p $T/same_2m.s1p --quiet
check "diff trivial drift"       0 $P diff $T/base_2m.s1p $T/drift_2m.s1p --quiet
check "diff RI vs MA same ant"   0 $P diff $T/base_2m.s1p $T/base_2m_ma.s1p --quiet
check "diff real fault"          2 $P diff $T/base_2m.s1p $T/wet_2m.s1p --quiet
check "diff tightened warn"      1 $P diff $T/base_2m.s1p $T/wet_2m.s1p --quiet --warn-db 1 --fail-db 99 --res-warn-pct 99
check "no frequency overlap"     3 $P diff $T/base_2m.s1p $T/uhf_70cm.s1p --quiet
check "band outside data"        3 $P analyze $T/base_2m.s1p --band 900 950 --quiet
check "missing file"             3 $P analyze $T/nope.s1p --quiet
check "json format"              2 $P diff $T/base_2m.s1p $T/wet_2m.s1p --format json --quiet
check "csv format"               2 $P diff $T/base_2m.s1p $T/wet_2m.s1p --format csv --quiet
check "markdown format"          2 $P diff $T/base_2m.s1p $T/wet_2m.s1p --format markdown --quiet

echo; echo "  $pass passed, $fail failed"
[ "$fail" = 0 ]
