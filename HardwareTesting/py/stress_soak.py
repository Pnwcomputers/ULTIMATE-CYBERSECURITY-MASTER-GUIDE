#!/usr/bin/env python3
"""
stress_soak.py — PNWC Hardware Stress & Reliability Soak Tester v1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What this does that the diagnostic scripts do NOT:
  • Hammers CPU + RAM + storage + GPU simultaneously (not sequentially)
  • Runs for hours, not seconds — exposing thermal soak, XMP instability,
    PSU marginal capacity, and VRM/cooler mount failures
  • Monitors thermals continuously, logs every reading to CSV
  • Watches kernel ring buffer for throttle events and hardware errors
  • Enforces memtester multi-pass RAM validation before combined load
  • Produces a PASS / FAIL verdict with per-check reasoning

Requires : stress-ng, fio, memtester, lm_sensors, inxi
Optional : glmark2 or glmark2-wayland (GPU stress), turbostat (Intel power)

Run with sudo from a desktop terminal (memtester needs root):
  sudo python3 stress_soak.py --mode quick
  sudo python3 stress_soak.py --mode standard
  sudo python3 stress_soak.py --mode overnight --client "Acme Corp"

Install missing tools:
  sudo pacman -S --needed stress-ng fio memtester lm_sensors
  pamac build glmark2    # optional GPU stress
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import argparse
import csv
import datetime
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

# ── Duration presets ───────────────────────────────────────────────────────────
# mt_gb     = memtester allocation (GB)
# mt_passes = memtester pass count
# stress_s  = combined CPU+RAM+IO stress duration (seconds)
# cooldown_s= post-stress monitoring window (seconds)
MODES = {
    "quick": {
        "label": "Quick (15 min)", "mt_gb": 2,  "mt_passes": 1,
        "stress_s": 9 * 60,        "cooldown_s": 3  * 60,
    },
    "short": {
        "label": "Short (1 hr)",   "mt_gb": 4,  "mt_passes": 2,
        "stress_s": 45 * 60,       "cooldown_s": 5  * 60,
    },
    "standard": {
        "label": "Standard (4 hr)","mt_gb": 8,  "mt_passes": 3,
        "stress_s": 3 * 3600,      "cooldown_s": 15 * 60,
    },
    "extended": {
        "label": "Extended (8 hr)","mt_gb": 16, "mt_passes": 5,
        "stress_s": 7 * 3600,      "cooldown_s": 30 * 60,
    },
    "overnight": {
        "label": "Overnight (24 hr)","mt_gb": 16,"mt_passes": 10,
        "stress_s": 23 * 3600,     "cooldown_s": 60 * 60,
    },
}

# ── Thresholds & tuning ────────────────────────────────────────────────────────
CPU_TEMP_WARN      = 90    # °C   — warn in report above this
CPU_TEMP_FAIL      = 100   # °C   — fail verdict above this (sustained throttle range)
THROTTLE_FAIL      = 5     # kernel throttle events before verdict is FAIL
HW_ERROR_FAIL      = 1     # any kernel hardware error = FAIL
GPU_FPS_DEGRADE_PCT= 25    # % FPS drop from first 3 scenes → GPU throttle flag
SENSOR_POLL_S      = 5     # seconds between sensor polls
KERNEL_POLL_S      = 30    # seconds between journalctl polls
VM_BYTES_PCT       = 60    # % of RAM stress-ng vm workers consume
FIO_TESTFILE       = "/tmp/soak_testfile.fio"
FIO_SIZE           = "2G"
REPORT_DIR         = os.getcwd()   # save reports next to wherever the script is invoked from

# ── Global process registry (for clean signal-handler shutdown) ────────────────
_active_procs: list[subprocess.Popen] = []
_procs_lock  = threading.Lock()
_interrupted = False


def _register(proc: subprocess.Popen) -> subprocess.Popen:
    with _procs_lock:
        _active_procs.append(proc)
    return proc


def _kill_all():
    """Terminate then force-kill every registered child process."""
    with _procs_lock:
        for p in _active_procs:
            try:
                p.terminate()
            except Exception:
                pass
    time.sleep(3)
    with _procs_lock:
        for p in _active_procs:
            try:
                p.kill()
            except Exception:
                pass


def _sigint_handler(sig, frame):
    global _interrupted
    if _interrupted:
        return
    _interrupted = True
    print("\n\n⚠️  Ctrl+C — stopping all stress processes and writing partial report...")
    _kill_all()


signal.signal(signal.SIGINT,  _sigint_handler)
signal.signal(signal.SIGTERM, _sigint_handler)


# ── Utilities ──────────────────────────────────────────────────────────────────

def _which(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(cmd: str, timeout: int = 30) -> str:
    """Run a short command and return stdout. Stderr silenced."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _fmt_s(seconds: int) -> str:
    """Format seconds as e.g. '3h 15m 42s'."""
    h, rem = divmod(int(seconds), 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def _progress(label: str, elapsed: int, total: int):
    """Overwrite the current line with a progress bar."""
    pct  = min(elapsed / total, 1.0)
    bars = int(pct * 30)
    bar  = "█" * bars + "░" * (30 - bars)
    rem  = max(0, total - elapsed)
    sys.stdout.write(
        f"\r  [{bar}] {pct*100:5.1f}%  {label}  "
        f"elapsed {_fmt_s(elapsed)}  remaining {_fmt_s(rem)}   "
    )
    sys.stdout.flush()


# ── Pre-flight ─────────────────────────────────────────────────────────────────

REQUIRED_BINS = ["stress-ng", "fio", "memtester", "sensors"]

def preflight() -> list[str]:
    """Return list of missing required binaries."""
    missing = [b for b in REQUIRED_BINS if not _which(b)]
    return missing


# ── Sensor polling ─────────────────────────────────────────────────────────────

class SensorPoller:
    """
    Background thread: polls `sensors` every SENSOR_POLL_S seconds.
    Stores all readings in memory and flushes each row to a CSV log.

    Parsing strategy:
      1. Try `sensors -j` (JSON) for structured access.
      2. Fall back to plain `sensors` text with regex if JSON fails.

    Both paths produce a flat {label: float_celsius} dict per sample.
    """

    _TEMP_RE = re.compile(r'^(.+?):\s+\+?([+-]?\d+\.\d+)°C', re.MULTILINE)
    _INPUT_RE = re.compile(r'_input$')

    def __init__(self, csv_path: str):
        self.csv_path   = csv_path
        self.running    = False
        self._thread: threading.Thread | None = None
        self._lock      = threading.Lock()

        # Raw per-sensor value lists
        self._all: dict[str, list[float]] = {}

        # Quick-access list of CPU package temps for threshold checks
        self._pkg_temps: list[float] = []
        self._pkg_label = ""           # detected label for CPU package sensor

        self._sample_count = 0

    # ── JSON parsing ──────────────────────────────────────────────────────────

    def _parse_json(self) -> dict[str, float]:
        out = _run("sensors -j", timeout=10)
        if not out:
            return {}
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return {}

        flat: dict[str, float] = {}
        for chip, chip_data in data.items():
            if not isinstance(chip_data, dict):
                continue
            for sensor, sensor_data in chip_data.items():
                if not isinstance(sensor_data, dict):
                    continue
                for key, val in sensor_data.items():
                    if self._INPUT_RE.search(key) and "temp" in key:
                        try:
                            flat[f"{chip}/{sensor}"] = float(val)
                        except (TypeError, ValueError):
                            pass
        return flat

    # ── Text fallback parsing ─────────────────────────────────────────────────

    def _parse_text(self) -> dict[str, float]:
        out = _run("sensors 2>/dev/null", timeout=10)
        flat: dict[str, float] = {}
        for name, val in self._TEMP_RE.findall(out):
            flat[name.strip()] = float(val)
        return flat

    # ── Identify the CPU package sensor label ─────────────────────────────────

    def _find_pkg_label(self, sample: dict[str, float]) -> str:
        for label in sample:
            lo = label.lower()
            if "package id 0" in lo or "pkg" in lo:
                return label
        # Fallback: largest temp value usually is the package
        if sample:
            return max(sample, key=sample.get)
        return ""

    # ── Thread body ───────────────────────────────────────────────────────────

    def _sample(self) -> dict[str, float]:
        data = self._parse_json()
        if not data:
            data = self._parse_text()
        return data

    def _run_loop(self):
        csv_file   = open(self.csv_path, "w", newline="")
        csv_writer = None

        while self.running:
            ts   = datetime.datetime.now().isoformat(timespec="seconds")
            data = self._sample()

            if data:
                # First sample: set up CSV header and detect package sensor
                if csv_writer is None:
                    fields     = ["timestamp"] + sorted(data.keys())
                    csv_writer = csv.DictWriter(csv_file, fieldnames=fields,
                                               extrasaction="ignore")
                    csv_writer.writeheader()
                    self._pkg_label = self._find_pkg_label(data)

                csv_writer.writerow({"timestamp": ts, **data})
                csv_file.flush()

                with self._lock:
                    self._sample_count += 1
                    for label, val in data.items():
                        self._all.setdefault(label, []).append(val)
                    if self._pkg_label and self._pkg_label in data:
                        self._pkg_temps.append(data[self._pkg_label])

            time.sleep(SENSOR_POLL_S)

        csv_file.close()

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self):
        self.running  = True
        self._thread  = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=SENSOR_POLL_S + 5)

    def sample_count(self) -> int:
        with self._lock:
            return self._sample_count

    def peak_cpu_temp(self) -> float:
        with self._lock:
            return max(self._pkg_temps) if self._pkg_temps else 0.0

    def avg_cpu_temp(self) -> float:
        with self._lock:
            if not self._pkg_temps:
                return 0.0
            return sum(self._pkg_temps) / len(self._pkg_temps)

    def time_above(self, threshold: float) -> int:
        """Estimated seconds the CPU package temp exceeded the threshold."""
        with self._lock:
            count = sum(1 for v in self._pkg_temps if v >= threshold)
        return count * SENSOR_POLL_S

    def summary(self) -> dict[str, dict]:
        """Return {label: {min, avg, max, samples}} for every tracked sensor."""
        with self._lock:
            return {
                label: {
                    "min":     min(vals),
                    "avg":     sum(vals) / len(vals),
                    "max":     max(vals),
                    "samples": len(vals),
                }
                for label, vals in self._all.items()
                if vals
            }


# ── Kernel event watcher ───────────────────────────────────────────────────────

class KernelWatcher:
    """
    Background thread: polls journalctl for kernel warnings/errors.
    Separates CPU throttle events from hardware faults so the report
    can distinguish "ran hot" from "hardware problem".
    """

    # Throttle/thermal events
    _THROTTLE_PAT = re.compile(
        r'throttl|thermal|prochot|package power limit|cpu freq|power cap',
        re.IGNORECASE
    )
    # Hardware fault events
    _HW_ERROR_PAT = re.compile(
        r'hardware error|machine check|mce:|corrected error|uncorrectable|'
        r'edac |gpu hang|drm:.*error|amdgpu.*error|nvidia.*error|'
        r'i/o error|ata.*error|nvme.*error',
        re.IGNORECASE
    )

    def __init__(self, start_epoch: int):
        self._start_epoch   = start_epoch
        self._seen          = set()          # deduplicate by message body
        self.throttle_events: list[str] = []
        self.hw_errors:       list[str] = []
        self.running        = False
        self._thread: threading.Thread | None = None
        self._lock          = threading.Lock()

    def _poll(self):
        out = _run(
            f"journalctl -k --since @{self._start_epoch} "
            f"-p 4 --no-pager --output=short-monotonic 2>/dev/null",
            timeout=15,
        )
        if not out:
            return

        for line in out.splitlines():
            sig = line[20:].strip() if len(line) > 20 else line
            if sig in self._seen:
                continue
            self._seen.add(sig)

            ts_label = datetime.datetime.now().strftime("%H:%M:%S")
            entry    = f"[{ts_label}] {sig}"

            with self._lock:
                if self._THROTTLE_PAT.search(line):
                    self.throttle_events.append(entry)
                    print(f"\n  ⚠️  THROTTLE EVENT: {sig[:100]}")
                elif self._HW_ERROR_PAT.search(line):
                    self.hw_errors.append(entry)
                    print(f"\n  🔴 HARDWARE ERROR: {sig[:100]}")

    def _run_loop(self):
        while self.running:
            self._poll()
            time.sleep(KERNEL_POLL_S)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=KERNEL_POLL_S + 5)

    def throttle_count(self) -> int:
        with self._lock:
            return len(self.throttle_events)

    def hw_error_count(self) -> int:
        with self._lock:
            return len(self.hw_errors)


# ── Phase 1: memtester ─────────────────────────────────────────────────────────

def run_memtester(gb: int, passes: int, poller: SensorPoller) -> dict:
    """
    Run memtester for RAM validation. Streams output live so FAILED lines
    are visible immediately. Returns result dict.
    """
    print(f"\n{'─'*60}")
    print(f"  PHASE 1 — RAM Validation")
    print(f"  memtester {gb}G × {passes} pass(es)")
    print(f"  Every test line ending with 'ok' is good.")
    print(f"  Any 'FAILED' line = bad RAM or unstable XMP/EXPO.")
    print(f"{'─'*60}\n")

    result = {
        "ran": True, "passed": True,
        "failed_lines": [], "output_tail": [],
        "start_temp": poller.peak_cpu_temp(),
    }

    cmd    = f"memtester {gb}G {passes}"
    lines: list[str] = []
    failed_detected   = False

    try:
        proc = _register(subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        ))

        def _reader():
            nonlocal failed_detected
            for raw in proc.stdout:
                line = raw.rstrip()
                lines.append(line)
                # Print everything so operator can watch
                if any(k in line for k in
                       ["Loop", "Test", " ok", "FAILED", "Done",
                        "memtester", "Memtester", "got"]):
                    print(f"  {line}")
                if "FAILED" in line:
                    failed_detected = True
                    result["failed_lines"].append(line)

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()

        # Wait with periodic interrupt checks
        while proc.poll() is None and not _interrupted:
            time.sleep(2)

        if _interrupted:
            proc.terminate()
            time.sleep(2)
            proc.kill()
        else:
            reader.join(timeout=30)

    except Exception as exc:
        result["error"] = str(exc)
        result["ran"]   = False

    result["passed"]      = not failed_detected
    result["output_tail"] = lines[-20:]
    return result


# ── Phase 2: combined stress ───────────────────────────────────────────────────

def run_combined_stress(stress_s: int, poller: SensorPoller,
                        watcher: KernelWatcher) -> dict:
    """
    Launch stress-ng (CPU + VM), fio (storage), and optionally glmark2 (GPU)
    simultaneously. Monitor all three for the full stress_s duration.
    Kill everything cleanly when done or interrupted.
    """
    print(f"\n{'─'*60}")
    print(f"  PHASE 2 — Combined Stress Soak ({_fmt_s(stress_s)})")
    print(f"  Stressors: CPU (all methods) + RAM (vm workers) + Storage (fio)")

    # ── Display/GPU detection ────────────────────────────────────────────────
    display = os.environ.get("WAYLAND_DISPLAY") and "wayland" or \
              (os.environ.get("DISPLAY") and "x11") or None
    glmark2_bin = None
    if display:
        prefs = (["glmark2-wayland", "glmark2-es2-wayland", "glmark2-es2", "glmark2"]
                 if display == "wayland"
                 else ["glmark2", "glmark2-es2"])
        glmark2_bin = next((b for b in prefs if _which(b)), None)

    if glmark2_bin:
        print(f"  GPU:       {glmark2_bin} --run-forever ({display.upper()})")
    else:
        print(f"  GPU:       skipped — no display or glmark2 not installed")
    print(f"{'─'*60}\n")

    result = {
        "stress_ng_ok": False,
        "fio_ok":       False,
        "gpu_fps":      [],        # list of (scene, fps) tuples
        "gpu_ok":       None,      # None = not tested
        "stress_ng_log": "",
        "fio_iops":     "",
    }

    nproc = int(_run("nproc") or 4)
    stress_ng_log = "/tmp/stress_ng_soak.log"

    # ── Launch stress-ng ─────────────────────────────────────────────────────
    # --cpu N --cpu-method all: cycles all stressor methods (widest instruction coverage)
    # --vm 2 --vm-bytes 60%:   two workers consuming 60% of RAM with bit-flip patterns
    # --metrics-brief:         print per-stressor metrics at end
    # --log-file:              redirect metrics to file (avoids polluting stdout)
    stress_cmd = (
        f"stress-ng "
        f"--cpu {nproc} --cpu-method all "
        f"--vm 2 --vm-bytes {VM_BYTES_PCT}% --vm-method all "
        f"--metrics-brief --log-file {stress_ng_log} "
        f"--timeout {stress_s}"
    )
    try:
        stress_proc = _register(subprocess.Popen(
            stress_cmd, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
    except Exception as exc:
        result["stress_ng_error"] = str(exc)
        stress_proc = None

    # ── Launch fio ───────────────────────────────────────────────────────────
    # --time_based --runtime N: run for exactly stress_s regardless of size
    # --rw=randrw:              mixed random read/write — most stressful for storage
    fio_log = "/tmp/fio_soak.log"
    fio_cmd = (
        f"fio --name=soak --ioengine=libaio --iodepth=32 "
        f"--rw=randrw --bs=4k --direct=1 --size={FIO_SIZE} --numjobs=2 "
        f"--runtime={stress_s} --time_based --group_reporting "
        f"--output={fio_log} --filename={FIO_TESTFILE}"
    )
    try:
        fio_proc = _register(subprocess.Popen(
            fio_cmd, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
    except Exception as exc:
        result["fio_error"] = str(exc)
        fio_proc = None

    # ── Launch GPU stress (background) ───────────────────────────────────────
    gpu_proc   = None
    gpu_lines: list[str] = []
    gpu_thread = None

    if glmark2_bin:
        result["gpu_ok"] = True   # assume pass until FPS drop detected
        gpu_cmd = f"{glmark2_bin} -s 1920x1080 --run-forever"
        try:
            gpu_proc = _register(subprocess.Popen(
                gpu_cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            ))

            def _gpu_reader():
                for raw in gpu_proc.stdout:
                    gpu_lines.append(raw.rstrip())

            gpu_thread = threading.Thread(target=_gpu_reader, daemon=True)
            gpu_thread.start()
        except Exception as exc:
            result["gpu_error"] = str(exc)
            result["gpu_ok"]    = None
            gpu_proc = None

    # ── Progress loop ─────────────────────────────────────────────────────────
    start    = time.time()
    deadline = start + stress_s

    while time.time() < deadline and not _interrupted:
        elapsed = int(time.time() - start)
        pkg_t   = poller.peak_cpu_temp()
        throt   = watcher.throttle_count()
        hw_err  = watcher.hw_error_count()

        status = (f"CPU_peak={pkg_t:.0f}°C  "
                  f"throttle={throt}  hw_err={hw_err}  "
                  f"samples={poller.sample_count()}")
        _progress("stress", elapsed, stress_s)
        sys.stdout.write(f"  {status}  ")
        sys.stdout.flush()
        time.sleep(5)

    print()   # newline after progress bar

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    for proc in filter(None, [stress_proc, fio_proc, gpu_proc]):
        try:
            proc.terminate()
        except Exception:
            pass

    time.sleep(3)

    for proc in filter(None, [stress_proc, fio_proc, gpu_proc]):
        try:
            proc.kill()
        except Exception:
            pass

    # ── Collect results ───────────────────────────────────────────────────────
    result["stress_ng_ok"] = (
        stress_proc is not None and stress_proc.returncode in (0, -15, None)
    )

    result["fio_ok"] = fio_proc is not None
    fio_out = _run(f"cat {fio_log} 2>/dev/null", timeout=5)
    result["fio_iops"] = "\n".join(
        l.strip() for l in fio_out.splitlines()
        if "IOPS=" in l or "bw=" in l or "err=" in l
    )

    stress_out = _run(f"cat {stress_ng_log} 2>/dev/null", timeout=5)
    result["stress_ng_log"] = stress_out[:3000]

    # ── Parse GPU FPS for degradation ────────────────────────────────────────
    if gpu_proc is not None and gpu_lines:
        fps_re = re.compile(r'^\[(.+?)\].+?FPS:\s+(\d+)', re.MULTILINE)
        scores = [(m.group(1), int(m.group(2))) for m in
                  fps_re.finditer("\n".join(gpu_lines))]
        result["gpu_fps"] = scores
        if len(scores) >= 6:
            first_avg = sum(s[1] for s in scores[:3]) / 3
            last_avg  = sum(s[1] for s in scores[-3:]) / 3
            drop_pct  = (first_avg - last_avg) / first_avg * 100
            if drop_pct > GPU_FPS_DEGRADE_PCT:
                result["gpu_ok"] = False
                result["gpu_degrade_pct"] = drop_pct
            else:
                result["gpu_degrade_pct"] = drop_pct

    # Cleanup fio testfile
    for f in [FIO_TESTFILE, f"{FIO_TESTFILE}.0", f"{FIO_TESTFILE}.1"]:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass

    return result


# ── Phase 3: cooldown ─────────────────────────────────────────────────────────

def run_cooldown(cooldown_s: int, poller: SensorPoller):
    """Watch temps recover after stress. Useful for diagnosing thermal paste."""
    print(f"\n{'─'*60}")
    print(f"  PHASE 3 — Cooldown Monitoring ({_fmt_s(cooldown_s)})")
    print(f"  Watching for thermal recovery...")
    print(f"{'─'*60}\n")

    start = time.time()
    while time.time() - start < cooldown_s and not _interrupted:
        elapsed = int(time.time() - start)
        _progress("cooldown", elapsed, cooldown_s)
        sys.stdout.write(f"  CPU_peak={poller.peak_cpu_temp():.0f}°C  ")
        sys.stdout.flush()
        time.sleep(5)
    print()


# ── Report ─────────────────────────────────────────────────────────────────────

def write_report(
    mode_cfg:    dict,
    client_name: str,
    start_dt:    datetime.datetime,
    end_dt:      datetime.datetime,
    sysinfo:     str,
    poller:      SensorPoller,
    watcher:     KernelWatcher,
    mt_result:   dict,
    stress_result: dict,
    csv_path:    str,
    interrupted: bool,
) -> str:

    # ── Verdict ───────────────────────────────────────────────────────────────
    checks: list[tuple[str, bool, str]] = []   # (check_name, passed, detail)

    # RAM
    ram_pass = mt_result.get("passed", True) and mt_result.get("ran", True)
    ram_detail = (
        "No FAILED lines detected"
        if ram_pass else
        f"{len(mt_result.get('failed_lines', []))} FAILED line(s) — bad stick or unstable XMP"
    )
    checks.append(("RAM (memtester)", ram_pass, ram_detail))

    # Peak CPU temp
    peak_t   = poller.peak_cpu_temp()
    temp_pass = peak_t < CPU_TEMP_FAIL
    temp_detail = (
        f"Peak {peak_t:.1f}°C (limit {CPU_TEMP_FAIL}°C)"
        if temp_pass else
        f"Peak {peak_t:.1f}°C EXCEEDED {CPU_TEMP_FAIL}°C — cooler issue"
    )
    checks.append(("CPU Temperature", temp_pass, temp_detail))

    # CPU temp warning (non-fatal)
    if peak_t >= CPU_TEMP_WARN and peak_t < CPU_TEMP_FAIL:
        warn_s = poller.time_above(CPU_TEMP_WARN)
        checks.append((
            f"CPU Temp Warning (>{CPU_TEMP_WARN}°C)",
            True,     # doesn't fail the verdict by itself
            f"Spent ~{_fmt_s(warn_s)} above {CPU_TEMP_WARN}°C — monitor cooling"
        ))

    # Throttle events
    throt     = watcher.throttle_count()
    throt_pass = throt < THROTTLE_FAIL
    checks.append((
        "CPU Throttle Events",
        throt_pass,
        f"{throt} event(s) detected (threshold: {THROTTLE_FAIL})"
    ))

    # Hardware errors
    hw_err     = watcher.hw_error_count()
    hw_err_pass = hw_err < HW_ERROR_FAIL
    checks.append((
        "Hardware Errors",
        hw_err_pass,
        f"{hw_err} error(s) detected" if hw_err else "None detected"
    ))

    # stress-ng survived
    if mt_result.get("ran", False) or stress_result.get("stress_ng_ok") is not None:
        stress_pass = bool(stress_result.get("stress_ng_ok", True))
        checks.append((
            "stress-ng Stability",
            stress_pass,
            "Completed full duration" if stress_pass else "Process crashed or was killed early"
        ))

    # GPU
    if stress_result.get("gpu_ok") is not None:
        gpu_pass    = bool(stress_result["gpu_ok"])
        drop        = stress_result.get("gpu_degrade_pct", 0)
        gpu_detail  = (
            f"FPS degraded {drop:.1f}% (threshold: {GPU_FPS_DEGRADE_PCT}%) — GPU throttling"
            if not gpu_pass else
            f"FPS stable (max drop: {drop:.1f}%)"
        )
        checks.append(("GPU Stability (glmark2)", gpu_pass, gpu_detail))

    overall_pass = all(c[1] for c in checks)
    verdict_str  = "✅ PASS" if overall_pass else "❌ FAIL"
    if interrupted:
        verdict_str = "⚠️ INCOMPLETE (interrupted)"

    # ── Build report string ───────────────────────────────────────────────────
    cb          = "```"
    ts_str      = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    elapsed_str = _fmt_s(int((end_dt - start_dt).total_seconds()))
    client_str  = f"**Prepared For:** {client_name}\n" if client_name else ""

    # Verdict table
    verdict_rows = ""
    for name, passed, detail in checks:
        icon = "✅" if passed else "❌"
        verdict_rows += f"| {icon} | {name} | {detail} |\n"

    # Temperature summary table
    sensor_rows = ""
    for label, stats in sorted(poller.summary().items()):
        warn = " ⚠️" if stats["max"] >= CPU_TEMP_WARN else ""
        fail = " 🔴" if stats["max"] >= CPU_TEMP_FAIL else ""
        sensor_rows += (
            f"| {label} | {stats['min']:.1f} | "
            f"{stats['avg']:.1f} | {stats['max']:.1f}{warn}{fail} | "
            f"{stats['samples']} |\n"
        )
    if not sensor_rows:
        sensor_rows = "| — | no sensor data collected | — | — | — |\n"

    # Throttle events
    throttle_block = (
        "\n".join(watcher.throttle_events) if watcher.throttle_events
        else "None detected."
    )
    hw_error_block = (
        "\n".join(watcher.hw_errors) if watcher.hw_errors
        else "None detected."
    )

    # memtester output
    mt_output = "\n".join(mt_result.get("output_tail", ["No output captured."]))
    mt_failed  = "\n".join(mt_result.get("failed_lines", ["None"]))

    # GPU FPS table
    gpu_section = ""
    if stress_result.get("gpu_fps"):
        fps_rows = ""
        scores   = stress_result["gpu_fps"]
        for i, (scene, fps) in enumerate(scores):
            note = ""
            if i >= len(scores) - 3:
                # Compare to first 3
                first3_avg = sum(s[1] for s in scores[:3]) / min(3, len(scores))
                drop       = (first3_avg - fps) / first3_avg * 100
                if drop > GPU_FPS_DEGRADE_PCT:
                    note = f" ⚠️ {drop:.0f}% drop"
            fps_rows += f"| {i+1} | {scene} | {fps} |{note}\n"
        drop_pct = stress_result.get("gpu_degrade_pct", 0)
        gpu_section = f"""
## 6. GPU Stress (glmark2 --run-forever)

**FPS degradation from first→last 3 scenes:** {drop_pct:.1f}%
*(>{GPU_FPS_DEGRADE_PCT}% sustained drop indicates GPU thermal throttling)*

| # | Scene | FPS |
| :--- | :--- | :--- |
{fps_rows}"""
    elif stress_result.get("gpu_ok") is None:
        gpu_section = "\n## 6. GPU Stress\n\nSkipped — no display or glmark2 not installed.\n"

    # stress-ng metrics
    stress_log_block = (
        stress_result.get("stress_ng_log", "").strip()
        or "No metrics file found (stress-ng may not have been installed)."
    )

    # fio results
    fio_block = (
        stress_result.get("fio_iops", "").strip()
        or "No fio output captured."
    )

    report = f"""# Hardware Stress & Reliability Soak Report
**Date:** {ts_str}
**Mode:** {mode_cfg['label']}
**Elapsed:** {elapsed_str}
{client_str}
---

## Overall Verdict: {verdict_str}

| Result | Check | Detail |
| :--- | :--- | :--- |
{verdict_rows}
> **Interpreting FAIL:** A single ❌ is enough to flag the machine as unreliable.
> Always investigate the failing check before returning hardware to a client.

---

## 1. System Under Test
{cb}text
{sysinfo}
{cb}

---

## 2. Continuous Temperature Log

*{poller.sample_count()} samples at {SENSOR_POLL_S}s intervals.
Full CSV: `{csv_path}`*

| Sensor | Min °C | Avg °C | Max °C | Samples |
| :--- | ---: | ---: | ---: | ---: |
{sensor_rows}
> Thresholds: ⚠️ >{CPU_TEMP_WARN}°C (warning)  🔴 >{CPU_TEMP_FAIL}°C (FAIL)

---

## 3. Kernel Events

### Throttle Events ({watcher.throttle_count()})
{cb}text
{throttle_block}
{cb}

### Hardware Errors ({watcher.hw_error_count()})
{cb}text
{hw_error_block}
{cb}

---

## 4. RAM Validation (memtester {mode_cfg['mt_gb']}G × {mode_cfg['mt_passes']} pass)

**Result:** {'✅ PASSED — no bit errors detected' if mt_result.get('passed') else '❌ FAILED — bit errors detected'}

### FAILED lines (if any)
{cb}text
{mt_failed}
{cb}

### Last 20 lines of output
{cb}text
{mt_output}
{cb}

---

## 5. Combined Stress — stress-ng + fio ({_fmt_s(mode_cfg['stress_s'])})

### stress-ng Metrics
{cb}text
{stress_log_block}
{cb}

### fio Storage IOPS During Stress
{cb}text
{fio_block}
{cb}
{gpu_section}
---
*Generated by PNWC stress_soak.py v1.0*
"""

    ts_file  = start_dt.strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(REPORT_DIR, f"Soak_Report_{ts_file}.md")
    with open(filename, "w") as fh:
        fh.write(report)

    return filename


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PNWC Hardware Stress & Reliability Soak Tester v1.0"
    )
    parser.add_argument(
        "--mode", choices=list(MODES.keys()), default="standard",
        help="Soak duration preset (default: standard = 4 hours)",
    )
    parser.add_argument(
        "--client", default="", metavar="NAME",
        help="Client name to embed in the report header",
    )
    parser.add_argument(
        "--skip-gpu", action="store_true",
        help="Skip GPU stress even if glmark2 is available",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("❌  Must be run with sudo (memtester requires root).")
        sys.exit(1)

    mode_cfg = MODES[args.mode]

    print("=" * 60)
    print(f"  PNWC Stress & Reliability Soak Tester v1.0")
    print(f"  Mode    : {mode_cfg['label']}")
    print(f"  memtest : {mode_cfg['mt_gb']}G × {mode_cfg['mt_passes']} pass(es)")
    print(f"  Stress  : {_fmt_s(mode_cfg['stress_s'])} combined load")
    print(f"  Cooldown: {_fmt_s(mode_cfg['cooldown_s'])}")
    print("=" * 60)

    # Pre-flight
    missing = preflight()
    if missing:
        print(f"\n❌  Missing required tools: {', '.join(missing)}")
        print("    Install with:")
        print(f"    sudo pacman -S --needed {' '.join(missing)}")
        sys.exit(1)

    if args.skip_gpu:
        os.environ.pop("DISPLAY", None)
        os.environ.pop("WAYLAND_DISPLAY", None)

    # Gather system info
    sysinfo = _run("inxi -Fzx -c0 2>/dev/null", timeout=30) or "(inxi unavailable)"

    # Set up monitoring output files
    ts_str   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(REPORT_DIR, f"soak_temps_{ts_str}.csv")

    start_dt    = datetime.datetime.now()
    start_epoch = int(start_dt.timestamp())

    # Start background monitors
    poller  = SensorPoller(csv_path)
    watcher = KernelWatcher(start_epoch)
    poller.start()
    watcher.start()

    print(f"\n  Sensor log   → {csv_path}")
    print(f"  Start time   : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")

    mt_result     = {"ran": False, "passed": True, "failed_lines": [], "output_tail": []}
    stress_result = {}

    try:
        # Phase 1 — RAM validation
        mt_result = run_memtester(mode_cfg["mt_gb"], mode_cfg["mt_passes"], poller)

        if _interrupted:
            raise KeyboardInterrupt

        # Phase 2 — Combined stress
        stress_result = run_combined_stress(mode_cfg["stress_s"], poller, watcher)

        if _interrupted:
            raise KeyboardInterrupt

        # Phase 3 — Cooldown
        run_cooldown(mode_cfg["cooldown_s"], poller)

    except KeyboardInterrupt:
        pass
    finally:
        _kill_all()
        poller.stop()
        watcher.stop()

    end_dt = datetime.datetime.now()
    print(f"\n\n  Soak complete — elapsed {_fmt_s(int((end_dt - start_dt).total_seconds()))}")
    print("  Compiling report...")

    client = args.client or input("Client name (Enter to skip): ").strip()

    report_path = write_report(
        mode_cfg=mode_cfg,
        client_name=client,
        start_dt=start_dt,
        end_dt=end_dt,
        sysinfo=sysinfo,
        poller=poller,
        watcher=watcher,
        mt_result=mt_result,
        stress_result=stress_result,
        csv_path=csv_path,
        interrupted=_interrupted,
    )

    print(f"\n✅  Report → {report_path}")
    print(f"    Temps  → {csv_path}")


if __name__ == "__main__":
    main()
