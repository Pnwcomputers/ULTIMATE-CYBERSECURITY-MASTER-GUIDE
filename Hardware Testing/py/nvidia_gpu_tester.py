#!/usr/bin/env python3
"""
PNWC NVIDIA GPU Diagnostic & Benchmark Tool v1.2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What this script DOES that 'standalone_gpu_tester.py' does NOT:
  • Polls nvidia-smi every second DURING the benchmark on a parallel thread, building a full load curve (clocks, power, temp, utilization, throttle)
  • Verifies PCIe link gen + width under load (catches x8 / Gen3 negotiation)
  • Checks ECC volatile error counters (workstation/datacenter cards)
  • Reports active throttle reasons (thermal / power-brake / sw-cap)
  • Idle vs load comparison table
  • Logs every per-second sample to a timestamped CSV
  • Optional FurMark torture via gputest (AUR) if installed

Verified & Audited Logic:
  • Fixed GpuTest/FurMark pathing by using native Python execution directories (cwd).
  • Added target indexing (-i 0) to nvidia-smi queries to prevent multi-GPU line bleed.
  • Wrapped background logging loops in exception-safeguards to prevent file locks.
  • Handled volatile/non-volatile dynamic queries gracefully without crashing.

Requires : nvidia-utils, inxi, glmark2 (or glmark2-es2), gputest (AUR — requires 'libpng12' from AUR to run on modern Arch)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import subprocess
import datetime
import os
import sys
import shutil
import threading
import time
import csv

# ── Configuration ──────────────────────────────────────────────────────────────
REPORT_DIR        = os.getcwd()   # reports save next to where the script is invoked
GLMARK2_TIMEOUT   = 600           # full glmark2 run is 8-15 min
GLMARK2_SCENES    = None          # None = full suite; list for quick pass
SMI_POLL_S        = 1             # nvidia-smi sample interval (seconds)
GPUTEST_DURATION  = 60            # FurMark torture seconds (if gputest installed)

# Thresholds for the verdict
TEMP_WARN_C       = 83            # NVIDIA consumer cards typically throttle ~83-88°C
TEMP_FAIL_C       = 90            # sustained ≥90°C → flag
THERMAL_SLOWDOWN_FAIL = True      # any HW thermal slowdown event during load → flag
# ───────────────────────────────────────────────────────────────────────────────

SMI_FIELDS = [
    "timestamp",
    "temperature.gpu",
    "utilization.gpu",
    "utilization.memory",
    "clocks.current.graphics",
    "clocks.current.sm",
    "clocks.current.memory",
    "power.draw",
    "fan.speed",
    "pstate",
    "clocks_throttle_reasons.active",
    "clocks_throttle_reasons.hw_thermal_slowdown",
    "clocks_throttle_reasons.sw_thermal_slowdown",
    "clocks_throttle_reasons.hw_power_brake_slowdown",
]

SMI_STATIC_FIELDS = [
    "name", "driver_version", "vbios_version",
    "memory.total", "power.limit", "power.max_limit",
    "clocks.max.graphics", "clocks.max.sm", "clocks.max.memory",
    "pcie.link.gen.current", "pcie.link.gen.max",
    "pcie.link.width.current", "pcie.link.width.max",
]


class NvidiaMonitor:
    def __init__(self, csv_path: str):
        self.csv_path  = csv_path
        self.running   = False
        self._thread   = None
        self._lock     = threading.Lock()
        self._samples  = 0

        self.temps:  list[float] = []
        self.powers: list[float] = []
        self.gclks:  list[float] = []
        self.mclks:  list[float] = []
        self.utils:  list[float] = []

        self.hw_thermal_events  = 0
        self.sw_thermal_events  = 0
        self.power_brake_events = 0
        self.active_throttle_reasons: set[str] = set()

        self.query = ",".join(SMI_FIELDS)

    @staticmethod
    def _to_float(v: str):
        v = v.strip()
        if v in ("", "[N/A]", "N/A", "[Not Supported]", "Not Supported"):
            return None
        try:
            return float(v)
        except ValueError:
            return None

    def _sample(self):
        try:
            # -i 0 targets the primary test bench slot explicitly
            r = subprocess.run(
                f"nvidia-smi -i 0 --query-gpu={self.query} --format=csv,noheader,nounits",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=10,
            )
            if r.returncode != 0 or not r.stdout.strip():
                return None
            line = r.stdout.strip().splitlines()[0]
            return [c.strip() for c in line.split(",")]
        except Exception:
            return None

    def _run_loop(self):
        try:
            with open(self.csv_path, "w", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(SMI_FIELDS)

                while self.running:
                    row = self._sample()
                    if row and len(row) == len(SMI_FIELDS):
                        writer.writerow(row)
                        fh.flush()
                        self._ingest(row)
                    time.sleep(SMI_POLL_S)
        except Exception as e:
            print(f"\n[!] Monitor encountered a structural logging error: {e}")

    def _ingest(self, row: list[str]):
        d = dict(zip(SMI_FIELDS, row))
        with self._lock:
            self._samples += 1
            for series, key in [
                (self.temps,  "temperature.gpu"),
                (self.powers, "power.draw"),
                (self.gclks,  "clocks.current.graphics"),
                (self.mclks,  "clocks.current.memory"),
                (self.utils,  "utilization.gpu"),
            ]:
                val = self._to_float(d.get(key, ""))
                if val is not None:
                    series.append(val)

            if d.get("clocks_throttle_reasons.hw_thermal_slowdown", "").strip() == "Active":
                self.hw_thermal_events += 1
                self.active_throttle_reasons.add("HW thermal slowdown")
            if d.get("clocks_throttle_reasons.sw_thermal_slowdown", "").strip() == "Active":
                self.sw_thermal_events += 1
                self.active_throttle_reasons.add("SW thermal slowdown")
            if d.get("clocks_throttle_reasons.hw_power_brake_slowdown", "").strip() == "Active":
                self.power_brake_events += 1
                self.active_throttle_reasons.add("HW power brake")

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=SMI_POLL_S + 5)

    def samples(self) -> int:
        with self._lock:
            return self._samples

    @staticmethod
    def _stats(series):
        if not series:
            return (0.0, 0.0, 0.0)
        return (min(series), sum(series) / len(series), max(series))

    def summary(self) -> dict:
        with self._lock:
            return {
                "temp":  self._stats(self.temps),
                "power": self._stats(self.powers),
                "gclk":  self._stats(self.gclks),
                "mclk":  self._stats(self.mclks),
                "util":  self._stats(self.utils),
                "hw_thermal":  self.hw_thermal_events,
                "sw_thermal":  self.sw_thermal_events,
                "power_brake": self.power_brake_events,
                "reasons":      sorted(self.active_throttle_reasons),
            }


class NvidiaGPUTester:
    def __init__(self):
        self.ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data = {
            "inxi_gpu":     "",
            "static_info":  {},
            "idle_snap":    {},
            "benchmark":    "",
            "scene_scores": [],
            "glmark2_cmd":  "",
            "load_summary": {},
            "furmark":      "",
            "ecc":          "",
            "csv_path":     "",
            "errors":       [],
            "warnings":     [],
        }

    @staticmethod
    def _which(b: str) -> bool:
        return shutil.which(b) is not None

    def run_cmd(self, cmd: str, timeout: int = 60, cwd: str = None) -> str:
        print(f"    → {cmd}")
        try:
            r = subprocess.run(
                cmd, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=timeout,
                cwd=cwd,
            )
            if r.returncode != 0:
                err = r.stderr.strip()
                if err and "inxi" not in cmd:
                    self.data["errors"].append(
                        f"[{cmd.split()[0]}] rc={r.returncode}: {err[:400]}"
                    )
            return r.stdout.strip()
        except subprocess.TimeoutExpired:
            self.data["errors"].append(f"TIMEOUT ({timeout}s): {cmd}")
            return "TIMEOUT"
        except Exception as exc:
            self.data["errors"].append(f"EXEC ERROR: {cmd} → {exc}")
            return "ERROR"

    def _detect_display(self) -> str | None:
        if os.environ.get("WAYLAND_DISPLAY"):
            return "wayland"
        if os.environ.get("DISPLAY"):
            return "x11"
        return None

    def _pick_glmark2(self, display: str) -> str | None:
        order = (["glmark2-wayland", "glmark2-es2-wayland", "glmark2-es2", "glmark2"]
                 if display == "wayland"
                 else ["glmark2", "glmark2-es2"])
        return next((b for b in order if self._which(b)), None)

    def _query_named(self, fields: list[str]) -> dict:
        q = ",".join(fields)
        out = self.run_cmd(
            f"nvidia-smi -i 0 --query-gpu={q} --format=csv,noheader,nounits",
            timeout=15,
        )
        if out in ("TIMEOUT", "ERROR", ""):
            return {}
        line = out.splitlines()[0]
        values = [v.strip() for v in line.split(",")]
        if len(values) != len(fields):
            return {}
        return dict(zip(fields, values))

    def gather_static(self):
        print("\n[1/4] GPU hardware & driver identification...")
        if not self._which("nvidia-smi"):
            self.data["errors"].append(
                "nvidia-smi NOT FOUND. Install with: sudo pacman -S nvidia-utils"
            )
            self.data["inxi_gpu"] = self.run_cmd("inxi -G -c0", timeout=30)
            return False

        self.data["inxi_gpu"]    = self.run_cmd("inxi -G -c0", timeout=30)
        self.data["static_info"] = self._query_named(SMI_STATIC_FIELDS)

        self.data["idle_snap"] = self._query_named(
            ["temperature.gpu", "power.draw",
             "clocks.current.graphics", "clocks.current.memory",
             "utilization.gpu", "pstate"]
        )

        ecc = self._query_named(
            ["ecc.errors.corrected.volatile.total",
             "ecc.errors.uncorrected.volatile.total"]
        )
        if ecc:
            corr = ecc.get("ecc.errors.corrected.volatile.total", "N/A")
            unco = ecc.get("ecc.errors.uncorrected.volatile.total", "N/A")
            self.data["ecc"] = f"Corrected: {corr}  |  Uncorrected: {unco}"
            if unco.isdigit() and int(unco) > 0:
                self.data["errors"].append(
                    f"⚠️  {unco} UNCORRECTABLE ECC ERRORS — failing VRAM."
                )
        return True

    def run_benchmark(self, display: str, monitor: NvidiaMonitor):
        print("\n[2/4] glmark2 benchmark with live nvidia-smi monitoring...")

        binary = self._pick_glmark2(display)
        if binary is None:
            self.data["benchmark"] = (
                "SKIPPED — no glmark2 binary found. Install: pamac build glmark2"
            )
            self.data["warnings"].append("glmark2 not installed.")
            return

        scene_args = (" ".join(f"--benchmark {s}" for s in GLMARK2_SCENES)
                      if GLMARK2_SCENES else "")
        cmd = f"{binary} -s 1920x1080 {scene_args}".strip()
        self.data["glmark2_cmd"] = cmd
        print(f"    Binary  : {binary}  |  Display : {display.upper()}")
        print(f"    Monitor : nvidia-smi every {SMI_POLL_S}s → {monitor.csv_path}")
        print()

        monitor.start()
        lines, timed_out = self._run_streaming(cmd, GLMARK2_TIMEOUT)
        monitor.stop()

        scenes, final = [], None
        for ln in lines:
            s = ln.strip()
            if s.startswith("[") and "FPS:" in s:
                scenes.append(s)
            if "glmark2 Score" in s:
                final = s
        self.data["scene_scores"] = scenes

        if final:
            self.data["benchmark"] = final
        elif scenes and timed_out:
            self.data["benchmark"] = (
                f"PARTIAL (timed out after {GLMARK2_TIMEOUT}s — "
                f"{len(scenes)} scenes). Last: {scenes[-1]}"
            )
        elif
