#!/usr/bin/env python3
"""
nvidia_gpu_tester.py — PNWC NVIDIA GPU Diagnostic & Benchmark Tool v1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What this does that standalone_gpu_tester.py does NOT:
  • Polls nvidia-smi every second DURING the benchmark on a parallel thread,
    building a full load curve (clocks, power, temp, utilization, throttle)
  • Verifies PCIe link gen + width under load (catches x8 / Gen3 negotiation)
  • Checks ECC volatile error counters (workstation/datacenter cards)
  • Reports active throttle reasons (thermal / power-brake / sw-cap)
  • Idle vs load comparison table
  • Logs every per-second sample to a timestamped CSV
  • Optional FurMark torture via gputest (AUR) if installed

Requires : nvidia-smi (ships with nvidia-utils), inxi, glmark2 (or glmark2-es2)
Optional : gputest (AUR — FurMark/TessMark torture)

Run from a desktop session (X11 or Wayland). sudo NOT required.

Install missing tools:
  sudo pacman -S --needed nvidia-utils      # provides nvidia-smi
  pamac build glmark2                        # OpenGL benchmark
  pamac build gputest                        # optional FurMark torture
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

# nvidia-smi --query-gpu fields. Verified against the stable query spec.
# Order here is the order columns appear in CSV output.
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

# Static fields gathered once (info / capability)
SMI_STATIC_FIELDS = [
    "name", "driver_version", "vbios_version",
    "memory.total", "power.limit", "power.max_limit",
    "clocks.max.graphics", "clocks.max.sm", "clocks.max.memory",
    "pcie.link.gen.current", "pcie.link.gen.max",
    "pcie.link.width.current", "pcie.link.width.max",
]


class NvidiaMonitor:
    """
    Background thread polling nvidia-smi every SMI_POLL_S seconds during load.
    Writes every sample to CSV and keeps numeric series for the report summary.
    """

    def __init__(self, csv_path: str):
        self.csv_path  = csv_path
        self.running   = False
        self._thread   = None
        self._lock     = threading.Lock()
        self._samples  = 0

        # Numeric series for min/avg/max
        self.temps:  list[float] = []
        self.powers: list[float] = []
        self.gclks:  list[float] = []
        self.mclks:  list[float] = []
        self.utils:  list[float] = []

        # Throttle tracking
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
            r = subprocess.run(
                f"nvidia-smi --query-gpu={self.query} "
                f"--format=csv,noheader,nounits",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=10,
            )
            if r.returncode != 0 or not r.stdout.strip():
                return None
            # First GPU only (index 0); split on comma
            line = r.stdout.strip().splitlines()[0]
            return [c.strip() for c in line.split(",")]
        except Exception:
            return None

    def _run_loop(self):
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

            # Throttle reasons: "Active" means currently throttling
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
                "reasons":     sorted(self.active_throttle_reasons),
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

    def run_cmd(self, cmd: str, timeout: int = 60) -> str:
        print(f"    → {cmd}")
        try:
            r = subprocess.run(
                cmd, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=timeout,
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

    # ── Static info & idle snapshot ─────────────────────────────────────────────

    def _query_named(self, fields: list[str]) -> dict:
        """Query a set of nvidia-smi fields, return as a dict keyed by field name."""
        q = ",".join(fields)
        out = self.run_cmd(
            f"nvidia-smi --query-gpu={q} --format=csv,noheader,nounits",
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

        # Idle snapshot (before load)
        self.data["idle_snap"] = self._query_named(
            ["temperature.gpu", "power.draw",
             "clocks.current.graphics", "clocks.current.memory",
             "utilization.gpu", "pstate"]
        )

        # ECC error counters (will be [N/A] on consumer GeForce cards — that's fine)
        ecc = self._query_named(
            ["ecc.errors.corrected.volatile.total",
             "ecc.errors.uncorrected.volatile.total"]
        )
        if ecc:
            corr = ecc.get("ecc.errors.corrected.volatile.total", "N/A")
            unco = ecc.get("ecc.errors.uncorrected.volatile.total", "N/A")
            self.data["ecc"] = f"Corrected: {corr}  |  Uncorrected: {unco}"
            # Uncorrectable ECC errors are a hard fault
            if unco.isdigit() and int(unco) > 0:
                self.data["errors"].append(
                    f"⚠️  {unco} UNCORRECTABLE ECC ERRORS — failing VRAM."
                )
        return True

    # ── Benchmark with parallel monitoring ──────────────────────────────────────

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

        # Start monitoring, run benchmark, stop monitoring
        monitor.start()
        lines, timed_out = self._run_streaming(cmd, GLMARK2_TIMEOUT)
        monitor.stop()

        # Parse scene FPS + final score
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
        elif not lines:
            self.data["benchmark"] = "FAILED — no output. Check driver/display."
        else:
            self.data["benchmark"] = "FAILED — could not parse score."

        self.data["load_summary"] = monitor.summary()

    def _run_streaming(self, cmd: str, timeout: int):
        lines, timed_out = [], False
        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
            )

            def _reader():
                for raw in proc.stdout:
                    line = raw.rstrip()
                    lines.append(line)
                    if any(k in line for k in
                           ["[", "glmark2 Score", "Error", "Failed", "WARNING"]):
                        print(f"       {line}")

            t = threading.Thread(target=_reader, daemon=True)
            t.start()
            t.join(timeout=timeout)
            if t.is_alive():
                proc.terminate(); time.sleep(2); proc.kill()
                timed_out = True
                self.data["errors"].append(
                    f"glmark2 killed after {timeout}s timeout."
                )
            else:
                proc.wait()
        except Exception as exc:
            self.data["errors"].append(f"Streaming error: {exc}")
            timed_out = True
        return lines, timed_out

    # ── Optional FurMark torture ────────────────────────────────────────────────

    def run_furmark(self, monitor_csv_base: str):
        print("\n[3/4] FurMark thermal torture (gputest)...")
        if not self._which("GpuTest") and not os.path.exists("/opt/gputest/GpuTest"):
            self.data["furmark"] = (
                "SKIPPED — gputest not installed. Install: pamac build gputest"
            )
            self.data["warnings"].append("gputest not installed; skipped FurMark.")
            return

        # gputest installs to /opt/gputest and must be run from there
        furmark_csv = monitor_csv_base.replace(".csv", "_furmark.csv")
        mon = NvidiaMonitor(furmark_csv)

        cmd = (f"cd /opt/gputest && ./GpuTest /test=fur /width=1920 /height=1080 "
               f"/msaa=0 /benchmark /benchmark_duration_ms={GPUTEST_DURATION*1000} "
               f"/no_scorebox")
        print(f"    → {cmd}")
        print(f"    Monitor : nvidia-smi every {SMI_POLL_S}s → {furmark_csv}")

        mon.start()
        out = self.run_cmd(cmd, timeout=GPUTEST_DURATION + 60)
        mon.stop()

        summ = mon.summary()
        t = summ["temp"]
        p = summ["power"]
        self.data["furmark"] = (
            f"FurMark {GPUTEST_DURATION}s @ 1920×1080\n"
            f"Peak temp: {t[2]:.0f}°C (avg {t[1]:.0f}°C)  |  "
            f"Peak power: {p[2]:.0f}W (avg {p[1]:.0f}W)\n"
            f"HW thermal slowdown events: {summ['hw_thermal']}  |  "
            f"Power brake events: {summ['power_brake']}\n"
            f"Per-second log: {furmark_csv}"
        )
        if t[2] >= TEMP_FAIL_C:
            self.data["warnings"].append(
                f"FurMark peak {t[2]:.0f}°C ≥ {TEMP_FAIL_C}°C — check cooling."
            )

    # ── Report ──────────────────────────────────────────────────────────────────

    def build_report(self, client: str = "") -> str:
        print("\n[4/4] Compiling report...")
        cb = "```"
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        client_str = f"**Prepared For:** {client}\n" if client else ""

        si = self.data["static_info"]
        idle = self.data["idle_snap"]
        ls = self.data["load_summary"]

        # ── Verdict checks ──
        checks = []

        # PCIe link
        if si:
            cur_gen = si.get("pcie.link.gen.current", "?")
            max_gen = si.get("pcie.link.gen.max", "?")
            cur_w   = si.get("pcie.link.width.current", "?")
            max_w   = si.get("pcie.link.width.max", "?")
            pcie_ok = (cur_gen == max_gen and cur_w == max_w)
            checks.append((
                "PCIe Link", pcie_ok,
                f"Gen{cur_gen} x{cur_w} (max Gen{max_gen} x{max_w})"
                + ("" if pcie_ok else " — NOT at full link! Reseat card / check slot.")
            ))

        # Temp under load
        if ls and ls.get("temp"):
            peak_t = ls["temp"][2]
            temp_ok = peak_t < TEMP_FAIL_C
            checks.append((
                "Load Temperature", temp_ok,
                f"Peak {peak_t:.0f}°C (limit {TEMP_FAIL_C}°C)"
            ))

        # Thermal throttle
        if ls:
            hw_th = ls.get("hw_thermal", 0)
            th_ok = not (THERMAL_SLOWDOWN_FAIL and hw_th > 0)
            checks.append((
                "Thermal Throttling", th_ok,
                f"{hw_th} HW thermal slowdown sample(s) during load"
            ))

        # ECC
        if self.data["ecc"]:
            ecc_ok = "Uncorrected: 0" in self.data["ecc"] or "N/A" in self.data["ecc"]
            checks.append((
                "ECC Memory", ecc_ok,
                self.data["ecc"]
            ))

        overall = all(c[1] for c in checks) if checks else True
        verdict = "✅ PASS" if overall else "❌ FAIL"

        verdict_rows = "".join(
            f"| {'✅' if ok else '❌'} | {name} | {detail} |\n"
            for name, ok, detail in checks
        ) or "| — | No checks performed | — |\n"

        # Static info block
        if si:
            static_block = (
                f"Name              : {si.get('name','?')}\n"
                f"Driver            : {si.get('driver_version','?')}\n"
                f"VBIOS             : {si.get('vbios_version','?')}\n"
                f"VRAM              : {si.get('memory.total','?')} MiB\n"
                f"Power limit       : {si.get('power.limit','?')} W "
                f"(max {si.get('power.max_limit','?')} W)\n"
                f"Max graphics clock: {si.get('clocks.max.graphics','?')} MHz\n"
                f"Max memory clock  : {si.get('clocks.max.memory','?')} MHz\n"
                f"PCIe link         : Gen{si.get('pcie.link.gen.current','?')} "
                f"x{si.get('pcie.link.width.current','?')} "
                f"(max Gen{si.get('pcie.link.gen.max','?')} "
                f"x{si.get('pcie.link.width.max','?')})"
            )
        else:
            static_block = "nvidia-smi static query unavailable."

        # Idle vs load table
        def _fmt_stat(s):
            return f"{s[0]:.0f} / {s[1]:.0f} / {s[2]:.0f}" if s else "— / — / —"

        if ls and idle:
            load_table = (
                f"| Metric | Idle | Load min/avg/max |\n"
                f"| :--- | ---: | ---: |\n"
                f"| Temp (°C) | {idle.get('temperature.gpu','?')} | "
                f"{_fmt_stat(ls['temp'])} |\n"
                f"| Power (W) | {idle.get('power.draw','?')} | "
                f"{_fmt_stat(ls['power'])} |\n"
                f"| Graphics clk (MHz) | {idle.get('clocks.current.graphics','?')} | "
                f"{_fmt_stat(ls['gclk'])} |\n"
                f"| Memory clk (MHz) | {idle.get('clocks.current.memory','?')} | "
                f"{_fmt_stat(ls['mclk'])} |\n"
                f"| GPU util (%) | {idle.get('utilization.gpu','?')} | "
                f"{_fmt_stat(ls['util'])} |\n"
            )
            throttle_note = (
                ", ".join(ls["reasons"]) if ls.get("reasons")
                else "None observed"
            )
        else:
            load_table = "_No load monitoring data collected._\n"
            throttle_note = "n/a"

        scenes_block = ("\n".join(self.data["scene_scores"])
                        if self.data["scene_scores"] else "No per-scene data.")

        diag = ""
        issues = self.data["errors"] + self.data["warnings"]
        if issues:
            diag = f"\n## Diagnostics Log\n{cb}text\n" + "\n".join(issues) + f"\n{cb}\n"
        else:
            diag = "\n**Status:** ✅ No errors or warnings.\n"

        furmark_block = ""
        if self.data["furmark"]:
            furmark_block = (
                f"\n## 5. FurMark Thermal Torture\n{cb}text\n"
                f"{self.data['furmark']}\n{cb}\n"
            )

        report = f"""# NVIDIA GPU Diagnostic & Benchmark Report
**Date:** {self.ts}
{client_str}
---

## Overall Verdict: {verdict}

| Result | Check | Detail |
| :--- | :--- | :--- |
{verdict_rows}
---

## 1. Hardware & Driver
{cb}text
{static_block}
{cb}

inxi:
{cb}text
{self.data['inxi_gpu']}
{cb}

---

## 2. Idle vs Load Comparison
*nvidia-smi polled every {SMI_POLL_S}s during benchmark
({ls.get('temp') and self.data.get('csv_path') or 'see CSV'})*

{load_table}
**Throttle reasons observed under load:** {throttle_note}

---

## 3. glmark2 Benchmark
*Command:* `{self.data['glmark2_cmd']}`

**Result:** `{self.data['benchmark']}`

### Per-Scene FPS
{cb}text
{scenes_block}
{cb}

---

## 4. ECC Memory
{cb}text
{self.data['ecc'] or 'Not applicable (consumer GeForce cards report N/A).'}
{cb}
{furmark_block}{diag}
---
*Per-second monitoring log: {self.data['csv_path']}*
*Generated by PNWC nvidia_gpu_tester.py v1.0*
"""

        fname = os.path.join(REPORT_DIR, f"NVIDIA_GPU_Report_{ts_file}.md")
        with open(fname, "w") as fh:
            fh.write(report)
        print(f"\n✅  Report → {fname}")
        return fname


def main():
    import argparse
    ap = argparse.ArgumentParser(description="PNWC NVIDIA GPU Tester v1.0")
    ap.add_argument("--client", default="", help="Client name for the report")
    ap.add_argument("--furmark", action="store_true",
                    help="Also run FurMark torture (requires gputest from AUR)")
    args = ap.parse_args()

    print("=" * 60)
    print("  PNWC NVIDIA GPU Diagnostic & Benchmark Tool v1.0")
    print("=" * 60)

    tester = NvidiaGPUTester()

    display = tester._detect_display()
    if display is None:
        print("\n❌  No display detected ($DISPLAY / $WAYLAND_DISPLAY unset).")
        print("    Run from a desktop terminal, not SSH.")
        # Still gather static info, which doesn't need a display
        tester.gather_static()
        tester.build_report(client=args.client)
        sys.exit(1)

    print(f"\nDisplay server : {display.upper()}")

    if not tester.gather_static():
        print("\n⚠️  nvidia-smi unavailable — is this an NVIDIA system with drivers?")
        tester.build_report(client=args.client)
        sys.exit(1)

    ts_file  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(REPORT_DIR, f"nvidia_load_{ts_file}.csv")
    tester.data["csv_path"] = csv_path
    monitor = NvidiaMonitor(csv_path)

    tester.run_benchmark(display, monitor)

    if args.furmark:
        tester.run_furmark(csv_path)
    else:
        tester.data["furmark"] = ""

    client = args.client or input("\nClient name (Enter to skip): ").strip()
    tester.build_report(client=client)


if __name__ == "__main__":
    main()
