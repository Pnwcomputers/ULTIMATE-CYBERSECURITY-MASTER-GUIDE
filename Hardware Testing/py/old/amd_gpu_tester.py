#!/usr/bin/env python3
"""
amd_gpu_tester.py — PNWC AMD Radeon GPU Diagnostic & Benchmark Tool v1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What this does that standalone_gpu_tester.py does NOT:
  • Polls amdgpu sysfs every second DURING the benchmark on a parallel thread,
    building a full load curve (temp, power, busy%, sclk/mclk states)
  • Reads DPM clock states (pp_dpm_sclk/mclk) — shows whether the card reaches
    its top performance level under load or stays pinned low
  • PCIe link state from pp_dpm_pcie (catches x8 / Gen3 negotiation)
  • VRAM usage from mem_info_vram_used/total
  • Watches dmesg for amdgpu ring timeout / GPU reset events during the run
  • Logs every per-second sample to a timestamped CSV
  • Optional FurMark torture via gputest (AUR) — WITH a safety warning

All sysfs paths verified against kernel.org amdgpu hwmon/thermal documentation.

Requires : inxi, glmark2 (or glmark2-es2)
Optional : amdgpu_top, radeontop (richer snapshots), gputest (AUR — FurMark)

Run from a desktop session (X11 or Wayland). sudo NOT required for sysfs reads.

Install missing tools:
  pamac build glmark2                 # OpenGL benchmark
  sudo pacman -S amdgpu_top radeontop # richer AMD snapshots
  pamac build gputest                 # optional FurMark (see WARNING below)

⚠️  FURMARK WARNING: On some Manjaro kernels (6.18 reported), GpuTest/FurMark
    can trigger amdgpu ring timeouts and GPU resets. The --furmark flag is
    opt-in and the script watches dmesg for reset events. Use with caution on
    a dedicated test bench, not production hardware.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import subprocess
import datetime
import os
import sys
import glob
import shutil
import threading
import time
import csv
import re

# ── Configuration ──────────────────────────────────────────────────────────────
REPORT_DIR        = os.getcwd()
GLMARK2_TIMEOUT   = 600
GLMARK2_SCENES    = None
SYSFS_POLL_S      = 1
GPUTEST_DURATION  = 60

TEMP_WARN_C       = 90    # amdgpu crit is typically ~94-100°C; warn at 90
TEMP_FAIL_C       = 100
# ───────────────────────────────────────────────────────────────────────────────


def _read_sysfs(path: str):
    """Read a sysfs file, returning stripped text or None on any error.

    gpu_busy_percent and others can return -EINVAL / -ENODATA on some cards;
    every read must be defensive.
    """
    try:
        with open(path) as fh:
            return fh.read().strip()
    except Exception:
        return None


def _read_int(path: str):
    v = _read_sysfs(path)
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


class AmdCard:
    """Resolve sysfs paths for an AMD card and read its sensors."""

    def __init__(self, card_path: str):
        self.device = card_path                      # /sys/class/drm/cardN/device
        self.hwmon  = self._find_hwmon(card_path)    # .../hwmon/hwmonX or None

    @staticmethod
    def _find_hwmon(device_path: str):
        candidates = glob.glob(os.path.join(device_path, "hwmon", "hwmon*"))
        return candidates[0] if candidates else None

    # ── Individual sensor reads (all defensive) ─────────────────────────────────

    def temp_c(self):
        if not self.hwmon:
            return None
        raw = _read_int(os.path.join(self.hwmon, "temp1_input"))   # millidegrees
        return raw / 1000.0 if raw is not None else None

    def power_w(self):
        if not self.hwmon:
            return None
        raw = _read_int(os.path.join(self.hwmon, "power1_average"))  # microwatts
        return raw / 1_000_000.0 if raw is not None else None

    def fan_rpm(self):
        if not self.hwmon:
            return None
        return _read_int(os.path.join(self.hwmon, "fan1_input"))

    def pwm(self):
        if not self.hwmon:
            return None
        return _read_int(os.path.join(self.hwmon, "pwm1"))           # 0-255

    def busy_pct(self):
        return _read_int(os.path.join(self.device, "gpu_busy_percent"))

    def mem_busy_pct(self):
        return _read_int(os.path.join(self.device, "mem_busy_percent"))

    def vram_used_mb(self):
        raw = _read_int(os.path.join(self.device, "mem_info_vram_used"))
        return raw / (1024 * 1024) if raw is not None else None

    def vram_total_mb(self):
        raw = _read_int(os.path.join(self.device, "mem_info_vram_total"))
        return raw / (1024 * 1024) if raw is not None else None

    def _active_dpm_level(self, fname: str):
        """Parse pp_dpm_sclk/mclk: the active level line ends with '*'."""
        raw = _read_sysfs(os.path.join(self.device, fname))
        if not raw:
            return None
        for line in raw.splitlines():
            if "*" in line:
                # e.g. "1: 2787Mhz *"
                m = re.search(r":\s*([\d.]+\s*\w?hz)", line, re.IGNORECASE)
                if m:
                    return m.group(1).strip()
                return line.strip()
        return None

    def sclk_active(self):
        return self._active_dpm_level("pp_dpm_sclk")

    def mclk_active(self):
        return self._active_dpm_level("pp_dpm_mclk")

    def pcie_active(self):
        """Parse pp_dpm_pcie active level. Format differs from clk files:
        '1: 8.0GT/s, x16 *' — capture the speed+width, not a Mhz value."""
        raw = _read_sysfs(os.path.join(self.device, "pp_dpm_pcie"))
        if not raw:
            return None
        for line in raw.splitlines():
            if "*" in line:
                m = re.search(r":\s*(.+?)\s*\*", line)
                if m:
                    return m.group(1).strip()
                return line.strip()
        return None

    def sclk_max(self):
        """Highest available sclk level (last non-deepsleep line)."""
        raw = _read_sysfs(os.path.join(self.device, "pp_dpm_sclk"))
        if not raw:
            return None
        levels = [l for l in raw.splitlines() if not l.strip().startswith("S:")]
        if not levels:
            return None
        m = re.search(r":\s*([\d.]+\s*\w?hz)", levels[-1], re.IGNORECASE)
        return m.group(1).strip() if m else levels[-1].strip()


def find_amd_cards() -> list:
    """Return AmdCard objects for every amdgpu-driven card found."""
    cards = []
    for card_path in sorted(glob.glob("/sys/class/drm/card*/device")):
        # Confirm it's amdgpu by checking the driver symlink
        driver = os.path.join(card_path, "driver")
        try:
            target = os.readlink(driver)
            if "amdgpu" in target:
                cards.append(AmdCard(card_path))
        except OSError:
            # Some entries (card0-eDP-1 etc.) won't have a driver link; skip
            continue
    return cards


# ── CSV / numeric-sampling monitor ──────────────────────────────────────────────

CSV_FIELDS = ["timestamp", "temp_c", "power_w", "busy_pct", "mem_busy_pct",
              "fan_rpm", "pwm", "sclk", "mclk", "vram_used_mb"]


class AmdMonitor:
    def __init__(self, card: AmdCard, csv_path: str):
        self.card     = card
        self.csv_path = csv_path
        self.running  = False
        self._thread  = None
        self._lock    = threading.Lock()
        self._samples = 0

        self.temps:  list[float] = []
        self.powers: list[float] = []
        self.busy:   list[float] = []
        self.sclks:  list[str]   = []

    def _sample_row(self):
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        t  = self.card.temp_c()
        p  = self.card.power_w()
        b  = self.card.busy_pct()
        mb = self.card.mem_busy_pct()
        fr = self.card.fan_rpm()
        pw = self.card.pwm()
        sc = self.card.sclk_active()
        mc = self.card.mclk_active()
        vu = self.card.vram_used_mb()

        with self._lock:
            self._samples += 1
            if t is not None: self.temps.append(t)
            if p is not None: self.powers.append(p)
            if b is not None: self.busy.append(b)
            if sc:            self.sclks.append(sc)

        return [
            ts,
            f"{t:.1f}" if t is not None else "",
            f"{p:.1f}" if p is not None else "",
            b  if b  is not None else "",
            mb if mb is not None else "",
            fr if fr is not None else "",
            pw if pw is not None else "",
            sc or "",
            mc or "",
            f"{vu:.0f}" if vu is not None else "",
        ]

    def _run_loop(self):
        with open(self.csv_path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(CSV_FIELDS)
            while self.running:
                w.writerow(self._sample_row())
                fh.flush()
                time.sleep(SYSFS_POLL_S)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=SYSFS_POLL_S + 5)

    def samples(self):
        with self._lock:
            return self._samples

    @staticmethod
    def _stats(series):
        if not series:
            return (0.0, 0.0, 0.0)
        return (min(series), sum(series) / len(series), max(series))

    def summary(self):
        with self._lock:
            top_sclk = max(set(self.sclks), key=self.sclks.count) if self.sclks else None
            return {
                "temp":  self._stats(self.temps),
                "power": self._stats(self.powers),
                "busy":  self._stats(self.busy),
                "top_sclk_seen": top_sclk,
            }


# ── dmesg watcher for amdgpu resets ─────────────────────────────────────────────

class AmdgpuResetWatcher:
    _PAT = re.compile(r"amdgpu.*(ring.*timeout|reset|GPU reset|hang)", re.IGNORECASE)

    def __init__(self, start_epoch: int):
        self.start_epoch = start_epoch
        self.events: list[str] = []
        self.running = False
        self._thread = None
        self._lock = threading.Lock()
        self._seen = set()

    def _poll(self):
        try:
            out = subprocess.run(
                f"journalctl -k --since @{self.start_epoch} --no-pager "
                f"--output=short-monotonic 2>/dev/null",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, timeout=15,
            ).stdout
        except Exception:
            return
        for line in out.splitlines():
            if self._PAT.search(line):
                sig = line[20:].strip() if len(line) > 20 else line
                if sig not in self._seen:
                    self._seen.add(sig)
                    with self._lock:
                        self.events.append(sig)
                    print(f"\n  🔴 AMDGPU RESET/TIMEOUT: {sig[:100]}")

    def _run_loop(self):
        while self.running:
            self._poll()
            time.sleep(10)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=12)
        self._poll()  # final sweep

    def count(self):
        with self._lock:
            return len(self.events)


class AmdGPUTester:
    def __init__(self):
        self.ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data = {
            "inxi_gpu":     "",
            "card_info":    "",
            "idle_snap":    {},
            "benchmark":    "",
            "scene_scores": [],
            "glmark2_cmd":  "",
            "load_summary": {},
            "amdgpu_top":   "",
            "furmark":      "",
            "reset_events": 0,
            "csv_path":     "",
            "errors":       [],
            "warnings":     [],
        }

    @staticmethod
    def _which(b):
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
                        f"[{cmd.split()[0]}] rc={r.returncode}: {err[:400]}")
            return r.stdout.strip()
        except subprocess.TimeoutExpired:
            self.data["errors"].append(f"TIMEOUT ({timeout}s): {cmd}")
            return "TIMEOUT"
        except Exception as exc:
            self.data["errors"].append(f"EXEC ERROR: {cmd} → {exc}")
            return "ERROR"

    def _detect_display(self):
        if os.environ.get("WAYLAND_DISPLAY"):
            return "wayland"
        if os.environ.get("DISPLAY"):
            return "x11"
        return None

    def _pick_glmark2(self, display):
        order = (["glmark2-wayland", "glmark2-es2-wayland", "glmark2-es2", "glmark2"]
                 if display == "wayland"
                 else ["glmark2", "glmark2-es2"])
        return next((b for b in order if self._which(b)), None)

    def gather_static(self, card: AmdCard):
        print("\n[1/4] AMD GPU identification & idle snapshot...")
        self.data["inxi_gpu"] = self.run_cmd("inxi -G -c0", timeout=30)

        vram_total = card.vram_total_mb()
        info_lines = [
            f"sysfs device     : {card.device}",
            f"hwmon path       : {card.hwmon or 'NOT FOUND'}",
            f"VRAM total       : {vram_total:.0f} MiB" if vram_total else "VRAM total       : unknown",
            f"Max sclk level   : {card.sclk_max() or 'unknown'}",
            f"PCIe (active)    : {card.pcie_active() or 'unknown'}",
        ]
        self.data["card_info"] = "\n".join(info_lines)

        # Idle snapshot
        self.data["idle_snap"] = {
            "temp":  card.temp_c(),
            "power": card.power_w(),
            "busy":  card.busy_pct(),
            "sclk":  card.sclk_active(),
            "mclk":  card.mclk_active(),
        }

        # amdgpu_top snapshot if available
        if self._which("amdgpu_top"):
            self.data["amdgpu_top"] = self.run_cmd(
                "amdgpu_top --dump 2>/dev/null || amdgpu_top -d 2>/dev/null | head -60",
                timeout=15,
            )
        elif self._which("radeontop"):
            self.data["amdgpu_top"] = self.run_cmd(
                "radeontop -d - -l 2 2>/dev/null", timeout=15)
        else:
            self.data["warnings"].append(
                "Neither amdgpu_top nor radeontop installed — "
                "install with: sudo pacman -S amdgpu_top radeontop")

        # Warn if busy% sysfs unsupported (some cards)
        if card.busy_pct() is None:
            self.data["warnings"].append(
                "gpu_busy_percent unsupported on this card — "
                "utilization will read as blank in the CSV (not an error).")

    def run_benchmark(self, display, monitor: AmdMonitor, watcher: AmdgpuResetWatcher):
        print("\n[2/4] glmark2 benchmark with live sysfs monitoring...")
        binary = self._pick_glmark2(display)
        if binary is None:
            self.data["benchmark"] = "SKIPPED — glmark2 not installed (pamac build glmark2)."
            self.data["warnings"].append("glmark2 not installed.")
            return

        scene_args = (" ".join(f"--benchmark {s}" for s in GLMARK2_SCENES)
                      if GLMARK2_SCENES else "")
        cmd = f"{binary} -s 1920x1080 {scene_args}".strip()
        self.data["glmark2_cmd"] = cmd
        print(f"    Binary  : {binary}  |  Display : {display.upper()}")
        print(f"    Monitor : amdgpu sysfs every {SYSFS_POLL_S}s → {monitor.csv_path}")
        print()

        monitor.start()
        watcher.start()
        lines, timed_out = self._run_streaming(cmd, GLMARK2_TIMEOUT)
        watcher.stop()
        monitor.stop()

        scenes, final = [], None
        for ln in lines:
            s = ln.strip()
            if s.startswith("[") and "FPS:" in s:
                scenes.append(s)
            if "glmark2 Score" in s:
                final = s
        self.data["scene_scores"] = scenes
        self.data["benchmark"] = (
            final if final
            else (f"PARTIAL ({len(scenes)} scenes)" if scenes else "FAILED — no score parsed.")
        )
        self.data["load_summary"] = monitor.summary()
        self.data["reset_events"] = watcher.count()

    def _run_streaming(self, cmd, timeout):
        lines, timed_out = [], False
        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1)

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
                self.data["errors"].append(f"glmark2 killed after {timeout}s.")
            else:
                proc.wait()
        except Exception as exc:
            self.data["errors"].append(f"Streaming error: {exc}")
            timed_out = True
        return lines, timed_out

    def run_furmark(self, card: AmdCard, csv_base: str, start_epoch: int):
        print("\n[3/4] FurMark thermal torture (gputest)...")
        print("    ⚠️  Watching dmesg for amdgpu ring timeouts / resets...")
        if not os.path.exists("/opt/gputest/GpuTest"):
            self.data["furmark"] = "SKIPPED — gputest not installed (pamac build gputest)."
            self.data["warnings"].append("gputest not installed; skipped FurMark.")
            return

        furmark_csv = csv_base.replace(".csv", "_furmark.csv")
        mon = AmdMonitor(card, furmark_csv)
        watcher = AmdgpuResetWatcher(start_epoch)

        cmd = (f"cd /opt/gputest && ./GpuTest /test=fur /width=1920 /height=1080 "
               f"/msaa=0 /benchmark /benchmark_duration_ms={GPUTEST_DURATION*1000} "
               f"/no_scorebox")
        print(f"    → {cmd}")

        mon.start()
        watcher.start()
        self.run_cmd(cmd, timeout=GPUTEST_DURATION + 60)
        watcher.stop()
        mon.stop()

        summ = mon.summary()
        t, p = summ["temp"], summ["power"]
        resets = watcher.count()
        self.data["furmark"] = (
            f"FurMark {GPUTEST_DURATION}s @ 1920×1080\n"
            f"Peak temp: {t[2]:.0f}°C (avg {t[1]:.0f}°C)  |  "
            f"Peak power: {p[2]:.0f}W (avg {p[1]:.0f}W)\n"
            f"amdgpu reset/timeout events: {resets}\n"
            f"Per-second log: {furmark_csv}"
        )
        if resets > 0:
            self.data["errors"].append(
                f"🔴 {resets} amdgpu reset/timeout event(s) during FurMark — "
                f"known FurMark+amdgpu instability or genuine GPU fault.")
        if t[2] >= TEMP_FAIL_C:
            self.data["warnings"].append(
                f"FurMark peak {t[2]:.0f}°C ≥ {TEMP_FAIL_C}°C — check cooling.")

    def build_report(self, client: str = "") -> str:
        print("\n[4/4] Compiling report...")
        cb = "```"
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        client_str = f"**Prepared For:** {client}\n" if client else ""
        ls = self.data["load_summary"]
        idle = self.data["idle_snap"]

        # Verdict
        checks = []
        if ls and ls.get("temp"):
            peak = ls["temp"][2]
            checks.append(("Load Temperature", peak < TEMP_FAIL_C,
                           f"Peak {peak:.0f}°C (limit {TEMP_FAIL_C}°C)"))
        checks.append(("amdgpu Resets", self.data["reset_events"] == 0,
                       f"{self.data['reset_events']} ring timeout/reset event(s)"))
        if ls and ls.get("busy"):
            peak_busy = ls["busy"][2]
            # If the card never went busy, the benchmark may not have hit the GPU
            checks.append(("GPU Engaged", peak_busy >= 50 or not self.data["scene_scores"],
                           f"Peak busy {peak_busy:.0f}%"
                           + ("" if peak_busy >= 50 else " — GPU may not have been exercised")))

        overall = all(c[1] for c in checks) if checks else True
        verdict = "✅ PASS" if overall else "❌ FAIL"
        verdict_rows = "".join(
            f"| {'✅' if ok else '❌'} | {name} | {detail} |\n"
            for name, ok, detail in checks
        ) or "| — | No checks | — |\n"

        def _fmt(s):
            return f"{s[0]:.0f} / {s[1]:.0f} / {s[2]:.0f}" if s else "— / — / —"

        if ls and idle:
            def _iv(v, suf=""):
                return f"{v:.0f}{suf}" if isinstance(v, (int, float)) else (v or "?")
            load_table = (
                f"| Metric | Idle | Load min/avg/max |\n| :--- | ---: | ---: |\n"
                f"| Temp (°C) | {_iv(idle.get('temp'))} | {_fmt(ls['temp'])} |\n"
                f"| Power (W) | {_iv(idle.get('power'))} | {_fmt(ls['power'])} |\n"
                f"| Busy (%) | {_iv(idle.get('busy'))} | {_fmt(ls['busy'])} |\n"
                f"| sclk idle→top | {idle.get('sclk') or '?'} | "
                f"top seen: {ls.get('top_sclk_seen') or '?'} |\n"
            )
        else:
            load_table = "_No load data collected._\n"

        scenes_block = ("\n".join(self.data["scene_scores"])
                        if self.data["scene_scores"] else "No per-scene data.")

        issues = self.data["errors"] + self.data["warnings"]
        diag = (f"\n## Diagnostics Log\n{cb}text\n" + "\n".join(issues) + f"\n{cb}\n"
                if issues else "\n**Status:** ✅ No errors or warnings.\n")

        furmark_block = ""
        if self.data["furmark"]:
            furmark_block = (f"\n## 5. FurMark Thermal Torture\n{cb}text\n"
                             f"{self.data['furmark']}\n{cb}\n")

        amdgpu_top_block = ""
        if self.data["amdgpu_top"]:
            amdgpu_top_block = (f"\n### amdgpu_top / radeontop snapshot\n{cb}text\n"
                                f"{self.data['amdgpu_top'][:2000]}\n{cb}\n")

        report = f"""# AMD Radeon GPU Diagnostic & Benchmark Report
**Date:** {self.ts}
{client_str}
---

## Overall Verdict: {verdict}

| Result | Check | Detail |
| :--- | :--- | :--- |
{verdict_rows}
---

## 1. Hardware Information
{cb}text
{self.data['card_info']}
{cb}

inxi:
{cb}text
{self.data['inxi_gpu']}
{cb}
{amdgpu_top_block}
---

## 2. Idle vs Load Comparison
*amdgpu sysfs polled every {SYSFS_POLL_S}s during benchmark*

{load_table}

---

## 3. glmark2 Benchmark
*Command:* `{self.data['glmark2_cmd']}`

**Result:** `{self.data['benchmark']}`

### Per-Scene FPS
{cb}text
{scenes_block}
{cb}

---

## 4. Kernel Stability
**amdgpu ring timeout / reset events during testing:** {self.data['reset_events']}
{furmark_block}{diag}
---
*Per-second monitoring log: {self.data['csv_path']}*
*Generated by PNWC amd_gpu_tester.py v1.0*
"""

        fname = os.path.join(REPORT_DIR, f"AMD_GPU_Report_{ts_file}.md")
        with open(fname, "w") as fh:
            fh.write(report)
        print(f"\n✅  Report → {fname}")
        return fname


def main():
    import argparse
    ap = argparse.ArgumentParser(description="PNWC AMD Radeon GPU Tester v1.0")
    ap.add_argument("--client", default="", help="Client name for the report")
    ap.add_argument("--furmark", action="store_true",
                    help="Also run FurMark torture (gputest). See WARNING in header.")
    args = ap.parse_args()

    print("=" * 60)
    print("  PNWC AMD Radeon GPU Diagnostic & Benchmark Tool v1.0")
    print("=" * 60)

    cards = find_amd_cards()
    if not cards:
        print("\n❌  No amdgpu-driven cards found under /sys/class/drm/.")
        print("    Is this an AMD system with the amdgpu driver loaded?")
        sys.exit(1)

    card = cards[0]
    if len(cards) > 1:
        print(f"\n  Found {len(cards)} AMD cards; testing first: {card.device}")

    tester = AmdGPUTester()

    display = tester._detect_display()
    if display is None:
        print("\n❌  No display detected. Run from a desktop terminal, not SSH.")
        tester.gather_static(card)
        tester.build_report(client=args.client)
        sys.exit(1)
    print(f"\nDisplay server : {display.upper()}")

    tester.gather_static(card)

    ts_file  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(REPORT_DIR, f"amd_load_{ts_file}.csv")
    tester.data["csv_path"] = csv_path

    start_epoch = int(time.time())
    monitor = AmdMonitor(card, csv_path)
    watcher = AmdgpuResetWatcher(start_epoch)

    tester.run_benchmark(display, monitor, watcher)

    if args.furmark:
        tester.run_furmark(card, csv_path, start_epoch)

    client = args.client or input("\nClient name (Enter to skip): ").strip()
    tester.build_report(client=client)


if __name__ == "__main__":
    main()
