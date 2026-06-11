#!/usr/bin/env python3
"""
amd_gpu_tester.py — PNWC AMD Radeon GPU Diagnostic & Benchmark Tool v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What this script DOES:
  • Keeps the PNWC-branded diagnostic identity and customer-facing report format
  • Polls amdgpu sysfs every second during the full GPU test window
  • Builds a per-second CSV load curve: edge/hotspot/memory temps when exposed,
    power, busy%, memory busy%, fan, PWM, sclk/mclk states, PCIe state, VRAM use
  • Reads DPM clock states (pp_dpm_sclk/mclk) to verify the card boosts under load
  • Reads PCIe state from pp_dpm_pcie plus current/max sysfs link fields when present
  • Runs optional-but-default deeper diagnostics when tools are installed:
      - memtest_vulkan for VRAM stability
      - vkmark for Vulkan load
      - glmark2 for OpenGL load
      - GpuTest/FurMark as opt-in legacy thermal torture only
  • Watches kernel logs during the test for amdgpu ring timeouts, GPU resets,
    VM faults, PCIe AER, and related GPU fault events
  • Captures optional amd-smi / amdgpu_top / radeontop snapshots when available
  • Detects likely software rendering / wrong renderer paths
  • Writes a timestamped Markdown report and telemetry CSV

Requires : inxi
Recommended: vulkan-tools, mesa-utils, memtest_vulkan, vkmark, glmark2,
             amdsmi or amdgpu_top
Optional : radeontop, gputest (AUR — FurMark; legacy/opt-in)

Run from a desktop session for vkmark/glmark2/FurMark. memtest_vulkan may work
without a desktop depending on the Vulkan stack.

Install baseline:
  sudo pacman -S --needed inxi vulkan-tools mesa-utils vkmark glmark2 \
      mesa vulkan-radeon amdsmi amdgpu_top radeontop

Optional:
  # memtest_vulkan: install/build from trusted package source or upstream
  pamac build gputest

⚠️  FURMARK WARNING:
    GpuTest/FurMark can trigger amdgpu ring timeouts and GPU resets on some
    kernel/driver/card combinations. The --furmark flag is opt-in and should be
    treated as legacy thermal torture, not the primary proof of GPU health.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import argparse
import csv
import datetime
import getpass
import glob
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────────
REPORT_DIR              = os.getcwd()
SYSFS_POLL_S            = 1
MEMTEST_DURATION        = 360       # upstream recommends at least ~6 minutes
VKMARK_TIMEOUT          = 600
GLMARK2_TIMEOUT         = 600
GPUTEST_DURATION        = 60
TEMP_WARN_C             = 90
TEMP_FAIL_C             = 100
GPU_BUSY_MIN_WARN       = 35
# ───────────────────────────────────────────────────────────────────────────────

SOFTWARE_RENDERERS = ("llvmpipe", "lavapipe", "softpipe", "software rasterizer", "swrast")

KERNEL_PATTERNS = [
    r"amdgpu.*ring.*timeout",
    r"amdgpu.*GPU reset",
    r"amdgpu.*reset",
    r"amdgpu.*hang",
    r"amdgpu.*VM fault",
    r"amdgpu.*fault",
    r"amdgpu.*device lost",
    r"PCIe Bus Error",
    r"AER:",
    r"pcieport.*error",
]


def timestamp_file() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def printable_cmd(cmd) -> str:
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(c) for c in cmd)
    return str(cmd)


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def trim_block(text: str, max_chars: int = 4000) -> str:
    text = text or ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [trimmed] ..."


def _read_sysfs(path: str):
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


def _to_mb(raw: Optional[int]):
    return raw / (1024 * 1024) if raw is not None else None


def print_banner(report_file_path="Not Generated Yet"):
    """Render the PNWC toolkit ASCII banner to the terminal window."""
    if platform.system() == "Windows":
        os.system("title PNWC AMD Radeon GPU Diagnostic v2.0")
    else:
        print("\033]0;PNWC AMD Radeon GPU Diagnostic v2.0\a", end="")

    os.system('cls' if os.name == 'nt' else 'clear')
    formatted_time = datetime.datetime.now().strftime('%A %B %d %Y  %H:%M:%S')

    print("")
    print("  ######   ##  ##   ##    ##   ######")
    print("  ##  ##   ### ##   ##    ##   ##    ")
    print("  ######   ######   ## ## ##   ##    ")
    print("  ##       ## ###   ########   ##    ")
    print("  ##       ##  ##   ##    ##   ######")
    print("")
    print("  Pacific Northwest Computers")
    print("  AMD Radeon GPU Testing & Benchmark Script v2.0")
    print("")
    print("=" * 70)
    print("   PNWC Diagnostic Tool - AMD GPU Hardware & Load Benchmarking")
    print("   Pacific Northwest Computers  |  support@pnwcomputers.com")
    print("   v2.0 -- Deep Diagnostics Variant")
    print("=" * 70)
    print("")
    print(f"  Started  : {formatted_time}")
    print(f"  Computer : {platform.node()}")
    print(f"  Operator : {getpass.getuser()}")
    print(f"  CSV Log  : {report_file_path}")
    print("")


class ProcessRunner:
    def __init__(self, errors: list[str], warnings: list[str]):
        self.errors = errors
        self.warnings = warnings

    def run_cmd(self, cmd, timeout: int = 60, cwd: str | None = None, allow_fail: bool = False) -> str:
        print(f"    → {printable_cmd(cmd)}")
        shell = isinstance(cmd, str)
        try:
            r = subprocess.run(
                cmd,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            if r.returncode != 0 and not allow_fail:
                err = r.stderr.strip()
                if err:
                    self.errors.append(f"[{printable_cmd(cmd).split()[0]}] rc={r.returncode}: {err[:500]}")
            return r.stdout.strip()
        except subprocess.TimeoutExpired:
            self.errors.append(f"TIMEOUT ({timeout}s): {printable_cmd(cmd)}")
            return "TIMEOUT"
        except Exception as exc:
            self.errors.append(f"EXEC ERROR: {printable_cmd(cmd)} → {exc}")
            return "ERROR"

    def run_streaming(self, cmd, timeout: int, cwd: str | None = None, label: str = "process") -> tuple[list[str], bool, int | None]:
        lines: list[str] = []
        timed_out = False
        rc: int | None = None
        shell = isinstance(cmd, str)

        print(f"    → {printable_cmd(cmd)}")
        print(f"       [streaming output — timeout {timeout}s / {timeout//60}m{timeout%60:02d}s]")

        try:
            proc = subprocess.Popen(
                cmd,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=cwd,
                start_new_session=True,
            )

            def _reader():
                if proc.stdout is None:
                    return
                for raw in proc.stdout:
                    line = raw.rstrip()
                    lines.append(line)
                    if any(k.lower() in line.lower() for k in [
                        "[", "score", "error", "failed", "warning", "fault", "gpu",
                        "mismatch", "corrupt", "timeout", "reset", "hang"
                    ]):
                        print(f"       {line}")

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()
            reader.join(timeout=timeout)

            if reader.is_alive():
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    time.sleep(2)
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    try:
                        proc.terminate()
                        time.sleep(2)
                        proc.kill()
                    except Exception:
                        pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                self.warnings.append(f"{label} stopped after {timeout}s timeout; partial output collected.")
            else:
                proc.wait()
                rc = proc.returncode
                if rc not in (0, None):
                    self.errors.append(f"{label} exited with rc={rc}.")
        except Exception as exc:
            timed_out = True
            self.errors.append(f"STREAM ERROR ({label}): {exc}")

        return lines, timed_out, rc


class KernelFaultWatcher:
    def __init__(self, start_epoch: int, patterns: list[str], errors: list[str]):
        self.start_epoch = start_epoch
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.errors = errors
        self.events: list[str] = []
        self.running = False
        self._thread = None
        self._seen = set()
        self._lock = threading.Lock()

    def _poll(self):
        try:
            out = subprocess.run(
                ["journalctl", "-k", "--since", f"@{self.start_epoch}", "--no-pager", "--output=short-monotonic"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=15,
            ).stdout
        except Exception:
            return
        for line in out.splitlines():
            if any(p.search(line) for p in self.patterns):
                sig = line.strip()
                if sig not in self._seen:
                    self._seen.add(sig)
                    with self._lock:
                        self.events.append(sig)
                    print(f"\n  🔴 AMDGPU/KERNEL GPU EVENT: {sig[:140]}")

    def _run_loop(self):
        while self.running:
            self._poll()
            time.sleep(5)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=8)
        self._poll()
        if self.count() > 0:
            self.errors.append(f"{self.count()} AMD/kernel GPU fault event(s) detected during testing.")

    def count(self) -> int:
        with self._lock:
            return len(self.events)

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self.events)


class AmdCard:
    """Resolve sysfs paths for an AMD card and read its sensors defensively."""

    def __init__(self, card_path: str):
        self.device = card_path
        self.hwmon = self._find_hwmon(card_path)
        self.drm_card = os.path.basename(os.path.dirname(card_path))

    @staticmethod
    def _find_hwmon(device_path: str):
        candidates = sorted(glob.glob(os.path.join(device_path, "hwmon", "hwmon*")))
        if not candidates:
            return None
        # Prefer hwmon whose name says amdgpu when present.
        for c in candidates:
            name = _read_sysfs(os.path.join(c, "name")) or ""
            if "amdgpu" in name.lower():
                return c
        return candidates[0]

    def hwmon_name(self):
        return _read_sysfs(os.path.join(self.hwmon, "name")) if self.hwmon else None

    def _temp_by_label(self, preferred: tuple[str, ...]):
        if not self.hwmon:
            return None
        inputs = sorted(glob.glob(os.path.join(self.hwmon, "temp*_input")))
        label_map = {}
        for inp in inputs:
            base = inp[:-6]  # remove _input
            label = (_read_sysfs(base + "_label") or "").strip().lower()
            raw = _read_int(inp)
            val = raw / 1000.0 if raw is not None else None
            if label:
                label_map[label] = val
        for wanted in preferred:
            for label, val in label_map.items():
                if wanted in label and val is not None:
                    return val
        # fallback to first available temp input
        for inp in inputs:
            raw = _read_int(inp)
            if raw is not None:
                return raw / 1000.0
        return None

    def temp_edge_c(self):
        return self._temp_by_label(("edge", "junction", "hotspot", "mem"))

    def temp_junction_c(self):
        return self._temp_by_label(("junction", "hotspot", "junction temperature"))

    def temp_mem_c(self):
        return self._temp_by_label(("mem", "memory", "vram"))

    def temp_peak_c(self):
        vals = [v for v in [self.temp_edge_c(), self.temp_junction_c(), self.temp_mem_c()] if v is not None]
        return max(vals) if vals else None

    def power_w(self):
        if not self.hwmon:
            return None
        # AMD normally exposes microwatts. Try average first, then input.
        raw = _read_int(os.path.join(self.hwmon, "power1_average"))
        if raw is None:
            raw = _read_int(os.path.join(self.hwmon, "power1_input"))
        return raw / 1_000_000.0 if raw is not None else None

    def fan_rpm(self):
        if not self.hwmon:
            return None
        return _read_int(os.path.join(self.hwmon, "fan1_input"))

    def pwm(self):
        if not self.hwmon:
            return None
        return _read_int(os.path.join(self.hwmon, "pwm1"))

    def busy_pct(self):
        return _read_int(os.path.join(self.device, "gpu_busy_percent"))

    def mem_busy_pct(self):
        return _read_int(os.path.join(self.device, "mem_busy_percent"))

    def vram_used_mb(self):
        return _to_mb(_read_int(os.path.join(self.device, "mem_info_vram_used")))

    def vram_total_mb(self):
        return _to_mb(_read_int(os.path.join(self.device, "mem_info_vram_total")))

    def _active_dpm_level(self, fname: str):
        raw = _read_sysfs(os.path.join(self.device, fname))
        if not raw:
            return None
        for line in raw.splitlines():
            if "*" in line:
                m = re.search(r":\s*(.+?)\s*\*", line)
                return m.group(1).strip() if m else line.strip()
        return None

    def _max_dpm_level(self, fname: str):
        raw = _read_sysfs(os.path.join(self.device, fname))
        if not raw:
            return None
        levels = [l.strip() for l in raw.splitlines() if l.strip() and not l.strip().startswith("S:")]
        if not levels:
            return None
        m = re.search(r":\s*(.+?)(?:\s*\*)?$", levels[-1])
        return m.group(1).strip() if m else levels[-1]

    def sclk_active(self):
        return self._active_dpm_level("pp_dpm_sclk")

    def mclk_active(self):
        return self._active_dpm_level("pp_dpm_mclk")

    def sclk_max(self):
        return self._max_dpm_level("pp_dpm_sclk")

    def mclk_max(self):
        return self._max_dpm_level("pp_dpm_mclk")

    def pcie_active(self):
        return self._active_dpm_level("pp_dpm_pcie")

    def current_link_speed(self):
        return _read_sysfs(os.path.join(self.device, "current_link_speed"))

    def current_link_width(self):
        return _read_sysfs(os.path.join(self.device, "current_link_width"))

    def max_link_speed(self):
        return _read_sysfs(os.path.join(self.device, "max_link_speed"))

    def max_link_width(self):
        return _read_sysfs(os.path.join(self.device, "max_link_width"))


def find_amd_cards() -> list[AmdCard]:
    cards: list[AmdCard] = []
    for card_path in sorted(glob.glob("/sys/class/drm/card*/device")):
        driver = os.path.join(card_path, "driver")
        try:
            target = os.readlink(driver)
            if "amdgpu" in target:
                cards.append(AmdCard(card_path))
        except OSError:
            continue
    return cards


CSV_FIELDS = [
    "timestamp",
    "temp_edge_c",
    "temp_junction_c",
    "temp_mem_c",
    "temp_peak_c",
    "power_w",
    "busy_pct",
    "mem_busy_pct",
    "fan_rpm",
    "pwm",
    "sclk",
    "mclk",
    "pcie_active",
    "current_link_speed",
    "current_link_width",
    "vram_used_mb",
    "vram_total_mb",
]


class AmdMonitor:
    def __init__(self, card: AmdCard, csv_path: str):
        self.card = card
        self.csv_path = csv_path
        self.running = False
        self._thread = None
        self._lock = threading.Lock()
        self._samples = 0

        self.temp_peak: list[float] = []
        self.temp_edge: list[float] = []
        self.temp_junction: list[float] = []
        self.temp_mem: list[float] = []
        self.powers: list[float] = []
        self.busy: list[float] = []
        self.mem_busy: list[float] = []
        self.vram_used: list[float] = []
        self.sclks: list[str] = []
        self.mclks: list[str] = []
        self.pcie: list[str] = []

    def _sample_row(self):
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        te = self.card.temp_edge_c()
        tj = self.card.temp_junction_c()
        tm = self.card.temp_mem_c()
        tp = self.card.temp_peak_c()
        p = self.card.power_w()
        b = self.card.busy_pct()
        mb = self.card.mem_busy_pct()
        fr = self.card.fan_rpm()
        pw = self.card.pwm()
        sc = self.card.sclk_active()
        mc = self.card.mclk_active()
        pc = self.card.pcie_active()
        cls = self.card.current_link_speed()
        clw = self.card.current_link_width()
        vu = self.card.vram_used_mb()
        vt = self.card.vram_total_mb()

        with self._lock:
            self._samples += 1
            for series, val in [
                (self.temp_edge, te), (self.temp_junction, tj), (self.temp_mem, tm),
                (self.temp_peak, tp), (self.powers, p), (self.busy, b),
                (self.mem_busy, mb), (self.vram_used, vu),
            ]:
                if val is not None:
                    series.append(float(val))
            if sc:
                self.sclks.append(sc)
            if mc:
                self.mclks.append(mc)
            if pc:
                self.pcie.append(pc)

        return [
            ts,
            f"{te:.1f}" if te is not None else "",
            f"{tj:.1f}" if tj is not None else "",
            f"{tm:.1f}" if tm is not None else "",
            f"{tp:.1f}" if tp is not None else "",
            f"{p:.1f}" if p is not None else "",
            b if b is not None else "",
            mb if mb is not None else "",
            fr if fr is not None else "",
            pw if pw is not None else "",
            sc or "",
            mc or "",
            pc or "",
            cls or "",
            clw or "",
            f"{vu:.0f}" if vu is not None else "",
            f"{vt:.0f}" if vt is not None else "",
        ]

    def _run_loop(self):
        try:
            with open(self.csv_path, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(CSV_FIELDS)
                while self.running:
                    w.writerow(self._sample_row())
                    fh.flush()
                    time.sleep(SYSFS_POLL_S)
        except Exception as e:
            print(f"\n[!] Monitor encountered a structural logging error: {e}")

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

    @staticmethod
    def _mode(series):
        if not series:
            return ""
        return max(set(series), key=series.count)

    def summary(self):
        with self._lock:
            return {
                "samples": self._samples,
                "temp_edge": self._stats(self.temp_edge),
                "temp_junction": self._stats(self.temp_junction),
                "temp_mem": self._stats(self.temp_mem),
                "temp_peak": self._stats(self.temp_peak),
                "power": self._stats(self.powers),
                "busy": self._stats(self.busy),
                "mem_busy": self._stats(self.mem_busy),
                "vram_used": self._stats(self.vram_used),
                "top_sclk_seen": self._mode(self.sclks),
                "top_mclk_seen": self._mode(self.mclks),
                "pcie_seen": self._mode(self.pcie),
            }


class AmdGPUTester:
    def __init__(self, card_index: int):
        self.card_index = card_index
        self.ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data = {
            "inxi_gpu": "",
            "lspci": "",
            "vulkan_summary": "",
            "glxinfo": "",
            "card_info": "",
            "idle_snap": {},
            "amdsmi": "",
            "amdgpu_top": "",
            "tests": {},
            "scene_scores": [],
            "load_summary": {},
            "kernel_events": [],
            "csv_path": "",
            "errors": [],
            "warnings": [],
        }
        self.runner = ProcessRunner(self.data["errors"], self.data["warnings"])

    def _which(self, b: str) -> bool:
        return tool_exists(b)

    def _detect_display(self):
        if os.environ.get("WAYLAND_DISPLAY"):
            return "wayland"
        if os.environ.get("DISPLAY"):
            return "x11"
        return None

    def _pick_glmark2(self, display):
        order = (["glmark2-wayland", "glmark2-es2-wayland", "glmark2-es2", "glmark2"]
                 if display == "wayland" else ["glmark2", "glmark2-es2"])
        return next((b for b in order if self._which(b)), None)

    def gather_static(self, card: AmdCard):
        print("\n[1/6] AMD GPU hardware, driver, and API identification...")
        self.data["inxi_gpu"] = self.runner.run_cmd(["inxi", "-G", "-c0"], timeout=30, allow_fail=True)
        self.data["lspci"] = self.runner.run_cmd("lspci -nnk | grep -A4 -E 'VGA|3D|Display|AMD|Radeon'", timeout=15, allow_fail=True)

        vram_total = card.vram_total_mb()
        pcie_sysfs = f"{card.current_link_speed() or '?'} x{card.current_link_width() or '?'}"
        max_pcie_sysfs = f"{card.max_link_speed() or '?'} x{card.max_link_width() or '?'}"
        info_lines = [
            f"sysfs device       : {card.device}",
            f"DRM card           : {card.drm_card}",
            f"hwmon path         : {card.hwmon or 'NOT FOUND'}",
            f"hwmon name         : {card.hwmon_name() or 'unknown'}",
            f"VRAM total         : {vram_total:.0f} MiB" if vram_total else "VRAM total         : unknown",
            f"Max sclk level     : {card.sclk_max() or 'unknown'}",
            f"Max mclk level     : {card.mclk_max() or 'unknown'}",
            f"PCIe DPM active    : {card.pcie_active() or 'unknown'}",
            f"PCIe sysfs current : {pcie_sysfs}",
            f"PCIe sysfs max     : {max_pcie_sysfs}",
        ]
        self.data["card_info"] = "\n".join(info_lines)

        self.data["idle_snap"] = {
            "temp_edge": card.temp_edge_c(),
            "temp_junction": card.temp_junction_c(),
            "temp_mem": card.temp_mem_c(),
            "temp_peak": card.temp_peak_c(),
            "power": card.power_w(),
            "busy": card.busy_pct(),
            "mem_busy": card.mem_busy_pct(),
            "sclk": card.sclk_active(),
            "mclk": card.mclk_active(),
            "pcie": card.pcie_active(),
            "vram_used": card.vram_used_mb(),
        }

        if self._which("amd-smi"):
            self.data["amdsmi"] = self.runner.run_cmd(["amd-smi", "static", "--gpu", str(self.card_index)], timeout=20, allow_fail=True)
            metric = self.runner.run_cmd(["amd-smi", "metric", "--gpu", str(self.card_index)], timeout=20, allow_fail=True)
            if metric:
                self.data["amdsmi"] += "\n\n--- amd-smi metric ---\n" + metric
        elif self._which("amdsmi"):
            self.data["amdsmi"] = self.runner.run_cmd(["amdsmi", "static", "--gpu", str(self.card_index)], timeout=20, allow_fail=True)
        else:
            self.data["warnings"].append("amd-smi/amdsmi not found; AMD SMI snapshot skipped.")

        if self._which("amdgpu_top"):
            self.data["amdgpu_top"] = self.runner.run_cmd("amdgpu_top --dump 2>/dev/null || amdgpu_top -d 2>/dev/null | head -80", timeout=20, allow_fail=True)
        elif self._which("radeontop"):
            self.data["amdgpu_top"] = self.runner.run_cmd("radeontop -d - -l 2 2>/dev/null", timeout=15, allow_fail=True)
        else:
            self.data["warnings"].append("Neither amdgpu_top nor radeontop installed; richer AMD snapshot skipped.")

        if card.busy_pct() is None:
            self.data["warnings"].append("gpu_busy_percent unsupported on this card; utilization may be blank in CSV.")

        if self._which("vulkaninfo"):
            self.data["vulkan_summary"] = self.runner.run_cmd(["vulkaninfo", "--summary"], timeout=30, allow_fail=True)
        else:
            self.data["warnings"].append("vulkaninfo not found. Install: sudo pacman -S vulkan-tools")

        if self._which("glxinfo"):
            self.data["glxinfo"] = self.runner.run_cmd(["glxinfo", "-B"], timeout=30, allow_fail=True)
        else:
            self.data["warnings"].append("glxinfo not found. Install: sudo pacman -S mesa-utils")

        renderer_text = f"{self.data['vulkan_summary']}\n{self.data['glxinfo']}".lower()
        if any(s in renderer_text for s in SOFTWARE_RENDERERS):
            self.data["errors"].append("Software renderer detected (llvmpipe/lavapipe/softpipe). Test may not be hitting AMD GPU.")

    def run_memtest_vulkan(self, duration: int):
        print("\n[2/6] Vulkan VRAM stability test (memtest_vulkan)...")
        if not self._which("memtest_vulkan"):
            self.data["tests"]["memtest_vulkan"] = "SKIPPED - memtest_vulkan not installed."
            self.data["warnings"].append("memtest_vulkan not installed; VRAM-specific Vulkan memory test skipped.")
            return
        lines, timed_out, rc = self.runner.run_streaming(["memtest_vulkan"], timeout=duration, label="memtest_vulkan")
        text = "\n".join(lines)
        bad_lines = [l for l in lines if re.search(r"(mismatch|corrupt|fail|fault|error)", l, re.I)
                     and not re.search(r"(0 errors|no errors|without errors)", l, re.I)]
        if bad_lines:
            self.data["errors"].append("memtest_vulkan reported possible VRAM/memory errors.")
            status = "FAILED - possible VRAM/memory errors detected."
        elif timed_out:
            status = f"NO ERRORS OBSERVED during {duration}s timed run."
        elif rc == 0:
            status = "COMPLETED - no obvious errors parsed."
        else:
            status = f"COMPLETED with rc={rc}; review output."
        self.data["tests"]["memtest_vulkan"] = status + "\n" + trim_block(text, 2500)

    def run_vkmark(self, display: str | None, timeout: int):
        print("\n[3/6] Vulkan rendering/load test (vkmark)...")
        if display is None:
            self.data["tests"]["vkmark"] = "SKIPPED - no display session detected."
            self.data["warnings"].append("No display session; vkmark skipped.")
            return
        if not self._which("vkmark"):
            self.data["tests"]["vkmark"] = "SKIPPED - vkmark not installed."
            self.data["warnings"].append("vkmark not installed; Vulkan rendering/load benchmark skipped.")
            return
        lines, timed_out, rc = self.runner.run_streaming(["vkmark"], timeout=timeout, label="vkmark")
        text = "\n".join(lines)
        score = next((l for l in reversed(lines) if "score" in l.lower()), "No score parsed.")
        if any(re.search(r"(segmentation fault|device lost|failed|error)", l, re.I) for l in lines):
            self.data["errors"].append("vkmark output contains error/failure indicators.")
        self.data["tests"]["vkmark"] = f"Result: {score}\nTimed out: {timed_out}\n" + trim_block(text, 2500)

    def run_glmark2(self, display: str | None, timeout: int, run_forever: bool):
        print("\n[4/6] OpenGL rendering/load test (glmark2)...")
        if display is None:
            self.data["tests"]["glmark2"] = "SKIPPED - no display detected ($DISPLAY / $WAYLAND_DISPLAY unset)."
            self.data["warnings"].append("Headless session; glmark2 skipped.")
            return
        binary = self._pick_glmark2(display)
        if binary is None:
            self.data["tests"]["glmark2"] = "SKIPPED - no compatible glmark2 binary found."
            self.data["warnings"].append("glmark2 not installed.")
            return
        cmd = [binary, "-s", "1920x1080"]
        if run_forever:
            cmd.append("--run-forever")
        print(f"    Binary  : {binary}  |  Display : {display.upper()}")
        lines, timed_out, rc = self.runner.run_streaming(cmd, timeout=timeout, label="glmark2")
        scenes, final = [], None
        for ln in lines:
            s = ln.strip()
            if s.startswith("[") and "FPS:" in s:
                scenes.append(s)
            if "glmark2 Score" in s:
                final = s
        self.data["scene_scores"] = scenes
        if final:
            result = final
        elif scenes and timed_out:
            result = f"PARTIAL/TORTURE STOPPED after {timeout}s - {len(scenes)} scenes. Last: {scenes[-1]}"
        elif not lines:
            result = "FAILED - no output. Check driver/display."
            self.data["errors"].append("glmark2 produced no output.")
        else:
            result = "FAILED - glmark2 exited without parseable score."
            if rc not in (0, None):
                self.data["errors"].append(f"glmark2 returned rc={rc}.")
        self.data["tests"]["glmark2"] = f"Command: {' '.join(cmd)}\nResult: {result}"

    def run_furmark(self, card: AmdCard, csv_base: str):
        print("\n[5/6] Optional legacy FurMark thermal torture (GpuTest)...")
        print("    ⚠️  Watching kernel logs for amdgpu ring timeouts / resets...")
        gputest_dir = "/opt/gputest"
        gputest_bin = os.path.join(gputest_dir, "GpuTest")
        if not os.path.exists(gputest_bin):
            self.data["tests"]["furmark"] = "SKIPPED - gputest not installed."
            self.data["warnings"].append("gputest not installed; skipped FurMark.")
            return
        furmark_csv = csv_base.replace(".csv", "_furmark.csv")
        mon = AmdMonitor(card, furmark_csv)
        watcher = KernelFaultWatcher(int(time.time()), KERNEL_PATTERNS, self.data["errors"])
        cmd = [
            "./GpuTest", "/test=fur", "/width=1920", "/height=1080", "/msaa=0",
            "/benchmark", f"/benchmark_duration_ms={GPUTEST_DURATION * 1000}", "/no_scorebox",
        ]
        mon.start()
        watcher.start()
        lines, timed_out, rc = self.runner.run_streaming(cmd, timeout=GPUTEST_DURATION + 60, cwd=gputest_dir, label="GpuTest/FurMark")
        watcher.stop()
        mon.stop()
        summ = mon.summary()
        t, p = summ["temp_peak"], summ["power"]
        resets = watcher.count()
        self.data["tests"]["furmark"] = (
            f"FurMark {GPUTEST_DURATION}s @ 1920x1080\n"
            f"Peak temp: {t[2]:.0f}C (avg {t[1]:.0f}C) | Peak power: {p[2]:.0f}W (avg {p[1]:.0f}W)\n"
            f"amdgpu/kernel reset/fault events: {resets}\n"
            f"Per-second log: {furmark_csv}\n"
            + trim_block("\n".join(lines), 1500)
        )
        if resets > 0:
            self.data["errors"].append(f"{resets} amdgpu/kernel fault event(s) during FurMark.")
        if t[2] >= TEMP_FAIL_C:
            self.data["warnings"].append(f"FurMark peak {t[2]:.0f}C >= {TEMP_FAIL_C}C - check cooling.")

    def run_test_suite(self, args, display: str | None, monitor: AmdMonitor, watcher: KernelFaultWatcher):
        monitor.start()
        watcher.start()
        try:
            if not args.skip_memtest:
                self.run_memtest_vulkan(args.memtest_duration)
            else:
                self.data["tests"]["memtest_vulkan"] = "SKIPPED by operator flag."
            if not args.skip_vkmark:
                self.run_vkmark(display, args.vkmark_timeout)
            else:
                self.data["tests"]["vkmark"] = "SKIPPED by operator flag."
            if not args.skip_glmark2:
                self.run_glmark2(display, args.glmark2_timeout, args.glmark2_run_forever)
            else:
                self.data["tests"]["glmark2"] = "SKIPPED by operator flag."
        finally:
            watcher.stop()
            monitor.stop()
        self.data["load_summary"] = monitor.summary()
        self.data["kernel_events"] = watcher.snapshot()

    def build_report(self, client: str = "") -> str:
        print("\n[REPORT] Compiling PNWC AMD diagnostic report...")
        cb = "```"
        ts_file = timestamp_file()
        client_str = f"**Prepared For:** {client}\n" if client else ""
        ls = self.data["load_summary"]
        idle = self.data["idle_snap"]

        checks = []
        if ls:
            peak = ls.get("temp_peak", (0, 0, 0))[2]
            checks.append(("Load Temperature", peak < TEMP_FAIL_C, f"Peak {peak:.0f}C (limit {TEMP_FAIL_C}C)"))
            peak_busy = ls.get("busy", (0, 0, 0))[2]
            checks.append(("GPU Engaged", peak_busy >= GPU_BUSY_MIN_WARN, f"Peak busy {peak_busy:.0f}%" + ("" if peak_busy >= GPU_BUSY_MIN_WARN else " - load may not have hit GPU")))
            checks.append(("Boost State", bool(ls.get("top_sclk_seen")), f"Top/mode sclk seen: {ls.get('top_sclk_seen') or 'unknown'}"))
        if self.data["kernel_events"]:
            checks.append(("Kernel GPU Faults", False, f"{len(self.data['kernel_events'])} event(s) detected"))
        else:
            checks.append(("Kernel GPU Faults", True, "No amdgpu/PCIe fault events detected during run"))
        if any("Software renderer detected" in e for e in self.data["errors"]):
            checks.append(("Renderer Path", False, "Software renderer detected"))

        verdict = "PASS" if checks and all(ok for _, ok, _ in checks) and not self.data["errors"] else "FAIL"
        if not checks:
            verdict = "REVIEW"
        verdict_rows = "".join(f"| {'PASS' if ok else 'FAIL'} | {name} | {detail} |\n" for name, ok, detail in checks) or "| - | No checks performed | - |\n"

        def _fmt(s):
            return f"{s[0]:.0f} / {s[1]:.0f} / {s[2]:.0f}" if s else "— / — / —"

        def _iv(v, suf=""):
            if isinstance(v, (int, float)):
                return f"{v:.0f}{suf}"
            return v or "?"

        if ls and idle:
            load_table = (
                f"| Metric | Idle | Load min/avg/max |\n| :--- | ---: | ---: |\n"
                f"| Peak temp (C) | {_iv(idle.get('temp_peak'))} | {_fmt(ls['temp_peak'])} |\n"
                f"| Edge temp (C) | {_iv(idle.get('temp_edge'))} | {_fmt(ls['temp_edge'])} |\n"
                f"| Junction/hotspot temp (C) | {_iv(idle.get('temp_junction'))} | {_fmt(ls['temp_junction'])} |\n"
                f"| Memory temp (C) | {_iv(idle.get('temp_mem'))} | {_fmt(ls['temp_mem'])} |\n"
                f"| Power (W) | {_iv(idle.get('power'))} | {_fmt(ls['power'])} |\n"
                f"| Busy (%) | {_iv(idle.get('busy'))} | {_fmt(ls['busy'])} |\n"
                f"| Memory busy (%) | {_iv(idle.get('mem_busy'))} | {_fmt(ls['mem_busy'])} |\n"
                f"| VRAM used (MiB) | {_iv(idle.get('vram_used'))} | {_fmt(ls['vram_used'])} |\n"
                f"| sclk idle→top/mode | {idle.get('sclk') or '?'} | {ls.get('top_sclk_seen') or '?'} |\n"
                f"| mclk idle→top/mode | {idle.get('mclk') or '?'} | {ls.get('top_mclk_seen') or '?'} |\n"
                f"| PCIe active | {idle.get('pcie') or '?'} | {ls.get('pcie_seen') or '?'} |\n"
            )
        else:
            load_table = "_No load data collected._\n"

        scenes_block = "\n".join(self.data["scene_scores"]) if self.data["scene_scores"] else "No per-scene data."
        test_blocks = []
        for name, body in self.data["tests"].items():
            test_blocks.append(f"### {name}\n{cb}text\n{trim_block(str(body), 5000)}\n{cb}\n")
        tests_section = "\n".join(test_blocks) if test_blocks else "No workload tests recorded."
        kernel_block = "\n".join(self.data["kernel_events"]) if self.data["kernel_events"] else "No matching amdgpu/kernel GPU fault events detected during test window."
        issues = self.data["errors"] + self.data["warnings"]
        diag = (f"\n## Diagnostics Log\n{cb}text\n" + "\n".join(issues) + f"\n{cb}\n") if issues else "\n**Status:** No errors or warnings.\n"

        report = f"""# AMD Radeon GPU Diagnostic & Benchmark Report
**Date:** {self.ts}
{client_str}---

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

lspci:
{cb}text
{self.data['lspci']}
{cb}

---

## 2. API / Renderer Validation

vulkaninfo --summary:
{cb}text
{trim_block(self.data['vulkan_summary'], 3000) or 'Not collected.'}
{cb}

glxinfo -B:
{cb}text
{trim_block(self.data['glxinfo'], 3000) or 'Not collected.'}
{cb}

---

## 3. AMD Vendor Snapshots

amd-smi / amdsmi:
{cb}text
{trim_block(self.data['amdsmi'], 4000) or 'Not collected.'}
{cb}

amdgpu_top / radeontop:
{cb}text
{trim_block(self.data['amdgpu_top'], 4000) or 'Not collected.'}
{cb}

---

## 4. Idle vs Load Comparison
*amdgpu sysfs polled every {SYSFS_POLL_S}s during workload test window*

{load_table}

---

## 5. Workload Tests
{tests_section}

### glmark2 Per-Scene FPS
{cb}text
{scenes_block}
{cb}

---

## 6. Kernel Stability
{cb}text
{kernel_block}
{cb}
{diag}
---
*Per-second monitoring log: {self.data['csv_path']}*  
*Generated by PNWC amd_gpu_tester.py v2.0*
"""
        fname = os.path.join(REPORT_DIR, f"AMD_GPU_Report_{ts_file}.md")
        with open(fname, "w") as fh:
            fh.write(report)
        print(f"\n✅  Report → {fname}")
        return fname


def main():
    ap = argparse.ArgumentParser(description="PNWC AMD Radeon GPU Tester v2.0")
    ap.add_argument("--client", default="", help="Client name for the report")
    ap.add_argument("--card-index", type=int, default=0, help="AMD card index from detected amdgpu card list")
    ap.add_argument("--skip-memtest", action="store_true", help="Skip memtest_vulkan")
    ap.add_argument("--memtest-duration", type=int, default=MEMTEST_DURATION, help="memtest_vulkan runtime seconds")
    ap.add_argument("--skip-vkmark", action="store_true", help="Skip vkmark")
    ap.add_argument("--vkmark-timeout", type=int, default=VKMARK_TIMEOUT, help="vkmark timeout seconds")
    ap.add_argument("--skip-glmark2", action="store_true", help="Skip glmark2")
    ap.add_argument("--glmark2-timeout", type=int, default=GLMARK2_TIMEOUT, help="glmark2 timeout seconds")
    ap.add_argument("--glmark2-run-forever", action="store_true", help="Run glmark2 in timed torture mode")
    ap.add_argument("--furmark", action="store_true", help="Also run legacy FurMark/GpuTest torture")
    args = ap.parse_args()

    csv_path = os.path.join(REPORT_DIR, f"amd_load_{timestamp_file()}.csv")
    print_banner(csv_path)

    cards = find_amd_cards()
    if not cards:
        print("\n❌  No amdgpu-driven cards found under /sys/class/drm/.")
        print("    Is this an AMD system with the amdgpu driver loaded?")
        sys.exit(1)
    if args.card_index < 0 or args.card_index >= len(cards):
        print(f"\n❌  Invalid --card-index {args.card_index}. Found {len(cards)} AMD card(s):")
        for i, c in enumerate(cards):
            print(f"    {i}: {c.device}")
        sys.exit(1)

    card = cards[args.card_index]
    if len(cards) > 1:
        print(f"\n  Found {len(cards)} AMD cards; testing index {args.card_index}: {card.device}")

    tester = AmdGPUTester(card_index=args.card_index)
    tester.data["csv_path"] = csv_path

    display = tester._detect_display()
    if display is None:
        print("\n[!] No display detected ($DISPLAY / $WAYLAND_DISPLAY unset).")
        print("    memtest_vulkan may still run; vkmark/glmark2/FurMark will be skipped.")
    else:
        print(f"\nDisplay server : {display.upper()}")

    tester.gather_static(card)

    monitor = AmdMonitor(card, csv_path)
    watcher = KernelFaultWatcher(int(time.time()), KERNEL_PATTERNS, tester.data["errors"])
    tester.run_test_suite(args, display, monitor, watcher)

    if args.furmark:
        tester.run_furmark(card, csv_path)

    print("\n[OK] Diagnostic Routine Complete.")
    print(f"    Total data samples   : {monitor.samples()}")
    print(f"    Kernel fault events  : {len(tester.data['kernel_events'])}")

    client = args.client or input("\nClient name (Enter to skip): ").strip()
    tester.build_report(client=client)


if __name__ == "__main__":
    main()
