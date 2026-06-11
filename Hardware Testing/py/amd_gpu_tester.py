#!/usr/bin/env python3
"""
PNWC AMD GPU Diagnostic & Benchmark Tool v1.0.0
(sibling/parity build to the NVIDIA tester v2.3.1)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What this script DOES:
  • Polls AMD telemetry every second during the full GPU test window via the
    amdgpu kernel driver's sysfs/hwmon interface (no rocm-smi dependency):
      - edge / junction(hotspot) / memory temperatures
      - power draw + power cap, fan RPM, core voltage
      - realtime shader (sclk) + memory (mclk) clocks
      - GPU + memory-controller utilization
      - VRAM used/total, PCIe link gen + width
  • Builds a per-second CSV load curve from those samples
  • Verifies PCIe link generation + width against the card's max capability
  • Reads AMD RAS error counters (the ECC analog) when the card exposes them
  • Runs optional-but-default deeper diagnostics when tools are installed:
      - memtest_vulkan for VRAM stability (RADV/AMDVLK)
      - vkmark for Vulkan load
      - glmark2 for OpenGL load
      - gpu-burn (HIP/ROCm build) or clpeak for compute stress when requested
      - GpuTest/FurMark as opt-in legacy thermal torture only
  • Watches kernel logs during the test for amdgpu GPU resets, ring timeouts,
    *ERROR* drm faults, VM/page faults, RAS, PCIe AER, and related events
  • Detects likely software rendering / wrong renderer paths (llvmpipe etc.)
  • Writes a timestamped Markdown report and telemetry CSV

Requires : the amdgpu kernel driver (sysfs telemetry), inxi
Recommended: vulkan-tools, mesa-utils, memtest_vulkan, vkmark, glmark2
Optional : rocm-smi / amdgpu_top (richer static info), clpeak or HIP gpu-burn
           (compute stress), gputest (AUR — FurMark; legacy/opt-in)

Run from a desktop session for vkmark/glmark2/FurMark. memtest_vulkan may work
without a desktop depending on the Vulkan stack.

Install baseline (Arch/Manjaro):
  sudo pacman -S --needed inxi vulkan-tools mesa-utils vkmark glmark2 \
                          vulkan-radeon clpeak

Optional:
  sudo pacman -S --needed rocm-smi-lib   # rocm-smi
  pamac install amdgpu_top               # AUR (live throttle/static context)
  # memtest_vulkan: install/build from trusted package source or upstream
  # gpu-burn: build the HIP/ROCm fork if CUDA-style compute stress is desired
  pamac build gputest libpng12           # FurMark, legacy/opt-in
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import argparse
import csv
import datetime
import getpass
import os
from pathlib import Path
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
SMI_POLL_S              = 1
MEMTEST_DURATION        = 360       # upstream recommends at least ~6 minutes
VKMARK_TIMEOUT          = 600
GLMARK2_TIMEOUT         = 600
COMPUTE_STRESS_DURATION = 300
GPUTEST_DURATION        = 60

# AMD thermal defaults used ONLY when the card does not expose temp*_crit trip
# points in hwmon. When crit is exposed it is preferred (per-sensor) instead.
EDGE_FAIL_C_DEFAULT     = 100
JUNCTION_FAIL_C_DEFAULT = 110      # hotspot/junction is the AMD throttle sensor
MEM_FAIL_C_DEFAULT      = 105      # GDDR6 junction
TEMP_WARN_MARGIN_C      = 8        # warn this many C below the fail/crit point
THERMAL_SLOWDOWN_FAIL   = True
GPU_UTIL_MIN_WARN       = 35       # warn if load tests never engage the GPU

# DRM sysfs root. Overridable for testing against a mock tree.
DRM_ROOT                = os.environ.get("PNWC_AMD_DRM_ROOT", "/sys/class/drm")
AMD_PCI_VENDOR          = "0x1002"
# ───────────────────────────────────────────────────────────────────────────────

SOFTWARE_RENDERERS = ("llvmpipe", "lavapipe", "softpipe", "software rasterizer", "swrast")

# These patterns are treated as utility/display compatibility issues unless
# accompanied by amdgpu kernel faults or true memory corruption messages.
VULKAN_UTILITY_EDGE_PATTERNS = [
    r"Selected present mode Mailbox is not supported",
    r"present mode .* not supported",
    r"surface.*not supported",
    r"no supported present modes",
]

# High-confidence card/driver-path fault indicators when observed during a test
# window. These are NOT treated as simple benchmark utility issues.
HIGH_CONFIDENCE_GPU_FAULT_PATTERNS = [
    r"amdgpu.*GPU reset",
    r"GPU reset\(",
    r"ring .* timeout",
    r"\*ERROR\* .*amdgpu",
    r"GPU fault detected",
    r"VM_L2",
    r"page fault",
    r"fallen off the bus",
    r"PCIe Bus Error",
    r"AER:",
    r"uncorrectable",
    r"RAS.*error",
    r"amdgpu.*hang",
    r"soft reset",
]

KERNEL_PATTERNS = [
    r"amdgpu",
    r"\[drm\].*ERROR",
    r"\*ERROR\*",
    r"GPU reset",
    r"ring .* timeout",
    r"Failed to .* ring",
    r"GPU fault detected",
    r"VM_L2",
    r"VMC page fault",
    r"page fault",
    r"IH ring buffer overflow",
    r"soft reset",
    r"atombios stuck",
    r"SMU.*failed",
    r"failed to send message",
    r"RAS",
    r"PCIe Bus Error",
    r"AER:",
    r"pcieport.*error",
]

CSV_FIELDS = [
    "timestamp",
    "edge_C",
    "junction_C",
    "mem_C",
    "power_W",
    "power_cap_W",
    "sclk_MHz",
    "mclk_MHz",
    "gpu_util_pct",
    "mem_util_pct",
    "vram_used_MiB",
    "vram_total_MiB",
    "fan_rpm",
    "vddgfx_mV",
    "pcie_gen",
    "pcie_width",
]


def timestamp_file() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def printable_cmd(cmd) -> str:
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(c) for c in cmd)
    return str(cmd)


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def safe_float(v) -> Optional[float]:
    if v is None:
        return None
    v = str(v).strip()
    if v in ("", "[N/A]", "N/A", "[Not Supported]", "Not Supported", "None"):
        return None
    try:
        return float(v.replace(",", ""))
    except ValueError:
        return None


def trim_block(text: str, max_chars: int = 4000) -> str:
    text = text or ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [trimmed] ..."


# ── Low-level sysfs readers ─────────────────────────────────────────────────────
def _read_text(path) -> Optional[str]:
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except Exception:
        return None


def _read_int(path) -> Optional[int]:
    t = _read_text(path)
    if t is None:
        return None
    try:
        return int(t)
    except ValueError:
        try:
            return int(t, 0)
        except ValueError:
            return None


def _parse_pp_dpm_active(path) -> Optional[float]:
    """Return the active DPM clock (MHz) — the line ending in '*'."""
    txt = _read_text(path)
    if not txt:
        return None
    for line in txt.splitlines():
        if line.strip().endswith("*"):
            m = re.search(r"([\d.]+)\s*Mhz", line, re.I)
            if m:
                return float(m.group(1))
    return None


def _parse_pp_dpm_max(path) -> Optional[float]:
    """Return the highest DPM clock state (MHz) listed in a pp_dpm_* file."""
    txt = _read_text(path)
    if not txt:
        return None
    vals = [float(m) for m in re.findall(r"([\d.]+)\s*Mhz", txt, re.I)]
    return max(vals) if vals else None


def _parse_link_gen(link_speed_str) -> Optional[int]:
    """'16.0 GT/s PCIe' -> PCIe generation int."""
    m = re.search(r"([\d.]+)\s*GT/s", link_speed_str or "")
    if not m:
        return None
    gts = float(m.group(1))
    return {2.5: 1, 5.0: 2, 8.0: 3, 16.0: 4, 32.0: 5}.get(gts)


def find_amd_cards(drm_root: str = DRM_ROOT) -> list[Path]:
    """Enumerate DRM cardN nodes whose PCI vendor is AMD (0x1002)."""
    cards: list[Path] = []
    base = Path(drm_root)
    if not base.exists():
        return cards
    for entry in sorted(base.glob("card*")):
        if not re.fullmatch(r"card\d+", entry.name):
            continue  # skip connector nodes like card0-DP-1
        vendor = _read_text(entry / "device" / "vendor")
        if vendor and vendor.lower() == AMD_PCI_VENDOR:
            cards.append(entry)
    return cards


class AmdCard:
    """Resolved handle to a single amdgpu DRM card with live sysfs telemetry."""

    def __init__(self, card_path: Path):
        self.card_path = Path(card_path)
        self.name = self.card_path.name
        self.dev = self.card_path / "device"
        self.hwmon = self._find_hwmon()
        self.temp_labels = self._map_temp_labels()
        self.crit = self._read_temp_crits()

    # -- resolution ----------------------------------------------------------
    def _find_hwmon(self) -> Optional[Path]:
        hw = self.dev / "hwmon"
        if not hw.exists():
            return None
        for h in sorted(hw.glob("hwmon*")):
            return h
        return None

    def _map_temp_labels(self) -> dict:
        """{label_lower: 'tempN'} e.g. {'edge':'temp1','junction':'temp2'}."""
        out = {}
        if not self.hwmon:
            return out
        for inp in sorted(self.hwmon.glob("temp*_input")):
            idx = inp.name[: -len("_input")]
            label = (_read_text(self.hwmon / f"{idx}_label") or idx).lower()
            out[label] = idx
        return out

    def _read_temp_crits(self) -> dict:
        out = {}
        if not self.hwmon:
            return out
        for label, idx in self.temp_labels.items():
            milli = _read_int(self.hwmon / f"{idx}_crit")
            if milli is not None:
                out[label] = milli / 1000.0
        return out

    # -- per-label helpers ---------------------------------------------------
    def _temp(self, label: str) -> Optional[float]:
        idx = self.temp_labels.get(label)
        if not idx or not self.hwmon:
            return None
        milli = _read_int(self.hwmon / f"{idx}_input")
        return milli / 1000.0 if milli is not None else None

    def fail_threshold(self, label: str, default: float) -> float:
        return self.crit.get(label, default)

    @property
    def junction_label(self) -> Optional[str]:
        for cand in ("junction", "hotspot", "mem", "edge"):
            if cand in self.temp_labels:
                return cand
        return None

    # -- live snapshot -------------------------------------------------------
    def read_snapshot(self) -> dict:
        d: dict = {}
        d["edge"] = self._temp("edge")
        d["junction"] = self._temp("junction") or self._temp("hotspot")
        d["mem"] = self._temp("mem")

        if self.hwmon:
            pw = _read_int(self.hwmon / "power1_average")
            if pw is None:
                pw = _read_int(self.hwmon / "power1_input")
            d["power"] = pw / 1e6 if pw is not None else None

            cap = _read_int(self.hwmon / "power1_cap")
            d["power_cap"] = cap / 1e6 if cap is not None else None

            f1 = _read_int(self.hwmon / "freq1_input")
            d["sclk"] = f1 / 1e6 if f1 is not None else _parse_pp_dpm_active(self.dev / "pp_dpm_sclk")
            f2 = _read_int(self.hwmon / "freq2_input")
            d["mclk"] = f2 / 1e6 if f2 is not None else _parse_pp_dpm_active(self.dev / "pp_dpm_mclk")

            fan = _read_int(self.hwmon / "fan1_input")
            d["fan"] = float(fan) if fan is not None else None
            mv = _read_int(self.hwmon / "in0_input")
            d["vddgfx"] = float(mv) if mv is not None else None
        else:
            d.update({"power": None, "power_cap": None, "fan": None, "vddgfx": None})
            d["sclk"] = _parse_pp_dpm_active(self.dev / "pp_dpm_sclk")
            d["mclk"] = _parse_pp_dpm_active(self.dev / "pp_dpm_mclk")

        gu = _read_int(self.dev / "gpu_busy_percent")
        d["gpu_util"] = float(gu) if gu is not None else None
        mu = _read_int(self.dev / "mem_busy_percent")
        d["mem_util"] = float(mu) if mu is not None else None

        used = _read_int(self.dev / "mem_info_vram_used")
        total = _read_int(self.dev / "mem_info_vram_total")
        d["vram_used"] = used / 1048576.0 if used is not None else None
        d["vram_total"] = total / 1048576.0 if total is not None else None

        d["pcie_gen"] = _parse_link_gen(_read_text(self.dev / "current_link_speed"))
        d["pcie_width"] = _read_int(self.dev / "current_link_width")
        return d

    # -- static identity -----------------------------------------------------
    def static_info(self) -> dict:
        info: dict = {}
        info["max_sclk"] = _parse_pp_dpm_max(self.dev / "pp_dpm_sclk")
        info["max_mclk"] = _parse_pp_dpm_max(self.dev / "pp_dpm_mclk")
        total = _read_int(self.dev / "mem_info_vram_total")
        info["vram_total_mib"] = total / 1048576.0 if total is not None else None
        info["pcie_gen_cur"] = _parse_link_gen(_read_text(self.dev / "current_link_speed"))
        info["pcie_gen_max"] = _parse_link_gen(_read_text(self.dev / "max_link_speed"))
        info["pcie_width_cur"] = _read_int(self.dev / "current_link_width")
        info["pcie_width_max"] = _read_int(self.dev / "max_link_width")
        info["unique_id"] = _read_text(self.dev / "unique_id")
        if self.hwmon:
            cap = _read_int(self.hwmon / "power1_cap")
            capmax = _read_int(self.hwmon / "power1_cap_max")
            info["power_cap_w"] = cap / 1e6 if cap is not None else None
            info["power_cap_max_w"] = capmax / 1e6 if capmax is not None else None
        return info

    def read_ras(self) -> Optional[dict]:
        """Sum AMD RAS uncorrectable (ue) and correctable (ce) counters."""
        ras_dir = self.dev / "ras"
        if not ras_dir.exists():
            return None
        ue_total = 0
        ce_total = 0
        found = False
        for f in sorted(ras_dir.glob("*_err_count")):
            txt = _read_text(f)
            if not txt:
                continue
            found = True
            for m in re.finditer(r"ue:\s*(\d+)", txt):
                ue_total += int(m.group(1))
            for m in re.finditer(r"ce:\s*(\d+)", txt):
                ce_total += int(m.group(1))
        if not found:
            return None
        return {"ue": ue_total, "ce": ce_total}


def print_banner(report_file_path="Not Generated Yet"):
    """Render the PNWC toolkit ASCII banner to the terminal window."""
    if platform.system() == "Windows":
        os.system("title PNWC AMD GPU Diagnostic v1.0.0")
    else:
        print("\033]0;PNWC AMD GPU Diagnostic v1.0.0\a", end="")

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
    print("  AMD GPU Testing & Benchmark Script v1.0.0")
    print("")
    print("=" * 70)
    print("   PNWC Diagnostic Tool - AMD GPU Hardware & Load Benchmarking")
    print("   Pacific Northwest Computers  |  support@pnwcomputers.com")
    print("   v1.0.0 -- amdgpu sysfs telemetry variant")
    print("=" * 70)
    print("")
    print(f"  Started  : {formatted_time}")
    print(f"  Computer : {platform.node()}")
    print(f"  Operator : {getpass.getuser()}")
    print(f"  CSV Log  : {report_file_path}")
    print("")


class ProcessRunner:
    def __init__(self, errors: list, warnings: list):
        self.errors = errors
        self.warnings = warnings

    def run_cmd(self, cmd, timeout: int = 60, cwd=None, allow_fail: bool = False) -> str:
        print(f"    -> {printable_cmd(cmd)}")
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
            self.errors.append(f"EXEC ERROR: {printable_cmd(cmd)} -> {exc}")
            return "ERROR"

    def run_streaming(self, cmd, timeout: int, cwd=None, label: str = "process", env=None, allow_fail: bool = False):
        lines: list = []
        timed_out = False
        rc = None
        shell = isinstance(cmd, str)

        print(f"    -> {printable_cmd(cmd)}")
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
                env=env,
            )

            def _reader():
                if proc.stdout is None:
                    return
                for raw in proc.stdout:
                    line = raw.rstrip()
                    lines.append(line)
                    if any(k.lower() in line.lower() for k in [
                        "[", "score", "error", "failed", "warning", "fault", "ring", "reset",
                        "gpu", "mismatch", "corrupt", "timeout", "amdgpu"
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
                if rc not in (0, None) and not allow_fail:
                    self.errors.append(f"{label} exited with rc={rc}.")
        except Exception as exc:
            timed_out = True
            self.errors.append(f"STREAM ERROR ({label}): {exc}")

        return lines, timed_out, rc


class KernelFaultWatcher:
    def __init__(self, start_epoch: int, patterns: list, errors: list):
        self.start_epoch = start_epoch
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.errors = errors
        self.events: list = []
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
            self.errors.append(f"{self.count()} amdgpu/kernel GPU fault event(s) detected during testing.")

    def count(self) -> int:
        with self._lock:
            return len(self.events)

    def snapshot(self) -> list:
        with self._lock:
            return list(self.events)


class AmdMonitor:
    """Background sysfs monitor writing every sample to CSV."""

    def __init__(self, card: AmdCard, csv_path: str):
        self.card = card
        self.csv_path = csv_path
        self.running = False
        self._thread = None
        self._lock = threading.Lock()
        self._samples = 0

        self.edge: list = []
        self.junction: list = []
        self.memtemp: list = []
        self.powers: list = []
        self.sclks: list = []
        self.mclks: list = []
        self.utils: list = []
        self.memutils: list = []
        self.vram_used: list = []
        self.pcie_gen_seen: list = []
        self.pcie_width_seen: list = []

        self.thermal_events = 0
        self.active_throttle_reasons: set = set()

        # Resolve per-sensor fail thresholds once (prefer hwmon crit trip points)
        self.edge_fail = card.fail_threshold("edge", EDGE_FAIL_C_DEFAULT)
        self.junction_fail = card.fail_threshold(
            card.junction_label or "junction", JUNCTION_FAIL_C_DEFAULT
        )
        self.mem_fail = card.fail_threshold("mem", MEM_FAIL_C_DEFAULT)

    def _row_from_snapshot(self, snap: dict) -> list:
        def fmt(v, nd=0):
            if v is None:
                return ""
            return f"{v:.{nd}f}" if isinstance(v, float) else str(v)
        return [
            datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3],
            fmt(snap.get("edge"), 1),
            fmt(snap.get("junction"), 1),
            fmt(snap.get("mem"), 1),
            fmt(snap.get("power"), 1),
            fmt(snap.get("power_cap"), 1),
            fmt(snap.get("sclk"), 0),
            fmt(snap.get("mclk"), 0),
            fmt(snap.get("gpu_util"), 0),
            fmt(snap.get("mem_util"), 0),
            fmt(snap.get("vram_used"), 0),
            fmt(snap.get("vram_total"), 0),
            fmt(snap.get("fan"), 0),
            fmt(snap.get("vddgfx"), 0),
            fmt(snap.get("pcie_gen"), 0),
            fmt(snap.get("pcie_width"), 0),
        ]

    def _run_loop(self):
        try:
            with open(self.csv_path, "w", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(CSV_FIELDS)
                while self.running:
                    snap = self.card.read_snapshot()
                    writer.writerow(self._row_from_snapshot(snap))
                    fh.flush()
                    self._ingest(snap)
                    time.sleep(SMI_POLL_S)
        except Exception as e:
            print(f"\n[!] Monitor encountered a structural logging error: {e}")

    def _ingest(self, snap: dict):
        with self._lock:
            self._samples += 1
            for series, key in [
                (self.edge, "edge"),
                (self.junction, "junction"),
                (self.memtemp, "mem"),
                (self.powers, "power"),
                (self.sclks, "sclk"),
                (self.mclks, "mclk"),
                (self.utils, "gpu_util"),
                (self.memutils, "mem_util"),
                (self.vram_used, "vram_used"),
            ]:
                val = snap.get(key)
                if val is not None:
                    series.append(float(val))

            if snap.get("pcie_gen") is not None:
                self.pcie_gen_seen.append(str(snap["pcie_gen"]))
            if snap.get("pcie_width") is not None:
                self.pcie_width_seen.append(str(snap["pcie_width"]))

            # Heuristic thermal-throttle detection: AMD does not expose a clean
            # throttle-reason register via sysfs the way nvidia-smi does, so we
            # flag a sample as thermal-limited when a sensor reaches its crit /
            # fail trip point. This is labeled as heuristic in the report.
            edge = snap.get("edge")
            junc = snap.get("junction")
            mem = snap.get("mem")
            tripped = False
            if junc is not None and junc >= self.junction_fail:
                tripped = True
                self.active_throttle_reasons.add(
                    f"Junction >= {self.junction_fail:.0f}C trip point")
            if edge is not None and edge >= self.edge_fail:
                tripped = True
                self.active_throttle_reasons.add(
                    f"Edge >= {self.edge_fail:.0f}C trip point")
            if mem is not None and mem >= self.mem_fail:
                tripped = True
                self.active_throttle_reasons.add(
                    f"Memory >= {self.mem_fail:.0f}C trip point")
            if tripped:
                self.thermal_events += 1

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

    @staticmethod
    def _mode(series):
        if not series:
            return ""
        return max(set(series), key=series.count)

    def primary_temp_series(self):
        return self.junction if self.junction else self.edge

    def summary(self) -> dict:
        with self._lock:
            return {
                "samples": self._samples,
                "temp": self._stats(self.primary_temp_series()),
                "edge": self._stats(self.edge),
                "junction": self._stats(self.junction),
                "memtemp": self._stats(self.memtemp),
                "power": self._stats(self.powers),
                "sclk": self._stats(self.sclks),
                "mclk": self._stats(self.mclks),
                "util": self._stats(self.utils),
                "memutil": self._stats(self.memutils),
                "vram_used": self._stats(self.vram_used),
                "pcie_gen_mode": self._mode(self.pcie_gen_seen),
                "pcie_width_mode": self._mode(self.pcie_width_seen),
                "thermal_events": self.thermal_events,
                "reasons": sorted(self.active_throttle_reasons),
                "junction_fail": self.junction_fail,
                "edge_fail": self.edge_fail,
                "mem_fail": self.mem_fail,
            }


class AmdGPUTester:
    def __init__(self, card: AmdCard):
        self.card = card
        self.ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data = {
            "inxi_gpu": "",
            "lspci": "",
            "product_name": "",
            "driver_block": "",
            "vbios": "",
            "vulkan_summary": "",
            "glxinfo": "",
            "static_info": {},
            "idle_snap": {},
            "ras": "",
            "tests": {},
            "scene_scores": [],
            "load_summary": {},
            "kernel_events": [],
            "csv_path": "",
            "errors": [],
            "warnings": [],
            "utility_notes": [],
            "tool_edge_notes": [],
            "hardware_suspect_notes": [],
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

    def _pick_glmark2(self, display: str):
        order = (["glmark2-wayland", "glmark2-es2-wayland", "glmark2-es2", "glmark2"]
                 if display == "wayland" else ["glmark2", "glmark2-es2"])
        return next((b for b in order if self._which(b)), None)

    def _amd_vulkan_env(self, prefer_amdvlk: bool, vk_device: str = "", dri_prime: str = "") -> dict:
        """Prefer the AMD Vulkan ICD (RADV by default, AMDVLK on request).

        This helps prevent llvmpipe/Intel/other Vulkan ICDs from being selected
        on mixed-GPU Linux benches. If the ICD is not found, the system Vulkan
        loader is used and the report explicitly notes that.
        """
        env = os.environ.copy()
        icd_dir = Path("/usr/share/vulkan/icd.d")
        radv = []
        amdvlk = []
        if icd_dir.exists():
            radv = sorted(icd_dir.glob("radeon_icd*.json"))
            amdvlk = sorted(icd_dir.glob("amd_icd*.json"))
        order = (amdvlk + radv) if prefer_amdvlk else (radv + amdvlk)
        icd = next((c for c in order if c.exists()), None)
        if icd:
            env["VK_DRIVER_FILES"] = str(icd)
            env["VK_ICD_FILENAMES"] = str(icd)
            note = f"AMD Vulkan ICD forced for AMD tests: {icd.name}"
            if note not in self.data["utility_notes"]:
                self.data["utility_notes"].append(note)
        else:
            note = "AMD Vulkan ICD file not found; using system Vulkan loader/device selection."
            if note not in self.data["tool_edge_notes"]:
                self.data["tool_edge_notes"].append(note)

        if vk_device:
            env["MESA_VK_DEVICE_SELECT"] = vk_device
            note = f"RADV device selection forced: MESA_VK_DEVICE_SELECT={vk_device}"
            if note not in self.data["utility_notes"]:
                self.data["utility_notes"].append(note)
        if dri_prime:
            env["DRI_PRIME"] = dri_prime
            note = f"GL device selection forced: DRI_PRIME={dri_prime}"
            if note not in self.data["utility_notes"]:
                self.data["utility_notes"].append(note)
        return env

    @staticmethod
    def _has_utility_edge(text: str) -> bool:
        return any(re.search(p, text, re.I) for p in VULKAN_UTILITY_EDGE_PATTERNS)

    @staticmethod
    def _classify_memtest_vulkan_lines(lines: list):
        """Return (classification, bad_lines) for memtest_vulkan output.

        memtest_vulkan is often stopped by timeout/SIGINT, so the parser must
        not treat every non-zero/controlled-stop condition as a card fault.
        It also must not misread phrases like "no any errors" as an error.
        """
        good_re = re.compile(r"(no\s+(any\s+)?errors|0\s+errors|testing\s+pass(ed)?|pass(ed)?!)", re.I)
        bad_re = re.compile(r"(error found|runtime error|device lost|mismatch|corrupt|failed|fault)", re.I)
        bad_lines = []
        for line in lines:
            if good_re.search(line):
                continue
            if bad_re.search(line):
                bad_lines.append(line)
        if bad_lines:
            return "FAIL", bad_lines
        if any(good_re.search(line) for line in lines):
            return "PASS", []
        return "NO_ERRORS_PARSED", []

    def gather_static(self) -> bool:
        print("\n[1/6] AMD GPU hardware, driver, and API identification...")
        self.data["inxi_gpu"] = self.runner.run_cmd(["inxi", "-G", "-c0"], timeout=30, allow_fail=True) if self._which("inxi") else "inxi not installed."
        self.data["lspci"] = self.runner.run_cmd("lspci -nnk | grep -A4 -E 'VGA|3D|Display'", timeout=15, allow_fail=True)

        # Product name: rocm-smi (if present) is the cleanest marketing name,
        # else fall back to the lspci device string.
        product = ""
        if self._which("rocm-smi"):
            out = self.runner.run_cmd(["rocm-smi", "--showproductname"], timeout=20, allow_fail=True)
            m = re.search(r"Card series:\s*(.+)", out) or re.search(r"Card model:\s*(.+)", out)
            if m:
                product = m.group(1).strip()
            vbios = self.runner.run_cmd(["rocm-smi", "--showvbios"], timeout=20, allow_fail=True)
            mv = re.search(r"VBIOS version:\s*(\S+)", vbios)
            self.data["vbios"] = mv.group(1) if mv else "Not reported by rocm-smi."
        else:
            self.data["warnings"].append("rocm-smi not installed; product/VBIOS taken from lspci where possible.")
            self.data["vbios"] = "Not available (rocm-smi not installed)."
        if not product:
            m = re.search(r"(VGA|3D|Display).*?:\s*(.+)", self.data["lspci"] or "")
            product = m.group(2).strip() if m else self.card.name
        self.data["product_name"] = product

        # Driver / stack identity
        kernel = platform.release()
        amdgpu_ver = _read_text("/sys/module/amdgpu/version") or "n/a"
        mesa = ""
        self.data["driver_block"] = (
            f"Kernel            : {kernel}\n"
            f"amdgpu module ver : {amdgpu_ver}\n"
            f"Mesa/GL renderer  : (see glxinfo below)\n"
            f"DRM card          : {self.card.name}  ({self.card.dev})"
        )

        self.data["static_info"] = self.card.static_info()
        self.data["idle_snap"] = self.card.read_snapshot()

        ras = self.card.read_ras()
        if ras is None:
            self.data["ras"] = "Not supported / no RAS counters exposed on this card."
        else:
            self.data["ras"] = f"Uncorrectable (ue): {ras['ue']}  |  Correctable (ce): {ras['ce']}"
            if ras["ue"] > 0:
                self.data["errors"].append(f"{ras['ue']} UNCORRECTABLE RAS error(s) - failing/suspect VRAM or GPU memory.")

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
            self.data["errors"].append("Software renderer detected (llvmpipe/lavapipe/softpipe). Test may not be hitting the AMD GPU.")

        return True

    def run_memtest_vulkan(self, duration: int, env: dict):
        print("\n[2/6] Vulkan VRAM stability test (memtest_vulkan)...")
        if not self._which("memtest_vulkan"):
            self.data["tests"]["memtest_vulkan"] = "SKIPPED - memtest_vulkan not installed."
            self.data["warnings"].append("memtest_vulkan not installed; VRAM-specific Vulkan memory test skipped.")
            return
        lines, timed_out, rc = self.runner.run_streaming(
            ["memtest_vulkan"], timeout=duration, label="memtest_vulkan", env=env, allow_fail=True
        )
        text = "\n".join(lines)
        classification, bad_lines = self._classify_memtest_vulkan_lines(lines)
        if classification == "FAIL":
            self.data["errors"].append("memtest_vulkan reported true error/device-loss/failure text.")
            self.data["hardware_suspect_notes"].append(
                "memtest_vulkan reported actual error/device-loss/failure text; this is not treated as a simple utility edge case."
            )
            status = "FAILED - memtest_vulkan reported true error/device-loss/failure text."
        elif timed_out:
            status = f"NO DATA ERRORS PARSED during {duration}s timed run; controlled stop/timeout is expected for this test style."
        elif classification == "PASS":
            status = "PASS - memtest_vulkan reported no errors."
        elif rc == 0:
            status = "COMPLETED - no obvious data errors parsed."
        else:
            status = f"COMPLETED with rc={rc}; no true data-error lines parsed; review output."
        if bad_lines:
            status += "\n\nNotable failure lines:\n" + "\n".join(bad_lines[:12])
        self.data["tests"]["memtest_vulkan"] = status + "\n" + trim_block(text, 2500)

    def run_vkmark(self, display, timeout: int, env: dict):
        print("\n[3/6] Vulkan rendering/load test (vkmark)...")
        if display is None:
            self.data["tests"]["vkmark"] = "SKIPPED - no display session detected."
            self.data["warnings"].append("No display session; vkmark skipped.")
            return
        if not self._which("vkmark"):
            self.data["tests"]["vkmark"] = "SKIPPED - vkmark not installed."
            self.data["warnings"].append("vkmark not installed; Vulkan rendering/load benchmark skipped.")
            return
        lines, timed_out, rc = self.runner.run_streaming(["vkmark"], timeout=timeout, label="vkmark", env=env, allow_fail=True)
        text = "\n".join(lines)

        retry_note = ""
        if self._has_utility_edge(text):
            note = "vkmark hit a Vulkan window-system/present-mode compatibility edge; not counted as card failure by itself."
            if note not in self.data["tool_edge_notes"]:
                self.data["tool_edge_notes"].append(note)
            winsys = "xcb" if display == "x11" else "wayland"
            retry_cmd = ["vkmark", "--winsys", winsys]
            retry_lines, retry_timeout, retry_rc = self.runner.run_streaming(
                retry_cmd, timeout=timeout, label=f"vkmark --winsys {winsys}", env=env, allow_fail=True
            )
            retry_text = "\n".join(retry_lines)
            text += "\n\n--- Retry with explicit window system ---\n" + retry_text
            timed_out = timed_out or retry_timeout
            rc = retry_rc
            retry_note = f"\nUtility-edge mitigation: retried with {' '.join(retry_cmd)}."

        score = next((l for l in reversed(text.splitlines()) if "score" in l.lower()), "No score parsed.")
        high_conf = any(re.search(r"(segmentation fault|device lost|VK_ERROR_DEVICE_LOST)", l, re.I) for l in text.splitlines())
        generic_error = any(re.search(r"(failed|error)", l, re.I) for l in text.splitlines())
        if high_conf:
            self.data["errors"].append("vkmark reported high-confidence crash/device-loss indicators.")
            self.data["hardware_suspect_notes"].append("vkmark produced crash/device-loss text; treat as suspect if reproducible.")
        elif generic_error and not self._has_utility_edge(text):
            self.data["warnings"].append("vkmark returned generic error text; review output, but not automatically treated as card failure.")
        self.data["tests"]["vkmark"] = f"Result: {score}\nTimed out: {timed_out}{retry_note}\n" + trim_block(text, 3000)

    def run_glmark2(self, display, timeout: int, run_forever: bool, env: dict):
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
        lines, timed_out, rc = self.runner.run_streaming(cmd, timeout=timeout, label="glmark2", env=env)
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

    def run_compute_stress(self, duration: int):
        print("\n[5/6] AMD compute stress (gpu-burn HIP / clpeak)...")
        burn_bin = next((b for b in ("gpu-burn", "gpu_burn") if self._which(b)), None)
        if burn_bin:
            lines, timed_out, rc = self.runner.run_streaming(
                [burn_bin, str(duration)], timeout=duration + 60, label=burn_bin
            )
            text = "\n".join(lines)
            if any(re.search(r"(error|fault|fail|unstable|bad)", l, re.I) for l in lines):
                self.data["errors"].append(f"{burn_bin} output contains error/failure indicators.")
            self.data["tests"]["compute_stress"] = f"Tool: {burn_bin} (HIP/ROCm)\nTimed out: {timed_out}; rc={rc}\n" + trim_block(text, 2500)
            return
        if self._which("clpeak"):
            lines, timed_out, rc = self.runner.run_streaming(["clpeak"], timeout=duration + 60, label="clpeak")
            text = "\n".join(lines)
            if any(re.search(r"(error|fault|fail|invalid)", l, re.I) for l in lines):
                self.data["warnings"].append("clpeak reported error/invalid text; review output.")
            self.data["tests"]["compute_stress"] = f"Tool: clpeak (OpenCL compute sanity/throughput)\nTimed out: {timed_out}; rc={rc}\n" + trim_block(text, 2500)
            return
        self.data["tests"]["compute_stress"] = "SKIPPED - neither HIP gpu-burn nor clpeak installed."
        self.data["warnings"].append("No compute-stress tool found (gpu-burn HIP or clpeak); compute stress skipped.")

    def run_furmark(self, monitor_csv_base: str):
        print("\n[6/6] Optional legacy FurMark thermal torture (GpuTest)...")
        gputest_dir = "/opt/gputest"
        gputest_bin = os.path.join(gputest_dir, "GpuTest")
        if not os.path.exists(gputest_bin):
            self.data["tests"]["furmark"] = "SKIPPED - gputest not installed."
            self.data["warnings"].append("gputest not installed; skipped FurMark.")
            return
        furmark_csv = monitor_csv_base.replace(".csv", "_furmark.csv")
        mon = AmdMonitor(self.card, furmark_csv)
        cmd = [
            "./GpuTest", "/test=fur", "/width=1920", "/height=1080", "/msaa=0",
            "/benchmark", f"/benchmark_duration_ms={GPUTEST_DURATION * 1000}", "/no_scorebox",
        ]
        print(f"    Monitor : sysfs every {SMI_POLL_S}s -> {furmark_csv}")
        mon.start()
        lines, timed_out, rc = self.runner.run_streaming(cmd, timeout=GPUTEST_DURATION + 60, cwd=gputest_dir, label="GpuTest/FurMark")
        mon.stop()
        summ = mon.summary()
        t, p = summ["temp"], summ["power"]
        self.data["tests"]["furmark"] = (
            f"FurMark {GPUTEST_DURATION}s @ 1920x1080\n"
            f"Peak temp: {t[2]:.0f}C (avg {t[1]:.0f}C) | Peak power: {p[2]:.0f}W (avg {p[1]:.0f}W)\n"
            f"Thermal trip samples: {summ['thermal_events']}\n"
            f"Per-second log: {furmark_csv}\n"
            + trim_block("\n".join(lines), 1500)
        )
        if t[2] >= summ["junction_fail"]:
            self.data["warnings"].append(f"FurMark peak {t[2]:.0f}C >= {summ['junction_fail']:.0f}C trip - check cooling.")

    def run_test_suite(self, args, display, monitor: AmdMonitor, watcher: KernelFaultWatcher, env: dict):
        monitor.start()
        watcher.start()
        try:
            if not args.skip_memtest:
                self.run_memtest_vulkan(args.memtest_duration, env)
            else:
                self.data["tests"]["memtest_vulkan"] = "SKIPPED by operator flag."
            if not args.skip_vkmark:
                self.run_vkmark(display, args.vkmark_timeout, env)
            else:
                self.data["tests"]["vkmark"] = "SKIPPED by operator flag."
            if not args.skip_glmark2:
                self.run_glmark2(display, args.glmark2_timeout, args.glmark2_run_forever, env)
            else:
                self.data["tests"]["glmark2"] = "SKIPPED by operator flag."
            if args.compute_stress:
                self.run_compute_stress(args.compute_stress_duration)
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
        si = self.data["static_info"]
        idle = self.data["idle_snap"]
        ls = self.data["load_summary"]

        def g(d, k, default="?"):
            v = d.get(k) if d else None
            return default if v is None else v

        checks = []
        if si:
            cur_gen = si.get("pcie_gen_cur")
            max_gen = si.get("pcie_gen_max")
            cur_w = si.get("pcie_width_cur")
            max_w = si.get("pcie_width_max")
            if None not in (cur_gen, max_gen, cur_w, max_w):
                pcie_ok = (cur_gen == max_gen and cur_w == max_w)
                detail = f"Gen{cur_gen} x{cur_w} (max Gen{max_gen} x{max_w})" + ("" if pcie_ok else " - not at full link")
            else:
                pcie_ok = True
                detail = f"Gen{g(si,'pcie_gen_cur')} x{g(si,'pcie_width_cur')} (max link not fully reported)"
            checks.append(("PCIe Link", pcie_ok, detail))
        if ls:
            peak_t = ls.get("temp", (0, 0, 0))[2]
            jfail = ls.get("junction_fail", JUNCTION_FAIL_C_DEFAULT)
            checks.append(("Load Temperature", peak_t < jfail, f"Peak {peak_t:.0f}C (trip {jfail:.0f}C)"))
            peak_util = ls.get("util", (0, 0, 0))[2]
            checks.append(("GPU Engaged", peak_util >= GPU_UTIL_MIN_WARN, f"Peak GPU util {peak_util:.0f}%" + ("" if peak_util >= GPU_UTIL_MIN_WARN else " - load may not have hit GPU")))
            th = ls.get("thermal_events", 0)
            checks.append(("Thermal Trip (heuristic)", not (THERMAL_SLOWDOWN_FAIL and th > 0), f"{th} sample(s) at/over a temp trip point"))
        if self.data["kernel_events"]:
            checks.append(("Kernel GPU Faults", False, f"{len(self.data['kernel_events'])} event(s) detected"))
        else:
            checks.append(("Kernel GPU Faults", True, "No amdgpu/ring-timeout/reset/PCIe fault events detected during run"))
        if self.data["ras"]:
            ras_ok = ("ue): 0" in self.data["ras"]) or ("Not supported" in self.data["ras"])
            checks.append(("RAS / ECC Memory", ras_ok, self.data["ras"]))
        if any("Software renderer detected" in e for e in self.data["errors"]):
            checks.append(("Renderer Path", False, "Software renderer detected"))

        verdict = "PASS" if checks and all(ok for _, ok, _ in checks) and not self.data["errors"] else "FAIL"
        if not checks:
            verdict = "REVIEW"

        verdict_rows = "".join(f"| {'PASS' if ok else 'FAIL'} | {name} | {detail} |\n" for name, ok, detail in checks) or "| - | No checks performed | - |\n"

        def mib(v):
            return f"{v:.0f}" if isinstance(v, (int, float)) else "?"

        static_block = (
            f"Product           : {self.data['product_name']}\n"
            f"VBIOS             : {self.data['vbios']}\n"
            f"VRAM              : {mib(si.get('vram_total_mib'))} MiB\n"
            f"Power cap         : {g(si,'power_cap_w')} W (max {g(si,'power_cap_max_w')} W)\n"
            f"Max shader clock  : {g(si,'max_sclk')} MHz\n"
            f"Max memory clock  : {g(si,'max_mclk')} MHz\n"
            f"Unique ID         : {g(si,'unique_id','n/a')}\n"
            f"PCIe link         : Gen{g(si,'pcie_gen_cur')} x{g(si,'pcie_width_cur')} "
            f"(max Gen{g(si,'pcie_gen_max')} x{g(si,'pcie_width_max')})"
        )

        def _fmt_stat(s):
            return f"{s[0]:.0f} / {s[1]:.0f} / {s[2]:.0f}" if s else "- / - / -"

        def _idle(v, nd=0):
            return f"{v:.{nd}f}" if isinstance(v, (int, float)) else "?"

        if ls and idle:
            load_table = (
                f"| Metric | Idle | Load min/avg/max |\n"
                f"| :--- | ---: | ---: |\n"
                f"| Edge temp (C) | {_idle(idle.get('edge'))} | {_fmt_stat(ls['edge'])} |\n"
                f"| Junction temp (C) | {_idle(idle.get('junction'))} | {_fmt_stat(ls['junction'])} |\n"
                f"| Memory temp (C) | {_idle(idle.get('mem'))} | {_fmt_stat(ls['memtemp'])} |\n"
                f"| Power (W) | {_idle(idle.get('power'),1)} | {_fmt_stat(ls['power'])} |\n"
                f"| Shader clk (MHz) | {_idle(idle.get('sclk'))} | {_fmt_stat(ls['sclk'])} |\n"
                f"| Memory clk (MHz) | {_idle(idle.get('mclk'))} | {_fmt_stat(ls['mclk'])} |\n"
                f"| GPU util (%) | {_idle(idle.get('gpu_util'))} | {_fmt_stat(ls['util'])} |\n"
                f"| Memory util (%) | {_idle(idle.get('mem_util'))} | {_fmt_stat(ls['memutil'])} |\n"
                f"| VRAM used (MiB) | {_idle(idle.get('vram_used'))} | {_fmt_stat(ls['vram_used'])} |\n"
            )
            throttle_note = ", ".join(ls["reasons"]) if ls.get("reasons") else "None observed (no sensor reached its trip point)"
        else:
            load_table = "_No load monitoring data collected._\n"
            throttle_note = "n/a"

        scenes_block = "\n".join(self.data["scene_scores"]) if self.data["scene_scores"] else "No per-scene data."
        test_blocks = []
        for name, body in self.data["tests"].items():
            test_blocks.append(f"### {name}\n{cb}text\n{trim_block(str(body), 5000)}\n{cb}\n")
        tests_section = "\n".join(test_blocks) if test_blocks else "No workload tests recorded."

        kernel_block = "\n".join(self.data["kernel_events"]) if self.data["kernel_events"] else "No matching amdgpu/kernel GPU fault events detected during test window."

        if self.data["kernel_events"]:
            kernel_text_lower = "\n".join(self.data["kernel_events"]).lower()
            if any(re.search(p, kernel_text_lower, re.I) for p in HIGH_CONFIDENCE_GPU_FAULT_PATTERNS):
                note = (
                    "High-confidence amdgpu/kernel GPU fault events were recorded during the workload window. "
                    "These are treated as card/driver-path suspect, not as simple benchmark utility failures."
                )
                if note not in self.data["hardware_suspect_notes"]:
                    self.data["hardware_suspect_notes"].append(note)

        interpretation_lines = []
        if self.data["utility_notes"]:
            interpretation_lines.append("Utility controls applied:")
            interpretation_lines.extend(f"- {x}" for x in dict.fromkeys(self.data["utility_notes"]))
        if self.data["tool_edge_notes"]:
            interpretation_lines.append("Tool/display edge cases isolated:")
            interpretation_lines.extend(f"- {x}" for x in dict.fromkeys(self.data["tool_edge_notes"]))
        if self.data["hardware_suspect_notes"]:
            interpretation_lines.append("Hardware/driver-path suspect indicators:")
            interpretation_lines.extend(f"- {x}" for x in dict.fromkeys(self.data["hardware_suspect_notes"]))
        if not interpretation_lines:
            interpretation_lines.append("No utility edge cases or hardware-suspect interpretation notes were generated.")
        interpretation_block = "\n".join(interpretation_lines)

        issues = self.data["errors"] + self.data["warnings"]
        diag = (f"\n## Diagnostics Log\n{cb}text\n" + "\n".join(issues) + f"\n{cb}\n") if issues else "\n**Status:** No errors or warnings.\n"

        report = f"""# AMD GPU Diagnostic & Benchmark Report
**Date:** {self.ts}
{client_str}---

## Overall Verdict: {verdict}

| Result | Check | Detail |
| :--- | :--- | :--- |
{verdict_rows}
---

## 1. Hardware & Driver
{cb}text
{static_block}
{cb}

Driver / stack:
{cb}text
{self.data['driver_block']}
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

## 3. Utility Edge-Case Controls / Interpretation
{cb}text
{interpretation_block}
{cb}

---

## 4. Idle vs Load Comparison
*amdgpu sysfs polled every {SMI_POLL_S}s during workload test window*

{load_table}
**Temp trip points observed under load:** {throttle_note}

> Note: AMD does not expose a discrete throttle-reason register via sysfs the
> way nvidia-smi does. "Thermal trip" samples are flagged heuristically when a
> sensor reaches its hwmon crit / configured fail point. For authoritative live
> throttle status, cross-check with `amdgpu_top`.

---

## 5. Workload Tests
{tests_section}

### glmark2 Per-Scene FPS
{cb}text
{scenes_block}
{cb}

---

## 6. RAS / ECC Memory
{cb}text
{self.data['ras'] or 'Not applicable / not supported.'}
{cb}

---

## 7. Kernel Stability
{cb}text
{kernel_block}
{cb}
{diag}
---
*Per-second monitoring log: {self.data['csv_path']}*  
*Generated by PNWC amd_gpu_tester.py v1.0.0*
"""
        fname = os.path.join(REPORT_DIR, f"AMD_GPU_Report_{ts_file}.md")
        with open(fname, "w") as fh:
            fh.write(report)
        print(f"\n[OK] Report -> {fname}")
        return fname


def main():
    ap = argparse.ArgumentParser(description="PNWC AMD GPU Tester v1.0.0")
    ap.add_argument("--client", default="", help="Client name for the report")
    ap.add_argument("--gpu-index", type=int, default=0, help="Index into detected AMD cards (see --list-gpus)")
    ap.add_argument("--list-gpus", action="store_true", help="List detected AMD DRM cards and exit")
    ap.add_argument("--skip-memtest", action="store_true", help="Skip memtest_vulkan")
    ap.add_argument("--memtest-duration", type=int, default=MEMTEST_DURATION, help="memtest_vulkan runtime seconds")
    ap.add_argument("--skip-vkmark", action="store_true", help="Skip vkmark")
    ap.add_argument("--vkmark-timeout", type=int, default=VKMARK_TIMEOUT, help="vkmark timeout seconds")
    ap.add_argument("--skip-glmark2", action="store_true", help="Skip glmark2")
    ap.add_argument("--glmark2-timeout", type=int, default=GLMARK2_TIMEOUT, help="glmark2 timeout seconds")
    ap.add_argument("--glmark2-run-forever", action="store_true", help="Run glmark2 in timed torture mode")
    ap.add_argument("--compute-stress", action="store_true", help="Run HIP gpu-burn or clpeak compute stress if installed")
    ap.add_argument("--compute-stress-duration", type=int, default=COMPUTE_STRESS_DURATION, help="Compute stress duration seconds")
    ap.add_argument("--furmark", action="store_true", help="Also run legacy FurMark/GpuTest torture")
    ap.add_argument("--amdvlk", action="store_true", help="Prefer AMDVLK ICD over RADV for Vulkan tests")
    ap.add_argument("--vk-device", default="", help="Force RADV device via MESA_VK_DEVICE_SELECT (e.g. 1002:73bf)")
    ap.add_argument("--dri-prime", default="", help="Force GL device via DRI_PRIME (e.g. 1)")
    args = ap.parse_args()

    cards = find_amd_cards()
    if args.list_gpus:
        if not cards:
            print(f"No AMD DRM cards found under {DRM_ROOT} (vendor {AMD_PCI_VENDOR}).")
        else:
            print(f"Detected AMD DRM cards under {DRM_ROOT}:")
            for i, c in enumerate(cards):
                ac = AmdCard(c)
                snap = ac.read_snapshot()
                print(f"  [{i}] {c.name}  hwmon={ac.hwmon.name if ac.hwmon else 'none'}  "
                      f"temps={sorted(ac.temp_labels)}  vram_total~{snap.get('vram_total')}")
        sys.exit(0)

    if not cards:
        print(f"[!] No AMD GPU detected under {DRM_ROOT} (PCI vendor {AMD_PCI_VENDOR}).")
        print("    Confirm the amdgpu kernel driver is loaded: lspci -nnk | grep -iA3 VGA")
        sys.exit(1)
    if args.gpu_index < 0 or args.gpu_index >= len(cards):
        print(f"[!] --gpu-index {args.gpu_index} out of range; {len(cards)} AMD card(s) detected. Use --list-gpus.")
        sys.exit(1)

    card = AmdCard(cards[args.gpu_index])

    csv_report_name = os.path.join(REPORT_DIR, f"amd_load_{timestamp_file()}.csv")
    print_banner(csv_report_name)
    print(f"  Target   : {card.name}  ({card.dev})")
    if not card.hwmon:
        print("  [!] No hwmon node found for this card; temperature/power/fan telemetry will be limited.")

    tester = AmdGPUTester(card)
    tester.data["csv_path"] = csv_report_name

    if not tester.gather_static():
        print("\n[!] Diagnostic aborted. Static gathering failed.")
        tester.build_report(client=args.client)
        sys.exit(1)

    display_server = tester._detect_display()
    if display_server is None:
        print("\n[!] No display detected ($DISPLAY / $WAYLAND_DISPLAY unset).")
        print("    memtest_vulkan may still run; vkmark/glmark2/FurMark will be skipped.")
    else:
        print(f"\nDisplay server : {display_server.upper()}")

    env = tester._amd_vulkan_env(prefer_amdvlk=args.amdvlk, vk_device=args.vk_device, dri_prime=args.dri_prime)

    monitor = AmdMonitor(card, csv_report_name)
    watcher = KernelFaultWatcher(int(time.time()), KERNEL_PATTERNS, tester.data["errors"])

    tester.run_test_suite(args, display_server, monitor, watcher, env)

    if args.furmark:
        tester.run_furmark(csv_report_name)

    print("\n[OK] Diagnostic Routine Complete.")
    print(f"    Total data samples   : {monitor.samples()}")
    print(f"    Kernel fault events  : {len(tester.data['kernel_events'])}")

    client = args.client or input("\nClient name (Enter to skip): ").strip()
    tester.build_report(client=client)


if __name__ == "__main__":
    main()
