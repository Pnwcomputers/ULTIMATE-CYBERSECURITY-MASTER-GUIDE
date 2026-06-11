#!/usr/bin/env python3
"""
PNWC NVIDIA GPU Diagnostic & Benchmark Tool v2.2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What this script DOES:
  • Keeps the PNWC-branded diagnostic banner and customer-facing report format
  • Polls nvidia-smi every second during the full GPU test window
  • Builds a per-second CSV load curve: temp, power, clocks, utilization,
    memory utilization, P-state, PCIe link, fan, and throttle reasons
  • Verifies PCIe link generation + width against max reported capability
  • Checks ECC volatile error counters when supported
  • Runs optional-but-default deeper diagnostics when tools are installed:
      - memtest_vulkan for VRAM stability
      - vkmark for Vulkan load
      - glmark2 for OpenGL load
      - gpu-burn for CUDA compute stress when requested/installed
      - GpuTest/FurMark as opt-in legacy thermal torture only
  • Watches kernel logs during the test for NVRM, Xid, fallen-off-bus,
    PCIe AER, and related GPU fault events
  • Detects likely software rendering / wrong renderer paths
  • Writes a timestamped Markdown report and telemetry CSV

Requires : nvidia-utils, inxi
Recommended: vulkan-tools, mesa-utils, memtest_vulkan, vkmark, glmark2
Optional : gpu-burn, gputest (AUR — FurMark; legacy/opt-in)

Run from a desktop session for vkmark/glmark2/FurMark. memtest_vulkan may work
without a desktop depending on the Vulkan stack.

Install baseline:
  sudo pacman -S --needed nvidia-utils inxi vulkan-tools mesa-utils vkmark glmark2

Optional:
  # memtest_vulkan: install/build from trusted package source or upstream
  # gpu-burn: build from upstream if CUDA stress is desired
  pamac build gputest libpng12
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import argparse
import csv
import datetime
import getpass
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
SMI_POLL_S              = 1
MEMTEST_DURATION        = 360       # upstream recommends at least ~6 minutes
VKMARK_TIMEOUT          = 600
GLMARK2_TIMEOUT         = 600
GPUBURN_DURATION        = 300
GPUTEST_DURATION        = 60
TEMP_WARN_C             = 83
TEMP_FAIL_C             = 90
THERMAL_SLOWDOWN_FAIL   = True
GPU_UTIL_MIN_WARN       = 35        # warn if load tests never engage GPU
# ───────────────────────────────────────────────────────────────────────────────

SOFTWARE_RENDERERS = ("llvmpipe", "lavapipe", "softpipe", "software rasterizer", "swrast")

# These patterns are treated as utility/display compatibility issues unless
# accompanied by NVIDIA kernel faults or true memory corruption messages.
VULKAN_UTILITY_EDGE_PATTERNS = [
    r"Selected present mode Mailbox is not supported",
    r"present mode .* not supported",
    r"surface.*not supported",
    r"no supported present modes",
]

# These are high-confidence card/driver-path fault indicators when observed
# during a test window. They are not treated as simple benchmark utility issues.
HIGH_CONFIDENCE_GPU_FAULT_PATTERNS = [
    r"NVRM",
    r"Xid",
    r"NV_ERR",
    r"ERROR_DEVICE_LOST",
    r"fallen off the bus",
    r"PCIe Bus Error",
    r"AER:",
    r"mmuWalkMap",
    r"dmaAllocMapping",
]

KERNEL_PATTERNS = [
    r"NVRM",
    r"Xid",
    r"GPU has fallen off the bus",
    r"fallen off the bus",
    r"PCIe Bus Error",
    r"AER:",
    r"pcieport.*error",
    r"nvidia.*error",
    r"nvidia.*timeout",
]

# nvidia-smi fields to try. Unsupported fields are dropped dynamically.
SMI_FIELDS_DESIRED = [
    "timestamp",
    "temperature.gpu",
    "utilization.gpu",
    "utilization.memory",
    "memory.used",
    "memory.total",
    "clocks.current.graphics",
    "clocks.current.sm",
    "clocks.current.memory",
    "power.draw",
    "fan.speed",
    "pstate",
    "pcie.link.gen.current",
    "pcie.link.width.current",
    "clocks_throttle_reasons.active",
    "clocks_throttle_reasons.hw_thermal_slowdown",
    "clocks_throttle_reasons.sw_thermal_slowdown",
    "clocks_throttle_reasons.hw_power_brake_slowdown",
    "clocks_throttle_reasons.sw_power_cap",
]

SMI_STATIC_FIELDS_DESIRED = [
    "name",
    "driver_version",
    "vbios_version",
    "memory.total",
    "power.limit",
    "power.max_limit",
    "clocks.max.graphics",
    "clocks.max.sm",
    "clocks.max.memory",
    "pcie.link.gen.current",
    "pcie.link.gen.max",
    "pcie.link.width.current",
    "pcie.link.width.max",
]

SMI_IDLE_FIELDS_DESIRED = [
    "temperature.gpu",
    "power.draw",
    "clocks.current.graphics",
    "clocks.current.memory",
    "utilization.gpu",
    "utilization.memory",
    "memory.used",
    "pstate",
    "pcie.link.gen.current",
    "pcie.link.width.current",
]

ECC_FIELDS_DESIRED = [
    "ecc.errors.corrected.volatile.total",
    "ecc.errors.uncorrected.volatile.total",
]


def timestamp_file() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def printable_cmd(cmd) -> str:
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(c) for c in cmd)
    return str(cmd)


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def safe_float(v: str) -> Optional[float]:
    if v is None:
        return None
    v = str(v).strip()
    if v in ("", "[N/A]", "N/A", "[Not Supported]", "Not Supported"):
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


def print_banner(report_file_path="Not Generated Yet"):
    """Render the PNWC toolkit ASCII banner to the terminal window."""
    if platform.system() == "Windows":
        os.system("title PNWC NVIDIA GPU Diagnostic v2.2")
    else:
        print("\033]0;PNWC NVIDIA GPU Diagnostic v2.2\a", end="")

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
    print("  NVIDIA GPU Testing & Benchmark Script v2.2")
    print("")
    print("=" * 70)
    print("   PNWC Diagnostic Tool - NVIDIA GPU Hardware & Load Benchmarking")
    print("   Pacific Northwest Computers  |  support@pnwcomputers.com")
    print("   v2.2 -- Robust Classification Variant")
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

    def run_streaming(self, cmd, timeout: int, cwd: str | None = None, label: str = "process", env: dict | None = None, allow_fail: bool = False) -> tuple[list[str], bool, int | None]:
        lines: list[str] = []
        timed_out = False
        rc: int | None = None
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
                        "[", "score", "error", "failed", "warning", "fault", "xid", "nvrm",
                        "gpu", "mismatch", "corrupt", "timeout"
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
                    print(f"\n  🔴 NVIDIA/KERNEL GPU EVENT: {sig[:140]}")

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
            self.errors.append(f"{self.count()} NVIDIA/kernel GPU fault event(s) detected during testing.")

    def count(self) -> int:
        with self._lock:
            return len(self.events)

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self.events)


class NvidiaMonitor:
    """Background nvidia-smi monitor writing every sample to CSV."""

    def __init__(self, gpu_index: int, csv_path: str, fields: list[str]):
        self.gpu_index = gpu_index
        self.csv_path = csv_path
        self.fields = fields
        self.query = ",".join(fields)
        self.running = False
        self._thread = None
        self._lock = threading.Lock()
        self._samples = 0

        self.temps: list[float] = []
        self.powers: list[float] = []
        self.gclks: list[float] = []
        self.mclks: list[float] = []
        self.utils: list[float] = []
        self.memutils: list[float] = []
        self.vram_used: list[float] = []
        self.pcie_gen_seen: list[str] = []
        self.pcie_width_seen: list[str] = []

        self.hw_thermal_events = 0
        self.sw_thermal_events = 0
        self.power_brake_events = 0
        self.sw_power_cap_events = 0
        self.active_throttle_reasons: set[str] = set()

    def _sample(self):
        try:
            r = subprocess.run(
                [
                    "nvidia-smi", "-i", str(self.gpu_index),
                    f"--query-gpu={self.query}",
                    "--format=csv,noheader,nounits",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
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
                writer.writerow(self.fields)
                while self.running:
                    row = self._sample()
                    if row and len(row) == len(self.fields):
                        writer.writerow(row)
                        fh.flush()
                        self._ingest(row)
                    time.sleep(SMI_POLL_S)
        except Exception as e:
            print(f"\n[!] Monitor encountered a structural logging error: {e}")

    def _ingest(self, row: list[str]):
        d = dict(zip(self.fields, row))
        with self._lock:
            self._samples += 1
            for series, key in [
                (self.temps, "temperature.gpu"),
                (self.powers, "power.draw"),
                (self.gclks, "clocks.current.graphics"),
                (self.mclks, "clocks.current.memory"),
                (self.utils, "utilization.gpu"),
                (self.memutils, "utilization.memory"),
                (self.vram_used, "memory.used"),
            ]:
                val = safe_float(d.get(key, ""))
                if val is not None:
                    series.append(val)

            if d.get("pcie.link.gen.current"):
                self.pcie_gen_seen.append(d.get("pcie.link.gen.current", ""))
            if d.get("pcie.link.width.current"):
                self.pcie_width_seen.append(d.get("pcie.link.width.current", ""))

            active = d.get("clocks_throttle_reasons.active", "").strip()
            if active and active not in ("Not Active", "N/A", "[N/A]"):
                self.active_throttle_reasons.add(f"Active throttle: {active}")
            if d.get("clocks_throttle_reasons.hw_thermal_slowdown", "").strip() == "Active":
                self.hw_thermal_events += 1
                self.active_throttle_reasons.add("HW thermal slowdown")
            if d.get("clocks_throttle_reasons.sw_thermal_slowdown", "").strip() == "Active":
                self.sw_thermal_events += 1
                self.active_throttle_reasons.add("SW thermal slowdown")
            if d.get("clocks_throttle_reasons.hw_power_brake_slowdown", "").strip() == "Active":
                self.power_brake_events += 1
                self.active_throttle_reasons.add("HW power brake")
            if d.get("clocks_throttle_reasons.sw_power_cap", "").strip() == "Active":
                self.sw_power_cap_events += 1
                self.active_throttle_reasons.add("SW power cap")

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

    def summary(self) -> dict:
        with self._lock:
            return {
                "samples": self._samples,
                "temp": self._stats(self.temps),
                "power": self._stats(self.powers),
                "gclk": self._stats(self.gclks),
                "mclk": self._stats(self.mclks),
                "util": self._stats(self.utils),
                "memutil": self._stats(self.memutils),
                "vram_used": self._stats(self.vram_used),
                "pcie_gen_mode": self._mode(self.pcie_gen_seen),
                "pcie_width_mode": self._mode(self.pcie_width_seen),
                "hw_thermal": self.hw_thermal_events,
                "sw_thermal": self.sw_thermal_events,
                "power_brake": self.power_brake_events,
                "sw_power_cap": self.sw_power_cap_events,
                "reasons": sorted(self.active_throttle_reasons),
            }


class NvidiaGPUTester:
    def __init__(self, gpu_index: int):
        self.gpu_index = gpu_index
        self.ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data = {
            "inxi_gpu": "",
            "lspci": "",
            "vulkan_summary": "",
            "glxinfo": "",
            "static_info": {},
            "idle_snap": {},
            "ecc": "",
            "tests": {},
            "scene_scores": [],
            "load_summary": {},
            "kernel_events": [],
            "csv_path": "",
            "supported_smi_fields": [],
            "unsupported_smi_fields": [],
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

    def _nvidia_vulkan_env(self) -> dict:
        """Prefer the NVIDIA Vulkan ICD for NVIDIA-specific validation.

        This helps prevent llvmpipe/Intel/other Vulkan ICDs from being selected
        on mixed-GPU Linux benches. If the ICD is not found, the system Vulkan
        loader is used and the report explicitly notes that.
        """
        env = os.environ.copy()
        candidates = [
            Path("/usr/share/vulkan/icd.d/nvidia_icd.json"),
            Path("/usr/share/vulkan/icd.d/nvidia_icd.x86_64.json"),
            Path("/etc/vulkan/icd.d/nvidia_icd.json"),
        ]
        icd_dir = Path("/usr/share/vulkan/icd.d")
        if icd_dir.exists():
            candidates.extend(sorted(icd_dir.glob("*nvidia*.json")))
        icd = next((c for c in candidates if c.exists()), None)
        if icd:
            env["VK_DRIVER_FILES"] = str(icd)
            env["VK_ICD_FILENAMES"] = str(icd)
            note = f"NVIDIA Vulkan ICD forced for NVIDIA tests: {icd}"
            if note not in self.data["utility_notes"]:
                self.data["utility_notes"].append(note)
        else:
            note = "NVIDIA Vulkan ICD file not found; using system Vulkan loader/device selection."
            if note not in self.data["tool_edge_notes"]:
                self.data["tool_edge_notes"].append(note)
        return env

    @staticmethod
    def _has_utility_edge(text: str) -> bool:
        return any(re.search(p, text, re.I) for p in VULKAN_UTILITY_EDGE_PATTERNS)

    @staticmethod
    def _classify_memtest_vulkan_lines(lines: list[str]) -> tuple[str, list[str]]:
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

    def _query_named(self, fields: list[str], allow_fail: bool = True) -> dict:
        if not fields:
            return {}
        out = self.runner.run_cmd(
            [
                "nvidia-smi", "-i", str(self.gpu_index),
                f"--query-gpu={','.join(fields)}",
                "--format=csv,noheader,nounits",
            ],
            timeout=15,
            allow_fail=allow_fail,
        )
        if out in ("TIMEOUT", "ERROR", ""):
            return {}
        line = out.splitlines()[0]
        values = [v.strip() for v in line.split(",")]
        if len(values) != len(fields):
            return {}
        return dict(zip(fields, values))

    def _probe_smi_fields(self, desired: list[str]) -> list[str]:
        supported = []
        unsupported = []
        for field in desired:
            test = self._query_named([field], allow_fail=True)
            if test:
                supported.append(field)
            else:
                unsupported.append(field)
        if unsupported:
            self.data["unsupported_smi_fields"].extend(unsupported)
            self.data["warnings"].append(
                "Some nvidia-smi fields are unsupported on this card/driver and were skipped: "
                + ", ".join(unsupported)
            )
        return supported

    def gather_static(self) -> bool:
        print("\n[1/6] NVIDIA GPU hardware, driver, and API identification...")
        if not self._which("nvidia-smi"):
            self.data["errors"].append("nvidia-smi NOT FOUND. Install with: sudo pacman -S nvidia-utils")
            self.data["inxi_gpu"] = self.runner.run_cmd(["inxi", "-G", "-c0"], timeout=30, allow_fail=True)
            return False

        self.data["inxi_gpu"] = self.runner.run_cmd(["inxi", "-G", "-c0"], timeout=30, allow_fail=True)
        self.data["lspci"] = self.runner.run_cmd("lspci -nnk | grep -A4 -E 'VGA|3D|Display|NVIDIA'", timeout=15, allow_fail=True)

        static_fields = self._probe_smi_fields(SMI_STATIC_FIELDS_DESIRED)
        idle_fields = self._probe_smi_fields(SMI_IDLE_FIELDS_DESIRED)
        monitor_fields = self._probe_smi_fields(SMI_FIELDS_DESIRED)
        self.data["supported_smi_fields"] = monitor_fields

        self.data["static_info"] = self._query_named(static_fields)
        self.data["idle_snap"] = self._query_named(idle_fields)

        ecc_fields = self._probe_smi_fields(ECC_FIELDS_DESIRED)
        ecc = self._query_named(ecc_fields) if ecc_fields else {}
        if ecc:
            corr = ecc.get("ecc.errors.corrected.volatile.total", "N/A")
            unco = ecc.get("ecc.errors.uncorrected.volatile.total", "N/A")
            self.data["ecc"] = f"Corrected: {corr}  |  Uncorrected: {unco}"
            unco_clean = str(unco).replace(",", "")
            if unco_clean.isdigit() and int(unco_clean) > 0:
                self.data["errors"].append(f"{unco} UNCORRECTABLE ECC ERRORS - failing/suspect VRAM.")
        else:
            self.data["ecc"] = "Not supported or not applicable on this card."

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
            self.data["errors"].append("Software renderer detected (llvmpipe/lavapipe/softpipe). Test may not be hitting NVIDIA GPU.")

        return True

    def run_memtest_vulkan(self, duration: int):
        print("\n[2/6] Vulkan VRAM stability test (memtest_vulkan)...")
        if not self._which("memtest_vulkan"):
            self.data["tests"]["memtest_vulkan"] = "SKIPPED - memtest_vulkan not installed."
            self.data["warnings"].append("memtest_vulkan not installed; VRAM-specific Vulkan memory test skipped.")
            return
        env = self._nvidia_vulkan_env()
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
        env = self._nvidia_vulkan_env()
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

    def run_gpu_burn(self, duration: int):
        print("\n[5/6] NVIDIA CUDA compute stress (gpu-burn)...")
        if not self._which("gpu-burn"):
            self.data["tests"]["gpu_burn"] = "SKIPPED - gpu-burn not installed."
            self.data["warnings"].append("gpu-burn not installed; CUDA compute stress skipped.")
            return
        lines, timed_out, rc = self.runner.run_streaming(["gpu-burn", str(duration)], timeout=duration + 60, label="gpu-burn")
        text = "\n".join(lines)
        if any(re.search(r"(error|fault|fail|unstable|bad)", l, re.I) for l in lines):
            self.data["errors"].append("gpu-burn output contains error/failure indicators.")
        self.data["tests"]["gpu_burn"] = f"Timed out: {timed_out}; rc={rc}\n" + trim_block(text, 2500)

    def run_furmark(self, monitor_csv_base: str):
        print("\n[6/6] Optional legacy FurMark thermal torture (GpuTest)...")
        gputest_dir = "/opt/gputest"
        gputest_bin = os.path.join(gputest_dir, "GpuTest")
        if not os.path.exists(gputest_bin):
            self.data["tests"]["furmark"] = "SKIPPED - gputest not installed."
            self.data["warnings"].append("gputest not installed; skipped FurMark.")
            return
        furmark_csv = monitor_csv_base.replace(".csv", "_furmark.csv")
        fields = self.data["supported_smi_fields"] or self._probe_smi_fields(SMI_FIELDS_DESIRED)
        mon = NvidiaMonitor(self.gpu_index, furmark_csv, fields)
        cmd = [
            "./GpuTest", "/test=fur", "/width=1920", "/height=1080", "/msaa=0",
            "/benchmark", f"/benchmark_duration_ms={GPUTEST_DURATION * 1000}", "/no_scorebox",
        ]
        print(f"    Monitor : nvidia-smi every {SMI_POLL_S}s -> {furmark_csv}")
        mon.start()
        lines, timed_out, rc = self.runner.run_streaming(cmd, timeout=GPUTEST_DURATION + 60, cwd=gputest_dir, label="GpuTest/FurMark")
        mon.stop()
        summ = mon.summary()
        t, p = summ["temp"], summ["power"]
        self.data["tests"]["furmark"] = (
            f"FurMark {GPUTEST_DURATION}s @ 1920x1080\n"
            f"Peak temp: {t[2]:.0f}C (avg {t[1]:.0f}C) | Peak power: {p[2]:.0f}W (avg {p[1]:.0f}W)\n"
            f"HW thermal slowdown events: {summ['hw_thermal']} | Power brake events: {summ['power_brake']}\n"
            f"Per-second log: {furmark_csv}\n"
            + trim_block("\n".join(lines), 1500)
        )
        if t[2] >= TEMP_FAIL_C:
            self.data["warnings"].append(f"FurMark peak {t[2]:.0f}C >= {TEMP_FAIL_C}C - check cooling.")

    def run_test_suite(self, args, display: str | None, monitor: NvidiaMonitor, watcher: KernelFaultWatcher):
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
            if args.gpu_burn:
                self.run_gpu_burn(args.gpu_burn_duration)
        finally:
            watcher.stop()
            monitor.stop()
        self.data["load_summary"] = monitor.summary()
        self.data["kernel_events"] = watcher.snapshot()

    def build_report(self, client: str = "") -> str:
        print("\n[REPORT] Compiling PNWC NVIDIA diagnostic report...")
        cb = "```"
        ts_file = timestamp_file()
        client_str = f"**Prepared For:** {client}\n" if client else ""
        si = self.data["static_info"]
        idle = self.data["idle_snap"]
        ls = self.data["load_summary"]

        checks = []
        if si:
            cur_gen = si.get("pcie.link.gen.current", "?")
            max_gen = si.get("pcie.link.gen.max", "?")
            cur_w = si.get("pcie.link.width.current", "?")
            max_w = si.get("pcie.link.width.max", "?")
            pcie_ok = (cur_gen == max_gen and cur_w == max_w) if "?" not in (cur_gen, max_gen, cur_w, max_w) else True
            checks.append(("PCIe Link", pcie_ok, f"Gen{cur_gen} x{cur_w} (max Gen{max_gen} x{max_w})" + ("" if pcie_ok else " - not at full link")))
        if ls:
            peak_t = ls.get("temp", (0, 0, 0))[2]
            checks.append(("Load Temperature", peak_t < TEMP_FAIL_C, f"Peak {peak_t:.0f}C (limit {TEMP_FAIL_C}C)"))
            peak_util = ls.get("util", (0, 0, 0))[2]
            checks.append(("GPU Engaged", peak_util >= GPU_UTIL_MIN_WARN, f"Peak GPU util {peak_util:.0f}%" + ("" if peak_util >= GPU_UTIL_MIN_WARN else " - load may not have hit GPU")))
            hw_th = ls.get("hw_thermal", 0)
            checks.append(("Thermal Throttling", not (THERMAL_SLOWDOWN_FAIL and hw_th > 0), f"{hw_th} HW thermal slowdown sample(s)"))
        if self.data["kernel_events"]:
            checks.append(("Kernel GPU Faults", False, f"{len(self.data['kernel_events'])} event(s) detected"))
        else:
            checks.append(("Kernel GPU Faults", True, "No NVIDIA/Xid/PCIe fault events detected during run"))
        if self.data["ecc"]:
            ecc_ok = "Uncorrected: 0" in self.data["ecc"] or "Not supported" in self.data["ecc"] or "N/A" in self.data["ecc"]
            checks.append(("ECC Memory", ecc_ok, self.data["ecc"]))
        if any("Software renderer detected" in e for e in self.data["errors"]):
            checks.append(("Renderer Path", False, "Software renderer detected"))

        verdict = "PASS" if checks and all(ok for _, ok, _ in checks) and not self.data["errors"] else "FAIL"
        if not checks:
            verdict = "REVIEW"

        verdict_rows = "".join(f"| {'PASS' if ok else 'FAIL'} | {name} | {detail} |\n" for name, ok, detail in checks) or "| - | No checks performed | - |\n"

        static_block = "nvidia-smi static query unavailable."
        if si:
            static_block = (
                f"Name              : {si.get('name','?')}\n"
                f"Driver            : {si.get('driver_version','?')}\n"
                f"VBIOS             : {si.get('vbios_version','?')}\n"
                f"VRAM              : {si.get('memory.total','?')} MiB\n"
                f"Power limit       : {si.get('power.limit','?')} W (max {si.get('power.max_limit','?')} W)\n"
                f"Max graphics clock: {si.get('clocks.max.graphics','?')} MHz\n"
                f"Max memory clock  : {si.get('clocks.max.memory','?')} MHz\n"
                f"PCIe link         : Gen{si.get('pcie.link.gen.current','?')} x{si.get('pcie.link.width.current','?')} "
                f"(max Gen{si.get('pcie.link.gen.max','?')} x{si.get('pcie.link.width.max','?')})"
            )

        def _fmt_stat(s):
            return f"{s[0]:.0f} / {s[1]:.0f} / {s[2]:.0f}" if s else "- / - / -"

        if ls and idle:
            load_table = (
                f"| Metric | Idle | Load min/avg/max |\n"
                f"| :--- | ---: | ---: |\n"
                f"| Temp (C) | {idle.get('temperature.gpu','?')} | {_fmt_stat(ls['temp'])} |\n"
                f"| Power (W) | {idle.get('power.draw','?')} | {_fmt_stat(ls['power'])} |\n"
                f"| Graphics clk (MHz) | {idle.get('clocks.current.graphics','?')} | {_fmt_stat(ls['gclk'])} |\n"
                f"| Memory clk (MHz) | {idle.get('clocks.current.memory','?')} | {_fmt_stat(ls['mclk'])} |\n"
                f"| GPU util (%) | {idle.get('utilization.gpu','?')} | {_fmt_stat(ls['util'])} |\n"
                f"| Memory util (%) | {idle.get('utilization.memory','?')} | {_fmt_stat(ls['memutil'])} |\n"
                f"| VRAM used (MiB) | {idle.get('memory.used','?')} | {_fmt_stat(ls['vram_used'])} |\n"
            )
            throttle_note = ", ".join(ls["reasons"]) if ls.get("reasons") else "None observed"
        else:
            load_table = "_No load monitoring data collected._\n"
            throttle_note = "n/a"

        scenes_block = "\n".join(self.data["scene_scores"]) if self.data["scene_scores"] else "No per-scene data."
        test_blocks = []
        for name, body in self.data["tests"].items():
            test_blocks.append(f"### {name}\n{cb}text\n{trim_block(str(body), 5000)}\n{cb}\n")
        tests_section = "\n".join(test_blocks) if test_blocks else "No workload tests recorded."

        kernel_block = "\n".join(self.data["kernel_events"]) if self.data["kernel_events"] else "No matching NVIDIA/kernel GPU fault events detected during test window."

        if self.data["kernel_events"]:
            kernel_text_lower = "\n".join(self.data["kernel_events"]).lower()
            if any(re.search(p, kernel_text_lower, re.I) for p in HIGH_CONFIDENCE_GPU_FAULT_PATTERNS):
                note = (
                    "High-confidence NVIDIA/kernel GPU fault events were recorded during the workload window. "
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

        report = f"""# NVIDIA GPU Diagnostic & Benchmark Report
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
*nvidia-smi polled every {SMI_POLL_S}s during workload test window*

{load_table}
**Throttle reasons observed under load:** {throttle_note}

---

## 5. Workload Tests
{tests_section}

### glmark2 Per-Scene FPS
{cb}text
{scenes_block}
{cb}

---

## 6. ECC Memory
{cb}text
{self.data['ecc'] or 'Not applicable / not supported.'}
{cb}

---

## 7. Kernel Stability
{cb}text
{kernel_block}
{cb}
{diag}
---
*Per-second monitoring log: {self.data['csv_path']}*  
*Generated by PNWC nvidia_gpu_tester.py v2.2*
"""
        fname = os.path.join(REPORT_DIR, f"NVIDIA_GPU_Report_{ts_file}.md")
        with open(fname, "w") as fh:
            fh.write(report)
        print(f"\n[OK] Report -> {fname}")
        return fname


def main():
    ap = argparse.ArgumentParser(description="PNWC NVIDIA GPU Tester v2.2")
    ap.add_argument("--client", default="", help="Client name for the report")
    ap.add_argument("--gpu-index", type=int, default=0, help="nvidia-smi GPU index to test")
    ap.add_argument("--skip-memtest", action="store_true", help="Skip memtest_vulkan")
    ap.add_argument("--memtest-duration", type=int, default=MEMTEST_DURATION, help="memtest_vulkan runtime seconds")
    ap.add_argument("--skip-vkmark", action="store_true", help="Skip vkmark")
    ap.add_argument("--vkmark-timeout", type=int, default=VKMARK_TIMEOUT, help="vkmark timeout seconds")
    ap.add_argument("--skip-glmark2", action="store_true", help="Skip glmark2")
    ap.add_argument("--glmark2-timeout", type=int, default=GLMARK2_TIMEOUT, help="glmark2 timeout seconds")
    ap.add_argument("--glmark2-run-forever", action="store_true", help="Run glmark2 in timed torture mode")
    ap.add_argument("--gpu-burn", action="store_true", help="Run gpu-burn CUDA stress if installed")
    ap.add_argument("--gpu-burn-duration", type=int, default=GPUBURN_DURATION, help="gpu-burn duration seconds")
    ap.add_argument("--furmark", action="store_true", help="Also run legacy FurMark/GpuTest torture")
    args = ap.parse_args()

    csv_report_name = os.path.join(REPORT_DIR, f"nvidia_load_{timestamp_file()}.csv")
    print_banner(csv_report_name)

    tester = NvidiaGPUTester(gpu_index=args.gpu_index)
    tester.data["csv_path"] = csv_report_name

    if not tester.gather_static():
        print("\n[!] Diagnostic aborted. Static gathering failed (check nvidia-smi / driver).")
        tester.build_report(client=args.client)
        sys.exit(1)

    display_server = tester._detect_display()
    if display_server is None:
        print("\n[!] No display detected ($DISPLAY / $WAYLAND_DISPLAY unset).")
        print("    memtest_vulkan may still run; vkmark/glmark2/FurMark will be skipped.")
    else:
        print(f"\nDisplay server : {display_server.upper()}")

    monitor_fields = tester.data["supported_smi_fields"] or tester._probe_smi_fields(SMI_FIELDS_DESIRED)
    monitor = NvidiaMonitor(args.gpu_index, csv_report_name, monitor_fields)
    watcher = KernelFaultWatcher(int(time.time()), KERNEL_PATTERNS, tester.data["errors"])

    tester.run_test_suite(args, display_server, monitor, watcher)

    if args.furmark:
        tester.run_furmark(csv_report_name)

    print("\n[OK] Diagnostic Routine Complete.")
    print(f"    Total data samples   : {monitor.samples()}")
    print(f"    Kernel fault events  : {len(tester.data['kernel_events'])}")

    client = args.client or input("\nClient name (Enter to skip): ").strip()
    tester.build_report(client=client)


if __name__ == "__main__":
    main()
