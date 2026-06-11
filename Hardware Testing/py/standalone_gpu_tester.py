#!/usr/bin/env python3
"""
standalone_gpu_tester.py — PNWC GPU Diagnostic & Benchmark Tool v2.1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
General-purpose GPU diagnostic script for Manjaro / Arch Linux.

What this version adds beyond v2.0:
  • Preserves PNWC branding / banner output
  • Adds Vulkan and OpenGL renderer validation
  • Adds optional VRAM stability testing with memtest_vulkan
  • Adds optional Vulkan benchmark/load testing with vkmark
  • Keeps glmark2 as the OpenGL benchmark/load test
  • Adds kernel log monitoring for GPU resets, Xid, amdgpu faults, i915 hangs,
    PCIe AER errors, and DRM faults during the run
  • Uses process-group termination for reliable timeout cleanup
  • Adds vendor snapshots for NVIDIA, AMD, and Intel when tools are available
  • Produces a clearer PASS / WARN / FAIL report table

Requires : inxi, glmark2 or glmark2-es2
Recommended : vulkan-tools, mesa-utils, vkmark, memtest_vulkan
Optional : nvidia-smi (NVIDIA), amd-smi/amdgpu_top/radeontop (AMD), intel-gpu-tools

Run from a desktop session (X11 or Wayland). sudo is NOT required.

Install common tools:
  sudo pacman -S --needed inxi pciutils vulkan-tools mesa-utils vkmark glmark2

Optional vendor tools:
  sudo pacman -S --needed nvidia-utils          # NVIDIA telemetry
  sudo pacman -S --needed amdsmi amdgpu_top     # AMD telemetry
  sudo pacman -S --needed intel-gpu-tools       # Intel iGPU telemetry

Optional VRAM test:
  Install memtest_vulkan from a trusted package source or upstream build.

Examples:
  python3 standalone_gpu_tester.py --client "Client Name"
  python3 standalone_gpu_tester.py --quick --client "Client Name"
  python3 standalone_gpu_tester.py --glmark2-run-forever --glmark2-timeout 900
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import argparse
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
from dataclasses import dataclass

# ── Configuration ──────────────────────────────────────────────────────────────
REPORT_DIR             = os.getcwd()
DEFAULT_SIZE           = "1920x1080"
DEFAULT_GLMARK2_TIMEOUT = 600
DEFAULT_VKMARK_TIMEOUT  = 300
DEFAULT_MEMTEST_TIMEOUT = 360   # upstream recommends at least ~6 minutes
KERNEL_POLL_S          = 5

# Quick scene set for a faster smoke test. Full glmark2 remains the default.
QUICK_GLMARK2_SCENES = ["build", "texture", "shading", "desktop", "buffer"]

# Kernel patterns used during the diagnostic run.
KERNEL_GPU_FAULT_PATTERNS = [
    r"NVRM",
    r"Xid",
    r"GPU has fallen off the bus",
    r"amdgpu.*(ring.*timeout|GPU reset|reset|VM fault|hang)",
    r"i915.*(GPU HANG|reset|engine.*stuck|wedged)",
    r"drm.*(ERROR|fault|hang|reset)",
    r"PCIe Bus Error",
    r"AER:.*(Corrected|Uncorrected|Fatal|Non-Fatal)",
]
KERNEL_GPU_FAULT_RE = re.compile("|".join(f"({p})" for p in KERNEL_GPU_FAULT_PATTERNS), re.IGNORECASE)

SOFTWARE_RENDER_RE = re.compile(r"llvmpipe|lavapipe|software rasterizer|softpipe", re.IGNORECASE)


def print_banner(report_hint: str = "Not Generated Yet"):
    """Render the PNWC toolkit banner to the terminal window."""
    title = "PNWC GPU Diagnostic v2.1"
    if platform.system() == "Windows":
        os.system(f"title {title}")
    else:
        print(f"\033]0;{title}\a", end="")

    os.system("cls" if os.name == "nt" else "clear")
    formatted_time = datetime.datetime.now().strftime("%A %B %d %Y  %H:%M:%S")

    print("")
    print("  ######   ##  ##   ##    ##   ######")
    print("  ##  ##   ### ##   ##    ##   ##    ")
    print("  ######   ######   ## ## ##   ##    ")
    print("  ##       ## ###   ########   ##    ")
    print("  ##       ##  ##   ##    ##   ######")
    print("")
    print("  Pacific Northwest Computers")
    print("  GPU Diagnostic & Benchmark Tool v2.1")
    print("")
    print("=" * 72)
    print("   PNWC Diagnostic Tool - General GPU Hardware & Load Benchmarking")
    print("   Pacific Northwest Computers  |  support@pnwcomputers.com")
    print("   v2.1 -- Standalone General GPU Diagnostic")
    print("=" * 72)
    print("")
    print(f"  Started  : {formatted_time}")
    print(f"  Computer : {platform.node()}")
    print(f"  Operator : {getpass.getuser()}")
    print(f"  Report   : {report_hint}")
    print("")


@dataclass
class StreamResult:
    lines: list[str]
    timed_out: bool
    returncode: int | None


class KernelWatcher:
    """Poll journalctl for GPU/PCIe/DRM hardware events during the test."""

    def __init__(self, start_epoch: int):
        self.start_epoch = start_epoch
        self.events: list[str] = []
        self.running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._seen: set[str] = set()

    def _poll(self):
        cmd = (
            f"journalctl -k --since @{self.start_epoch} --no-pager "
            f"--output=short-monotonic 2>/dev/null"
        )
        try:
            out = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=15,
            ).stdout
        except Exception:
            return

        for line in out.splitlines():
            if not KERNEL_GPU_FAULT_RE.search(line):
                continue
            sig = line[20:].strip() if len(line) > 20 else line.strip()
            if not sig or sig in self._seen:
                continue
            self._seen.add(sig)
            entry = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {sig}"
            with self._lock:
                self.events.append(entry)
            print(f"\n  🔴 GPU/KERNEL EVENT: {sig[:120]}")

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
        self._poll()

    def count(self) -> int:
        with self._lock:
            return len(self.events)

    def summary(self) -> str:
        with self._lock:
            return "\n".join(self.events) if self.events else "None detected."


class GPUTester:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data = {
            "gpu_hardware": "",
            "lspci": "",
            "vulkan_info": "",
            "glx_info": "",
            "renderer_findings": [],
            "driver_info": "",
            "vendor_stats": "",
            "memtest": "",
            "vkmark": "",
            "glmark2_cmd": "",
            "benchmark": "",
            "scene_scores": [],
            "kernel_events": "",
            "errors": [],
            "warnings": [],
            "checks": [],  # list of (result, check, detail), result PASS/WARN/FAIL/SKIP
        }

    # ── Utilities ──────────────────────────────────────────────────────────────

    @staticmethod
    def _which(binary: str) -> bool:
        return shutil.which(binary) is not None

    @staticmethod
    def _find_memtest_vulkan() -> str | None:
        found = shutil.which("memtest_vulkan")
        if found:
            return found
        local = os.path.join(os.getcwd(), "memtest_vulkan")
        if os.path.exists(local) and os.access(local, os.X_OK):
            return local
        return None

    def _add_check(self, result: str, check: str, detail: str):
        self.data["checks"].append((result, check, detail))

    def run_cmd(self, cmd: str, timeout: int = 60, record_error: bool = True, cwd: str | None = None) -> str:
        print(f"    → {cmd}")
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            if result.returncode != 0 and record_error:
                stderr = result.stderr.strip()
                if stderr and "inxi" not in cmd:
                    self.data["errors"].append(
                        f"[{cmd.split()[0]}] rc={result.returncode}: {stderr[:500]}"
                    )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            if record_error:
                self.data["errors"].append(f"TIMEOUT ({timeout}s): {cmd}")
            return "TIMEOUT"
        except Exception as exc:
            if record_error:
                self.data["errors"].append(f"EXEC ERROR: {cmd} → {exc}")
            return "ERROR"

    def run_streaming(
        self,
        cmd: str,
        timeout: int,
        echo_filter: tuple[str, ...] = (),
        timeout_is_error: bool = True,
        cwd: str | None = None,
    ) -> StreamResult:
        """Run a command with live output and kill the whole process group on timeout."""
        lines: list[str] = []
        timed_out = False
        rc: int | None = None

        print(f"    → {cmd}")
        print(f"       [streaming output — timeout {timeout}s / {timeout//60}m{timeout%60:02d}s]")
        print()

        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
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
                for raw_line in proc.stdout:
                    line = raw_line.rstrip()
                    lines.append(line)
                    if not echo_filter or any(k in line for k in echo_filter):
                        print(f"       {line}")

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()
            reader.join(timeout=timeout)

            if reader.is_alive():
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                time.sleep(2)
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                rc = proc.returncode
                msg = f"Command stopped after {timeout}s timeout: {cmd}"
                if timeout_is_error:
                    self.data["errors"].append(msg)
                else:
                    self.data["warnings"].append(msg + " (planned timed run)")
            else:
                proc.wait()
                rc = proc.returncode
                if rc not in (0, None):
                    self.data["warnings"].append(f"Command exited rc={rc}: {cmd}")

        except Exception as exc:
            self.data["errors"].append(f"Streaming error: {exc}")
            timed_out = True

        return StreamResult(lines=lines, timed_out=timed_out, returncode=rc)

    # ── Detection ──────────────────────────────────────────────────────────────

    def detect_display_server(self) -> str | None:
        if os.environ.get("WAYLAND_DISPLAY"):
            return "wayland"
        if os.environ.get("DISPLAY"):
            return "x11"
        return None

    def detect_gpu_vendor(self) -> str:
        lo = f"{self.data['gpu_hardware']}\n{self.data['lspci']}".lower()
        if "nvidia" in lo:
            return "nvidia"
        if "advanced micro devices" in lo or "amd" in lo or "radeon" in lo:
            return "amd"
        if "intel" in lo:
            return "intel"
        return "unknown"

    def pick_glmark2(self, display_server: str) -> str | None:
        if display_server == "wayland":
            preference = ["glmark2-wayland", "glmark2-es2-wayland", "glmark2-es2", "glmark2"]
        else:
            preference = ["glmark2", "glmark2-es2"]
        return next((binary for binary in preference if self._which(binary)), None)

    def validate_renderers(self):
        print("\n[2/6] Vulkan/OpenGL renderer validation...")

        if self._which("vulkaninfo"):
            self.data["vulkan_info"] = self.run_cmd("vulkaninfo --summary", timeout=30, record_error=False)
            if SOFTWARE_RENDER_RE.search(self.data["vulkan_info"]):
                self.data["errors"].append("Vulkan appears to be using a software renderer (lavapipe/llvmpipe).")
                self._add_check("FAIL", "Vulkan Renderer", "Software renderer detected")
            elif self.data["vulkan_info"]:
                self._add_check("PASS", "Vulkan Renderer", "vulkaninfo produced a hardware/API summary")
            else:
                self.data["warnings"].append("vulkaninfo produced no summary output.")
                self._add_check("WARN", "Vulkan Renderer", "vulkaninfo produced no summary output")
        else:
            self.data["warnings"].append("vulkaninfo not found. Install: sudo pacman -S vulkan-tools")
            self._add_check("SKIP", "Vulkan Renderer", "vulkaninfo not installed")

        if self._which("glxinfo"):
            self.data["glx_info"] = self.run_cmd("glxinfo -B", timeout=20, record_error=False)
            if SOFTWARE_RENDER_RE.search(self.data["glx_info"]):
                self.data["errors"].append("OpenGL appears to be using a software renderer (llvmpipe/softpipe).")
                self._add_check("FAIL", "OpenGL Renderer", "Software renderer detected")
            elif self.data["glx_info"]:
                renderer = "unknown"
                for line in self.data["glx_info"].splitlines():
                    if "OpenGL renderer string" in line:
                        renderer = line.split(":", 1)[-1].strip()
                        break
                self._add_check("PASS", "OpenGL Renderer", renderer)
            else:
                self.data["warnings"].append("glxinfo produced no renderer output.")
                self._add_check("WARN", "OpenGL Renderer", "glxinfo produced no renderer output")
        else:
            self.data["warnings"].append("glxinfo not found. Install: sudo pacman -S mesa-utils")
            self._add_check("SKIP", "OpenGL Renderer", "glxinfo not installed")

    # ── Hardware Info ──────────────────────────────────────────────────────────

    def gather_hardware_info(self) -> str:
        print("\n[1/6] GPU hardware identification...")
        self.data["gpu_hardware"] = self.run_cmd("inxi -G -c0", timeout=30, record_error=False)
        self.data["lspci"] = self.run_cmd("lspci -nnk | grep -A4 -E 'VGA|3D|Display'", timeout=20, record_error=False)
        vendor = self.detect_gpu_vendor()

        print(f"    Detected vendor: {vendor.upper()}")

        if vendor == "nvidia":
            if self._which("nvidia-smi"):
                self.data["driver_info"] = self.run_cmd(
                    "nvidia-smi --query-gpu="
                    "name,driver_version,vbios_version,memory.total,temperature.gpu,"
                    "power.draw,power.limit,clocks.current.graphics,clocks.current.memory,"
                    "pcie.link.gen.current,pcie.link.gen.max,pcie.link.width.current,pcie.link.width.max "
                    "--format=csv,noheader,nounits",
                    timeout=15,
                    record_error=False,
                )
                self.data["vendor_stats"] = self.run_cmd("nvidia-smi", timeout=15, record_error=False)
            else:
                self.data["warnings"].append("nvidia-smi not found. Install nvidia-utils for detailed NVIDIA diagnostics.")

        elif vendor == "amd":
            stats = []
            if self._which("amd-smi"):
                stats.append("[amd-smi list]\n" + self.run_cmd("amd-smi list", timeout=15, record_error=False))
                stats.append("[amd-smi static]\n" + self.run_cmd("amd-smi static --gpu 0", timeout=20, record_error=False))
                stats.append("[amd-smi metric]\n" + self.run_cmd("amd-smi metric --gpu 0", timeout=20, record_error=False))
            if self._which("amdgpu_top"):
                stats.append("[amdgpu_top]\n" + self.run_cmd(
                    "amdgpu_top --dump 2>/dev/null || amdgpu_top -d 2>/dev/null | head -80",
                    timeout=15,
                    record_error=False,
                ))
            elif self._which("radeontop"):
                stats.append("[radeontop]\n" + self.run_cmd("radeontop -d - -l 3 2>/dev/null", timeout=15, record_error=False))
            if stats:
                self.data["vendor_stats"] = "\n\n".join(s for s in stats if s.strip())
            else:
                self.data["warnings"].append("No AMD telemetry helper found. Install: sudo pacman -S amdsmi amdgpu_top")

        elif vendor == "intel":
            if self._which("intel_gpu_top"):
                self.data["vendor_stats"] = self.run_cmd(
                    "timeout 5s intel_gpu_top -J -s 1000 2>/dev/null | head -80",
                    timeout=10,
                    record_error=False,
                )
            else:
                self.data["warnings"].append("intel_gpu_top not found. Install: sudo pacman -S intel-gpu-tools")

        else:
            self.data["warnings"].append("Unable to confidently detect GPU vendor from inxi/lspci output.")

        return vendor

    # ── Tests ──────────────────────────────────────────────────────────────────

    def run_memtest_vulkan(self):
        print("\n[3/6] VRAM stability test (memtest_vulkan)...")
        if self.args.no_memtest:
            self.data["memtest"] = "SKIPPED by --no-memtest."
            self._add_check("SKIP", "VRAM Stability", "Skipped by operator")
            return

        binary = self._find_memtest_vulkan()
        if not binary:
            self.data["memtest"] = "SKIPPED — memtest_vulkan not installed or not executable in current directory."
            self.data["warnings"].append("memtest_vulkan not found; VRAM stability test skipped.")
            self._add_check("SKIP", "VRAM Stability", "memtest_vulkan not installed")
            return

        res = self.run_streaming(
            binary,
            timeout=self.args.memtest_timeout,
            echo_filter=("test", "Test", "pass", "Pass", "error", "Error", "fail", "FAILED", "Bad", "bad"),
            timeout_is_error=False,
        )
        output = "\n".join(res.lines[-80:]) if res.lines else "No output captured."
        self.data["memtest"] = output

        joined = "\n".join(res.lines)
        fail_re = re.compile(r"FAILED|\bfail\b|\bbad\b|errors?\s*[:=]\s*[1-9]", re.IGNORECASE)
        if fail_re.search(joined):
            self.data["errors"].append("memtest_vulkan reported possible VRAM errors/failures.")
            self._add_check("FAIL", "VRAM Stability", "memtest_vulkan reported errors/failures")
        elif res.lines:
            detail = f"No obvious error lines detected during {self.args.memtest_timeout}s timed window"
            self._add_check("PASS", "VRAM Stability", detail)
        else:
            self.data["warnings"].append("memtest_vulkan produced no output; verify manually.")
            self._add_check("WARN", "VRAM Stability", "No output captured")

    def run_vkmark(self):
        print("\n[4/6] Vulkan benchmark/load test (vkmark)...")
        if self.args.no_vkmark:
            self.data["vkmark"] = "SKIPPED by --no-vkmark."
            self._add_check("SKIP", "Vulkan Load", "Skipped by operator")
            return

        if not self._which("vkmark"):
            self.data["vkmark"] = "SKIPPED — vkmark not installed. Install: sudo pacman -S vkmark"
            self.data["warnings"].append("vkmark not found; Vulkan benchmark skipped.")
            self._add_check("SKIP", "Vulkan Load", "vkmark not installed")
            return

        cmd = f"vkmark --size {self.args.size}"
        res = self.run_streaming(
            cmd,
            timeout=self.args.vkmark_timeout,
            echo_filter=("vkmark", "Score", "FPS", "Error", "Failed", "WARNING"),
            timeout_is_error=False,
        )
        lines = res.lines
        self.data["vkmark"] = "\n".join(lines[-80:]) if lines else "No output captured."
        joined = "\n".join(lines)
        if re.search(r"vkmark\s+Score|Score:", joined, re.IGNORECASE):
            last_score = next((l.strip() for l in reversed(lines) if "Score" in l), "Score line detected")
            self._add_check("PASS", "Vulkan Load", last_score)
        elif re.search(r"error|failed|segmentation|core dumped", joined, re.IGNORECASE):
            self.data["errors"].append("vkmark reported errors/failures.")
            self._add_check("FAIL", "Vulkan Load", "vkmark reported errors/failures")
        elif lines:
            self._add_check("WARN", "Vulkan Load", "vkmark ran but no score was parsed")
        else:
            self._add_check("WARN", "Vulkan Load", "No output captured")

    def run_glmark2(self, display_server: str | None):
        print("\n[5/6] OpenGL benchmark/load test (glmark2)...")
        if self.args.no_glmark2:
            self.data["benchmark"] = "SKIPPED by --no-glmark2."
            self._add_check("SKIP", "OpenGL Load", "Skipped by operator")
            return

        if display_server is None:
            self.data["benchmark"] = (
                "SKIPPED — No display detected ($DISPLAY / $WAYLAND_DISPLAY unset).\n"
                "Re-run from a desktop terminal emulator, not a raw SSH session."
            )
            self.data["warnings"].append("Headless session — glmark2 skipped.")
            self._add_check("SKIP", "OpenGL Load", "No display server detected")
            return

        binary = self.pick_glmark2(display_server)
        if binary is None:
            self.data["benchmark"] = "SKIPPED — no compatible glmark2 binary found. Install glmark2."
            self.data["warnings"].append(f"glmark2 not found for {display_server}.")
            self._add_check("SKIP", "OpenGL Load", "glmark2 not installed")
            return

        scene_list = QUICK_GLMARK2_SCENES if self.args.quick else None
        scene_args = " ".join(f"--benchmark {s}" for s in scene_list) if scene_list else ""
        forever = " --run-forever" if self.args.glmark2_run_forever else ""
        cmd = f"{binary} -s {self.args.size}{forever} {scene_args}".strip()
        self.data["glmark2_cmd"] = cmd

        print(f"    Binary  : {binary}")
        print(f"    Display : {display_server.upper()}")
        print(f"    Mode    : {'run-forever timed soak' if self.args.glmark2_run_forever else ('quick scenes' if scene_list else 'full suite')}")

        res = self.run_streaming(
            cmd,
            timeout=self.args.glmark2_timeout,
            echo_filter=("[", "glmark2 Score", "Error", "WARNING", "Failed", "Unable", "Could not"),
            timeout_is_error=not self.args.glmark2_run_forever,
        )

        scene_scores = []
        final_score = None
        for line in res.lines:
            stripped = line.strip()
            if stripped.startswith("[") and "FPS:" in stripped:
                scene_scores.append(stripped)
            if "glmark2 Score" in stripped:
                final_score = stripped

        self.data["scene_scores"] = scene_scores

        if final_score:
            self.data["benchmark"] = final_score
            self._add_check("PASS", "OpenGL Load", final_score)
        elif scene_scores and self.args.glmark2_run_forever:
            self.data["benchmark"] = (
                f"TIMED RUN-FOR-EVER WINDOW COMPLETE ({len(scene_scores)} scene result lines captured).\n"
                f"Last scene: {scene_scores[-1]}"
            )
            self._add_check("PASS", "OpenGL Load", f"Timed run captured {len(scene_scores)} scene results")
        elif scene_scores and res.timed_out:
            self.data["benchmark"] = (
                f"PARTIAL (timed out after {self.args.glmark2_timeout}s — {len(scene_scores)} scenes completed)\n"
                f"Last scene: {scene_scores[-1]}"
            )
            self._add_check("WARN", "OpenGL Load", "Partial glmark2 run before timeout")
        elif not res.lines:
            self.data["benchmark"] = "FAILED — glmark2 produced no output. Check driver/display."
            self.data["errors"].append("glmark2 produced no output.")
            self._add_check("FAIL", "OpenGL Load", "No glmark2 output")
        else:
            error_lines = [l for l in res.lines if any(k in l for k in ["Error", "error", "Failed", "Unable"])]
            self.data["benchmark"] = "FAILED — could not parse a glmark2 score.\n" + (
                "\n".join(error_lines[:8]) if error_lines else "\n".join(res.lines[-8:])
            )
            self._add_check("FAIL", "OpenGL Load", "No parseable glmark2 score")

    # ── Report ─────────────────────────────────────────────────────────────────

    def build_report(self, client_name: str = "") -> str:
        print("\n[6/6] Compiling report...")
        cb = "```"
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        client_str = f"**Prepared For:** {client_name}\n" if client_name else ""

        checks = self.data["checks"]
        fatal = any(result == "FAIL" for result, _, _ in checks)
        warn = any(result == "WARN" for result, _, _ in checks) or bool(self.data["warnings"])
        verdict = "FAIL" if fatal else ("WARN" if warn else "PASS")

        result_icon = {"PASS": "PASS", "WARN": "WARN", "FAIL": "FAIL", "SKIP": "SKIP"}
        verdict_rows = "".join(
            f"| {result_icon.get(result, result)} | {check} | {detail} |\n"
            for result, check, detail in checks
        ) or "| - | No checks performed | - |\n"

        scenes_block = "\n".join(self.data["scene_scores"]) if self.data["scene_scores"] else "No scene-level data collected."

        vendor_section = ""
        if self.data["vendor_stats"]:
            vendor_section = f"""
## 5. Vendor-Specific Diagnostics
{cb}text
{self.data['vendor_stats'][:6000]}
{cb}
"""

        driver_block = self.data["driver_info"] if self.data["driver_info"] else "(not available)"
        lspci_block = self.data["lspci"] if self.data["lspci"] else "(not available)"
        vulkan_block = self.data["vulkan_info"] if self.data["vulkan_info"] else "(not available)"
        glx_block = self.data["glx_info"] if self.data["glx_info"] else "(not available)"

        issues = []
        for w in self.data["warnings"]:
            issues.append(f"[WARN]  {w}")
        for e in self.data["errors"]:
            issues.append(f"[ERROR] {e}")
        diag_section = (
            f"\n## Diagnostics Log\n{cb}text\n" + "\n".join(issues) + f"\n{cb}\n"
            if issues else "\n**Status:** No errors or warnings.\n"
        )

        glmark2_cmd_note = f"\n*Command:* `{self.data['glmark2_cmd']}`\n" if self.data["glmark2_cmd"] else ""

        report = f"""# GPU Diagnostic & Benchmark Report
**Date:** {self.ts}
{client_str}
---

## Overall Verdict: {verdict}

| Result | Check | Detail |
| :--- | :--- | :--- |
{verdict_rows}
---

## 1. Hardware & Driver Information
{cb}text
{self.data['gpu_hardware']}

[lspci]
{lspci_block}

Driver / Device Details:
{driver_block}
{cb}

---

## 2. API / Renderer Validation

### Vulkan
{cb}text
{vulkan_block}
{cb}

### OpenGL
{cb}text
{glx_block}
{cb}

---

## 3. VRAM Stability — memtest_vulkan
{cb}text
{self.data['memtest'] or 'Not run.'}
{cb}

---

## 4. Vulkan Load — vkmark
{cb}text
{self.data['vkmark'] or 'Not run.'}
{cb}

---

## 5. OpenGL Rendering Performance — glmark2 @ {self.args.size}
{glmark2_cmd_note}
**Result:** `{self.data['benchmark']}`

### Per-Scene Scores
{cb}text
{scenes_block}
{cb}
{vendor_section}
---

## 6. Kernel GPU / PCIe Stability Events
{cb}text
{self.data['kernel_events'] or 'None detected.'}
{cb}
{diag_section}
---
*Generated by PNWC standalone_gpu_tester.py v2.1*
"""

        filename = os.path.join(REPORT_DIR, f"GPU_Report_{ts_file}.md")
        with open(filename, "w") as fh:
            fh.write(report)

        print(f"\n✅  Report saved → {filename}")
        return filename


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PNWC GPU Diagnostic & Benchmark Tool v2.1")
    parser.add_argument("--client", default="", help="Client name for the report")
    parser.add_argument("--size", default=DEFAULT_SIZE, help="Benchmark window size, e.g. 1920x1080")
    parser.add_argument("--quick", action="store_true", help="Use a smaller glmark2 scene set")
    parser.add_argument("--no-memtest", action="store_true", help="Skip memtest_vulkan even if available")
    parser.add_argument("--no-vkmark", action="store_true", help="Skip vkmark even if available")
    parser.add_argument("--no-glmark2", action="store_true", help="Skip glmark2")
    parser.add_argument("--no-kernel-watch", action="store_true", help="Do not monitor kernel logs during testing")
    parser.add_argument("--memtest-timeout", type=int, default=DEFAULT_MEMTEST_TIMEOUT, help="Seconds to run memtest_vulkan")
    parser.add_argument("--vkmark-timeout", type=int, default=DEFAULT_VKMARK_TIMEOUT, help="Seconds before stopping vkmark")
    parser.add_argument("--glmark2-timeout", type=int, default=DEFAULT_GLMARK2_TIMEOUT, help="Seconds before stopping glmark2")
    parser.add_argument("--glmark2-run-forever", action="store_true", help="Run glmark2 --run-forever for the timeout window")
    return parser.parse_args()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_hint = os.path.join(REPORT_DIR, f"GPU_Report_{timestamp}.md")
    print_banner(report_hint)

    tester = GPUTester(args)

    display = tester.detect_display_server()
    if display:
        print(f"Display server : {display.upper()}")
        glmark_bin = tester.pick_glmark2(display)
        print(f"glmark2 binary : {glmark_bin or 'NOT FOUND — benchmark may be skipped'}")
    else:
        print("⚠️  No display server detected — glmark2 will be skipped.")

    start_epoch = int(time.time())
    watcher = KernelWatcher(start_epoch)
    if not args.no_kernel_watch:
        watcher.start()

    try:
        vendor = tester.gather_hardware_info()
        print(f"\nGPU vendor : {vendor.upper()}")
        tester.validate_renderers()
        tester.run_memtest_vulkan()
        tester.run_vkmark()
        tester.run_glmark2(display)
    finally:
        if not args.no_kernel_watch:
            watcher.stop()
            tester.data["kernel_events"] = watcher.summary()
            if watcher.count() > 0:
                tester.data["errors"].append(f"{watcher.count()} GPU/PCIe kernel event(s) detected during testing.")
                tester._add_check("FAIL", "Kernel GPU/PCIe Events", f"{watcher.count()} event(s) detected")
            else:
                tester._add_check("PASS", "Kernel GPU/PCIe Events", "None detected during test window")
        else:
            tester.data["kernel_events"] = "Skipped by --no-kernel-watch."
            tester._add_check("SKIP", "Kernel GPU/PCIe Events", "Skipped by operator")

    client = args.client or input("\nClient name (Enter to skip): ").strip()
    tester.build_report(client_name=client)


if __name__ == "__main__":
    main()
