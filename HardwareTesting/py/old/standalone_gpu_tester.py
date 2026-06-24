#!/usr/bin/env python3
"""
standalone_gpu_tester.py — PNWC GPU Diagnostic & Benchmark Tool v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requires : glmark2 or glmark2-es2 (AUR), inxi
Optional : nvidia-smi (NVIDIA), amdgpu_top or radeontop (AMD), intel-gpu-tools (Intel iGPU)

Run from a desktop session (X11 or Wayland). sudo NOT required.

Install missing tools:
  pamac build glmark2            # or glmark2-es2 for Wayland-only systems
  sudo pacman -S amdgpu_top      # AMD (in extra repos on recent Manjaro)
  sudo pacman -S intel-gpu-tools # Intel iGPU
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import subprocess
import datetime
import os
import sys
import shutil
import threading
import time

# ── Configuration ──────────────────────────────────────────────────────────────
GLMARK2_TIMEOUT = 600       # seconds — full run is 8-15 min; 600 is safe for any GPU
REPORT_DIR      = os.getcwd()   # save reports next to wherever the script is invoked from

# Set to a list to run only specific scenes for a faster pass, e.g.:
#   GLMARK2_SCENES = ["build", "texture", "shading", "desktop", "buffer"]
# Set to None to run the full suite (recommended for final reports).
GLMARK2_SCENES  = None
# ───────────────────────────────────────────────────────────────────────────────


class GPUTester:
    def __init__(self):
        self.ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data = {
            "gpu_hardware":  "",
            "driver_info":   "",
            "vendor_stats":  "",
            "glmark2_cmd":   "",
            "benchmark":     "",
            "scene_scores":  [],
            "errors":        [],
            "warnings":      [],
        }

    # ── Utilities ──────────────────────────────────────────────────────────────

    @staticmethod
    def _which(binary: str) -> bool:
        return shutil.which(binary) is not None

    def run_cmd(self, cmd: str, timeout: int = 60) -> str:
        """
        Run a short command, return stdout.
        Stderr is captured and logged on non-zero exit.
        """
        print(f"    → {cmd}")
        try:
            result = subprocess.run(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()
                if stderr:
                    short = stderr[:400]
                    self.data["errors"].append(
                        f"[{cmd.split()[0]}] rc={result.returncode}: {short}"
                    )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            self.data["errors"].append(f"TIMEOUT ({timeout}s): {cmd}")
            return "TIMEOUT"
        except Exception as exc:
            self.data["errors"].append(f"EXEC ERROR: {cmd} → {exc}")
            return "ERROR"

    def run_streaming(self, cmd: str, timeout: int = GLMARK2_TIMEOUT):
        """
        Run a long-running command and stream stdout/stderr line-by-line.

        Fixes the core timeout problem:
          • subprocess.run() with capture_output buffers everything silently.
          • Popen + a reader thread lets us see progress and collect partial
            results even if we have to kill the process.

        Returns (lines: list[str], timed_out: bool)
        """
        lines: list[str] = []
        timed_out = False

        print(f"    → {cmd}")
        print(f"       [streaming output — timeout {timeout}s / "
              f"{timeout//60}m{timeout%60:02d}s]")
        print()

        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,   # merge stderr so driver errors are visible
                text=True,
                bufsize=1,
            )

            def _reader():
                for raw_line in proc.stdout:
                    line = raw_line.rstrip()
                    lines.append(line)
                    # Echo scene completions and score lines live so the
                    # operator can watch progress instead of a frozen terminal.
                    if any(k in line for k in
                           ["[", "glmark2 Score", "Error", "WARNING",
                            "Failed", "Unable", "Could not"]):
                        print(f"       {line}")

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()
            reader.join(timeout=timeout)

            if reader.is_alive():
                # Timeout — kill gracefully, then force-kill
                proc.terminate()
                time.sleep(2)
                proc.kill()
                timed_out = True
                self.data["errors"].append(
                    f"glmark2 killed after {timeout}s timeout. "
                    f"Partial results ({len(lines)} lines) collected below."
                )
            else:
                proc.wait()
                if proc.returncode not in (0, None):
                    self.data["errors"].append(
                        f"glmark2 exited with rc={proc.returncode}. "
                        f"Check errors above."
                    )

        except Exception as exc:
            self.data["errors"].append(f"Streaming error: {exc}")
            timed_out = True

        return lines, timed_out

    # ── Detection ──────────────────────────────────────────────────────────────

    def detect_display_server(self) -> str | None:
        """Return 'wayland', 'x11', or None (headless/SSH)."""
        if os.environ.get("WAYLAND_DISPLAY"):
            return "wayland"
        if os.environ.get("DISPLAY"):
            return "x11"
        return None

    def detect_gpu_vendor(self, inxi_out: str) -> str:
        lo = inxi_out.lower()
        if "nvidia" in lo:
            return "nvidia"
        if "amd" in lo or "radeon" in lo:
            return "amd"
        if "intel" in lo:
            return "intel"
        return "unknown"

    def pick_glmark2(self, display_server: str) -> str | None:
        """
        Choose the correct glmark2 binary for the active display server.

        glmark2         → X11 native (OpenGL)
        glmark2-wayland → Wayland native (OpenGL)
        glmark2-es2     → X11 OpenGL ES (fallback)
        glmark2-es2-wayland → Wayland OpenGL ES (fallback)

        Mixing X11/Wayland binaries is the #1 cause of silent glmark2 hangs.
        """
        if display_server == "wayland":
            preference = ["glmark2-wayland", "glmark2-es2-wayland",
                          "glmark2-es2", "glmark2"]
        else:
            preference = ["glmark2", "glmark2-es2"]

        for binary in preference:
            if self._which(binary):
                return binary

        return None

    # ── Hardware Info ──────────────────────────────────────────────────────────

    def gather_hardware_info(self) -> str:
        """Collect GPU hardware info and vendor-specific diagnostics."""
        print("\n[1/3] Identifying GPU hardware...")
        self.data["gpu_hardware"] = self.run_cmd("inxi -G -c0", timeout=30)
        vendor = self.detect_gpu_vendor(self.data["gpu_hardware"])

        # ── NVIDIA ────────────────────────────────────────────────────────────
        if vendor == "nvidia":
            if self._which("nvidia-smi"):
                # Structured query — much cleaner than parsing nvidia-smi table
                self.data["driver_info"] = self.run_cmd(
                    "nvidia-smi --query-gpu="
                    "gpu_name,driver_version,vbios_version,memory.total,"
                    "temperature.gpu,power.limit,clocks.max.sm,clocks.max.memory "
                    "--format=csv,noheader,nounits",
                    timeout=15,
                )
                self.data["vendor_stats"] = self.run_cmd("nvidia-smi", timeout=15)
            else:
                self.data["warnings"].append(
                    "nvidia-smi not found. Install nvidia-utils for detailed NVIDIA diagnostics."
                )

        # ── AMD ───────────────────────────────────────────────────────────────
        elif vendor == "amd":
            if self._which("amdgpu_top"):
                # --dump-to-stdout gives a snapshot without the interactive TUI
                out = self.run_cmd(
                    "amdgpu_top --dump-to-stdout -s 1 2>/dev/null || "
                    "amdgpu_top -d 2>/dev/null | head -80",
                    timeout=15,
                )
                self.data["vendor_stats"] = out if out not in ("TIMEOUT", "ERROR", "") \
                    else "amdgpu_top snapshot unavailable — run it manually."
            elif self._which("radeontop"):
                self.data["vendor_stats"] = self.run_cmd(
                    "radeontop -d - -l 3 2>/dev/null", timeout=15
                )
            else:
                self.data["warnings"].append(
                    "amdgpu_top not found. Install with: sudo pacman -S amdgpu_top"
                )

        # ── Intel iGPU ────────────────────────────────────────────────────────
        elif vendor == "intel":
            if self._which("intel_gpu_top"):
                self.data["vendor_stats"] = self.run_cmd(
                    "sudo intel_gpu_top -J -s 1000 2>/dev/null | head -40",
                    timeout=10,
                )
            else:
                self.data["warnings"].append(
                    "intel_gpu_top not found. Install with: sudo pacman -S intel-gpu-tools"
                )

        return vendor

    # ── Benchmark ──────────────────────────────────────────────────────────────

    def run_benchmark(self, display_server: str | None):
        print("\n[2/3] Running GPU benchmark (glmark2)...")

        # Guard: no display
        if display_server is None:
            self.data["benchmark"] = (
                "SKIPPED — No display detected ($DISPLAY / $WAYLAND_DISPLAY unset).\n"
                "Re-run from a desktop terminal emulator, not a raw SSH session.\n"
                "For headless benchmarking, use: glmark2 --off-screen"
            )
            self.data["warnings"].append("Headless session — glmark2 skipped.")
            return

        # Guard: binary not installed
        binary = self.pick_glmark2(display_server)
        if binary is None:
            missing_hint = (
                "glmark2-wayland (AUR: pamac build glmark2)"
                if display_server == "wayland"
                else "glmark2 (AUR: pamac build glmark2)"
            )
            self.data["benchmark"] = (
                f"SKIPPED — No compatible glmark2 binary found for {display_server.upper()}.\n"
                f"Install: {missing_hint}"
            )
            self.data["warnings"].append(
                f"glmark2 not found for {display_server}. {missing_hint}"
            )
            return

        # Build the command
        scene_args = (
            " ".join(f"--benchmark {s}" for s in GLMARK2_SCENES)
            if GLMARK2_SCENES else ""
        )
        cmd = f"{binary} -s 1920x1080 {scene_args}".strip()
        self.data["glmark2_cmd"] = cmd

        print(f"    Binary  : {binary}")
        print(f"    Display : {display_server.upper()}")
        if GLMARK2_SCENES:
            print(f"    Scenes  : {', '.join(GLMARK2_SCENES)}")
        else:
            print( "    Scenes  : full suite (expect 8-15 min)")
        print()

        lines, timed_out = self.run_streaming(cmd, timeout=GLMARK2_TIMEOUT)

        # Parse scene-level scores:  "[build] FPS: 142  FrameTime: 7.042 ms"
        scene_scores = []
        final_score  = None

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[") and "FPS:" in stripped:
                scene_scores.append(stripped)
            if "glmark2 Score" in stripped:
                final_score = stripped

        self.data["scene_scores"] = scene_scores

        if final_score:
            self.data["benchmark"] = final_score
        elif scene_scores and timed_out:
            self.data["benchmark"] = (
                f"PARTIAL (timed out after {GLMARK2_TIMEOUT}s — "
                f"{len(scene_scores)} scenes completed)\n"
                f"Last scene: {scene_scores[-1]}"
            )
            self.data["warnings"].append(
                f"Increase GLMARK2_TIMEOUT (currently {GLMARK2_TIMEOUT}s) "
                f"or add GLMARK2_SCENES to limit the scene set."
            )
        elif not lines:
            self.data["benchmark"] = (
                "FAILED — glmark2 produced no output.\n"
                "Possible causes:\n"
                "  • Wrong binary for display server "
                f"(tried: {binary}, session: {display_server})\n"
                "  • Missing OpenGL driver / Mesa not installed\n"
                "  • Run manually to see the error:\n"
                f"    {cmd}"
            )
        else:
            # Some output but no parseable score
            error_lines = [l for l in lines if
                           any(k in l for k in ["Error", "error", "Failed", "Unable"])]
            self.data["benchmark"] = (
                "FAILED — could not parse a score.\n"
                + ("\n".join(error_lines[:5]) if error_lines else
                   f"Last output lines:\n" + "\n".join(lines[-5:]))
            )

    # ── Report ─────────────────────────────────────────────────────────────────

    def build_report(self, client_name: str = "") -> str:
        print("\n[3/3] Compiling report...")

        cb = "```"
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        client_str = f"**Prepared For:** {client_name}\n" if client_name else ""

        # Scene table
        if self.data["scene_scores"]:
            scenes_block = "\n".join(self.data["scene_scores"])
        else:
            scenes_block = "No scene-level data collected."

        # Vendor stats section (optional)
        vendor_section = ""
        if self.data["vendor_stats"]:
            vendor_section = f"""
## 3. Vendor-Specific Diagnostics
{cb}text
{self.data['vendor_stats']}
{cb}
"""

        driver_block = self.data["driver_info"] if self.data["driver_info"] else "(not available)"

        # Status / errors section
        has_issues = bool(self.data["errors"] or self.data["warnings"])
        if has_issues:
            diag_lines = []
            for w in self.data["warnings"]:
                diag_lines.append(f"[WARN]  {w}")
            for e in self.data["errors"]:
                diag_lines.append(f"[ERROR] {e}")
            diag_section = (
                f"\n## ⚠️ Diagnostics Log\n{cb}text\n"
                + "\n".join(diag_lines)
                + f"\n{cb}\n"
            )
        else:
            diag_section = "\n**Status:** ✅ All tests completed without errors.\n"

        glmark2_cmd_note = (
            f"\n*Command:* `{self.data['glmark2_cmd']}`\n"
            if self.data["glmark2_cmd"] else ""
        )

        report = f"""# GPU Diagnostic & Benchmark Report
**Date:** {self.ts}
{client_str}
---

## 1. Hardware & Driver Information
{cb}text
{self.data['gpu_hardware']}

Driver / Device Details:
{driver_block}
{cb}

## 2. 3D Rendering Performance
*Benchmark: glmark2 @ 1920×1080*
{glmark2_cmd_note}
**Result:** `{self.data['benchmark']}`

### Per-Scene Scores
{cb}text
{scenes_block}
{cb}
{vendor_section}{diag_section}---
*Generated by PNWC standalone_gpu_tester.py v2.0*
"""

        filename = os.path.join(REPORT_DIR, f"GPU_Report_{ts_file}.md")
        with open(filename, "w") as fh:
            fh.write(report)

        print(f"\n✅  Report saved → {filename}")
        return filename


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  PNWC GPU Diagnostic & Benchmark Tool v2.0")
    print("=" * 60)

    tester = GPUTester()

    # Detect session type up front so the user knows immediately if there's
    # a display problem rather than waiting 10 minutes for a timeout.
    display = tester.detect_display_server()
    if display:
        print(f"\nDisplay server : {display.upper()}")
        glmark_bin = tester.pick_glmark2(display)
        if glmark_bin:
            print(f"glmark2 binary : {glmark_bin}")
        else:
            print(f"glmark2 binary : ⚠️  NOT FOUND — benchmark will be skipped")
    else:
        print("\n⚠️  No display server detected — benchmark will be skipped.")

    vendor = tester.gather_hardware_info()
    print(f"\n   GPU vendor : {vendor.upper()}")

    tester.run_benchmark(display)

    client = input("\nClient name (Enter to skip): ").strip()
    tester.build_report(client_name=client)


if __name__ == "__main__":
    main()
