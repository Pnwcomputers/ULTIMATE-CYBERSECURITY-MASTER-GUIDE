#!/usr/bin/env python3
"""
full_hw_suite.py — PNWC Unified Hardware Diagnostic & Benchmark Suite v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requires : inxi, dmidecode, sysbench, memtester, fio, glmark2 or glmark2-es2
Optional : nvidia-smi, amdgpu_top, intel-gpu-tools, nvtop, s-tui

Run with sudo from a desktop terminal (memtester + dmidecode need root).
glmark2 requires an active X11 or Wayland session — do not run headless.

  sudo python3 full_hw_suite.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import subprocess
import datetime
import os
import sys
import shutil
import threading
import time

# ── Configuration ──────────────────────────────────────────────────────────────
REPORT_DIR         = os.getcwd()   # save reports next to wherever the script is invoked from

# CPU / RAM
SYSBENCH_THREADS   = 0         # 0 = auto-detect (nproc)
SYSBENCH_PRIME     = 20000
SYSBENCH_DURATION  = 30        # seconds for CPU benchmark
RAM_BW_SIZE        = "10G"
MEMTESTER_SIZE     = "1G"
MEMTESTER_PASSES   = 1

# Storage (fio)
FIO_SIZE           = "1G"
FIO_RUNTIME        = 30        # seconds
FIO_TIMEOUT        = 120       # hard timeout

# GPU (glmark2)
GLMARK2_TIMEOUT    = 600       # 600s = 10 min; full run is 8-15 min
GLMARK2_SCENES     = None      # None = full suite; list of scene names for quick pass
# ───────────────────────────────────────────────────────────────────────────────


class HardwareTester:
    """Shared base — all test classes inherit run_cmd and run_streaming."""

    def __init__(self):
        self.data   = {"errors": [], "warnings": []}

    @staticmethod
    def _which(binary: str) -> bool:
        return shutil.which(binary) is not None

    def run_cmd(self, cmd: str, timeout: int = 60) -> str:
        """
        Run a short command synchronously.
        Captures stdout; logs stderr to errors on non-zero exit.
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
                # inxi legitimately exits non-zero sometimes — skip it
                if stderr and "inxi" not in cmd:
                    self.data["errors"].append(
                        f"[{cmd.split()[0]}] rc={result.returncode}: {stderr[:400]}"
                    )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            self.data["errors"].append(f"TIMEOUT ({timeout}s): {cmd}")
            return "TIMEOUT"
        except Exception as exc:
            self.data["errors"].append(f"EXEC ERROR: {cmd} → {exc}")
            return "ERROR"

    def run_streaming(self, cmd: str, timeout: int = 300,
                      echo_filter: tuple = ()) -> tuple:
        """
        Run a long command, streaming stdout/stderr line-by-line.
        Returns (lines: list[str], timed_out: bool).

        echo_filter: tuple of substrings — lines containing any of these
                     are printed live so the operator can watch progress.
        """
        lines: list[str] = []
        timed_out = False

        print(f"    → {cmd}")
        print(f"       [streaming — timeout {timeout}s / "
              f"{timeout//60}m{timeout%60:02d}s]")

        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            def _reader():
                for raw in proc.stdout:
                    line = raw.rstrip()
                    lines.append(line)
                    if not echo_filter or any(k in line for k in echo_filter):
                        print(f"       {line}")

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()
            reader.join(timeout=timeout)

            if reader.is_alive():
                proc.terminate()
                time.sleep(2)
                proc.kill()
                timed_out = True
                self.data["errors"].append(
                    f"Command killed after {timeout}s. "
                    f"Partial output: {len(lines)} lines collected."
                )
            else:
                proc.wait()

        except Exception as exc:
            self.data["errors"].append(f"Streaming error: {exc}")
            timed_out = True

        return lines, timed_out


class SystemInfo(HardwareTester):
    def __init__(self):
        super().__init__()
        self.system      = ""
        self.motherboard = ""
        self.cpu_info    = ""

    def run(self):
        print("\n[1/6] System & Motherboard Info")
        self.system = self.run_cmd("inxi -Fzx -c0", timeout=30)

        raw_mobo = self.run_cmd("dmidecode -t baseboard", timeout=15)
        keep = [l.strip() for l in raw_mobo.splitlines()
                if any(k in l for k in
                       ["Manufacturer", "Product Name", "Version", "Serial Number"])]
        self.motherboard = "\n".join(keep) or "Could not read DMI data."

        self.cpu_info = self.run_cmd("lscpu", timeout=15)


class CPUTest(HardwareTester):
    def __init__(self, threads: int = 0, prime: int = 20000, duration: int = 30):
        super().__init__()
        self.threads  = threads or int(self.run_cmd("nproc", timeout=5) or 4)
        self.prime    = prime
        self.duration = duration
        self.result   = ""
        self.thermals = ""

    def run(self):
        print(f"\n[2/6] CPU Benchmark  ({self.threads} threads, {self.duration}s)")
        cmd = (f"sysbench cpu --cpu-max-prime={self.prime} "
               f"--threads={self.threads} --time={self.duration} run")
        out = self.run_cmd(cmd, timeout=self.duration + 30)
        wanted = ("events per second", "total time:", "total number of events",
                  "min:", "avg:", "max:", "95th percentile:")
        parsed = [l.strip() for l in out.splitlines()
                  if any(k in l for k in wanted)]
        self.result = "\n".join(parsed) or "CPU benchmark failed — check errors."

        # Grab a thermal snapshot immediately after load
        print("    → sensors (post-load thermal snapshot)")
        self.thermals = self.run_cmd("sensors 2>/dev/null", timeout=10)


class RAMTest(HardwareTester):
    def __init__(self, bw_size: str = "10G", mt_size: str = "1G", passes: int = 1):
        super().__init__()
        self.bw_size = bw_size
        self.mt_size = mt_size
        self.passes  = passes
        self.hw_info = ""
        self.bw      = ""
        self.stab    = ""

    def run(self):
        print("\n[3/6] RAM Diagnostics")

        # Script already runs as root (sudo enforced at entry) — no double-sudo
        self.hw_info = self.run_cmd("dmidecode -t memory", timeout=15)

        print("    Bandwidth test (sysbench)...")
        cmd_bw = (f"sysbench memory --memory-block-size=1M "
                  f"--memory-total-size={self.bw_size} run")
        out_bw = self.run_cmd(cmd_bw, timeout=120)
        bw_wanted = ("transferred", "Total operations", "MiB/sec", "Operations/sec")
        parsed_bw = [l.strip() for l in out_bw.splitlines()
                     if any(k in l for k in bw_wanted)]
        self.bw = "\n".join(parsed_bw) or "RAM bandwidth test failed."

        print(f"    Stability test (memtester {self.mt_size}, {self.passes} pass)...")
        print(f"       [streaming — watching for FAILED lines]")
        # Use run_streaming so the operator sees progress instead of a frozen terminal.
        # memtester output is line-buffered and a 1G/1-pass run takes 3-8 minutes.
        mt_lines, _ = self.run_streaming(
            f"memtester {self.mt_size} {self.passes}",
            timeout=900,
            echo_filter=("Loop", "Test", "ok", "FAILED", "Done", "Memtester",
                         "memtester"),
        )
        failed = any("FAILED" in l for l in mt_lines)
        summary = [l for l in mt_lines
                   if any(k in l.lower() for k in
                          ["ok", "failed", "done", "loop", "memtester"])]
        self.stab = "\n".join(summary[-15:]) or "Memtester produced no output."
        if failed:
            self.data["errors"].append(
                "⚠️  MEMTESTER DETECTED RAM ERRORS — possible bad stick or XMP instability. "
                "Reseat sticks, reduce XMP speed, or test sticks individually."
            )


class StorageTest(HardwareTester):
    def __init__(self, size: str = "1G", runtime: int = 30):
        super().__init__()
        self.size    = size
        self.runtime = runtime
        self.smart   = {}    # device → smart output
        self.fio     = ""

    def run(self):
        print("\n[4/6] Storage Diagnostics")

        # SMART for every NVMe and SATA device found
        nvme_devs = self.run_cmd(
            "ls /dev/nvme?n1 2>/dev/null", timeout=5
        ).splitlines()
        sata_devs = self.run_cmd(
            "ls /dev/sd? 2>/dev/null", timeout=5
        ).splitlines()

        for dev in nvme_devs:
            dev = dev.strip()
            if dev:
                out = self.run_cmd(f"nvme smart-log {dev} 2>/dev/null", timeout=15)
                self.smart[dev] = out or f"Could not read SMART data for {dev}."

        for dev in sata_devs:
            dev = dev.strip()
            if dev:
                out = self.run_cmd(f"smartctl -a {dev} 2>/dev/null", timeout=15)
                self.smart[dev] = out or f"Could not read SMART data for {dev}."

        # fio random 4K read/write
        print(f"    fio 4K randrw ({self.size}, {self.runtime}s)...")
        fio_cmd = (
            f"fio --name=randrw-4k --ioengine=libaio --iodepth=64 "
            f"--rw=randrw --bs=4k --direct=1 --size={self.size} "
            f"--numjobs=4 --runtime={self.runtime} --group_reporting "
            f"--filename=testfile.fio"
        )
        out_fio = self.run_cmd(fio_cmd, timeout=FIO_TIMEOUT)
        parsed = [l.strip() for l in out_fio.splitlines()
                  if "IOPS=" in l or "bw=" in l]
        self.fio = "\n".join(parsed) or "fio failed — check errors."
        if os.path.exists("testfile.fio"):
            os.remove("testfile.fio")


class GPUTest(HardwareTester):
    def __init__(self):
        super().__init__()
        self.hw_info     = ""
        self.driver_info = ""
        self.vendor_stats = ""
        self.benchmark   = ""
        self.scene_scores: list[str] = []
        self.glmark2_cmd = ""

    def _detect_display(self) -> str | None:
        if os.environ.get("WAYLAND_DISPLAY"):
            return "wayland"
        if os.environ.get("DISPLAY"):
            return "x11"
        return None

    def _detect_vendor(self) -> str:
        lo = self.hw_info.lower()
        if "nvidia" in lo:   return "nvidia"
        if "amd" in lo or "radeon" in lo: return "amd"
        if "intel" in lo:    return "intel"
        return "unknown"

    def _pick_glmark2(self, display: str) -> str | None:
        order = (
            ["glmark2-wayland", "glmark2-es2-wayland", "glmark2-es2", "glmark2"]
            if display == "wayland"
            else ["glmark2", "glmark2-es2"]
        )
        return next((b for b in order if self._which(b)), None)

    def run(self):
        print("\n[5/6] GPU Diagnostics & Benchmark")

        self.hw_info = self.run_cmd("inxi -G -c0", timeout=30)
        vendor       = self._detect_vendor()
        display      = self._detect_display()

        # Vendor-specific snapshot
        if vendor == "nvidia" and self._which("nvidia-smi"):
            self.driver_info  = self.run_cmd(
                "nvidia-smi --query-gpu=gpu_name,driver_version,memory.total,"
                "temperature.gpu,power.limit,clocks.max.sm "
                "--format=csv,noheader,nounits",
                timeout=15,
            )
            self.vendor_stats = self.run_cmd("nvidia-smi", timeout=15)

        elif vendor == "amd":
            if self._which("amdgpu_top"):
                self.vendor_stats = self.run_cmd(
                    "amdgpu_top --dump-to-stdout -s 1 2>/dev/null || "
                    "amdgpu_top -d 2>/dev/null | head -60",
                    timeout=15,
                )
            elif self._which("radeontop"):
                self.vendor_stats = self.run_cmd(
                    "radeontop -d - -l 3 2>/dev/null", timeout=15
                )

        # glmark2
        if display is None:
            self.benchmark = (
                "SKIPPED — headless session. Re-run from a desktop terminal,\n"
                "or use: glmark2 --off-screen"
            )
            self.data["warnings"].append("GPU benchmark skipped — no display.")
            return

        binary = self._pick_glmark2(display)
        if binary is None:
            self.benchmark = (
                "SKIPPED — glmark2 not installed.\n"
                "Install: pamac build glmark2"
            )
            self.data["warnings"].append("glmark2 not found.")
            return

        scene_args = (
            " ".join(f"--benchmark {s}" for s in GLMARK2_SCENES)
            if GLMARK2_SCENES else ""
        )
        cmd = f"{binary} -s 1920x1080 {scene_args}".strip()
        self.glmark2_cmd = cmd
        print(f"    Binary : {binary}  |  Display : {display.upper()}")
        if not GLMARK2_SCENES:
            print("    Scenes : full suite — expect 8–15 min")

        lines, timed_out = self.run_streaming(
            cmd,
            timeout=GLMARK2_TIMEOUT,
            echo_filter=("[", "glmark2 Score", "Error", "Failed", "WARNING"),
        )

        scene_scores = []
        final_score  = None
        for line in lines:
            s = line.strip()
            if s.startswith("[") and "FPS:" in s:
                scene_scores.append(s)
            if "glmark2 Score" in s:
                final_score = s

        self.scene_scores = scene_scores

        if final_score:
            self.benchmark = final_score
        elif scene_scores:
            self.benchmark = (
                f"PARTIAL ({len(scene_scores)} scenes before "
                f"{'timeout' if timed_out else 'exit'})\n"
                f"Last: {scene_scores[-1]}"
            )
        else:
            self.benchmark = "FAILED — no output parsed. Check errors."


class UnifiedReport:
    """Collect results from all test objects and write a single Markdown report."""

    def __init__(self, sysinfo, cpu, ram, storage, gpu):
        self.sysinfo = sysinfo
        self.cpu     = cpu
        self.ram     = ram
        self.storage = storage
        self.gpu     = gpu
        self.ts      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _all_errors(self) -> list[str]:
        out = []
        for obj, label in [
            (self.sysinfo, "System"),
            (self.cpu,     "CPU"),
            (self.ram,     "RAM"),
            (self.storage, "Storage"),
            (self.gpu,     "GPU"),
        ]:
            for e in obj.data.get("errors", []):
                out.append(f"[{label}] [ERROR] {e}")
            for w in obj.data.get("warnings", []):
                out.append(f"[{label}] [WARN]  {w}")
        return out

    def write(self, client_name: str = "") -> str:
        cb = "```"
        ts_file     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        client_str  = f"**Prepared For:** {client_name}\n" if client_name else ""

        # SMART section — one block per device
        smart_section = ""
        for dev, out in self.storage.smart.items():
            smart_section += f"\n### {dev}\n{cb}text\n{out}\n{cb}\n"
        if not smart_section:
            smart_section = f"\n{cb}text\nNo storage devices enumerated.\n{cb}\n"

        # GPU vendor stats (optional)
        gpu_vendor_block = ""
        if self.gpu.vendor_stats:
            gpu_vendor_block = f"""
### Vendor Diagnostics
{cb}text
{self.gpu.vendor_stats}
{cb}
"""

        # Scene scores
        scenes_block = (
            "\n".join(self.gpu.scene_scores)
            if self.gpu.scene_scores else "No scene data collected."
        )

        # Errors / warnings footer
        all_issues = self._all_errors()
        if all_issues:
            diag_section = (
                f"\n## ⚠️ Diagnostics & Errors Log\n{cb}text\n"
                + "\n".join(all_issues)
                + f"\n{cb}\n"
            )
        else:
            diag_section = "\n**Status:** ✅ All tests completed without errors.\n"

        glmark2_note = (
            f"\n*Command:* `{self.gpu.glmark2_cmd}`\n"
            if self.gpu.glmark2_cmd else ""
        )

        report = f"""# Master Hardware Diagnostic & Benchmark Report
**Date:** {self.ts}
{client_str}
---

## 1. System & Motherboard
{cb}text
[Motherboard DMI]
{self.sysinfo.motherboard}

[Full System Info — inxi]
{self.sysinfo.system}
{cb}

### CPU Architecture (lscpu)
{cb}text
{self.sysinfo.cpu_info}
{cb}

---

## 2. CPU Performance
*Sysbench — {self.cpu.threads} threads, prime={self.cpu.prime}, {self.cpu.duration}s*
{cb}text
{self.cpu.result}
{cb}

### Post-Load Thermal Snapshot
{cb}text
{self.cpu.thermals if self.cpu.thermals else "sensors not available."}
{cb}

---

## 3. Memory (RAM) Health & Speed

### Hardware Topology (dmidecode)
{cb}text
{self.ram.hw_info[:3000]}
{cb}

### Bandwidth — Sysbench {self.ram.bw_size} Block Transfer
{cb}text
{self.ram.bw}
{cb}

### Stability — Memtester ({self.ram.mt_size}, {self.ram.passes} pass)
{cb}text
{self.ram.stab}
{cb}

---

## 4. Storage Performance & Health

### SMART Data
{smart_section}
### fio 4K Random Read/Write (iodepth=64, 4 jobs, {self.storage.runtime}s)
{cb}text
{self.storage.fio}
{cb}

---

## 5. GPU Diagnostics & Benchmark

### Hardware & Driver Info
{cb}text
{self.gpu.hw_info}

{self.gpu.driver_info}
{cb}

### glmark2 Benchmark @ 1920×1080
{glmark2_note}
**Result:** `{self.gpu.benchmark}`

#### Per-Scene Scores
{cb}text
{scenes_block}
{cb}
{gpu_vendor_block}
---
{diag_section}
---
*Generated by PNWC full_hw_suite.py v2.0*
"""

        filename = os.path.join(REPORT_DIR, f"Full_Hardware_Report_{ts_file}.md")
        with open(filename, "w") as fh:
            fh.write(report)

        print(f"\n✅  Report saved → {filename}")
        return filename


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("❌  This script must be run with sudo.")
        print("    memtester and dmidecode require root access.")
        sys.exit(1)

    print("=" * 60)
    print("  PNWC Unified Hardware Test Suite v2.0")
    print("=" * 60)

    sysinfo = SystemInfo()
    sysinfo.run()

    cpu = CPUTest(
        threads=SYSBENCH_THREADS,
        prime=SYSBENCH_PRIME,
        duration=SYSBENCH_DURATION,
    )
    cpu.run()

    ram = RAMTest(
        bw_size=RAM_BW_SIZE,
        mt_size=MEMTESTER_SIZE,
        passes=MEMTESTER_PASSES,
    )
    ram.run()

    storage = StorageTest(size=FIO_SIZE, runtime=FIO_RUNTIME)
    storage.run()

    gpu = GPUTest()
    gpu.run()

    client = input("\nClient name (Enter to skip): ").strip()
    UnifiedReport(sysinfo, cpu, ram, storage, gpu).write(client_name=client)


if __name__ == "__main__":
    main()
