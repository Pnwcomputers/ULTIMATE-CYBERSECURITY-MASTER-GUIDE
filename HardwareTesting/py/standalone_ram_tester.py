#!/usr/bin/env python3
"""
standalone_ram_tester.py — PNWC RAM Diagnostic & Benchmark Tool v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requires : inxi, dmidecode, sysbench, memtester
Run with sudo — memtester requires root to lock memory pages.

  sudo python3 standalone_ram_tester.py
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
REPORT_DIR       = os.path.expanduser("~")
BW_TOTAL_SIZE    = "10G"     # Total data for sysbench bandwidth test
MEMTESTER_SIZE   = "1G"      # RAM to allocate — increase for thoroughness
MEMTESTER_PASSES = 1         # 1 pass catches most faults; use 3-5 for full validation
MEMTESTER_TIMEOUT = 900      # seconds — 1G/1pass ~3-5 min; scale with size×passes
# ───────────────────────────────────────────────────────────────────────────────


class RAMTester:
    def __init__(self):
        self.ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data = {
            "ram_hardware": "",
            "ram_topology": "",
            "ram_bw":       "",
            "ram_stab":     "",
            "errors":       [],
            "warnings":     [],
        }

    @staticmethod
    def _which(binary: str) -> bool:
        return shutil.which(binary) is not None

    def run_cmd(self, cmd: str, timeout: int = 60) -> str:
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

    def run_streaming_memtester(self, size: str, passes: int,
                                timeout: int = MEMTESTER_TIMEOUT) -> str:
        """
        Stream memtester output live.

        memtester is interactive and slow. Running it with capture_output=True
        is particularly bad — the operator gets zero feedback for minutes at a
        time and can't tell if it's running or crashed.
        """
        lines: list[str] = []
        timed_out = False
        cmd = f"memtester {size} {passes}"

        print(f"    → {cmd}")
        print(f"       [streaming — timeout {timeout}s / "
              f"{timeout//60}m{timeout%60:02d}s]")
        print(f"       [watching for FAILED lines — none is good]")

        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            failed_detected = False

            def _reader():
                nonlocal failed_detected
                for raw in proc.stdout:
                    line = raw.rstrip()
                    lines.append(line)
                    # Always echo test lines so operator sees progress
                    if any(k in line for k in
                           ["Loop", "Test", "ok", "FAILED", "Done", "Memtester"]):
                        print(f"       {line}")
                    if "FAILED" in line:
                        failed_detected = True

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()
            reader.join(timeout=timeout)

            if reader.is_alive():
                proc.terminate()
                time.sleep(2)
                proc.kill()
                timed_out = True
                self.data["errors"].append(
                    f"memtester killed after {timeout}s. "
                    f"Increase MEMTESTER_TIMEOUT or reduce MEMTESTER_SIZE."
                )

            if failed_detected:
                self.data["errors"].append(
                    "⚠️  MEMTESTER REPORTED FAILURES — "
                    "possible bad RAM stick or XMP/EXPO instability. "
                    "Reseat sticks, reduce XMP speed, or test sticks individually."
                )

        except Exception as exc:
            self.data["errors"].append(f"Streaming error: {exc}")
            timed_out = True

        if not lines:
            return "No output captured."

        # Return summary lines
        summary = [l for l in lines
                   if any(k in l for k in
                          ["Loop", "ok", "FAILED", "Done", "memtester", "Memtester"])]
        return "\n".join(summary[-20:]) if summary else "\n".join(lines[-20:])

    # ── Tests ──────────────────────────────────────────────────────────────────

    def gather_hardware_info(self):
        print("\n[1/3] RAM hardware identification...")
        self.data["ram_hardware"] = self.run_cmd("inxi -m -c0", timeout=30)
        self.data["ram_topology"] = self.run_cmd("dmidecode -t memory", timeout=15)

    def test_bandwidth(self):
        print("\n[2/3] RAM bandwidth (sysbench)...")
        cmd = (f"sysbench memory --memory-block-size=1M "
               f"--memory-total-size={BW_TOTAL_SIZE} run")
        out = self.run_cmd(cmd, timeout=180)
        wanted = ("transferred", "Total operations", "MiB/sec", "Operations/sec")
        parsed = [l.strip() for l in out.splitlines()
                  if any(k in l for k in wanted)]
        self.data["ram_bw"] = "\n".join(parsed) or "Bandwidth test failed."

    def test_stability(self):
        print(f"\n[3/3] RAM stability (memtester {MEMTESTER_SIZE}, "
              f"{MEMTESTER_PASSES} pass)...")
        self.data["ram_stab"] = self.run_streaming_memtester(
            MEMTESTER_SIZE, MEMTESTER_PASSES, timeout=MEMTESTER_TIMEOUT
        )

    # ── Report ─────────────────────────────────────────────────────────────────

    def build_report(self, client_name: str = "") -> str:
        print("\nCompiling report...")
        cb = "```"
        ts_file    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        client_str = f"**Prepared For:** {client_name}\n" if client_name else ""

        # Trim dmidecode output to just the populated slots
        topo_lines = [l for l in self.data["ram_topology"].splitlines()
                      if any(k in l for k in
                             ["Size", "Speed", "Manufacturer", "Part Number",
                              "Configured", "Rank", "Type", "Form Factor",
                              "Memory Device"])]
        topo_trimmed = "\n".join(topo_lines) or self.data["ram_topology"]

        all_issues = self.data["errors"] + self.data["warnings"]
        if all_issues:
            diag_section = f"\n## ⚠️ Diagnostics Log\n{cb}text\n"
            diag_section += "\n".join(all_issues) + f"\n{cb}\n"
        else:
            diag_section = "\n**Status:** ✅ All tests completed without errors.\n"

        report = f"""# RAM Diagnostic & Benchmark Report
**Date:** {self.ts}
{client_str}
---

## 1. Hardware Information

### inxi Summary
{cb}text
{self.data['ram_hardware']}
{cb}

### DMI Topology (populated slots)
{cb}text
{topo_trimmed}
{cb}

---

## 2. Memory Bandwidth
*Sysbench — 1MB blocks, {BW_TOTAL_SIZE} total transfer*
{cb}text
{self.data['ram_bw']}
{cb}

---

## 3. Hardware Stability
*Memtester — {MEMTESTER_SIZE}, {MEMTESTER_PASSES} pass(es)*

> **Interpreting results:** Every test line should end with `ok`.
> Any `FAILED` line indicates a hardware fault or unstable XMP/EXPO profile.
{cb}text
{self.data['ram_stab']}
{cb}
{diag_section}
---
*Generated by PNWC standalone_ram_tester.py v2.0*
"""

        filename = os.path.join(REPORT_DIR, f"RAM_Report_{ts_file}.md")
        with open(filename, "w") as fh:
            fh.write(report)
        print(f"\n✅  Report saved → {filename}")
        return filename


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("❌  This script must be run with sudo.")
        print("    memtester requires root to lock memory pages.")
        sys.exit(1)

    print("=" * 60)
    print("  PNWC RAM Diagnostic & Benchmark Tool v2.0")
    print("=" * 60)

    tester = RAMTester()
    tester.gather_hardware_info()
    tester.test_bandwidth()
    tester.test_stability()

    client = input("\nClient name (Enter to skip): ").strip()
    tester.build_report(client_name=client)


if __name__ == "__main__":
    main()
