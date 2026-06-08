# 🖥️ Manjaro Linux Dedicated Hardware Testing & Benchmarking PC ~ Cheat Sheet

This document serves as a quick reference for hardware diagnostics, stress testing, and benchmarking on Manjaro (Arch-based) Linux. It is specifically tailored for modern Intel test benches (**Z790 motherboards and 13th/14th Gen Core i9 processors**) but applies broadly to any modern PC hardware testing environment.

---

## 1. Package Management (`pacman` and `pamac`)

Manjaro is based on Arch Linux, meaning `apt` is replaced by `pacman` (standard repositories) and `pamac` (Manjaro's native package manager with Arch User Repository / AUR support).

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -Syu` | **System Update** | Synchronizes repositories and updates all installed packages. Always do this before testing. |
| `sudo pacman -S [pkg]` | **Install Package** | Basic command to install a software package from the official Manjaro repos. |
| `sudo pacman -Rns [pkg]` | **Remove Package Cleanly** | Removes the package, its configuration files, and any unneeded dependencies. |
| `pacman -Qdt` | **List Orphans** | Lists packages installed as dependencies that are no longer needed. |
| `sudo pacman -Sc` | **Clean Cache** | Clears out the local cache of downloaded package files. |
| `pamac build [pkg]` | **Install from AUR** | Builds and installs a community package from the Arch User Repository (e.g., proprietary benchmarks). |

---

## 2. Hardware Diagnostics and System Info

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `inxi -Fzx` | **Full System Specs** | Provides a highly detailed, human-readable summary of CPU, RAM, Motherboard, GPU, and network. |
| `sudo dmidecode -t memory` | **RAM Topology** | Reads the DMI table to show installed RAM modules, speeds (MT/s), slots used, and vendor info. |
| `sudo dmidecode -t baseboard` | **Motherboard Info** | Displays exact motherboard model, BIOS revision, and vendor (crucial for Z790 setups). |
| `lscpu` | **CPU Architecture** | Shows CPU topology, core counts (P-Cores and E-Cores), threads, and cache sizes. |
| `sudo lspci -vv` | **PCIe Devices** | Extremely detailed output of all PCIe devices, link speeds (e.g., PCIe 4.0/5.0), and active lanes. |
| `journalctl -k -p err` | **Kernel Hardware Errors** | Filters the kernel ring buffer for hardware-level errors, critical for spotting faulty components. |
| `dmesg | grep -i throttle` | **Check Throttling** | Checks the kernel log for any CPU thermal throttling events during heavy workloads. |

---

## 3. Thermal Monitoring and Power Management

With an i9 processor, monitoring thermals and power draw (PL1/PL2 limits) is critical.

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `watch -n 1 sensors` | **Basic Thermals** | Reads motherboard and CPU temperature sensors every second. Run `sudo sensors-detect` first. |
| `s-tui` | **Terminal UI Monitor** | A highly visual terminal graph for CPU frequency, utilization, temperature, and power consumption. |
| `sudo turbostat` | **Deep Intel CPU Data** | Essential for i9s. Shows exact C-states, turbo frequencies per core, and precise package power (Watts). |
| `sudo intel_gpu_top` | **iGPU Monitoring** | Monitors utilization of the integrated Intel graphics on the i9 chip (requires `intel-gpu-tools`). |
| `nvtop` | **GPU Monitor** | Like `htop` but for GPUs. Supports Intel, AMD, and NVIDIA dedicated GPUs. |

---

## 4. CPU & System Stress Testing

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `stress-ng --cpu 32 --timeout 10m` | **General CPU Stress** | Hits all 32 threads (adjust for your specific i9) for 10 minutes to test basic cooling capacity. |
| `stress-ng --matrix 0 -t 5m` | **FPU / Matrix Stress** | A highly intense floating-point test that draws maximum power and generates massive heat. |
| `sysbench cpu --cpu-max-prime=20000 run` | **CPU Benchmark** | Computes prime numbers to benchmark pure CPU arithmetic performance. |
| `mprime -t` | **Prime95 Torture Test** | The gold standard for validating CPU and RAM overclocks/stability. Uses intense AVX instructions. |

> **Note on P-Cores and E-Cores:** Modern Linux kernels (5.18+) fully support Intel's Thread Director. Manjaro defaults to newer kernels (6.x+), meaning background tasks will correctly route to E-Cores, and stress tests will appropriately saturate P-Cores.

---

## 5. Memory & Storage Diagnostics

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo memtester 16G 5` | **User-space RAM Test** | Allocates 16GB of RAM and runs 5 passes of bit-flip testing. Great for testing XMP/EXPO stability. |
| `sudo nvme smart-log /dev/nvme0n1` | **NVMe Health** | Prints out raw SMART data from an NVMe drive, showing temperature, data written, and media errors. |
| `sudo smartctl -a /dev/sda` | **SATA SMART Data** | Standard SMART reporting for SATA SSDs and HDDs. |
| `sudo hdparm -tT /dev/nvme0n1` | **Basic Drive Speed** | Performs a quick cache and raw disk read speed test. |
| `kdiskmark` | **GUI Storage Benchmark** | A Linux clone of CrystalDiskMark. Excellent for testing NVMe Gen 4/5 sequential and random IOPS. |

---

## 6. Fresh Install — Z790/i9 Test Bench Toolkit (One-Liner)

Run these scripts on a fresh Manjaro installation to immediately provision the system with all necessary diagnostic, benchmarking, and monitoring tools.

### 6.1 Standard Repository Tools (pacman)

This command installs core system utilities, sensors, terminal monitors, storage diagnostics, and basic stress utilities.

```bash
sudo pacman -Syu --needed \
base-devel git curl wget jq rsync tree tmux screen htop btop \
inxi hwinfo dmidecode lshw pciutils usbutils \
lm_sensors sysstat cpupower s-tui stress-ng sysbench \
smartmontools nvme-cli hdparm fio kdiskmark \
memtester intel-gpu-tools nvtop
```

### 6.2 AUR Tools (pamac)

Some specialized testing tools (like Prime95 and specific GPU benchmarks) are only available in the Arch User Repository. We use `pamac build` for this, which comes standard on Manjaro.

*(Note: The standalone `linpack` AUR package frequently fails to build due to Intel gating the source downloads. It has been removed from this script. Use Phoronix Test Suite in Section 8 to run Linpack instead.)*

```bash
pamac build \
mprime-bin \
glmark2 \
unigine-superposition \
phoronix-test-suite
```

### 6.3 Post-Install Setup

**Detect Motherboard Sensors:**
To ensure your Z790 motherboard sensors are properly read by `lm_sensors` and `s-tui`:

```bash
sudo sensors-detect --auto
```

**Enable microcode updates (Intel):**
Ensures the i9 processor has the latest microcode patches (crucial for stability and security).

```bash
sudo pacman -S intel-ucode
```

*(Note: You may need to regenerate your GRUB/systemd-boot config depending on your bootloader to load the microcode).*

---

## 7. Storage Benchmarking with `fio`

For deep analysis of NVMe drives on your test bench, `fio` (Flexible I/O Tester) is the enterprise standard.

**Random 4K Read/Write Test (Storage IOPS):**

```bash
fio --name=randrw-4k --ioengine=libaio --iodepth=64 --rw=randrw --bs=4k --direct=1 --size=4G --numjobs=4 --runtime=60 --group_reporting --filename=testfile.fio
```

> **Warning:** This command creates a 4GB `testfile.fio` in your current directory. Make sure you are in the mount point of the drive you actually want to test before running it!

---

## 8. The Phoronix Test Suite (Automated Benchmarking)

For comprehensive, standardized hardware reviews and comparisons, use the Phoronix Test Suite installed in the one-liner above. PTS will automatically download and compile the necessary dependencies for tests like Linpack, bypassing AUR build issues.

| Task | Command |
| :--- | :--- |
| **List Available Tests** | `phoronix-test-suite list-available-tests` |
| **Run a CPU Suite** | `phoronix-test-suite benchmark cpu` |
| **Run a Memory Suite** | `phoronix-test-suite benchmark memory` |
| **Run Linpack Benchmark** | `phoronix-test-suite benchmark pts/linpack` |
| **System Info Summary** | `phoronix-test-suite system-info` |

---

## 9. Dedicated GPU Testing (NVIDIA & AMD)

For test benches equipped with dedicated graphics cards alongside or instead of the Intel iGPU, Manjaro provides native and AUR tools for monitoring and stressing both Team Green and Team Red.

### 9.1 Universal GPU Tools

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -S nvtop` | **Universal Monitor** | An excellent `htop`-style visual monitor that supports NVIDIA, AMD, and Intel GPUs simultaneously. |
| `pamac build unigine-superposition` | **Superposition Benchmark** | A visually demanding 3D benchmark. Perfect for testing maximum GPU boost clocks, thermal limits, and VRAM stability. |
| `pamac build gputest` | **FurMark / Thermal Torture** | A "power virus" style OpenGL test designed to push the GPU to its absolute thermal and power draw limits. |

### 9.2 NVIDIA-Specific Tools

NVIDIA diagnostics on Linux rely heavily on the proprietary drivers (`nvidia` package). The core CLI utilities are included in the `nvidia-utils` package.

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `nvidia-smi` | **GPU Snapshot** | Displays the current driver version, CUDA version, VRAM usage, temperature, and power consumption (Watts). |
| `watch -n 1 nvidia-smi` | **Live NVIDIA Monitor** | Refreshes the `nvidia-smi` readout every second for real-time monitoring under load. |
| `nvidia-smi dmon` | **Device Monitor** | Outputs a scrolling, compact table of stats (utilization, clocks, power)—ideal for logging metrics to a file during a benchmark. |
| `nvidia-settings` | **NVIDIA GUI Panel** | The graphical control panel for checking thermals, adjusting fan curves, and configuring display pipelines. |

### 9.3 AMD-Specific Tools

Modern AMD Radeon cards use the open-source `amdgpu` kernel driver, which integrates deeply with the Linux kernel and provides excellent transparency out of the box.

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `sudo pacman -S amdgpu_top radeontop` | **Install AMD Monitors** | Installs the best dedicated CLI monitoring utilities for Radeon RX series cards. |
| `amdgpu_top` | **Detailed AMD Monitor** | Shows deep metrics including CU (Compute Unit) usage, VRAM/GTT allocation, power consumption, and exact clock states. |
| `radeontop` | **Graphics Pipe Monitor** | A TUI that shows specific hardware block utilization (e.g., Vertex Grouper, Shader Export, Primitive Assembly). |
| `sudo cat /sys/kernel/debug/dri/0/amdgpu_pm_info` | **Raw Kernel Data** | Reads raw power limits, current clocks, and thermal parameters directly from the AMD kernel driver. |

---

## 10. Automated Hardware Testing & Reporting Scripts

The following provides modular Python orchestration scripts designed for Manjaro Linux test benches. Instead of writing low-level hardware tests in pure Python, these scripts act as orchestrators—running robust CLI tools (`sysbench`, `inxi`, `hdparm`, `fio`, `glmark2`), capturing their output, and compiling the results into clean, client-facing Markdown reports.

### 10.1 Prerequisites

Ensure the necessary diagnostic tools are installed on your Manjaro system before running the scripts:

```bash
sudo pacman -Syu --needed python sysbench inxi hdparm
```

### 10.2 The Unified Hardware Test Suite (`full_hw_suite.py`)

This script runs sequentially through your entire test bench suite, captures the outputs, and compiles them into a comprehensive report.

> **Important Notes Before Running:**
> * **Run with `sudo`:** Tools like `memtester` and `dmidecode` require root access.
> * **Desktop Environment:** `glmark2` requires an active display (X11/Wayland). Run this from a terminal emulator inside your desktop GUI, not a headless SSH session.
> * **Fio Target:** The script creates a temporary `testfile.fio` in the directory you run it from. Ensure you run the script from the drive you actually want to test!

```python
#!/usr/bin/env python3

import subprocess
import datetime
import os
import sys

class UnifiedHardwareTester:
    def __init__(self):
        self.report_data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "client_name": "",
            "system": "",
            "motherboard": "",
            "cpu": "",
            "ram_bw": "",
            "ram_stab": "",
            "storage": "",
            "gpu": "",
            "errors": []
        }

    def run_cmd(self, cmd, timeout=600):
        """Helper to execute shell commands and capture standard output."""
        print(f"[*] Running: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0 and "inxi" not in cmd:  # inxi sometimes exits non-zero safely
                self.report_data["errors"].append(f"Command failed: {cmd}\nError: {result.stderr.strip()}")
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            self.report_data["errors"].append(f"TIMEOUT ({timeout}s): {cmd}")
            return "Test Timed Out."
        except Exception as e:
            self.report_data["errors"].append(f"EXEC ERROR: {cmd} -> {str(e)}")
            return "Execution Error."

    def test_system_and_mobo(self):
        print("\n[+] Gathering System & Motherboard Info (inxi & dmidecode)...")
        self.report_data["system"] = self.run_cmd("inxi -Fzx -c0")
        
        mobo_out = self.run_cmd("dmidecode -t baseboard")
        # Filter for the most relevant motherboard lines
        mobo_lines = [line.strip() for line in mobo_out.split('\n') if "Manufacturer" in line or "Product Name" in line or "Version" in line]
        self.report_data["motherboard"] = "\n".join(mobo_lines) if mobo_lines else "Could not read motherboard DMI data."

    def test_cpu(self):
        print("\n[+] Running CPU Stress Test (sysbench)...")
        out = self.run_cmd("sysbench cpu --cpu-max-prime=20000 --time=10 run")
        parsed = [line.strip() for line in out.split('\n') if "events per second" in line or "total time:" in line or "total number of events:" in line]
        self.report_data["cpu"] = "\n".join(parsed) if parsed else "CPU Test Failed."

    def test_ram(self):
        print("\n[+] Running RAM Bandwidth Test (sysbench)...")
        bw_out = self.run_cmd("sysbench memory --memory-block-size=1M --memory-total-size=10G run")
        parsed_bw = [line.strip() for line in bw_out.split('\n') if "transferred" in line or "Total operations" in line]
        self.report_data["ram_bw"] = "\n".join(parsed_bw) if parsed_bw else "RAM Bandwidth Test Failed."

        print("\n[+] Running RAM Stability Test (memtester - 1GB)...")
        stab_out = self.run_cmd("memtester 1G 1")
        lines = stab_out.split('\n')
        summary = [line for line in lines if "ok" in line.lower() or "failed" in line.lower() or "Done" in line]
        self.report_data["ram_stab"] = "\n".join(summary[-10:]) if summary else "RAM Stability Test Failed."

    def test_storage(self):
        print("\n[+] Running Storage IOPS Test (fio)...")
        print("    (Note: Creating 1GB testfile.fio in current directory)")
        fio_cmd = "fio --name=randrw-4k --ioengine=libaio --iodepth=64 --rw=randrw --bs=4k --direct=1 --size=1G --numjobs=4 --runtime=30 --group_reporting --filename=testfile.fio"
        out = self.run_cmd(fio_cmd, timeout=120)
        
        # Parse FIO for just the vital IOPS and Bandwidth lines
        parsed = [line.strip() for line in out.split('\n') if "IOPS=" in line or "bw=" in line]
        self.report_data["storage"] = "\n".join(parsed) if parsed else "Storage Test Failed."
        
        # Cleanup
        if os.path.exists("testfile.fio"):
            os.remove("testfile.fio")

    def test_gpu(self):
        print("\n[+] Running GPU Benchmark (glmark2)...")
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            self.report_data["gpu"] = "SKIPPED: No graphical display detected. glmark2 requires a desktop session."
            return

        out = self.run_cmd("glmark2 -s 1920x1080", timeout=300)
        score_lines = [line.strip() for line in out.split('\n') if "glmark2 Score" in line]
        self.report_data["gpu"] = score_lines[0] if score_lines else "GPU Benchmark Failed."

    def build_report(self):
        print("\n[+] Compiling Client Report...")
        self.report_data["client_name"] = input("Enter Client Name (or press Enter to skip): ").strip()
        client_str = f"### Prepared For: {self.report_data['client_name']}\n" if self.report_data['client_name'] else ""
        cb = "```"

        report = f"""# Master Hardware Diagnostic & Benchmark Report
**Date:** {self.report_data['timestamp']}
{client_str}
---

## 1. Core System & Motherboard
{cb}text
[Motherboard DMI]
{self.report_data['motherboard']}

[System Specifications]
{self.report_data['system']}
{cb}

## 2. CPU Performance
*Test: Sysbench Prime Number Calculation*
{cb}text
{self.report_data['cpu']}
{cb}

## 3. Memory (RAM) Health & Speed
*Bandwidth Test: Sysbench 10GB Block Transfer*
{cb}text
{self.report_data['ram_bw']}
{cb}
*Stability Test: Memtester (1GB Sample, 1 Pass)*
{cb}text
{self.report_data['ram_stab']}
{cb}

## 4. Storage Performance
*Test: Fio Random Read/Write (4K, 64 Queue Depth)*
{cb}text
{self.report_data['storage']}
{cb}

## 5. GPU 3D Rendering
*Test: glmark2 (1920x1080)*
{cb}text
{self.report_data['gpu']}
{cb}
"""
        if self.report_data["errors"]:
            report += f"\n## ⚠️ Diagnostic Errors Log\n{cb}text\n"
            for err in self.report_data["errors"]:
                report += f"- {err}\n"
            report += f"{cb}\n"
        else:
            report += "\n**Status:** ✅ All tests completed without execution errors.\n"

        filename = f"Full_Hardware_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filename, "w") as f:
            f.write(report)
        print(f"\n[SUCCESS] Master report saved to: {os.path.abspath(filename)}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ CRITICAL: This script must be run with sudo! (Required for memtester and dmidecode)")
        sys.exit(1)

    tester = UnifiedHardwareTester()
    tester.test_system_and_mobo()
    tester.test_cpu()
    tester.test_ram()
    tester.test_storage()
    tester.test_gpu()
    tester.build_report()
```

### 10.3 Standalone GPU Tester (`standalone_gpu_tester.py`)

> **Note:** Requires an active display (X11/Wayland) to run `glmark2`. Do not run headless.

```python
#!/usr/bin/env python3

import subprocess
import datetime
import os
import sys

class StandaloneGPUTester:
    def __init__(self):
        self.report_data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "client_name": "",
            "gpu_hardware": "",
            "benchmark": "",
            "errors": []
        }

    def run_cmd(self, cmd, timeout=300):
        print(f"[*] Running: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0 and "inxi" not in cmd:
                self.report_data["errors"].append(f"Command failed: {cmd}\nError: {result.stderr.strip()}")
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            self.report_data["errors"].append(f"TIMEOUT ({timeout}s): {cmd}")
            return "Test Timed Out."
        except Exception as e:
            self.report_data["errors"].append(f"EXEC ERROR: {cmd} -> {str(e)}")
            return "Execution Error."

    def test_gpu(self):
        print("\n[+] Identifying GPU Hardware (inxi)...")
        self.report_data["gpu_hardware"] = self.run_cmd("inxi -G -c0")

        print("\n[+] Running GPU Benchmark (glmark2)...")
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            self.report_data["benchmark"] = "SKIPPED: No graphical display detected. glmark2 requires a desktop session."
            return

        out = self.run_cmd("glmark2 -s 1920x1080", timeout=300)
        score_lines = [line.strip() for line in out.split('\n') if "glmark2 Score" in line]
        self.report_data["benchmark"] = score_lines[0] if score_lines else "GPU Benchmark Failed or could not parse score."

    def build_report(self):
        print("\n[+] Compiling GPU Report...")
        self.report_data["client_name"] = input("Enter Client Name (or press Enter to skip): ").strip()
        client_str = f"### Prepared For: {self.report_data['client_name']}\n" if self.report_data['client_name'] else ""
        cb = "```"

        report = f"""# GPU Diagnostic & Benchmark Report
**Date:** {self.report_data['timestamp']}
{client_str}
---

## 1. Hardware & Driver Information
{cb}text
{self.report_data['gpu_hardware']}
{cb}

## 2. 3D Rendering Performance
*Test: glmark2 (1920x1080)*
{cb}text
{self.report_data['benchmark']}
{cb}
"""
        if self.report_data["errors"]:
            report += f"\n## ⚠️ Diagnostic Errors Log\n{cb}text\n"
            for err in self.report_data["errors"]:
                report += f"- {err}\n"
            report += f"{cb}\n"
        else:
            report += "\n**Status:** ✅ All tests completed without execution errors.\n"

        filename = f"GPU_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filename, "w") as f:
            f.write(report)
        print(f"\n[SUCCESS] GPU report saved to: {os.path.abspath(filename)}")

if __name__ == "__main__":
    tester = StandaloneGPUTester()
    tester.test_gpu()
    tester.build_report()
```

### 10.4 Standalone RAM Tester (`standalone_ram_tester.py`)

> **Note:** Requires `sudo` to run `memtester` for memory allocation locking.

```python
#!/usr/bin/env python3

import subprocess
import datetime
import os
import sys

class StandaloneRAMTester:
    def __init__(self):
        self.report_data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "client_name": "",
            "ram_hardware": "",
            "ram_bw": "",
            "ram_stab": "",
            "errors": []
        }

    def run_cmd(self, cmd, timeout=600):
        print(f"[*] Running: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0 and "inxi" not in cmd:
                self.report_data["errors"].append(f"Command failed: {cmd}\nError: {result.stderr.strip()}")
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            self.report_data["errors"].append(f"TIMEOUT ({timeout}s): {cmd}")
            return "Test Timed Out."
        except Exception as e:
            self.report_data["errors"].append(f"EXEC ERROR: {cmd} -> {str(e)}")
            return "Execution Error."

    def test_ram(self):
        print("\n[+] Gathering RAM Hardware Info (inxi)...")
        self.report_data["ram_hardware"] = self.run_cmd("inxi -m -c0")

        print("\n[+] Running RAM Bandwidth Test (sysbench)...")
        bw_out = self.run_cmd("sysbench memory --memory-block-size=1M --memory-total-size=10G run")
        parsed_bw = [line.strip() for line in bw_out.split('\n') if "transferred" in line or "Total operations" in line]
        self.report_data["ram_bw"] = "\n".join(parsed_bw) if parsed_bw else "RAM Bandwidth Test Failed."

        print("\n[+] Running RAM Stability Test (memtester - 1GB)...")
        stab_out = self.run_cmd("memtester 1G 1")
        lines = stab_out.split('\n')
        summary = [line for line in lines if "ok" in line.lower() or "failed" in line.lower() or "Done" in line]
        self.report_data["ram_stab"] = "\n".join(summary[-10:]) if summary else "RAM Stability Test Failed."

    def build_report(self):
        print("\n[+] Compiling RAM Report...")
        self.report_data["client_name"] = input("Enter Client Name (or press Enter to skip): ").strip()
        client_str = f"### Prepared For: {self.report_data['client_name']}\n" if self.report_data['client_name'] else ""
        cb = "```"

        report = f"""# RAM Diagnostic & Benchmark Report
**Date:** {self.report_data['timestamp']}
{client_str}
---

## 1. Hardware Information
{cb}text
{self.report_data['ram_hardware']}
{cb}

## 2. Memory Bandwidth Performance
*Test: Sysbench 10GB Block Transfer*
{cb}text
{self.report_data['ram_bw']}
{cb}

## 3. Hardware Stability 
*Test: Memtester (1GB Sample, 1 Pass)*
{cb}text
{self.report_data['ram_stab']}
{cb}
"""
        if self.report_data["errors"]:
            report += f"\n## ⚠️ Diagnostic Errors Log\n{cb}text\n"
            for err in self.report_data["errors"]:
                report += f"- {err}\n"
            report += f"{cb}\n"
        else:
            report += "\n**Status:** ✅ All tests completed without execution errors.\n"

        filename = f"RAM_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filename, "w") as f:
            f.write(report)
        print(f"\n[SUCCESS] RAM report saved to: {os.path.abspath(filename)}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ CRITICAL: This script must be run with sudo! (Required for memtester)")
        sys.exit(1)

    tester = StandaloneRAMTester()
    tester.test_ram()
    tester.build_report()
```

---

## 11. Test Bench Best Practices ⚠️

* **BIOS Updates:** Z790 platforms and 13th/14th Gen Intel CPUs frequently receive BIOS updates affecting power limits (e.g., "Intel Baseline Profile"). Always flash the latest BIOS before establishing benchmark baselines.
* **Kernel Versions:** Manjaro offers multiple kernels. Always test hardware on the latest stable kernel (e.g., `Linux 6.8+`) using Manjaro Settings Manager to ensure maximum compatibility with the newest Thread Directors and chipset drivers.
* **Thermal Paste/Mounts:** If `turbostat` shows immediate thermal throttling (hitting 100°C) before PL2 duration expires, physically check the cooler mounting pressure and thermal paste application before assuming a software or hardware failure.
