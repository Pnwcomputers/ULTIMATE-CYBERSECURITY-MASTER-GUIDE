# 🖥️ Manjaro Linux Dedicated Hardware Testing & Benchmarking PC (Intel CPU)

This document serves as a quick reference for hardware diagnostics, stress testing, and benchmarking on Manjaro (Arch-based) Linux. It is specifically tailored for modern Intel test benches (**Z790 motherboards and 13th/14th Gen Core i9 processors**) but applies broadly to any modern PC hardware testing environment.

---

## 1. Package Management (`pacman` and `pamac`)

[Manjaro](https://manjaro.org/) Arch is based on [Arch](https://archlinux.org/) Linux, meaning [`apt`]([https://linuxize.com/post/how-to-use-apt-command/](https://linuxize.com/post/how-to-use-apt-command/)) is replaced by [`pacman`]([https://wiki.archlinux.org/title/Pacman](https://wiki.archlinux.org/title/Pacman)) (standard repositories) and [`pamac`]([https://github.com/manjaro/pamac](https://github.com/manjaro/pamac)) (Manjaro's native package manager with [Arch User Repository / AUR support](https://aur.archlinux.org/)). Arch's killer feature is the AUR or the Arch User Repository. Instead of hunting down PPAs, users can use an [AUR helper](https://wiki.archlinux.org/title/AUR_helpers) (like Manjaro's pamac, or terminal tools like [yay](https://aur.archlinux.org/packages/yay) and [paru](https://github.com/Morganamilo/paru)) to automatically compile and install virtually any Linux software in existence directly from source scripts!

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
| `dmesg \| grep -i throttle` | **Check Throttling** | Checks the kernel log for any CPU thermal throttling events during heavy workloads. |

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

## 6. Fresh Install: Z790/i9 Test Bench Toolkit

Run these commands on a fresh Manjaro installation to immediately provision the system with all necessary diagnostic, benchmarking, and monitoring tools.

### 6.1 Standard Repository Tools (pacman)

Installs core system utilities, sensors, terminal monitors, storage diagnostics, and testing engines. Both `vkmark` (Vulkan benchmark) and `glmark2` (OpenGL/ES benchmark) are now packaged natively in Arch/Manjaro. 

**Base Diagnostics & System Tools:**
```bash
sudo pacman -S --needed \
  base-devel git python \
  inxi pciutils usbutils lm_sensors smartmontools \
  vulkan-tools mesa-utils \
  vkmark glmark2
```

**For AMD Test Environments:**
*(Note: `amdsmi` is currently packaged in Arch Extra as AMD’s System Management Interface library).*
```bash
sudo pacman -S --needed \
  mesa vulkan-radeon \
  amdsmi amdgpu_top radeontop
```

**For NVIDIA Test Environments:**
```bash
sudo pacman -S --needed \
  nvidia-utils cuda
```

### 6.2 AUR Tools (pamac)

Some specialized testing tools are only available in the Arch User Repository. We use `pamac build`, which comes standard on Manjaro.

*(Note: The standalone `linpack` AUR package frequently fails to build due to Intel gating the source downloads. It has been removed from this list. Use Phoronix Test Suite in Section 8 to run Linpack instead.)*

```bash
pamac build \
  mprime-bin \
  kdiskmark \
  unigine-superposition \
  phoronix-test-suite
```

### 6.3 Post-Install Setup

**Detect Motherboard Sensors:**
Run once after installing `lm_sensors` to write sensor configuration for your specific motherboard. Required for `sensors`, `s-tui`, and the thermal logging in `stress_soak.py` to return data.

```bash
sudo sensors-detect --auto
```

**Enable Intel Microcode Updates:**
Ensures the i9 processor has the latest microcode patches, which are critical for stability and security on 13th/14th Gen platforms.

```bash
sudo pacman -S intel-ucode
```

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

For comprehensive, standardized hardware reviews and comparisons, use the Phoronix Test Suite installed in Section 6.2. PTS will automatically download and compile the necessary dependencies for tests like Linpack, bypassing AUR build issues.

| Task | Command |
| :--- | :--- |
| **List Available Tests** | `phoronix-test-suite list-available-tests` |
| **Run a CPU Suite** | `phoronix-test-suite benchmark cpu` |
| **Run a Memory Suite** | `phoronix-test-suite benchmark memory` |
| **Run Linpack Benchmark** | `phoronix-test-suite benchmark pts/linpack` |
| **System Info Summary** | `phoronix-test-suite system-info` |

---

## 9. Dedicated GPU Testing (NVIDIA & AMD)

### 9.1 Modern GPU Diagnostic Methodology

The scripts and testing methodology now treat **FurMark / GpuTest as optional**, rather than the main diagnostic engine. The stronger standard path for GPU validation relies on:
1.  **`memtest_vulkan`** for VRAM stability (Now treated as a first-class diagnostic. The upstream project describes it as a Vulkan compute video-memory stability test for overclocking or repair. Upstream recommends 6+ minutes; default is set to 360 seconds).
2.  **`vkmark`** for standardized Vulkan loads.
3.  **`glmark2`** for standardized OpenGL loads.
4.  **Vendor telemetry tracking** during all tests.
5.  **Kernel log scanning** for GPU/PCIe faults.

### 9.2 Universal GPU Tools

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `nvtop` | **Universal Monitor** | An excellent `htop`-style visual monitor that supports NVIDIA, AMD, and Intel GPUs simultaneously. |
| `pamac build unigine-superposition` | **Superposition Benchmark** | A visually demanding 3D benchmark. Perfect for testing maximum GPU boost clocks, thermal limits, and VRAM stability. |
| `pamac build gputest` | **FurMark (Optional)** | A legacy "power virus" style OpenGL test designed to push the GPU to its absolute limits. |

### 9.3 NVIDIA-Specific Tools

NVIDIA diagnostics on Linux rely heavily on the proprietary drivers (`nvidia` package). 

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `nvidia-smi` | **GPU Snapshot** | Displays current driver/CUDA versions, VRAM usage, temp, and power consumption (Watts). |
| `watch -n 1 nvidia-smi` | **Live Monitor** | Refreshes the `nvidia-smi` readout every second for real-time monitoring under load. |
| `nvidia-smi dmon` | **Device Monitor** | Outputs a scrolling, compact table of stats; ideal for logging metrics to a file. |
| `nvidia-settings` | **NVIDIA GUI Panel** | Graphical control panel for checking thermals, adjusting fan curves, and display pipelines. |

### 9.4 AMD-Specific Tools

Modern AMD Radeon cards use the open-source `amdgpu` kernel driver, integrating deeply with the Linux kernel for excellent transparency.

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `amdgpu_top` | **Detailed AMD Monitor** | Shows deep metrics including CU usage, VRAM/GTT allocation, power consumption, and clocks. |
| `radeontop` | **Graphics Pipe Monitor** | A TUI showing specific hardware block utilization. |
| `sudo cat /sys/kernel/debug/dri/0/amdgpu_pm_info` | **Raw Kernel Data** | Reads raw power limits, current clocks, and thermal parameters directly from the kernel driver. |

---

## 10. Automated Hardware Testing & Reporting Scripts

Modular Python orchestration scripts for Manjaro Linux test benches. These act as orchestrators; running robust CLI tools, streaming output live so the terminal never freezes, and compiling results into clean Markdown reports.

All scripts are located in the [`py/`](./py/) subdirectory. Ensure all tools from Section 6 are installed before running any script.

### 10.1 The Unified Hardware Test Suite (`full_hw_suite.py`)

Runs a full sequential diagnostic pass (v2.1): system info → CPU benchmark → RAM bandwidth/stability → storage SMART/IOPS → GPU benchmark. Compiles everything into a timestamped Markdown report.
**Requires:** `sudo` (for memtester/dmidecode), a desktop terminal (for glmark2), and execution from the target drive's mount point.

```bash
sudo python3 full_hw_suite.py --client "Client Name"
```

---

### 10.2 Universal Standalone GPU Tester (`standalone_gpu_tester.py`)

A general first-pass GPU validation script (v2.1) for any vendor (Intel, AMD, NVIDIA). It checks hardware via `inxi`/`lspci`, validates Vulkan/OpenGL renderers, warns on software rendering, and optionally runs `memtest_vulkan` and `vkmark`. It uses `glmark2` for the main OpenGL load test while scanning kernel logs for Xid/NVRM, amdgpu resets, i915 hangs, DRM, and PCIe AER errors. Uses strict process-group cleanup for hung tests.

*For a serious suspected AMD or NVIDIA card failure, run the vendor-specific scripts (10.3/10.4) afterward for richer per-second telemetry.*

**Run Commands:**
```bash
# Standard general diagnostic:
python3 standalone_gpu_tester.py --client "Client Name"

# Quick smoke test:
python3 standalone_gpu_tester.py --quick --client "Client Name"

# Longer OpenGL timed soak:
python3 standalone_gpu_tester.py --glmark2-run-forever --glmark2-timeout 900 --client "Client Name"

# Skip optional tests if needed:
python3 standalone_gpu_tester.py --no-memtest --no-vkmark --client "Client Name"
```

---

### 10.3 AMD GPU Diagnostic Script (`pnwc_amd_gpu_diag.py`)

Dedicated diagnostic path for Radeon GPUs. This script uses `amdgpu sysfs` as the baseline telemetry path. AMD's current SMI CLI documentation includes static, metric, and monitor-style workflows, so the script collects `amd-smi` snapshots when present, but will *not* fail a consumer Radeon card just because ROCm/SMI support is incomplete. 

**Features:** `--card-index` support, PCIe current/max sysfs checks, `amd-smi` & `amdgpu_top` snapshots, `memtest_vulkan`, `vkmark`, `glmark2`, optional FurMark, kernel GPU/PCIe fault scanning, and a stricter Markdown verdict.

**Run Commands:**
```bash
# Standard Diagnostic Run
python3 pnwc_amd_gpu_diag.py --client "Client Name"

# More aggressive OpenGL stress mode
python3 pnwc_amd_gpu_diag.py --client "Client Name" --glmark2-run-forever --glmark2-timeout 900

# Optional FurMark/GpuTest mode
python3 pnwc_amd_gpu_diag.py --client "Client Name" --furmark
```

---

### 10.4 NVIDIA GPU Diagnostic Script (`pnwc_nvidia_gpu_diag.py`)

Dedicated diagnostic path for GeForce/Quadro/RTX GPUs. 

**Features:** `--gpu-index` support, dynamic `nvidia-smi` field probing, PCIe link tracking during load, throttle tracking, ECC checks, `memtest_vulkan`, `vkmark`, `glmark2`, optional `gpu-burn`, optional FurMark, kernel GPU/PCIe fault scanning, and a complete Markdown verdict.

**Run Commands:**
```bash
# Standard Diagnostic Run
python3 pnwc_nvidia_gpu_diag.py --client "Client Name"

# More aggressive OpenGL stress mode
python3 pnwc_nvidia_gpu_diag.py --client "Client Name" --glmark2-run-forever --glmark2-timeout 900

# Optional FurMark/GpuTest mode
python3 pnwc_nvidia_gpu_diag.py --client "Client Name" --furmark
```

---

### 10.5 Standalone RAM Tester (`standalone_ram_tester.py`)

Tests RAM in isolation (v2.1). Reads hardware topology from `dmidecode`, runs a `sysbench` memory bandwidth test, then runs `memtester` for bit-pattern stability validation. Outputs stream live and kernel logs are scanned for MCE/EDAC/OOM errors.
**Requires:** `sudo`. For thorough XMP/EXPO validation, increase `MEMTESTER_SIZE` and `MEMTESTER_PASSES` via CLI flags before running.

```bash
sudo python3 standalone_ram_tester.py --client "Client Name" --memtester-size 4G --passes 3
```

---

### 10.6 Stress Soak Reliability Tester (`stress_soak.py`)

Purpose-built for reliability validation (v1.1). Hammers CPU, RAM, storage, and GPU **simultaneously** for hours, exposing failures that quick benchmarks miss (thermal soak through marginal cooler mounts, combined-load PSU issues, VRM thermal limits). 

Logs sensor readings to CSV every 5 seconds. The kernel ring buffer is polled every 30 seconds for throttle events, MCEs, and hardware errors. The final report opens with a strict PASS/FAIL verdict table.

**Requires:** `sudo` — run from a desktop terminal for GPU stress; use `--skip-gpu` for headless.

```bash
# Modes: quick (15 min) | short (1 hr) | standard (4 hr) | extended (8 hr) | overnight (24 hr)
sudo python3 stress_soak.py --mode standard --client "Client Name"
```

---

## 11. Test Bench Best Practices ⚠️

* **BIOS Updates:** Z790 platforms and 13th/14th Gen Intel CPUs frequently receive BIOS updates affecting power limits (e.g., "Intel Baseline Profile"). Always flash the latest BIOS before establishing benchmark baselines.
* **Kernel Versions:** Manjaro offers multiple kernels. Always test hardware on the latest stable kernel (e.g., `Linux 6.8+`) using Manjaro Settings Manager to ensure maximum compatibility with the newest Thread Directors and chipset drivers.
* **Thermal Paste/Mounts:** If `turbostat` shows immediate thermal throttling (hitting 100°C) before PL2 duration expires, physically check the cooler mounting pressure and thermal paste application before assuming a software or hardware failure.

---

*Last Updated: 06-11-2026*
