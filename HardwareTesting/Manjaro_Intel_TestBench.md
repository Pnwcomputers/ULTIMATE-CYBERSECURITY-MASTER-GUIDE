# 🖥️ Manjaro Linux Dedicated Hardware Testing & Benchmarking PC (Intel CPU)

This document serves as a quick reference for hardware diagnostics, stress testing, and benchmarking on Manjaro (Arch-based) Linux. It is specifically tailored for modern Intel test benches (**Z790 motherboards and 13th/14th Gen Core i9 processors**) but applies broadly to any modern PC hardware testing environment.

---

## 1. Package Management (`pacman` and `pamac`)

[Manjaro](https://manjaro.org/) Arch is based on [Arch](https://archlinux.org/) Linux, meaning [`apt`](https://linuxize.com/post/how-to-use-apt-command/) is replaced by [`pacman`](https://wiki.archlinux.org/title/Pacman) (standard repositories) and [`pamac`](https://github.com/manjaro/pamac) (Manjaro's native package manager with [Arch User Repository / AUR support](https://aur.archlinux.org/)). Arch's killer feature is the AUR or the Arch User Repository. Instead of hunting down PPAs, users can use an [AUR helper](https://wiki.archlinux.org/title/AUR_helpers) (like Manjaro's pamac, or terminal tools like [yay](https://aur.archlinux.org/packages/yay) and [paru](https://github.com/Morganamilo/paru) to automatically compile and install virtually any Linux software in existence directly from source scripts!

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
# ── Universal tools (run this on every test bench) ─────────────────
sudo pacman -S --needed \
  python stress-ng fio memtester sysbench \
  inxi dmidecode hwinfo lshw pciutils usbutils \
  smartmontools nvme-cli hdparm \
  lm_sensors s-tui htop btop nvtop \
  intel-gpu-tools amdgpu_top radeontop \
  base-devel git curl wget nvidia-utils

# Detect motherboard sensors (run once after install)
sudo sensors-detect --auto
```

> **GPU tools — install the block that matches your hardware:**

```bash
# NVIDIA — nvidia-smi ships with the driver; nvidia-utils also included in the universal block above
# No additional steps required
```

```bash
# AMD — amdgpu_top and radeontop already included in the universal block above
# No additional steps required
```

---

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
To ensure your motherboard sensors are properly read by `lm_sensors` and `s-tui`:

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

### 10.3 Standalone GPU Tester (`standalone_gpu_tester.py`)
> **Note:** Requires an active display (X11/Wayland) to run `glmark2`. Do not run headless.

### 10.4 Standalone RAM Tester (`standalone_ram_tester.py`)
> **Note:** Requires `sudo` to run `memtester` for memory allocation locking.

---

## 11. Test Bench Best Practices ⚠️

* **BIOS Updates:** Z790 platforms and 13th/14th Gen Intel CPUs frequently receive BIOS updates affecting power limits (e.g., "Intel Baseline Profile"). Always flash the latest BIOS before establishing benchmark baselines.
* **Kernel Versions:** Manjaro offers multiple kernels. Always test hardware on the latest stable kernel (e.g., `Linux 6.8+`) using Manjaro Settings Manager to ensure maximum compatibility with the newest Thread Directors and chipset drivers.
* **Thermal Paste/Mounts:** If `turbostat` shows immediate thermal throttling (hitting 100°C) before PL2 duration expires, physically check the cooler mounting pressure and thermal paste application before assuming a software or hardware failure.

---

*Last Updated: 06-08-2026*
