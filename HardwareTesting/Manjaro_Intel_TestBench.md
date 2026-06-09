# 🖥️ Manjaro Linux Dedicated Hardware Testing & Benchmarking PC (Intel CPU)

This document serves as a quick reference for hardware diagnostics, stress testing, and benchmarking on Manjaro (Arch-based) Linux. It is specifically tailored for modern Intel test benches (**Z790 motherboards and 13th/14th Gen Core i9 processors**) but applies broadly to any modern PC hardware testing environment.

---

## 1. Package Management (`pacman` and `pamac`)

[Manjaro](https://manjaro.org/) Arch is based on [Arch](https://archlinux.org/) Linux, meaning [`apt`](https://linuxize.com/post/how-to-use-apt-command/) is replaced by [`pacman`](https://wiki.archlinux.org/title/Pacman) (standard repositories) and [`pamac`](https://github.com/manjaro/pamac) (Manjaro's native package manager with [Arch User Repository / AUR support](https://aur.archlinux.org/)). Arch's killer feature is the AUR or the Arch User Repository. Instead of hunting down PPAs, users can use an [AUR helper](https://wiki.archlinux.org/title/AUR_helpers) (like Manjaro's pamac, or terminal tools like [yay](https://aur.archlinux.org/packages/yay) and [paru](https://github.com/Morganamilo/paru)) to automatically compile and install virtually any Linux software in existence directly from source scripts!

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

Installs core system utilities, sensors, terminal monitors, storage diagnostics, and stress utilities. All GPU vendor tools (`intel-gpu-tools`, `amdgpu_top`, `radeontop`, `nvidia-utils`, `nvidia-smi`) are included in the universal block — they are small, do not conflict with each other, and a test bench may serve mixed hardware configurations.

```bash
sudo pacman -S --needed \
  python stress-ng fio memtester sysbench \
  inxi dmidecode hwinfo lshw pciutils usbutils \
  smartmontools nvme-cli nvidia-smi hdparm \
  lm_sensors s-tui htop btop nvtop \
  intel-gpu-tools amdgpu_top radeontop nvidia-utils \
  base-devel git curl wget
```

### 6.2 AUR Tools (pamac)

Some specialized testing tools are only available in the Arch User Repository. We use `pamac build`, which comes standard on Manjaro.

*(Note: The standalone `linpack` AUR package frequently fails to build due to Intel gating the source downloads. It has been removed from this list. Use Phoronix Test Suite in Section 8 to run Linpack instead.)*

```bash
pamac build \
  mprime-bin \
  glmark2 \
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

*(Note: You may need to regenerate your GRUB/systemd-boot config depending on your bootloader to load the microcode.)*

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

For test benches equipped with dedicated graphics cards alongside or instead of the Intel iGPU, Manjaro provides native and AUR tools for monitoring and stressing both Team Green and Team Red.

### 9.1 Universal GPU Tools

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `nvtop` | **Universal Monitor** | An excellent `htop`-style visual monitor that supports NVIDIA, AMD, and Intel GPUs simultaneously. |
| `pamac build unigine-superposition` | **Superposition Benchmark** | A visually demanding 3D benchmark. Perfect for testing maximum GPU boost clocks, thermal limits, and VRAM stability. |
| `pamac build gputest` | **FurMark / Thermal Torture** | A "power virus" style OpenGL test designed to push the GPU to its absolute thermal and power draw limits. |

### 9.2 NVIDIA-Specific Tools

NVIDIA diagnostics on Linux rely heavily on the proprietary drivers (`nvidia` package). The core CLI utilities are included in the `nvidia-utils` package, which is installed as part of the Section 6.1 universal block.

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `nvidia-smi` | **GPU Snapshot** | Displays the current driver version, CUDA version, VRAM usage, temperature, and power consumption (Watts). |
| `watch -n 1 nvidia-smi` | **Live NVIDIA Monitor** | Refreshes the `nvidia-smi` readout every second for real-time monitoring under load. |
| `nvidia-smi dmon` | **Device Monitor** | Outputs a scrolling, compact table of stats (utilization, clocks, power) — ideal for logging metrics to a file during a benchmark. |
| `nvidia-settings` | **NVIDIA GUI Panel** | The graphical control panel for checking thermals, adjusting fan curves, and configuring display pipelines. |

### 9.3 AMD-Specific Tools

Modern AMD Radeon cards use the open-source `amdgpu` kernel driver, which integrates deeply with the Linux kernel and provides excellent transparency out of the box. `amdgpu_top` and `radeontop` are installed as part of the Section 6.1 universal block.

| Command | Purpose | Explanation |
| :--- | :--- | :--- |
| `amdgpu_top` | **Detailed AMD Monitor** | Shows deep metrics including CU (Compute Unit) usage, VRAM/GTT allocation, power consumption, and exact clock states. |
| `radeontop` | **Graphics Pipe Monitor** | A TUI that shows specific hardware block utilization (e.g., Vertex Grouper, Shader Export, Primitive Assembly). |
| `sudo cat /sys/kernel/debug/dri/0/amdgpu_pm_info` | **Raw Kernel Data** | Reads raw power limits, current clocks, and thermal parameters directly from the AMD kernel driver. |

---

## 10. Automated Hardware Testing & Reporting Scripts

Modular Python orchestration scripts for Manjaro Linux test benches. Rather than writing low-level hardware tests in pure Python, these scripts act as orchestrators — running robust CLI tools (`stress-ng`, `sysbench`, `inxi`, `fio`, `glmark2`, `memtester`), streaming their output live so the terminal never appears frozen, and compiling results into clean client-facing Markdown reports.

All scripts are located in the [`py/`](./py/) subdirectory. See [`py/README.md`](./py/README.md) for full installation and usage documentation.

> **Prerequisites:** Ensure all tools from Section 6 are installed before running any script. Section 6 is the authoritative install reference.

### 10.2 The Unified Hardware Test Suite (`full_hw_suite.py`)

Runs a full sequential diagnostic pass: system and motherboard info → CPU benchmark → RAM bandwidth and stability → storage SMART and IOPS → GPU benchmark. All long-running tools stream output live so the terminal never appears frozen. Compiles everything into a single timestamped Markdown report saved to the directory the script is run from.

**Requires:** `sudo` — memtester and dmidecode need root. Run from a **desktop terminal**, not SSH — glmark2 needs a display. Run from the **mount point of the drive you want to test** — fio writes a temporary file to the current directory.

```bash
sudo python3 full_hw_suite.py
```

**Output:** `Full_Hardware_Report_YYYYMMDD_HHMMSS.md`

---

### 10.3 Standalone GPU Tester (`standalone_gpu_tester.py`)

Tests the GPU in isolation. Collects hardware and driver info via `inxi`, captures a vendor-specific diagnostic snapshot (`nvidia-smi` for NVIDIA, `amdgpu_top` for AMD, `intel_gpu_top` for iGPU), then runs a full `glmark2` benchmark with per-scene FPS scores. Automatically detects X11 vs Wayland and selects the correct glmark2 binary — binary/display-server mismatch is the most common cause of silent glmark2 hangs.

**Requires:** Active desktop session (X11 or Wayland) — do not run over SSH. Does **not** require `sudo`.

> **Quick-pass mode:** Set `GLMARK2_SCENES` at the top of the script to a short list (e.g. `["build", "texture", "shading"]`) to finish in ~2 minutes instead of 15.

```bash
python3 standalone_gpu_tester.py
```

**Output:** `GPU_Report_YYYYMMDD_HHMMSS.md`

---

### 10.4 Standalone RAM Tester (`standalone_ram_tester.py`)

Tests RAM in isolation. Reads hardware topology from `dmidecode` (populated slots, speeds, part numbers), runs a `sysbench` memory bandwidth test, then runs `memtester` for bit-pattern stability validation. `memtester` output streams live — every test line prints as it completes so you can watch for `FAILED` lines in real time without waiting for the full run.

**Requires:** `sudo` — memtester must lock memory pages. For thorough XMP/EXPO validation, increase `MEMTESTER_SIZE` to half your installed RAM and `MEMTESTER_PASSES` to 3–5 before running.

```bash
sudo python3 standalone_ram_tester.py
```

**Output:** `RAM_Report_YYYYMMDD_HHMMSS.md`

---

### 10.5 Stress Soak Reliability Tester (`stress_soak.py`)

Purpose-built for reliability validation — fundamentally different from the diagnostic scripts above, which test each subsystem sequentially for seconds at a time. `stress_soak.py` hammers CPU, RAM, storage, and GPU **simultaneously** for hours, exposing failures that quick benchmarks miss entirely: thermal soak through a marginal cooler mount, XMP instability under sustained pressure, PSU marginal capacity under combined load, and VRM thermal limits that only appear when everything runs at once.

Runs in three phases:

1. **RAM validation** — `memtester` runs first with dedicated RAM before any competing vm workers, so bit errors surface in minutes rather than at the end of a 4-hour run
2. **Combined stress** — `stress-ng` (CPU + RAM workers), `fio` (storage), and `glmark2 --run-forever` (GPU, if display available) all simultaneously for the full soak duration
3. **Cooldown monitoring** — post-stress thermal monitoring; a slow recovery indicates a cooler mount problem even if the system never throttled under load

Sensor readings log to CSV every 5 seconds throughout all phases. The kernel ring buffer is polled every 30 seconds for throttle events and hardware errors. The final report opens with a **PASS / FAIL verdict table** — one row per check, one ❌ fails the machine.

**Requires:** `sudo` — run from a desktop terminal for GPU stress; use `--skip-gpu` for headless.

```bash
# Modes: quick (15 min) | short (1 hr) | standard (4 hr) | extended (8 hr) | overnight (24 hr)
sudo python3 stress_soak.py --mode standard --client "Client Name"
```

**Output:** `Soak_Report_YYYYMMDD_HHMMSS.md` + `soak_temps_YYYYMMDD_HHMMSS.csv`

---

## 11. Test Bench Best Practices ⚠️

* **BIOS Updates:** Z790 platforms and 13th/14th Gen Intel CPUs frequently receive BIOS updates affecting power limits (e.g., "Intel Baseline Profile"). Always flash the latest BIOS before establishing benchmark baselines.
* **Kernel Versions:** Manjaro offers multiple kernels. Always test hardware on the latest stable kernel (e.g., `Linux 6.8+`) using Manjaro Settings Manager to ensure maximum compatibility with the newest Thread Directors and chipset drivers.
* **Thermal Paste/Mounts:** If `turbostat` shows immediate thermal throttling (hitting 100°C) before PL2 duration expires, physically check the cooler mounting pressure and thermal paste application before assuming a software or hardware failure.

---

*Last Updated: 06-08-2026*
