# 🖥️ PNWC Hardware Testing Scripts (Manjaro Linux - Intel CPU)

## 🎯 Purpose
Python orchestration scripts for automated hardware diagnostics, benchmarking, and reliability stress testing on Manjaro Linux test benches (Z790/i9 platform, broadly compatible).

## ⚙️ Function
Documents the Python test suite: automated CPU/memory/storage/GPU test orchestration, result logging and comparison, thermal monitoring during tests, pass/fail thresholds, and HTML report generation for test results.

## 🏆 Goal
Automate the full hardware qualification test suite so results are reproducible, logged, and comparable across systems without manual command-by-command execution.

## 📋 When to Use
- Running a full automated hardware qualification suite on a new system
- Comparing test results across multiple systems for consistency
- Generating documented test reports for hardware procurement or RMA
- Scheduling periodic automated health checks on lab hardware

Python orchestration scripts for diagnostics, benchmarking, and reliability stress testing on Manjaro Linux test benches. Designed for Z790/i9 platforms but works on any modern PC hardware.

These scripts wrap robust CLI tools (`stress-ng`, `fio`, `glmark2`, `vkmark`, `memtester`, `sysbench`, etc.), stream their output live so you always see progress, and compile results into clean client-facing Markdown reports with a clear **PASS / FAIL verdict**.

> Part of the [PNWC ULTIMATE-CYBERSECURITY-MASTER-GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE) · Pacific Northwest Computers · Vancouver, WA

---

## Scripts in this directory

| Script | Purpose | Requires sudo |
| :--- | :--- | :---: |
| [`full_hw_suite.py`](#full_hw_suitepy-v21) | Full diagnostic pass - system info, CPU, RAM, storage, GPU | ✅ |
| [`standalone_gpu_tester.py`](#standalone_gpu_testerpy-v21) | Universal GPU benchmark (OpenGL/Vulkan validation, memtest, kernel fault scanning) | ❌ |
| [`amd_gpu_tester.py`](#vendor-gpu-testers-amd_gpu_testerpy--nvidia_gpu_testerpy) | AMD Radeon GPU diagnostic with amdgpu telemetry & Vulkan/OpenGL testing | ❌ |
| [`nvidia_gpu_tester.py`](#vendor-gpu-testers-amd_gpu_testerpy--nvidia_gpu_testerpy) | NVIDIA GPU diagnostic with nvidia-smi telemetry & Vulkan/OpenGL testing | ❌ |
| [`standalone_ram_tester.py`](#standalone_ram_testerpy-v21) | RAM-only - bandwidth (sysbench) + stability (memtester) | ✅ |
| [`stress_soak.py`](#stress_soakpy-v11) | Reliability burn-in - simultaneous CPU+RAM+storage+GPU stress with continuous thermal logging | ✅ |

> **GPU-only scripts run as your normal desktop user - not `sudo`.** Launching the GUI benchmarks (`glmark2`, `vkmark`) under `sudo` can block access to the display server. Their kernel-fault scan needs read access to the kernel journal, so run as a user in the `systemd-journal` group (or as root in a session where the display is reachable); otherwise that one check is reported as **REVIEW** rather than PASS. The full-suite, RAM, and soak scripts do need `sudo` and internally route the GPU workload back to the desktop user.

> **Quick rule of thumb:** Run the diagnostic scripts first to establish a baseline and catch obvious failures. Run `stress_soak.py` before returning hardware to a client to validate long-term reliability.

---

## Prerequisites

### Step 1 - Core tools (official Manjaro/Arch repos)

```bash
sudo pacman -Syu --needed \
  base-devel git python \
  stress-ng fio memtester sysbench \
  inxi dmidecode smartmontools nvme-cli pciutils usbutils \
  lm_sensors intel-gpu-tools \
  vulkan-tools mesa-utils vkmark glmark2 \
  nvidia-utils cuda mesa vulkan-radeon \
  amdsmi amdgpu_top radeontop
```

Notes:
- `nvidia-smi` is **not** a separate package - it ships with `nvidia-utils`. (Installing `nvidia-smi` directly will fail with "target not found".)
- `cuda` is large (~3 GB) and is only needed if you plan to run CUDA/`gpu-burn` compute stress. Drop it on AMD/Intel-only benches.
- Install the cross-vendor set above only on a universal bench. Otherwise install just the GPU tools that match your hardware (see Step 3).

### Or install everything at once

You can install the full AMD + NVIDIA + Intel tool set in one shot using the [`install_testbench_tools.sh`](/HardwareTesting/install_testbench_tools.sh) script.

### Step 2 - Sensor detection (run once after install)

```bash
sudo sensors-detect --auto
```

Without this, `sensors` returns no data and post-load thermal snapshots will be empty.

### Step 3 - GPU tools (install what matches your hardware)

**Intel iGPU** (all Z790/i9 systems - already covered by `intel-gpu-tools` above)

**AMD Radeon:**
```bash
sudo pacman -S --needed mesa vulkan-radeon amdsmi amdgpu_top radeontop
```

**NVIDIA:**
```bash
sudo pacman -S --needed nvidia-utils cuda
```
Verify the NVIDIA tools are present:
```bash
nvidia-smi --version
```

### Step 4 - Verify everything is on PATH

```bash
for bin in inxi dmidecode sysbench memtester fio stress-ng \
           smartctl nvme sensors glmark2 vkmark intel_gpu_top \
           vulkaninfo glxinfo; do
  printf "%-20s %s\n" "$bin" "$(command -v $bin || echo '❌ NOT FOUND')"
done
```

Any `❌ NOT FOUND` line means that tool needs to be installed before running the relevant script. *(Note: `glmark2` and `vkmark` are natively packaged in Manjaro/Arch.)*

---

## `full_hw_suite.py` (v2.1)

Runs a complete diagnostic pass sequentially: System info → CPU benchmark → RAM (bandwidth + stability) → Storage (SMART + fio IOPS) → GPU benchmark. Produces a single Markdown report with a report-level verdict.

**Run from the mount point of the drive you want to test.**

```bash
sudo python3 full_hw_suite.py --client "Client Name"
```

**Output:** `~/Full_Hardware_Report_YYYYMMDD_HHMMSS.md`

**Key v2.1 improvements:**
- Safer timeout and process-group handling to prevent zombie processes.
- Better storage testing using temporary `fio` files rather than repo-folder test files.
- Deep SMART analysis via `smartctl`.
- Renderer validation for both Vulkan and OpenGL environments.
- Proper desktop GPU command handling when running under `sudo` (avoids display server blocks).
- Kernel hardware error snapshots embedded directly in the report.
- Clear report-level **PASS / FAIL verdict**.

---

## `standalone_gpu_tester.py` (v2.1)

Tests the GPU in isolation. This is an excellent **general first-pass GPU script** for any vendor (Intel, AMD, NVIDIA). For a serious suspected AMD or NVIDIA card failure, run the vendor-specific AMD/NVIDIA script afterward - those collect richer per-second telemetry.

No `sudo` required. Run from a desktop terminal session (X11 or Wayland - **not SSH**).

**Features:**
- Keeps the PNWC ASCII banner branding.
- Checks GPU hardware with `inxi` and `lspci`.
- Validates Vulkan (`vulkaninfo --summary`) and OpenGL (`glxinfo -B`).
- Warns/fails if it detects software rendering (e.g., llvmpipe, lavapipe, softpipe, or software rasterizer).
- Optionally runs `memtest_vulkan` for VRAM stability if installed.
- Optionally runs `vkmark` for Vulkan load testing if installed.
- Keeps `glmark2` as the core OpenGL benchmark/load test.
- Watches kernel logs during the run for NVIDIA Xid/NVRM events, amdgpu resets/ring timeouts/VM faults, Intel i915 hangs, DRM errors, and PCIe AER errors.
- Uses process-group timeout cleanup so hung GPU tests are killed more reliably.

**Example runs:**

```bash
# Standard run:
python3 standalone_gpu_tester.py --client "Client Name"

# Quick smoke test:
python3 standalone_gpu_tester.py --quick --client "Client Name"

# Longer OpenGL timed soak:
python3 standalone_gpu_tester.py --glmark2-run-forever --glmark2-timeout 900 --client "Client Name"

# Skip optional tests if needed:
python3 standalone_gpu_tester.py --no-memtest --no-vkmark --client "Client Name"
```

**Output:** `~/GPU_Report_YYYYMMDD_HHMMSS.md`

---

## Vendor GPU testers: `amd_gpu_tester.py` & `nvidia_gpu_tester.py`

Dedicated, vendor-specific diagnostic paths for deep GPU telemetry.

- **AMD** - `amd_gpu_tester.py` (**v1.0.0**): reads the `amdgpu` kernel driver's sysfs/hwmon interface directly (edge/junction/memory temps, power, clocks, fan, VRAM, PCIe link), with optional `rocm-smi`/`amdgpu_top` for richer product/VBIOS context.
- **NVIDIA** - `nvidia_gpu_tester.py` (**v2.3.2**): dynamic `nvidia-smi` field probing for per-second telemetry, with the 590-era `clocks_event_reasons.*` throttle-field rename handled, hardened `gpu-burn` result parsing, a kernel-journal access probe, and hybrid/Optimus OpenGL routing.

Run from a desktop session as your normal user (see the sudo note near the top):

```bash
# AMD run:
python3 amd_gpu_tester.py --client "Client Name"

# NVIDIA run:
python3 nvidia_gpu_tester.py --client "Client Name"

# List detected AMD cards first (handy on multi-GPU benches):
python3 amd_gpu_tester.py --list-gpus
```

**Output (written to the current working directory):**
`AMD_GPU_Report_YYYYMMDD_HHMMSS.md` or `NVIDIA_GPU_Report_YYYYMMDD_HHMMSS.md`, plus the matching per-second telemetry CSV (`amd_load_*.csv` / `nvidia_load_*.csv`).

**Features:**
- Leverages `memtest_vulkan` for thorough VRAM stability testing (default 360 seconds).
- Standardized load testing using both `vkmark` (Vulkan) and `glmark2` (OpenGL/ES).
- Collects continuous vendor telemetry - `amdgpu` sysfs/hwmon (plus optional `rocm-smi`/`amdgpu_top`) on AMD, or dynamic `nvidia-smi` field probing on NVIDIA - once per second during all tests.
- Scans kernel logs specifically for GPU/PCIe faults (Xid/NVRM, amdgpu resets/ring timeouts/VM faults, PCIe AER).
- Tri-state verdicts (**PASS / FAIL / REVIEW**) so an unmeasured check is never silently reported as a pass.
- Optional aggressive stress modes (`--glmark2-run-forever --glmark2-timeout 900`), optional CUDA/compute stress (`--gpu-burn` on NVIDIA, `--compute-stress` on AMD), and optional legacy torture mode (`--furmark`).

---

## `standalone_ram_tester.py` (v2.1)

Tests RAM only. Reads hardware topology from `dmidecode`, runs `sysbench` memory bandwidth, then `memtester` for bit-pattern stability. Output streams live so you can watch for `FAILED` lines in real time.

```bash
sudo python3 standalone_ram_tester.py --client "Client Name" --memtester-size 4G --passes 3
```

**Output:** `~/RAM_Report_YYYYMMDD_HHMMSS.md` and full memtester log.

**Key v2.1 improvements:**
- Keeps the PNWC banner and adds robust CLI options (`--client`, `--memtester-size`, `--passes`, `--auto-size`).
- Dynamically checks available memory before launching `memtester` to prevent hard system locks.
- Saves a complete raw `memtester` log alongside the Markdown report.
- Watches kernel logs specifically for MCE, EDAC, OOM, and memory faults during the run.
- Produces a real **PASS / FAIL verdict table**.

---

## `stress_soak.py` (v1.1)

Reliability burn-in tester. Fundamentally different from the diagnostic scripts - it exists to answer the question *"will this machine hold up under real sustained load?"* not just *"is this machine functional right now?"*

### Why the diagnostic scripts aren't enough for reliability testing

The diagnostic scripts run each subsystem **sequentially** and for **seconds at a time**. A machine can pass all of them and still fail 45 minutes into a real workload when:

- Thermals soak through a marginal cooler mount.
- XMP/EXPO instability surfaces under sustained memory pressure.
- A PSU with marginal capacity can't sustain simultaneous CPU + GPU + storage load.
- A VRM thermal limit kicks in that only appears under combined load.

`stress_soak.py` addresses this by:

- Running CPU, RAM, storage, and GPU stressors **simultaneously** for hours.
- Logging every thermal reading to CSV throughout the entire run.
- Watching the kernel ring buffer continuously for throttle events and hardware errors.
- Running `memtester` before the combined load so RAM errors surface early.
- Producing a **PASS / FAIL verdict** with one row per check.

### Usage

```bash
# Quick smoke test (~15 min) - good for first run on new hardware
sudo python3 stress_soak.py --mode quick --client "Client Name"

# Standard burn-in before returning hardware to a client (~4 hrs)
sudo python3 stress_soak.py --mode standard --client "Client Name"

# Overnight burn-in for rebuilt, re-pasted, or overclocked systems
sudo python3 stress_soak.py --mode overnight --client "Client Name"

# Skip GPU stress (headless, or CPU/RAM focus only)
sudo python3 stress_soak.py --mode standard --client "Client Name" --skip-gpu
```

### Duration modes

| Mode | Total | memtester | Stress | Cooldown |
| :--- | :--- | :--- | :--- | :--- |
| `quick` | ~15 min | 2G × 1 pass | 9 min | 3 min |
| `short` | ~1 hr | 4G × 2 passes | 45 min | 5 min |
| `standard` | ~4 hr | 8G × 3 passes | 3 hr | 15 min |
| `extended` | ~8 hr | 16G × 5 passes | 7 hr | 30 min |
| `overnight` | ~24 hr | 16G × 10 passes | 23 hr | 60 min |

### What it tests and how (v1.1 improvements)

**Phase 1 - RAM validation (memtester)**
Runs first with dedicated RAM. Any `FAILED` line is flagged immediately. If `memtester` finds errors, you know within the first few minutes rather than at the end of a 4-hour run.

**Phase 2 - Combined stress soak (stress-ng + fio + glmark2)**
- `stress-ng --cpu N --cpu-method all` - cycles every stressor method across all threads.
- `stress-ng --vm 2 --vm-bytes 60%` - two RAM workers running bit-flip patterns simultaneously.
- `fio` - 4K random read/write on storage, running alongside CPU/RAM stress.
- `glmark2 --run-forever` - continuous GPU render loop. **(v1.1: GPU execution is properly routed under the original desktop user to bypass root display-server blocks.)**
- **v1.1:** Adds strict return-code checks for `fio` and `stress-ng`.

**Phase 3 - Cooldown monitoring**
Post-stress thermal monitoring. A slow cooldown with still-elevated temps indicates a cooler mount problem.

**Continuous throughout all phases:**
- `SensorPoller` - polls `sensors` (now with better CPU package sensor detection in v1.1) every 5 seconds, writing every reading to a timestamped CSV.
- `KernelWatcher` - polls `journalctl -k` every 30 seconds for tighter kernel fault patterns (throttle events, MCE, GPU hangs).
- **v1.1:** Improved GPU FPS degradation logic to catch thermal throttling.

### Output

```
~/Soak_Report_YYYYMMDD_HHMMSS.md   - full report with PASS/FAIL verdict
~/soak_temps_YYYYMMDD_HHMMSS.csv   - complete thermal log, one row per 5-second sample
```

### Report verdict table

The report opens with a verdict table - one row per check. A single ❌ flags the machine as unreliable for client deployment.

| Result | Check | Detail |
| :--- | :--- | :--- |
| ✅ | RAM (memtester) | No FAILED lines detected |
| ✅ | CPU Temperature | Peak 74.2°C (limit 100°C) |
| ❌ | CPU Throttle Events | 12 events detected (threshold: 5) |
| ✅ | Hardware Errors | None detected |
| ✅ | stress-ng Stability | Completed full duration |
| ✅ | GPU Stability (glmark2) | FPS stable (max drop: 3.1%) |

### Interrupt handling

`Ctrl+C` at any point terminates all stress child processes cleanly (v1.1 adds better process cleanup), stops monitoring threads, and writes a partial report marked `⚠️ INCOMPLETE`. Thermal CSV data collected up to the interrupt point is preserved.

---

## Thresholds (configurable at top of `stress_soak.py`)

| Constant | Default | Meaning |
| :--- | :--- | :--- |
| `CPU_TEMP_WARN` | `90°C` | Warning flag in report (non-fatal) |
| `CPU_TEMP_FAIL` | `100°C` | Verdict FAIL - sustained throttle territory |
| `THROTTLE_FAIL` | `5` | Max kernel throttle events before FAIL |
| `HW_ERROR_FAIL` | `1` | Any kernel hardware error = FAIL |
| `GPU_FPS_DEGRADE_PCT` | `25%` | FPS drop from first→last 3 scenes = GPU throttle flag |
| `SENSOR_POLL_S` | `5` | Seconds between sensor readings |
| `VM_BYTES_PCT` | `60` | % of RAM stress-ng vm workers consume |

---

## Reference - Cheat Sheet

For manual commands, package manager reference, sensor detection, turbostat, Phoronix Test Suite, fio deep-dives, and BIOS/kernel best practices, see the [Manjaro_TestBench.md](../Manjaro_Intel_TestBench.md) cheat sheet in the parent directory.

---

*Pacific Northwest Computers · [pnwcomputers.com](https://pnwcomputers.com) · Vancouver, WA*
*Last updated: 06-11-2026*

## Related Files
- [../README.md](../README.md) - HardwareTesting section index
- [../Manjaro_Intel_TestBench.md](../Manjaro_Intel_TestBench.md) - Manual test procedures these scripts automate
