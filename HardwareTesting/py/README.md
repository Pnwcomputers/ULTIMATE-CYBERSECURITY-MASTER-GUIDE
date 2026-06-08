# 🖥️ PNWC Hardware Testing Scripts (Manjaro Linux - Intel CPU)

Python orchestration scripts for diagnostics, benchmarking, and reliability stress testing on Manjaro Linux test benches. Designed for Z790/i9 platforms but works on any modern PC hardware.

These scripts wrap robust CLI tools (`stress-ng`, `fio`, `glmark2`, `memtester`, `sysbench`, etc.), stream their output live so you always see progress, and compile results into clean client-facing Markdown reports with a clear **PASS / FAIL verdict**.

> Part of the [PNWC ULTIMATE-CYBERSECURITY-MASTER-GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE) · Pacific Northwest Computers · Vancouver, WA

---

## Scripts in this directory

| Script | Purpose | Requires sudo |
| :--- | :--- | :---: |
| [`full_hw_suite.py`](#full_hw_suitepy) | Full diagnostic pass — system info, CPU, RAM, storage, GPU | ✅ |
| [`standalone_gpu_tester.py`](#standalone_gpu_testerpy) | GPU-only benchmark (glmark2 with display server auto-detection) | ❌ |
| [`standalone_ram_tester.py`](#standalone_ram_testerpy) | RAM-only — bandwidth (sysbench) + stability (memtester) | ✅ |
| [`stress_soak.py`](#stress_soakpy) | Reliability burn-in — simultaneous CPU+RAM+storage+GPU stress with continuous thermal logging | ✅ |

> **Quick rule of thumb:** Run the diagnostic scripts first to establish a baseline and catch obvious failures. Run `stress_soak.py` before returning hardware to a client to validate long-term reliability.

---

## Prerequisites

### Step 1 — Core tools (official Manjaro/Arch repos)

```bash
sudo pacman -Syu --needed \
  python stress-ng fio memtester sysbench \
  inxi dmidecode smartmontools nvme-cli \
  lm_sensors intel-gpu-tools
```

### Step 2 — Sensor detection (run once after install)

```bash
sudo sensors-detect --auto
```

Without this, `sensors` returns no data and post-load thermal snapshots will be empty.

### Step 3 — GPU tools (install what matches your hardware)

**Intel iGPU** (all Z790/i9 systems — already covered by `intel-gpu-tools` above)

**AMD Radeon:**
```bash
sudo pacman -S --needed amdgpu_top radeontop
```

**NVIDIA** — `nvidia-smi` ships with the driver. Verify it's present:
```bash
nvidia-smi --version
# If missing:
sudo pacman -S --needed nvidia-utils
```

### Step 4 — glmark2 (AUR — required for GPU benchmarks)

```bash
pamac build glmark2
```

This builds all four binaries (`glmark2`, `glmark2-es2`, `glmark2-wayland`, `glmark2-es2-wayland`). The scripts auto-detect your display server and pick the correct one. **Wayland/X11 binary mismatch is the #1 cause of silent glmark2 hangs** — let the scripts handle selection.

### Step 5 — Verify everything is on PATH

```bash
for bin in inxi dmidecode sysbench memtester fio stress-ng \
           smartctl nvme sensors glmark2 intel_gpu_top; do
  printf "%-20s %s\n" "$bin" "$(command -v $bin || echo '❌ NOT FOUND')"
done
```

Any `❌ NOT FOUND` line means that tool needs to be installed before running the relevant script.

---

## `full_hw_suite.py`

Runs a complete diagnostic pass sequentially: System info → CPU benchmark → RAM (bandwidth + stability) → Storage (SMART + fio IOPS) → GPU benchmark. Produces a single Markdown report.

**Run from the mount point of the drive you want to test** — `fio` writes a temp file to the current directory.

```bash
sudo python3 full_hw_suite.py
```

**Output:** `~/Full_Hardware_Report_YYYYMMDD_HHMMSS.md`

**Key v2.0 improvements over the original:**
- All long-running tests stream output live (no more frozen terminals)
- glmark2 auto-detects the correct X11/Wayland binary
- All storage devices (`nvme?n1`, `sd?`) auto-enumerated; SMART run on each
- Post-CPU-load thermal snapshot via `sensors` captured immediately after benchmark
- `stderr` now surfaced in the errors log instead of silently discarded
- Errors tagged by subsystem `[CPU]`, `[RAM]`, `[GPU]` in report footer

---

## `standalone_gpu_tester.py`

Tests the GPU only. No `sudo` required. Run from a desktop terminal session (X11 or Wayland — **not SSH**).

```bash
python3 standalone_gpu_tester.py
```

**Quick-pass mode** — set `GLMARK2_SCENES` at the top of the file for a ~2 minute run instead of 15:

```python
# In standalone_gpu_tester.py, edit this line:
GLMARK2_SCENES = ["build", "texture", "shading", "desktop", "buffer"]
```

**Output:** `~/GPU_Report_YYYYMMDD_HHMMSS.md`

---

## `standalone_ram_tester.py`

Tests RAM only. For thorough XMP/EXPO validation, increase `MEMTESTER_SIZE` to half your installed RAM and `MEMTESTER_PASSES` to 3–5 before running. Output streams live — every test line is printed as it completes so you can watch for `FAILED` lines in real time.

```bash
sudo python3 standalone_ram_tester.py
```

**Output:** `~/RAM_Report_YYYYMMDD_HHMMSS.md`

---

## `stress_soak.py`

Reliability burn-in tester. Fundamentally different from the diagnostic scripts — it exists to answer the question *"will this machine hold up under real sustained load?"* not just *"is this machine functional right now?"*

### Why the diagnostic scripts aren't enough for reliability testing

The diagnostic scripts run each subsystem **sequentially** and for **seconds at a time**. A machine can pass all of them and still fail 45 minutes into a real workload when:

- Thermals soak through a marginal cooler mount
- XMP instability surfaces under sustained memory pressure
- A PSU with marginal capacity can't sustain simultaneous CPU + GPU + storage load
- A VRM thermal limit kicks in that only appears under combined load

`stress_soak.py` addresses this by:

- Running CPU, RAM, storage, and GPU stressors **simultaneously** for hours
- Logging every thermal reading to CSV throughout the entire run
- Watching the kernel ring buffer continuously for throttle events and hardware errors
- Running memtester before the combined load so RAM errors surface early
- Producing a **PASS / FAIL verdict** with one row per check

### Installation

`stress-ng` is the key new dependency not required by the other scripts:

```bash
sudo pacman -S --needed stress-ng
```

All other dependencies are shared with the diagnostic scripts (see [Prerequisites](#prerequisites) above).

### Usage

```bash
# Quick smoke test (~15 min) — good for first run on new hardware
sudo python3 stress_soak.py --mode quick

# Standard burn-in before returning hardware to a client (~4 hrs)
sudo python3 stress_soak.py --mode standard --client "Acme Corp"

# Overnight burn-in for rebuilt, re-pasted, or overclocked systems
sudo python3 stress_soak.py --mode overnight --client "Acme Corp"

# Skip GPU stress (headless, or CPU/RAM focus only)
sudo python3 stress_soak.py --mode standard --skip-gpu
```

### Duration modes

| Mode | Total | memtester | Stress | Cooldown |
| :--- | :--- | :--- | :--- | :--- |
| `quick` | ~15 min | 2G × 1 pass | 9 min | 3 min |
| `short` | ~1 hr | 4G × 2 passes | 45 min | 5 min |
| `standard` | ~4 hr | 8G × 3 passes | 3 hr | 15 min |
| `extended` | ~8 hr | 16G × 5 passes | 7 hr | 30 min |
| `overnight` | ~24 hr | 16G × 10 passes | 23 hr | 60 min |

### What it tests and how

**Phase 1 — RAM validation (memtester)**
Runs first with dedicated RAM — no competing vm workers. Any `FAILED` line is flagged immediately and surfaced in the final report. If memtester finds errors, you know within the first few minutes rather than at the end of a 4-hour run.

**Phase 2 — Combined stress soak (stress-ng + fio + glmark2)**

- `stress-ng --cpu N --cpu-method all` — cycles every stressor method (integer, FP, AVX, matrix ops) across all threads
- `stress-ng --vm 2 --vm-bytes 60%` — two RAM workers running bit-flip patterns simultaneously with the CPU stressors
- `fio` — 4K random read/write on storage, running the full duration alongside CPU/RAM stress
- `glmark2 --run-forever` — if a display is available, continuous GPU render loop; FPS tracked for throttle detection

Running all three at once is what exposes PSU marginal capacity and VRM thermal limits that sequential testing misses entirely.

**Phase 3 — Cooldown monitoring**
Post-stress thermal monitoring. A slow cooldown with still-elevated temps after load ends is a strong indicator of a cooler mount problem — even if the system never technically throttled during the run.

**Continuous throughout all phases:**

- `SensorPoller` — polls `sensors` every 5 seconds, writes every reading to a timestamped CSV. After an overnight run you have a full 24-hour temperature timeline you can graph in a spreadsheet.
- `KernelWatcher` — polls `journalctl -k` every 30 seconds and classifies new kernel entries into throttle events (PROCHOT, package power limit, thermal) vs hardware errors (EDAC, MCE, GPU hang, NVMe errors). Both print live to the terminal with ⚠️/🔴 prefixes.

### Output

```
~/Soak_Report_YYYYMMDD_HHMMSS.md   — full report with PASS/FAIL verdict
~/soak_temps_YYYYMMDD_HHMMSS.csv   — complete thermal log, one row per 5-second sample
```

### Report verdict table

The report opens with a verdict table — one row per check. A single ❌ flags the machine as unreliable for client deployment.

| Result | Check | Detail |
| :--- | :--- | :--- |
| ✅ | RAM (memtester) | No FAILED lines detected |
| ✅ | CPU Temperature | Peak 74.2°C (limit 100°C) |
| ❌ | CPU Throttle Events | 12 events detected (threshold: 5) |
| ✅ | Hardware Errors | None detected |
| ✅ | stress-ng Stability | Completed full duration |
| ✅ | GPU Stability (glmark2) | FPS stable (max drop: 3.1%) |

### Interrupt handling

`Ctrl+C` at any point terminates all stress child processes cleanly, stops monitoring threads, and writes a partial report marked `⚠️ INCOMPLETE`. Thermal CSV data collected up to the interrupt point is preserved.

---

## Thresholds (configurable at top of `stress_soak.py`)

| Constant | Default | Meaning |
| :--- | :--- | :--- |
| `CPU_TEMP_WARN` | `90°C` | Warning flag in report (non-fatal) |
| `CPU_TEMP_FAIL` | `100°C` | Verdict FAIL — sustained throttle territory |
| `THROTTLE_FAIL` | `5` | Max kernel throttle events before FAIL |
| `HW_ERROR_FAIL` | `1` | Any kernel hardware error = FAIL |
| `GPU_FPS_DEGRADE_PCT` | `25%` | FPS drop from first→last 3 scenes = GPU throttle flag |
| `SENSOR_POLL_S` | `5` | Seconds between sensor readings |
| `VM_BYTES_PCT` | `60` | % of RAM stress-ng vm workers consume |

---

## Reference — Cheat Sheet

For manual commands, package manager reference, sensor detection, turbostat, Phoronix Test Suite, fio deep-dives, and BIOS/kernel best practices, see the [Manjaro_TestBench.md](../Manjaro_TestBench.md) cheat sheet in the parent directory.

---

*Pacific Northwest Computers · [pnwcomputers.com](https://pnwcomputers.com) · Vancouver, WA*
*Last updated: 06-08-2026*
