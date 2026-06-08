### 10.2 The Unified Hardware Test Suite (`full_hw_suite.py`)

Runs a full sequential diagnostic pass: system and motherboard info → CPU benchmark → RAM bandwidth and stability → storage SMART and IOPS → GPU benchmark. All long-running tools stream output live so the terminal never appears frozen. Compiles everything into a single timestamped Markdown report saved to the directory the script is run from.

**Requires:** `sudo` (memtester and dmidecode need root). Run from a **desktop terminal**, not SSH — glmark2 needs a display. Run from the **mount point of the drive you want to test** — fio writes a temporary file to the current directory.

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

**Requires:** `sudo` (memtester must lock memory pages). For thorough XMP/EXPO validation, increase `MEMTESTER_SIZE` to half your installed RAM and `MEMTESTER_PASSES` to 3–5 before running.

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

**Requires:** `sudo`. Run from a desktop terminal for GPU stress; use `--skip-gpu` for headless.

```bash
# Modes: quick (15 min) | short (1 hr) | standard (4 hr) | extended (8 hr) | overnight (24 hr)
sudo python3 stress_soak.py --mode standard --client "Client Name"
```

**Output:** `Soak_Report_YYYYMMDD_HHMMSS.md` + `soak_temps_YYYYMMDD_HHMMSS.csv`
