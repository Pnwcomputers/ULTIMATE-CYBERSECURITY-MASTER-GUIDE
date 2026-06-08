# 🖥️ Hardware Testing & Benchmarking

<div align="center">

**Diagnostic, benchmarking, and reliability stress testing guides and scripts for PC test benches**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![Hardware Testing](https://img.shields.io/badge/Hardware-Diagnostics%20%26%20Stress%20Testing-blue?style=for-the-badge)]()
[![Manjaro](https://img.shields.io/badge/OS-Manjaro%20Linux-35BF5D?style=for-the-badge&logo=manjaro)]()
[![Intel](https://img.shields.io/badge/CPU-Intel%20i9%20%2F%20Z790-0071C5?style=for-the-badge&logo=intel)]()
[![AMD](https://img.shields.io/badge/CPU-AMD%20%E2%80%94%20Coming%20Soon-ED1C24?style=for-the-badge&logo=amd)]()
[![Debian](https://img.shields.io/badge/OS-Debian%20%E2%80%94%20Coming%20Soon-A81D33?style=for-the-badge&logo=debian)]()

</div>

---

## Overview

This section contains platform-specific cheat sheets and Python automation scripts for hardware diagnostics, benchmarking, and reliability testing on dedicated PC test benches. Each platform combination (OS + CPU architecture) gets its own reference document and any platform-specific tooling.

The Python scripts in [`py/`](./py/) are designed to be OS-agnostic where possible — the same orchestration logic runs on any Linux system with the right CLI tools installed. The cheat sheets document the platform-specific package managers, driver stacks, and tooling that differ between distributions and architectures.

---

## Contents

### ✅ Available Now

| Platform | Cheat Sheet | Scripts |
| :--- | :--- | :--- |
| **Manjaro Linux — Intel (Z790 / 13th–14th Gen i9)** | [Manjaro_Intel_TestBench.md](./Manjaro_Intel_TestBench.md) | [py/](./py/) |

### 🔜 Planned

| Platform | Status |
| :--- | :--- |
| **Manjaro Linux — AMD (X670 / Ryzen 7000)** | Planned |
| **Debian — Intel (Z790 / 13th–14th Gen i9)** | Planned |
| **Debian — AMD (X670 / Ryzen 7000)** | Planned |

---

## Manjaro Linux — Intel ✅

**Reference:** [`Manjaro_Intel_TestBench.md`](./Manjaro_Intel_TestBench.md)

Covers Z790 motherboards with 13th/14th Gen Core i9 processors running Manjaro (Arch-based). Includes:

- `pacman` / `pamac` / AUR package management for diagnostic tools
- Hardware diagnostics and system info (`inxi`, `dmidecode`, `lscpu`, `lspci`)
- Thermal monitoring and Intel power management (`turbostat`, `s-tui`, `sensors`)
- CPU and system stress testing (`stress-ng`, `sysbench`, `mprime`)
- Memory and storage diagnostics (`memtester`, `nvme-cli`, `smartmontools`, `fio`, `kdiskmark`)
- Fresh install provisioning one-liners for the full tool stack
- Phoronix Test Suite for standardized benchmarks and Linpack
- NVIDIA and AMD dedicated GPU testing alongside the Intel iGPU
- Python automation scripts with client-facing Markdown report generation

---

## Python Scripts — [`py/`](./py/)

Four Python scripts that orchestrate CLI tools, stream output live, and compile results into Markdown reports. Designed for Manjaro/Intel but largely portable to any Linux system with the appropriate tools installed.

| Script | What it does | Sudo |
| :--- | :--- | :---: |
| `full_hw_suite.py` | Full sequential diagnostic — system info, CPU, RAM, storage, GPU | ✅ |
| `standalone_gpu_tester.py` | GPU benchmark with X11/Wayland auto-detection | ❌ |
| `standalone_ram_tester.py` | RAM bandwidth and multi-pass stability testing | ✅ |
| `stress_soak.py` | Reliability burn-in — simultaneous load with continuous thermal logging and PASS/FAIL verdict | ✅ |

See [`py/README.md`](./py/README.md) for full installation instructions, usage, and per-script documentation.

**Quick start:**

```bash
# ── Core tools (all platforms) ─────────────────────────────────────
sudo pacman -S --needed \
  python stress-ng fio memtester sysbench \
  inxi dmidecode hwinfo lshw pciutils usbutils \
  smartmontools nvme-cli hdparm \
  lm_sensors s-tui htop btop nvtop \
  base-devel git curl wget

# Detect motherboard sensors (run once after install)
sudo sensors-detect --auto

# ── Intel GPU / iGPU ───────────────────────────────────────────────
sudo pacman -S --needed intel-gpu-tools

# ── AMD GPU ────────────────────────────────────────────────────────
sudo pacman -S --needed amdgpu_top radeontop

# ── NVIDIA GPU ─────────────────────────────────────────────────────
# nvidia-smi ships with the driver; install nvidia-utils if missing
sudo pacman -S --needed nvidia-utils

# ── AUR: glmark2 (GPU benchmark) + additional tools ────────────────
pamac build glmark2 kdiskmark phoronix-test-suite

# ── Run a full diagnostic ──────────────────────────────────────────
sudo python3 py/full_hw_suite.py

# ── Run a 4-hour reliability soak before returning to a client ─────
sudo python3 py/stress_soak.py --mode standard --client "Client Name"
```

---

## Manjaro Linux — AMD 🔜

> **Status:** Planned

Will cover X670/X670E motherboards with Ryzen 7000 series processors. Key differences from the Intel guide:

- `amdgpu` driver stack vs Intel integrated graphics tooling
- `amd_pstate` vs `intel_pstate` CPU frequency scaling
- `ryzenadj` for CPU power limit configuration (equivalent to Intel's `turbostat`)
- EXPO vs XMP memory profile validation
- AMD-specific kernel parameters and chipset driver notes

---

## Debian — Intel 🔜

> **Status:** Planned

Will cover the same Z790/i9 hardware running Debian stable. Key differences from the Manjaro guide:

- `apt` package management; some tools require backports or manual install
- Mesa/OpenGL stack differences affecting glmark2 behavior
- `systemd` service configuration for persistent sensor monitoring
- Differences in kernel version availability and hardware support timelines

---

## Debian — AMD 🔜

> **Status:** Planned

Will cover X670/Ryzen 7000 hardware on Debian stable. Will combine the AMD-specific tooling notes and the Debian packaging differences from the two planned guides above.

---

## Contributing

If you're adding a new platform guide, follow the naming convention:

```
HardwareTesting/
├── {Distro}_{Arch}_TestBench.md    # cheat sheet
└── py/                              # shared Python scripts
```

Where `{Distro}` is `Manjaro`, `Debian`, etc. and `{Arch}` is `Intel` or `AMD`.

---

*Pacific Northwest Computers · [pnwcomputers.com](https://pnwcomputers.com) · Vancouver, WA*
*Last updated: 06-08-2026*
