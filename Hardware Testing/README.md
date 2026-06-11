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
- Dedicated modern GPU testing paths (memtest_vulkan, vkmark, glmark2, kernel PCIe fault scanning)
- Python automation scripts with client-facing Markdown report generation

---

## Python Scripts — [`py/`](./py/)

Modular Python scripts that orchestrate CLI tools, stream output live, and compile results into clean Markdown reports. 

| Script | What it does | Sudo |
| :--- | :--- | :---: |
| `full_hw_suite.py` | Full sequential diagnostic — system info, CPU, RAM, storage, GPU | ✅ |
| `standalone_gpu_tester.py` | Universal GPU first-pass benchmark (Vulkan/OpenGL, memtest, kernel faults) | ❌ |
| `pnwc_amd_gpu_diag.py` | Dedicated AMD GPU diagnostic with amdgpu telemetry & rigorous load testing | ❌ |
| `pnwc_nvidia_gpu_diag.py` | Dedicated NVIDIA GPU diagnostic with nvidia-smi telemetry & rigorous load testing | ❌ |
| `standalone_ram_tester.py` | RAM bandwidth and multi-pass stability testing | ✅ |
| `stress_soak.py` | Reliability burn-in — simultaneous load with continuous thermal logging | ✅ |

See [`py/README.md`](./py/README.md) for full installation instructions, usage, and per-script documentation.

**Quick start:**

```bash
# ── Base Diagnostics & System Tools (run this on every test bench) ─
sudo pacman -Syu --needed

sudo pacman -S --needed \
  base-devel git make gcc cmake ninja pkgconf rust cargo \
  python python-pip curl unzip jq \
  inxi dmidecode pciutils usbutils lshw hwinfo \
  lm_sensors smartmontools nvme-cli \
  sysbench memtester stress-ng fio \
  vulkan-tools mesa-utils \
  vkmark glmark2 \
  intel-gpu-tools nvtop

# Detect motherboard sensors (run once after install)
sudo sensors-detect --auto
sensors
```

> **GPU tools — install the block that matches your hardware:**

```bash
# For AMD Test Environments:
sudo pacman -S --needed \
  mesa vulkan-radeon \
  amdsmi amdgpu_top radeontop
```

```bash
# For NVIDIA Test Environments:
sudo pacman -S --needed \
  nvidia-utils cuda opencl-nvidia
```

```bash
# ── Optional GUI / Deep Benchmark Tools ────────────────────────────
pamac build mprime-bin kdiskmark unigine-superposition phoronix-test-suite
```

```bash
# ── Source-built GPU diagnostic tools ──────────────────────────────

# memtest_vulkan — cross-vendor Vulkan VRAM stability test
mkdir -p ~/src
cd ~/src

if [ ! -d memtest_vulkan ]; then
  git clone https://github.com/GpuZelenograd/memtest_vulkan.git
fi

cd memtest_vulkan
git pull
cargo build --release
sudo install -m 755 target/release/memtest_vulkan /usr/local/bin/memtest_vulkan
```

```bash
# gpu-burn — NVIDIA CUDA stress test
# This is only needed for NVIDIA diagnostic runs using --gpu-burn.

mkdir -p ~/src
cd ~/src

if command -v nvcc >/dev/null 2>&1; then
  if [ ! -d gpu-burn ]; then
    git clone https://github.com/wilicc/gpu-burn.git
  fi

  cd gpu-burn
  git pull
  make

  sudo install -m 755 gpu_burn /usr/local/bin/gpu-burn
  sudo ln -sf /usr/local/bin/gpu-burn /usr/local/bin/gpu_burn
else
  echo "nvcc was not found. Skipping gpu-burn build."
  echo "Install/repair CUDA first if this bench needs NVIDIA gpu-burn testing."
fi
```

```bash
# ── Verify Required and Optional Tools ─────────────────────────────
# Run this after installing the base tools, GPU tools, optional tools,
# memtest_vulkan, and gpu-burn.

echo "== Core script tools =="
for bin in \
  python git make gcc cmake ninja cargo rustc \
  inxi dmidecode lspci lsusb lshw hwinfo \
  sysbench memtester fio stress-ng \
  smartctl nvme sensors \
  glmark2 vkmark vulkaninfo glxinfo \
  intel_gpu_top nvtop; do
  printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo '❌ NOT FOUND')"
done

echo
echo "== AMD tools =="
for bin in amd-smi amdgpu_top radeontop; do
  printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo 'optional / not installed')"
done

echo
echo "== NVIDIA tools =="
for bin in nvidia-smi nvcc gpu-burn gpu_burn; do
  printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo 'optional / not installed')"
done

echo
echo "== GPU VRAM test =="
for bin in memtest_vulkan; do
  printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo '❌ NOT FOUND')"
done
```

```bash
# ── Run a Universal GPU Diagnostic (First Pass) ────────────────────
python3 py/standalone_gpu_tester.py --client "Client Name"

# ── Run a Full System Diagnostic ───────────────────────────────────
sudo python3 py/full_hw_suite.py --client "Client Name"

# ── Run a 4-hour Reliability Soak before returning to a client ─────
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
└── py/                             # shared Python scripts
```

Where `{Distro}` is `Manjaro`, `Debian`, etc. and `{Arch}` is `Intel` or `AMD`.

---

*Pacific Northwest Computers · [pnwcomputers.com](https://pnwcomputers.com) · Vancouver, WA*
*Last updated: 06-11-2026*
