# 🖥️ Hardware Testing & Benchmarking

<div align="center">

**Diagnostic, benchmarking, and reliability stress testing guides and scripts for PC test benches**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![Hardware Testing](https://img.shields.io/badge/Hardware-Diagnostics%20%26%20Stress%20Testing-blue?style=for-the-badge)]()
[![Manjaro](https://img.shields.io/badge/OS-Manjaro%20Linux-35BF5D?style=for-the-badge\&logo=manjaro)]()
[![Intel](https://img.shields.io/badge/CPU%20Platform-Intel%20i9%20%2F%20Z790-0071C5?style=for-the-badge\&logo=intel)]()
[![AMD](https://img.shields.io/badge/CPU%20Platform-AMD%20%E2%80%94%20Planned-ED1C24?style=for-the-badge\&logo=amd)]()
[![Debian](https://img.shields.io/badge/OS-Debian%20%E2%80%94%20Planned-A81D33?style=for-the-badge\&logo=debian)]()

</div>

---

## Overview

This section contains platform-specific cheat sheets and Python automation scripts for hardware diagnostics, benchmarking, and reliability testing on dedicated PC test benches. This can be a critically needed process for verifying functionality and performance of used or repurposed hardware; for General Operations, Password Hashing, Local AI, etc.

Each platform combination, such as Manjaro + Intel or Debian + AMD, gets its own reference document for package management, driver setup, kernel notes, and hardware-specific tooling.

The Python scripts in [`py/`](./py/) are Linux-focused and are designed to be portable where possible. The orchestration logic is shared across systems, but the install commands, driver packages, GPU tooling, and kernel behavior are platform-specific. The cheat sheets document those platform-specific differences.

---

## Contents

### ✅ Available Now

| Platform                                                         | Cheat Sheet                                                | Scripts      |
| :--------------------------------------------------------------- | :--------------------------------------------------------- | :----------- |
| **Manjaro Linux - Intel CPU Platform (Z790 / 13th–14th Gen i9)** | [Manjaro_Intel_TestBench.md](./Manjaro_Intel_TestBench.md) | [py/](./py/) |

### 🔜 Planned

| Platform                                                  | Status  |
| :-------------------------------------------------------- | :------ |
| **Manjaro Linux - AMD CPU Platform (X670 / Ryzen 7000)**  | Planned |
| **Debian - Intel CPU Platform (Z790 / 13th–14th Gen i9)** | Planned |
| **Debian - AMD CPU Platform (X670 / Ryzen 7000)**         | Planned |

---

## Manjaro Linux - Intel ✅

**Reference:** [`Manjaro_Intel_TestBench.md`](./Manjaro_Intel_TestBench.md)

Covers Z790 motherboards with 13th/14th Gen Core i9 processors running Manjaro Linux. The guide is written for an Intel CPU test bench, but the GPU testing workflow also supports AMD Radeon and NVIDIA GPUs when the correct GPU tools are installed.

Includes:

* `pacman`, `pamac`, and AUR package management for diagnostic tools.
* Hardware diagnostics and system info with `inxi`, `dmidecode`, `lscpu`, `lspci`, `lsusb`, `lshw`, and `hwinfo`.
* Thermal monitoring with `lm_sensors` / `sensors`.
* Intel-focused monitoring notes for tools such as `intel-gpu-tools`, `turbostat`, and `s-tui` where applicable.
* CPU and system stress testing with `stress-ng`, `sysbench`, and optional Prime95 / `mprime`.
* Memory and storage diagnostics with `memtester`, `nvme-cli`, `smartmontools`, `fio`, and optional `kdiskmark`.
* Fresh install provisioning one-liners for the test-bench tool stack.
* Optional Phoronix Test Suite workflows for standardized benchmark runs.
* Modern GPU testing paths using `memtest_vulkan`, `vkmark`, `glmark2`, vendor telemetry, and kernel PCIe/GPU fault scanning.
* Python automation scripts that generate client-facing Markdown reports.

---

## Python Scripts - [`py/`](./py/)

Modular Python scripts that orchestrate CLI tools, stream output live, and compile results into clean Markdown reports.

| Script                     | What it does                                                                                       | Sudo |
| :------------------------- | :------------------------------------------------------------------------------------------------- | :--: |
| `full_hw_suite.py`         | Full sequential diagnostic - system info, CPU, RAM, storage, GPU                                   |   ✅  |
| `standalone_gpu_tester.py` | Universal GPU first-pass benchmark - Vulkan/OpenGL validation, VRAM testing, kernel fault scanning |   ❌  |
| `amd_gpu_tester.py`        | Dedicated AMD Radeon GPU diagnostic with amdgpu telemetry and rigorous load testing                |   ❌  |
| `nvidia_gpu_tester.py`     | Dedicated NVIDIA GPU diagnostic with `nvidia-smi` telemetry and rigorous load testing              |   ❌  |
| `standalone_ram_tester.py` | RAM bandwidth and multi-pass stability testing                                                     |   ✅  |
| `stress_soak.py`           | Reliability burn-in - simultaneous CPU/RAM/storage/GPU load with continuous thermal logging        |   ✅  |

See [`py/README.md`](./py/README.md) for full installation instructions, usage, and per-script documentation.

> If the vendor-specific GPU scripts are renamed in the repo, keep the table and examples aligned with the actual filenames in `py/`.

---

## Quick Start

### 1. Install base diagnostics and system tools

Run this on every Manjaro / Arch-based test bench:

```bash
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
```

### 2. Detect motherboard sensors

Run once after installing the base tools:

```bash
sudo sensors-detect --auto
sensors
```

Without sensor detection, thermal reporting may be incomplete or empty.

---

## GPU Tooling

Install the GPU block that matches the hardware being tested.

### AMD Radeon test environments

```bash
sudo pacman -S --needed \
  mesa vulkan-radeon \
  amdsmi amdgpu_top radeontop
```

Useful AMD validation commands:

```bash
inxi -G -c0
lspci -nnk | grep -A4 -E "VGA|3D|Display"
vulkaninfo --summary
glxinfo -B
amd-smi list
amd-smi static --gpu 0
amd-smi metric --gpu 0
amdgpu_top --dump
```

### NVIDIA test environments

```bash
sudo pacman -S --needed \
  nvidia-utils cuda opencl-nvidia
```

Useful NVIDIA validation commands:

```bash
nvidia-smi
nvidia-smi -q
nvcc --version
vulkaninfo --summary
glxinfo -B
```

---

## Optional GUI / Deep Benchmark Tools

These are useful for manual benchmarking, client demonstrations, or deeper comparative testing. Availability can vary by Manjaro repository/AUR status, so verify with `pamac search` if any package fails.

```bash
pamac build mprime-bin kdiskmark unigine-superposition phoronix-test-suite
```

If `phoronix-test-suite` is available from your configured Manjaro repositories, it may also be installed with:

```bash
pamac install phoronix-test-suite
```

---

## Source-Built GPU Diagnostic Tools

### `memtest_vulkan` - cross-vendor Vulkan VRAM stability test

`memtest_vulkan` is used by the GPU scripts for VRAM stability testing. It is useful for AMD, NVIDIA, and Intel GPUs as long as the system exposes a working Vulkan device.

```bash
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

Verify:

```bash
command -v memtest_vulkan
memtest_vulkan
```

Stop the test with `Ctrl+C` after confirming it starts and detects the correct GPU.

### `gpu-burn` - NVIDIA CUDA stress test

`gpu-burn` is NVIDIA/CUDA-specific. It is only needed for NVIDIA diagnostic runs that use the `--gpu-burn` option.

```bash
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

Verify:

```bash
gpu-burn -l
gpu-burn 60
```

---

## Verify Required and Optional Tools

Run this after installing the base tools, GPU tools, optional benchmark tools, `memtest_vulkan`, and `gpu-burn`.

```bash
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

---

## Run the Scripts

### Universal GPU diagnostic - first pass

```bash
python3 py/standalone_gpu_tester.py --client "Client Name"
```

### Dedicated AMD GPU diagnostic

```bash
python3 py/amd_gpu_tester.py --client "Client Name"
```

### Dedicated NVIDIA GPU diagnostic

```bash
python3 py/nvidia_gpu_tester.py --client "Client Name"
```

Optional NVIDIA CUDA stress path:

```bash
python3 py/nvidia_gpu_tester.py --client "Client Name" --gpu-burn
```

### Full system diagnostic

```bash
sudo python3 py/full_hw_suite.py --client "Client Name"
```

### RAM-only diagnostic

```bash
sudo python3 py/standalone_ram_tester.py --client "Client Name" --memtester-size 4G --passes 3
```

### Reliability soak before returning hardware to a client

```bash
sudo python3 py/stress_soak.py --mode standard --client "Client Name"
```

Quick smoke-test soak:

```bash
sudo python3 py/stress_soak.py --mode quick --client "Client Name"
```

---

## Manjaro Linux - AMD CPU Platform 🔜

> **Status:** Planned

Will cover X670/X670E motherboards with Ryzen 7000 series processors. Key differences from the Intel guide will include:

* AMD CPU platform monitoring and validation.
* `amd_pstate` vs `intel_pstate` CPU frequency scaling.
* `k10temp` / optional `zenpower` temperature and voltage reporting.
* Optional Ryzen tuning tools such as `ryzenadj`, where appropriate.
* EXPO vs XMP memory profile validation.
* AMD chipset, IOMMU, and kernel parameter notes.
* AMD integrated/discrete graphics considerations where relevant.

---

## Debian - Intel CPU Platform 🔜

> **Status:** Planned

Will cover Z790/i9 hardware running Debian stable. Key differences from the Manjaro guide will include:

* `apt` package management.
* Backports or manual installation for newer kernels, Mesa, Vulkan, and hardware diagnostics.
* Mesa/OpenGL stack differences affecting `glmark2`, `vkmark`, and Vulkan behavior.
* `systemd` service configuration for persistent sensor monitoring.
* Kernel version availability and hardware support timelines.

---

## Debian - AMD CPU Platform 🔜

> **Status:** Planned

Will cover X670/Ryzen 7000 hardware on Debian stable. It will combine the AMD-specific platform notes and Debian packaging differences from the planned guides above.

---

## Contributing

If adding a new platform guide, follow the naming convention:

```text
Hardware Testing/
├── {Distro}_{CPUPlatform}_TestBench.md    # cheat sheet
└── py/                                    # shared Python scripts
```

Where `{Distro}` is `Manjaro`, `Debian`, etc. and `{CPUPlatform}` is `Intel`, `AMD`, or another hardware platform label.

Examples:

```text
Manjaro_Intel_TestBench.md
Manjaro_AMD_TestBench.md
Debian_Intel_TestBench.md
Debian_AMD_TestBench.md
```

---

*Pacific Northwest Computers · [pnwcomputers.com](https://pnwcomputers.com) · Vancouver, WA*
*Last updated: 06-11-2026*
