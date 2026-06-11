#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo "  PNWC Manjaro / Arch Hardware Test Bench Tool Installer"
echo "============================================================"

if ! command -v pacman >/dev/null 2>&1; then
  echo "This installer is intended for Manjaro / Arch systems with pacman."
  exit 1
fi

echo
echo "[1/7] Updating package database and installing core tools..."
sudo pacman -Syu --needed

sudo pacman -S --needed \
  base-devel git make gcc cmake ninja pkgconf rust cargo curl unzip jq \
  python python-pip \
  stress-ng fio memtester sysbench \
  inxi dmidecode smartmontools nvme-cli pciutils usbutils \
  lm_sensors lshw hwinfo util-linux \
  vulkan-tools mesa-utils vkmark glmark2 \
  intel-gpu-tools nvtop

echo
echo "[2/7] Installing AMD Radeon diagnostic tools..."
sudo pacman -S --needed \
  mesa vulkan-radeon \
  amdsmi amdgpu_top radeontop || {
    echo "WARN: One or more AMD packages failed to install. Continue if this bench does not need AMD testing."
  }

echo
echo "[3/7] Installing NVIDIA diagnostic tools..."
sudo pacman -S --needed \
  nvidia-utils cuda opencl-nvidia || {
    echo "WARN: NVIDIA packages failed to install. Continue if this bench does not need NVIDIA testing."
  }

echo
echo "[4/7] Building and installing memtest_vulkan..."
mkdir -p "$HOME/src"
cd "$HOME/src"

if [ ! -d memtest_vulkan ]; then
  git clone https://github.com/GpuZelenograd/memtest_vulkan.git
fi

cd memtest_vulkan
git pull
cargo build --release
sudo install -m 755 target/release/memtest_vulkan /usr/local/bin/memtest_vulkan

echo
echo "[5/7] Building and installing gpu-burn..."
cd "$HOME/src"

if [ ! -d gpu-burn ]; then
  git clone https://github.com/wilicc/gpu-burn.git
fi

cd gpu-burn
git pull

if command -v nvcc >/dev/null 2>&1; then
  make
  sudo install -m 755 gpu_burn /usr/local/bin/gpu-burn
  sudo ln -sf /usr/local/bin/gpu-burn /usr/local/bin/gpu_burn
else
  echo "WARN: nvcc was not found, so gpu-burn was not built."
  echo "      Install/repair CUDA first, then rerun this script or build gpu-burn manually."
fi

echo
echo "[6/7] Sensor detection reminder..."
echo "Run this once interactively if sensors are missing or incomplete:"
echo "  sudo sensors-detect --auto"
echo "Then verify:"
echo "  sensors"

echo
echo "[7/7] Tool verification..."
echo
echo "== Core tools =="
for bin in \
  python git make gcc cmake ninja cargo rustc curl jq unzip \
  inxi dmidecode sysbench memtester fio stress-ng \
  smartctl nvme sensors lspci lsusb lshw hwinfo \
  glmark2 vkmark vulkaninfo glxinfo intel_gpu_top nvtop; do
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
echo "== GPU memory tools =="
for bin in memtest_vulkan; do
  printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo '❌ NOT FOUND')"
done

echo
echo "============================================================"
echo "  PNWC test bench tool installation complete."
echo "============================================================"
