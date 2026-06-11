#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo "  PNWC Manjaro / Arch Hardware Test Bench Tool Installer"
echo "============================================================"

if ! command -v pacman >/dev/null 2>&1; then
  echo "This installer is intended for Manjaro / Arch systems with pacman."
  exit 1
fi

# Arch / Manjaro CUDA commonly installs nvcc under /opt/cuda/bin.
# Add it early so gpu-burn can build even when the user's shell PATH
# has not been updated yet.
if [ -d /opt/cuda/bin ]; then
  export PATH="/opt/cuda/bin:$PATH"
fi

if [ -d /opt/cuda/lib64 ]; then
  export LD_LIBRARY_PATH="/opt/cuda/lib64:${LD_LIBRARY_PATH:-}"
fi

PNWC_SRC_DIR="${PNWC_SRC_DIR:-$HOME/src}"

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
if ! sudo pacman -S --needed \
  mesa vulkan-radeon \
  amdsmi amdgpu_top radeontop; then
  echo "WARN: One or more AMD packages failed to install."
  echo "      Continue if this bench does not need AMD Radeon testing."
fi

echo
echo "[3/7] Installing NVIDIA diagnostic tools..."
if ! sudo pacman -S --needed \
  nvidia-utils cuda opencl-nvidia; then
  echo "WARN: One or more NVIDIA/CUDA packages failed to install."
  echo "      Continue if this bench does not need NVIDIA testing."
fi

# Re-add CUDA path after package install in case CUDA was installed above.
if [ -d /opt/cuda/bin ]; then
  export PATH="/opt/cuda/bin:$PATH"
fi

if [ -d /opt/cuda/lib64 ]; then
  export LD_LIBRARY_PATH="/opt/cuda/lib64:${LD_LIBRARY_PATH:-}"
fi

echo
echo "[4/7] Building and installing memtest_vulkan..."
mkdir -p "$PNWC_SRC_DIR"
cd "$PNWC_SRC_DIR"

if [ ! -d memtest_vulkan ]; then
  git clone https://github.com/GpuZelenograd/memtest_vulkan.git
fi

cd memtest_vulkan
git pull
cargo build --release
sudo install -m 755 target/release/memtest_vulkan /usr/local/bin/memtest_vulkan

echo
echo "[5/7] Building and installing gpu-burn..."

# gpu-burn is NVIDIA/CUDA-specific. It should be built when CUDA's nvcc
# is present. On Manjaro/Arch, nvcc may exist at /opt/cuda/bin/nvcc even
# when the shell has not added /opt/cuda/bin to PATH yet.
mkdir -p "$PNWC_SRC_DIR"

if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "WARN: nvidia-smi was not found."
  echo "      Skipping gpu-burn because this does not currently look like an NVIDIA-ready bench."
  echo "      If this is an NVIDIA test bench, confirm the NVIDIA driver is installed and loaded."
elif ! command -v nvcc >/dev/null 2>&1; then
  echo "WARN: nvcc was not found even after adding /opt/cuda/bin to PATH."
  echo "      gpu-burn was not built."
  echo "      Install/repair CUDA first, then rerun this script:"
  echo "      sudo pacman -S --needed cuda nvidia-utils opencl-nvidia"
  echo "      command -v nvcc || ls -l /opt/cuda/bin/nvcc"
else
  cd "$PNWC_SRC_DIR"

  if [ ! -d gpu-burn ]; then
    git clone https://github.com/wilicc/gpu-burn.git
  fi

  cd gpu-burn
  git pull

  make clean || true
  make

  if [ ! -f gpu_burn ]; then
    echo "ERROR: gpu-burn build completed but gpu_burn binary was not created."
    echo "       Check the make output above for CUDA/compiler errors."
  else
    sudo install -m 755 gpu_burn /usr/local/bin/gpu-burn
    sudo ln -sf /usr/local/bin/gpu-burn /usr/local/bin/gpu_burn

    echo "gpu-burn installed:"
    command -v gpu-burn || true
    command -v gpu_burn || true
  fi
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
for bin in nvidia-smi nvcc; do
  printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo 'optional / not installed')"
done

if command -v nvidia-smi >/dev/null 2>&1; then
  for bin in gpu-burn gpu_burn; do
    printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo '❌ NOT FOUND - needed for --gpu-burn')"
  done
else
  for bin in gpu-burn gpu_burn; do
    printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo 'optional / NVIDIA only')"
  done
fi

echo
echo "== GPU memory tools =="
for bin in memtest_vulkan; do
  printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo '❌ NOT FOUND')"
done

echo
echo "== Optional/manual tools =="
for bin in mprime kdiskmark phoronix-test-suite GpuTest s-tui turbostat; do
  printf "%-22s %s\n" "$bin" "$(command -v "$bin" || echo 'optional / not installed')"
done

echo
echo "============================================================"
echo "  PNWC test bench tool installation complete."
echo "============================================================"
