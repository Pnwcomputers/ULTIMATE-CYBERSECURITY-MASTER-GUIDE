# BlackArch / Arch Linux Post-Install Setup

## 🎯 Purpose
Command reference for bringing a fresh BlackArch or Arch install online and current — network adapter activation, GPG keyring setup for pacman, mirror optimization, cleanup of conflicting Java packages, and a full system update. This is the "first 15 minutes after install" checklist, not a general Arch admin guide.

## ⚙️ Function
A linear sequence: bring up network interfaces → get a DHCP lease → enable NetworkManager to persist across reboots → rebuild the pacman/BlackArch GPG keyring (required before any package operation on a fresh install, since keys expire and BlackArch's keyring isn't in the base Arch image) → optionally set fastest mirrors → remove conflicting old JDK/JRE packages → full system upgrade.

## 🏆 Goal
Get a freshly-installed BlackArch system to a state where `pacman -Syu` works cleanly and package installs won't fail on keyring or mirror issues — the most common first-boot blockers on a new install.

## 📋 When to Use
- Immediately after a fresh BlackArch or Arch Linux install, before installing any tools
- After a long-dormant install where pacman keys have expired (common failure mode: `pacman -Syu` fails with signature errors)
- Recovering a system where GPG keyring corruption is blocking all package operations

---

## Identify and "Bring Up" any needed network adapters
### ip link show
### ip link set "dev" up

## Allow new network adapter(s) to get an IPv4 address via DHCP
### sudo dhclient "dev"
### sudo dhclient -v "dev"

***

## Enable NetworkManager to persist across reboots
### sudo systemctl enable --now NetworkManager

*(Note: `nmtui` — NetworkManager's text UI for manually configuring connections — is a separate command you run interactively, not a systemd service. Run it on its own with `nmtui` if you need the interactive connection editor.)*

***

## Clear any currently stored GNUPG keys before doing ANY updates
### sudo rm -rf /etc/pacman.d/gnupg

## Download/Generate current GNUPG keys
### sudo pacman-key --init
### sudo pacman-key --populate archlinux blackarch
### sudo pacman -Sy archlinux-keyring blackarch-keyring

## *Optional: Set fastest/local mirrors
### sudo pacman -S reflector
### sudo reflector --country US --age 12 --protocol https --sort rate --save /etc/pacman.d/mirrorlist

***

## Remove any old Packages
### sudo pacman -Rdd jre-openjdk jdk-openjdk-headless jdk-openjdk jre11-openjdk jdk11-openjdk jdk17-openjdk jre17-openjdk jre17-openjdk-headless erlang-nox jre11-openjdk-headless python-gast03 python-uvicorn

***

## Do a full system update/upgrade
### sudo pacman -Syu

## *Can be used to automatically accept upgrades/updates; but WILL ALSO select default options for App/Software selection/preference prompts.
### sudo pacman -Syu --noconfirm

## *Can be used to overwrite any older conflicting packages
### sudo pacman -Syu --overwrite '*' --noconfirm
