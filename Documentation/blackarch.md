# BlackArch Linux Setup Reference

## 🎯 Purpose
Quick-reference commands for bootstrapping and maintaining a BlackArch or Arch-based penetration testing environment - covering network adapter activation, pacman keyring management, mirror optimization, and full system upgrades.

## ⚙️ Function
Covers: bringing up network adapters and DHCP, enabling NetworkManager, clearing/regenerating GNUPG keyring, adding BlackArch mirrors, removing conflicting packages, and running full system updates with various pacman flags.

## 🏆 Goal
Serve as a copy-paste command reference for the initial BlackArch setup steps and routine maintenance tasks that are easily forgotten between uses.

## 📋 When to Use
- Initial setup after installing BlackArch or adding it as a repo overlay on Arch/Manjaro
- Recovering from broken pacman keyring errors
- Resolving package conflicts before a major system update
- Activating a new wireless or USB network adapter in a live environment

---

## Identify and "Bring Up" any needed network adapters
### ip link show
### ip link set "dev" up

## Allow new network adapter(s) to get an IPv4 address via DHCP
### sudo dhclient "dev"
### sudo dhclient -v "dev"

***

## Create a scheduled task to start the local NetworkManager at system start-up
### sudo systemctl enable --now NetworkManager

*(To open the NetworkManager text UI for configuring connections interactively, run `sudo nmtui` as a separate command.)*

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

---

## Related Files
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [LinuxCheatSheet.md](LinuxCheatSheet.md) - Full Arch/pacman and Debian/apt command reference including the pacman commands used here
- [../Scripts/pnwc_install_tools.sh](../Scripts/pnwc_install_tools.sh) - Automated cybersecurity tool installer for Arch/Manjaro (pacman/BlackArch repo)
