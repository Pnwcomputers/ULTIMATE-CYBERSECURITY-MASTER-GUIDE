## Identify and "Bring Up" any needed network adapters
### ip link show
### ip link set "dev" up

## Allow new network adapter(s) to get an IPv4 address via DHCP
### sudo dhclient "dev"
### sudo dhclient -v "dev"

***

## Create a scheduled task to start the local NetworkManager and newly activated network adapter at system start-up
### sudo systemctl enable --now NetworkManager rmtui

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

## *Can be used to automatically accept upgrades/updates; but WILL ALSO select default options for App/Software selection/prefrence prompts.
### sudo pacman -Syu --noconfirm

## *Can be used to overwrite any older conflicting packages
### sudo pacman -Syu --overwrite '*' --noconfirm
