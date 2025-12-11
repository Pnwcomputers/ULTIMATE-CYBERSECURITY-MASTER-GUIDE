### ip link show
### ip link set "dev" up
### sudo dhclient "dev"
### sudo dhclient -v "dev"

### sudo systemctl enable --now NetworkManager rmtui

### sudo rm -rf /etc/pacman.d/gnupg

### sudo pacman-key --init
### sudo pacman-key --populate archlinux blackarch
### sudo pacman -Sy archlinux-keyring blackarch-keyring

### sudo pacman -S reflector
### sudo reflector --country US --age 12 --protocol https --sort rate --save /etc/pacman.d/mirrorlist

### sudo pacman -Rdd jre-openjdk jdk-openjdk-headless jdk-openjdk jre11-openjdk jdk11-openjdk jdk17-openjdk jre17-openjdk jre17-openjdk-headless erlang-nox jre11-openjdk-headless python-gast03 python-uvicorn

### sudo pacman -Syu
