# Cybersecurity Virtual Machines and Lab Environments

## Table of Contents

- [Specialized Virtual Machines](#specialized-virtual-machines)
  - [Privacy and Anonymity](#privacy-and-anonymity)
  - [OSINT (Open Source Intelligence)](#osint-open-source-intelligence)
  - [Penetration Testing](#penetration-testing)
  - [Digital Forensics](#digital-forensics)
  - [Reverse Engineering and Malware Analysis](#reverse-engineering-and-malware-analysis)
  - [Threat Hunting and Defense](#threat-hunting-and-defense)
- [Black Hat Bash Lab Environment](#black-hat-bash-lab-environment)
  - [Lab Architecture](#lab-architecture)
  - [Installation Scripts](#installation-scripts)
  - [Lab Management](#lab-management)
- [VM Setup and Configuration](#vm-setup-and-configuration)
  - [OSINT VM Setup](#osint-vm-setup)
  - [Pimp My Kali](#pimp-my-kali)

---

## Specialized Virtual Machines

### Privacy and Anonymity

#### 💿 Tails (The Amnesic Incognito Live System)
- **Purpose**: Privacy and Anonymity
- **Description**: A portable operating system that protects against surveillance and censorship. All connections go through Tor, and it leaves no trace on the computer.
- **Link**: https://tails.net/

#### 💿 Whonix
- **Purpose**: Privacy and Anonymity
- **Description**: An operating system focused on anonymity, privacy, and security. It's based on Tor, Debian GNU/Linux, and the principle of security by isolation.
- **Link**: https://www.whonix.org/wiki/Download

#### 💿 Qubes OS
- **Purpose**: Hypervisor-based Security
- **Description**: A security-oriented operating system that uses virtualization to provide security through isolation. Different tasks are compartmentalized in separate VMs.
- **Link**: https://www.qubes-os.org/

---

### OSINT (Open Source Intelligence)

#### 💿 Trace Labs OSINT VM
- **Purpose**: OSINT to Find Missing Persons
- **Description**: A VM specifically designed for OSINT investigations, with a focus on helping locate missing persons through ethical intelligence gathering.
- **Link**: https://www.tracelabs.org/initiatives/osint-vm

#### 💿 Buscador OSINT VM
- **Purpose**: OSINT Research and Investigation
- **Description**: A Linux Virtual Machine pre-configured for online investigations. Created by Michael Bazzell (IntelTechniques).
- **Link**: https://inteltechniques.com/blog/2019/01/25/buscador-2-0-osint-virtual-machine-released/

#### 💿 Tsurugi Linux
- **Purpose**: Digital Forensics and OSINT
- **Description**: A DFIR (Digital Forensics and Incident Response) Linux distribution designed for live forensics, incident response, and open-source intelligence.
- **Link**: https://tsurugi-linux.org/downloads.php

---

### Penetration Testing

#### 💿 Kali Linux
- **Purpose**: Penetration Testing
- **Description**: The industry-standard Linux distribution for penetration testing and ethical hacking. Contains hundreds of security tools.
- **Link**: https://www.kali.org/get-kali/#kali-virtual-machines

#### 💿 Kali Purple
- **Purpose**: SOC-in-a-box (Security Operations Center)
- **Description**: A defensive security distribution that provides a complete SOC environment with various defensive and offensive tools integrated.
- **Link**: https://www.kali.org/get-kali/#kali-installer-images

#### 💿 ParrotOS
- **Purpose**: Red and Blue Team Operations
- **Description**: A GNU/Linux distribution based on Debian and designed with Security, Development, and Privacy in mind. Suitable for both offensive and defensive security.
- **Link**: https://parrotsec.org/

#### 💿 BlackArch Linux
- **Purpose**: Penetration Testing
- **Description**: An Arch Linux-based distribution designed for penetration testers and security researchers with over 2,800 tools.
- **Link**: https://blackarch.org/index.html

#### 💿 BackBox
- **Purpose**: Penetration Testing
- **Description**: An Ubuntu-based distribution designed for penetration testing and security assessments, focused on simplicity and minimalism.
- **Link**: https://www.backbox.org/

#### 💿 Predator-OS
- **Purpose**: Penetration Testing
- **Description**: An Iranian penetration testing distribution with various security assessment tools pre-installed.
- **Link**: https://predator-os.ir/

#### 💿 Kookarai
- **Purpose**: Penetration Testing
- **Description**: A Docker-based penetration testing environment with web-based access for training and testing.
- **Link**: https://kookarai.idocker.hacking-lab.com/

#### 💿 Commando VM (Windows-based)
- **Purpose**: Windows-based Penetration Testing and Red Teaming
- **Description**: A Windows-based penetration testing distribution by Mandiant for security professionals working in Windows environments.
- **Link**: https://github.com/mandiant/commando-vm

---

### Digital Forensics

#### 💿 SIFT Workstation
- **Purpose**: Digital Forensics and Incident Response
- **Description**: SANS Investigative Forensics Toolkit - A powerful forensics workstation built on Ubuntu with numerous forensics tools pre-installed.
- **Link**: https://www.sans.org/tools/sift-workstation/

#### 💿 CSI Linux
- **Purpose**: Digital Forensics
- **Description**: A Linux distribution designed for Computer Security, Digital Forensics, and Open Source Intelligence gathering.
- **Link**: https://csilinux.com/

#### 💿 CAINE (Computer Aided INvestigative Environment)
- **Purpose**: Digital Forensics
- **Description**: An Italian Linux distribution created for digital forensics that offers a complete forensic environment with integrated tools.
- **Link**: https://www.caine-live.net/page5/page5.html

---

### Reverse Engineering and Malware Analysis

#### 💿 FLARE-VM
- **Purpose**: Reverse Engineering (Windows-based)
- **Description**: A Windows-based security distribution for reverse engineers and malware analysts by Mandiant (formerly FireEye).
- **Link**: https://github.com/mandiant/flare-vm

#### 💿 REMnux
- **Purpose**: Reverse Engineering and Malware Analysis
- **Description**: A Linux toolkit for reverse-engineering and analyzing malicious software. Maintained by Lenny Zeltser.
- **Link**: https://remnux.org/

---

### Threat Hunting and Defense

#### 💿 Security Onion
- **Purpose**: Threat Hunting, Network Security Monitoring, and Log Management
- **Description**: A free and open platform for threat hunting, network security monitoring, and log management. Includes Elasticsearch, Logstash, Kibana, Suricata, and many other tools.
- **Link**: https://github.com/Security-Onion-Solutions/securityonion/blob/2.4/main/DOWNLOAD_AND_VERIFY_ISO.md

#### 💿 RedHunt-OS Linux
- **Purpose**: Adversary Emulation and Threat Hunting
- **Description**: A virtual machine designed for adversary emulation and threat hunting with various tools for simulating attacks and hunting threats.
- **Link**: https://github.com/redhuntlabs/RedHunt-OS

#### 💿 Mandiant Threat Pursuit VM
- **Purpose**: Windows-based Threat Intelligence and Hunting
- **Description**: A Windows-based distribution designed for threat intelligence analysis and threat hunting operations by Mandiant.
- **Link**: https://github.com/mandiant/ThreatPursuit-VM

---

## Black Hat Bash Lab Environment

The Black Hat Bash Lab is a Docker-based penetration testing lab environment featuring multiple vulnerable machines for practicing security assessments.

### Lab Architecture

The lab consists of two networks:
- **Public Network** (172.16.10.0/24) - Internet-facing services
- **Corporate Network** (10.1.0.0/24) - Internal corporate network

#### Container Infrastructure

```yaml
services:
  p-jumpbox-01:
    container_name: p-jumpbox-01
    hostname: p-jumpbox-01.acme-infinity-servers.com
    build: 
      context: machines/p-jumpbox-01
      dockerfile: Dockerfile
    networks:
      public:
        ipv4_address: 172.16.10.13
      corporate:
        ipv4_address: 10.1.0.12
  
  c-backup-01:
    container_name: c-backup-01
    hostname: c-backup-01.acme-infinity-servers.com
    build: 
      context: machines/c-backup-01
      dockerfile: Dockerfile
    networks:
      corporate:
        ipv4_address: 10.1.0.13
    volumes:
      - shared_vol:/mnt/scripts
  
  c-redis-01:
    container_name: c-redis-01
    hostname: c-redis-01.acme-infinity-servers.com
    build: 
      context: machines/c-redis-01
      dockerfile: Dockerfile
    networks:
      corporate:
        ipv4_address: 10.1.0.14
  
  p-ftp-01:
    container_name: p-ftp-01
    hostname: p-ftp-01.acme-infinity-servers.com
    build: 
      context: machines/
      dockerfile: p-ftp-01/Dockerfile
    networks:
      public:
        ipv4_address: 172.16.10.11
  
  p-web-01:
    container_name: p-web-01
    hostname: p-web-01.acme-infinity-servers.com
    privileged: true
    build: 
      context: machines/p-web-01
      dockerfile: Dockerfile
    networks:
      public:
        ipv4_address: 172.16.10.10
    volumes:
      - shared_vol:/mnt/scripts/
  
  p-web-02:
    container_name: p-web-02
    privileged: true
    hostname: p-web-02.acme-infinity-servers.com
    build: 
      context: machines/p-web-02
      dockerfile: Dockerfile
    volumes:
      - p_web_02_vol:/var/www/html    
    networks:
      public:
        ipv4_address: 172.16.10.12
      corporate:
        ipv4_address: 10.1.0.11
    depends_on:
      - c-db-02
  
  c-db-02:
    container_name: c-db-02
    hostname: c-db-02.acme-infinity-servers.com
    build: 
      context: machines/c-db-02
      dockerfile: Dockerfile
    volumes:
      - c_db_02_vol:/var/lib/mysql
    networks:
      corporate:
        ipv4_address: 10.1.0.16
  
  c-db-01:
    container_name: c-db-01
    hostname: c-db-01.acme-infinity-servers.com
    build: 
      context: machines/c-db-01
      dockerfile: Dockerfile
    volumes:
      - c_db_01_vol:/var/lib/mysql
    networks:
      corporate:
        ipv4_address: 10.1.0.15
  
volumes:
  shared_vol:
  c_db_01_vol:
  c_db_02_vol:
  p_web_02_vol: 
networks:
  public:
    name: public
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: br_public
    ipam:
      config:
        - subnet: "172.16.10.0/24"
  corporate:
    internal: true
    name: corporate
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: br_corporate
    ipam:
      config:
        - subnet: "10.1.0.0/24"
```

#### Lab Machines

**Public Network Machines:**
- `p-jumpbox-01` (172.16.10.13) - Jump box with access to both networks
- `p-ftp-01` (172.16.10.11) - FTP server
- `p-web-01` (172.16.10.10) - Web server
- `p-web-02` (172.16.10.12) - WordPress server with corporate network access

**Corporate Network Machines:**
- `c-backup-01` (10.1.0.13) - Backup server
- `c-redis-01` (10.1.0.14) - Redis database server
- `c-db-01` (10.1.0.15) - Database server
- `c-db-02` (10.1.0.16) - Database server

---

### Installation Scripts

#### Lab Installation Script

```bash
#!/bin/bash

# shellcheck disable=SC2164

# Black Hat Bash - Automated Lab Build Script

# Script Checks system requirements
  # - Running Kali
  # - Minimum of 4 GB of RAM
  # - Minimum of 40 GB disk space available
  # - Internet connectivity

USER_HOME_BASE="/home/${SUDO_USER}"
BHB_TOOLS_FOLDER="/home/${SUDO_USER}/tools"

BHB_BASE_FOLDER="$(pwd)"
BHB_LAB_FOLDER="${BHB_BASE_FOLDER}/lab"
BHB_INSTALL_LOG="/var/log/lab-install.log"

check_prerequisites(){
  # Checks if script is running as root
  if [[ "$EUID" -ne 0 ]]; then
    echo "Error: Please run with sudo permissions."
    exit 1
  fi

  if [[ ! -f "${BHB_INSTALL_LOG}" ]]; then
    touch "${BHB_INSTALL_LOG}"
    chown "${SUDO_USER}:${SUDO_USER}" "${BHB_INSTALL_LOG}"
  fi

  # Check if Kali OS 
  if ! grep -q "ID=kali" /etc/os-release; then
    echo "Error: Operating system does not appear to be Kali."
  fi

  # Check internet connectivity (against Google)
  if ! ping -c 1 -W 5 -w 5 "8.8.8.8" &> /dev/null; then
    echo "Error: No internet connectivity."
  fi

  # Check if RAM +4 GB
  local total_ram
  total_ram=$(awk '/^MemTotal:/{print $2}' /proc/meminfo);
  if [ "${total_ram}" -lt 4194304 ]; then
    echo "Warning: System does not meet 4 GB RAM requirement."
    echo "This may impact the performance of the lab."
    read -p "Do you want to continue? [y/n] " -n 1 -r
    echo
    if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then
      echo "Exiting..."
      exit
    fi
  fi

  # Check disk space
  local free
  free=$(df -k --output=size "${PWD}" | tail -n1)
  if [[ "${free}" -lt 41943040 ]]; then
    echo "Warning: System does not meet 40 GB disk space requirement."
    echo "This may impact the performance of the lab."
    read -p "Do you want to continue? [y/n] " -n 1 -r
    echo
    if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then
      echo "Exiting..."
      exit
    fi
  fi

  if [[ ! -d "${BHB_TOOLS_FOLDER}" ]]; then
    mkdir "${BHB_TOOLS_FOLDER}"
  else
    rm -rf "${BHB_TOOLS_FOLDER:?}/"*
  fi

  local nr_config
  nr_config="/etc/needrestart/needrestart.conf"
  if [[ -f "${nr_config}" ]]; then
    if grep -q "#\$nrconf{restart}" "${nr_config}"; then
      sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/g" "${nr_config}"
    fi
  fi

  if ! grep kali /etc/passwd | grep -q /bin/bash; then
    usermod --shell /bin/bash kali
  fi
}

install_docker(){
  local docker_apt_src
  local docker_keyring

  docker_apt_src="/etc/apt/sources.list.d/docker-ce.list"
  docker_keyring="/etc/apt/trusted.gpg.d/docker-ce-archive-keyring.gpg"

  if ! docker compose version &> /dev/null; then 
    if [[ ! -f "${docker_apt_src}" ]]; then
      printf '%s\n' "deb https://download.docker.com/linux/debian bullseye stable" | tee "${docker_apt_src}"
    fi
    
    if [[ ! -f "${docker_keyring}" ]]; then
      curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o "${docker_keyring}"
    fi
    apt update -y 
    apt install docker-ce docker-ce-cli containerd.io -y
    systemctl enable docker --now
    usermod -aG docker "${SUDO_USER}"
  fi
}

deploy_containers(){
  make deploy
}

install_tools(){
  install_whatweb
  install_rustscan
  install_nuclei
  install_linux_exploit_suggester_2
  install_gitjacker
  install_linenum
  install_dirsearch
  install_sysutilities
  install_unixprivesccheck
}

install_whatweb(){
  apt install whatweb -y
}

install_rustscan(){
  docker pull --quiet rustscan/rustscan:2.1.1
  if ! grep -q rustscan "${USER_HOME_BASE}/.bashrc" ; then
    echo "alias rustscan='docker run --network=host -it --rm --name rustscan rustscan/rustscan:2.1.1'" >> "${USER_HOME_BASE}/.bashrc"
  fi
} 

install_nuclei(){
  apt install nuclei -y 
}

install_linux_exploit_suggester_2(){
  git clone https://github.com/jondonas/linux-exploit-suggester-2.git "${BHB_TOOLS_FOLDER}/linux-exploit-suggester-2"
}

install_gitjacker(){
  curl "https://raw.githubusercontent.com/liamg/gitjacker/master/scripts/install.sh" | bash
  if [[ -f "/usr/local/bin/gitjacker" ]]; then
    mv "/usr/local/bin/gitjacker" "${BHB_TOOLS_FOLDER}/gitjacker"
    rmdir bin
  fi 

  if ! grep -q gitjacker "${USER_HOME_BASE}/.bashrc"; then
    echo "alias gitjacker=\"${BHB_TOOLS_FOLDER}/gitjacker\"" >> "${USER_HOME_BASE}/.bashrc"
  fi
}

install_linenum(){
  wget -q https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O "${BHB_TOOLS_FOLDER}/LinEnum.sh"
  chmod u+x "${BHB_TOOLS_FOLDER}/LinEnum.sh"
}

install_dirsearch(){
  apt install dirsearch -y
}

install_sysutilities(){
  apt install jq -y
  apt install ncat -y
  apt install sshpass -y
  pip3 install pwncat-cs
}

install_unixprivesccheck(){
  if [[ ! -f "/usr/bin/unix-privesc-check" ]]; then
    apt install unix-privesc-check -y
  fi
  
  cp "/usr/bin/unix-privesc-check" "${BHB_TOOLS_FOLDER}/unix-privesc-check"
}

echo "This process may take a while, stay tuned..."

echo "Checking prerequisities..."
check_prerequisites 

sleep 2

echo "[1/3] Installing Docker..."
install_docker &>> "${BHB_INSTALL_LOG}"

echo "[2/3] Deploying containers..."
deploy_containers

echo "[3/3] Installing third party tools..."
install_tools &>> "${BHB_INSTALL_LOG}"

chown -R "${SUDO_USER}:${SUDO_USER}" "${BHB_TOOLS_FOLDER}"

echo "Lab build completed." | tee -a "${BHB_INSTALL_LOG}"

echo "NOTE: Log out and log back in for shell changes to take effect"
```

#### Lab Provisioning Script

```bash
#!/bin/bash

p_web_01() {
  if ! sudo docker exec -it p-web-01 bash -c "iptables -I INPUT -s 10.1.0.0/24 -m comment --comment \"Block Network\" -j DROP"; then
    return 1
  fi
  return 0
}

p_web_02() {
  local result
  # Provision WordPress (p-web-02)
  result=$(curl -s -X POST \
          -d 'weblog_title=ACME Impact Alliance&user_name=jtorres&first_name=Jane&last_name=Torres&admin_password=asfim2ne7asd7&admin_password2=asfim2ne7asd7&admin_email=jtorres@acme-impact-alliance.com&blog_public=0&Submit=Install WordPress&language=""' \
          "http://172.16.10.12/wp-admin/install.php?step=2")
  if ! echo "${result}" | grep -q -e "WordPress has been installed. Thank you" -e "already installed"; then
    echo "Error provisioning WordPress (p-web-02)"
    return 1
  fi
  
  return 0
}

check_post_actions(){
  p_web_01 || return 1
  p_web_02 || return 1
    
  return 0
}
```

---

### Lab Management

#### Lab Run Script

```bash
#!/bin/bash

set -o pipefail
source provision.sh

CHOICE="${1}"
LOG="/var/log/lab-install.log"

if [[ -n "${DEBUG}" ]] && [[ "${DEBUG}" = "true" ]]; then
  LOG=/dev/stderr
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: Please run using sudo permissions."
    exit 1
fi

if ! docker info > /dev/null 2>&1; then
    echo "Docker service appears to not be running. Use the service command to start it manually."
    echo "$ sudo service docker start"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "Docker Compose is not installed. Did you follow the Docker Compose setup instructions?"
    echo "https://github.com/dolevf/Black-Hat-Bash/tree/master/lab#install-docker"
    exit 1
fi

if [[ ! -f "${LOG}" ]]; then
    touch "${LOG}"
    chown "${SUDO_USER}:${SUDO_USER}" "${LOG}"
fi

wait() {
    local pid
    local counter
    local spinner

    pid=$1    
    counter=1
    spinner="/-\|"
    
    echo -n "$2"
    echo -n " "
    while ps -p "${pid}" &> /dev/null; do 
        printf "\b${spinner:counter++%${#spinner}:1}"
        sleep 0.5
    done
    echo
}

images_built(){
    local total_expected_containers
    local total_built_images

    total_expected_containers="$(grep -c container_name docker-compose.yml)"
    total_built_images="$(docker images | grep -c lab-)"
    
    if [[ "${total_built_images}" -eq "${total_expected_containers}" ]]; then
        return 0
    else
        return 1
    fi
}

status(){
    local total_expected_containers
    local actual_running_containers

    total_expected_containers="$(grep -c container_name docker-compose.yml)"
    actual_running_containers="$(docker ps | grep -c lab-)"

    if [[ "${actual_running_containers}" -ne "${total_expected_containers}" ]]; then
        return 1
    else
        return 0
    fi
}

deploy(){
    echo 
    echo "==== Deployment Started ===="

    if ! images_built; then
        echo "This process can take a few minutes to complete."
        echo "Start Time: $(date "+%T")" >> $LOG
        
        if [[ -z "${DEBUG}" ]]; then
            echo "You may run \"tail -f $LOG\" from another terminal session to see the progress of the deployment."
        fi
        
        docker build -f machines/Dockerfile-base -t lab_base . &>> $LOG
        docker compose build --parallel &>> $LOG &
        wait "$!" "Deploying the lab..."
        docker compose up --detach &>> $LOG
        
        if status; then
            echo "OK: all containers appear to be running. Performing a couple of post provisioning steps..."  | tee -a $LOG
            sleep 25
            if check_post_actions &>> $LOG; then
                echo "OK: Lab is up and provisioned." | tee -a $LOG
            else
                echo "Error: something went wrong during provisioning." | tee -a $LOG
            fi
        else
            echo "Error: not all containers are running. check the log file: $LOG"
        fi
    else
        docker compose up --detach &>> $LOG
        sleep 5
        if status; then
            echo "Lab is up."
        else
            echo "Lab is down. Try rebuilding the lab again."
        fi
    fi
    echo "End Time: $(date "+%T")" >> $LOG
}

teardown(){
    echo
    echo "==== Shutdown Started ====" | tee -a $LOG
    docker compose down --volumes
    echo "OK: lab has shut down." 
}

clean(){
    echo
    echo "==== Cleanup Started ====" 
    docker compose down --volumes --rmi all &> /dev/null &
    wait "$!" "Shutting down the lab..."
    
    docker system prune -a --volumes -f &> /dev/null &
    wait "$!" "Cleaning up..."
    
    [[ -f "${LOG}" ]] && > "${LOG}"
    echo "OK: lab environment has been destroyed."
}

rebuild(){
    clean
    deploy
}

case "${CHOICE}" in
    deploy)
        deploy
    ;;
    teardown)
        teardown
    ;;
    clean)
        clean
    ;;
    rebuild)
        rebuild
    ;;
    status)
        if status; then
            echo "Lab is up."
        else
            echo "Lab is down."
            exit 1
        fi
    ;;
    *)
        echo "Usage: ./$(basename "$0") deploy | teardown | rebuild | clean | status"
    ;;
esac
```

#### Lab Commands

**Deploy the lab:**
```bash
sudo ./run.sh deploy
```

**Check lab status:**
```bash
sudo ./run.sh status
```

**Teardown the lab:**
```bash
sudo ./run.sh teardown
```

**Clean and remove all lab components:**
```bash
sudo ./run.sh clean
```

**Rebuild the lab from scratch:**
```bash
sudo ./run.sh rebuild
```

#### Installed Security Tools

The installation script includes the following tools:

- **WhatWeb** - Web scanner
- **Rustscan** - Fast port scanner (Docker-based)
- **Nuclei** - Vulnerability scanner
- **Linux Exploit Suggester 2** - Privilege escalation tool
- **Gitjacker** - Git repository exposure tool
- **LinEnum** - Linux enumeration script
- **Dirsearch** - Web path scanner
- **jq** - JSON processor
- **ncat** - Network utility
- **sshpass** - SSH password tool
- **pwncat-cs** - Post-exploitation framework
- **unix-privesc-check** - Unix privilege escalation checker

---

## VM Setup and Configuration

### OSINT VM Setup

#### Buscador OSINT VM Automated Installation

For setting up the Buscador OSINT VM with all tools and configurations:

```bash
# Download the installation script with authentication
wget https://uvm:317@inteltechniques.com/osintvm/install.sh

# Make the script executable
chmod +x install.sh

# Run the installation script
./install.sh
```

**Note:** This script should be run **inside** the VM that you have already set up for OSINT work. It will configure and install all necessary OSINT tools and resources.

---

### Pimp My Kali

Pimp My Kali is a maintenance and hardening script for Kali Linux VMs that fixes common issues with newly imported VMs.

#### Installation and Usage

```bash
# Remove any existing pimpmykali folder
rm -rf pimpmykali/

# Clone the pimpmykali repository
git clone https://github.com/Dewalt-arch/pimpmykali

# Enter the directory
cd pimpmykali

# Execute the script with root privileges
# For a new Kali VM, run menu option 'N'
sudo ./pimpmykali.sh
```

#### What Pimp My Kali Does

- Fixes common issues with Kali VMs
- Updates and upgrades system packages
- Fixes broken dependencies
- Configures proper DNS settings
- Sets up correct repository sources
- Resolves networking issues
- Improves overall system stability

#### Usage Notes

- **Must be run with root/sudo privileges**
- For new Kali VMs, select menu option **'N'** when prompted
- Recommended for all fresh Kali Linux installations
- Run after importing a new Kali VM or after system updates

---

## System Requirements

### Black Hat Bash Lab Requirements

- **Operating System**: Kali Linux (recommended)
- **RAM**: Minimum 4 GB (more recommended for multiple containers)
- **Disk Space**: Minimum 40 GB available
- **Network**: Internet connectivity required
- **Software**: Docker and Docker Compose

### General VM Requirements

Most cybersecurity VMs have similar requirements:

- **Hypervisor**: VirtualBox, VMware Workstation/Player, or KVM
- **RAM**: 4-8 GB minimum (more for analysis VMs)
- **Disk Space**: 40-100 GB depending on the distribution
- **CPU**: Multi-core processor recommended
- **Network**: Bridged or NAT networking capability

---

## Best Practices

### Security Lab Setup

1. **Isolate Lab Environments**: Run vulnerable machines in isolated networks
2. **Snapshot Regularly**: Take VM snapshots before major changes
3. **Update Tools**: Keep security tools and VMs updated
4. **Document Findings**: Maintain detailed notes of discoveries and techniques
5. **Legal Compliance**: Only test on systems you own or have permission to test

### VM Management

1. **Resource Allocation**: Don't over-allocate RAM/CPU to VMs
2. **Network Segmentation**: Use host-only or isolated networks for labs
3. **Backup Important Work**: Regular backups of custom configurations
4. **Clean Shutdown**: Always shut down VMs properly to prevent corruption
5. **Monitor Performance**: Keep an eye on host system resources

---

## Additional Resources

- **Black Hat Bash Lab**: https://github.com/dolevf/Black-Hat-Bash
- **Kali Linux Documentation**: https://www.kali.org/docs/
- **Docker Documentation**: https://docs.docker.com/
- **OSINT Framework**: https://osintframework.com/
- **Hack The Box**: https://www.hackthebox.com/
- **TryHackMe**: https://tryhackme.com/

---

## Legal Disclaimer

These tools and lab environments are intended for:
- Educational purposes
- Authorized security testing
- Research in controlled environments
- Professional security assessments with proper authorization

**Unauthorized access to computer systems is illegal.** Always obtain proper authorization before conducting security testing on any systems you do not own.
