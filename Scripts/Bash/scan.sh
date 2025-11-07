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
    echo "║                   WiFi Network Scanner                     ║"
    echo "║                 Enhanced with Style                       ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Spinner animation
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Show countdown
countdown() {
    local seconds=$1
    while [ $seconds -gt 0 ]; do
        echo -ne "${YELLOW}Starting scan in $seconds seconds...${NC}\033[0K\r"
        sleep 1
        ((seconds--))
    done
    echo -e "\033[0K"
}

# Main script
show_banner

# Check for monitor mode interface
animate "Scanning for monitor mode interfaces..."

iface=$(iwconfig 2>/dev/null | grep "mon" | awk '{print $1}' | head -n1)

if [[ -z "$iface" ]]; then
    echo -e "${RED}[-] No monitor mode interface found (ending with 'mon').${NC}"
    echo -e "${YELLOW}[!] Please enable monitor mode first.${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Found monitor mode interface: ${CYAN}$iface${NC}"
echo

# Brief countdown before starting
countdown 3

clear
show_banner

echo -e "${GREEN}[✓] Monitoring with interface: ${CYAN}$iface${NC}"
echo -e "${YELLOW}[!] Press ${RED}CTRL+C${YELLOW} to stop scanning${NC}"
echo

# Start airodump-ng with some visual enhancements
echo -e "${PURPLE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║                 STARTING NETWORK SCAN                     ║${NC}"
echo -e "${PURPLE}╚════════════════════════════════════════════════════════════╝${NC}"
echo

# Function to handle cleanup on exit
cleanup() {
    echo
    echo -e "${PURPLE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                 SCAN TERMINATED                          ║${NC}"
    echo -e "${PURPLE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${GREEN}[✓] Scan completed. Returning to normal mode.${NC}"
    exit 0
}

# Set trap to catch CTRL+C
trap cleanup EXIT

# Start airodump-ng with a slight delay to show the message
sleep 1
airodump-ng "$iface"
