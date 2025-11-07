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
        sleep 0.03
    done
    echo -e "${NC}"
}

# Banner function
show_banner() {
    echo -e "${PURPLE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                  WiFi Mode Manager                        ║"
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

# Function to check if interface exists
check_interface() {
    local int=$1
    if ! iwconfig 2>/dev/null | grep -q "^$int"; then
        echo -e "${RED}[!] Interface $int not found!${NC}"
        return 1
    fi
    return 0
}

# Main script
show_banner

# Display available interfaces with animation
echo -e "${YELLOW}Scanning for available WiFi interfaces...${NC}"
sleep 1

interfaces=$(iwconfig 2>/dev/null | grep -o "^[a-zA-Z0-9_-]*" | grep "^wlan")
if [ -z "$interfaces" ]; then
    echo -e "${RED}[!] No WiFi interfaces found!${NC}"
    exit 1
fi

echo -e "${GREEN}Available interfaces:${NC}"
count=1
declare -A int_map
while IFS= read -r int; do
    echo -e "  ${CYAN}$count) $int${NC}"
    int_map[$count]=$int
    ((count++))
done <<< "$interfaces"

# Get user input for interface selection
echo
read -p "$(echo -e ${YELLOW}"[?] Select interface (number or name): "${NC})" int_input

# Validate interface selection
if [[ $int_input =~ ^[0-9]+$ ]] && [ ${int_map[$int_input]+isset} ]; then
    int=${int_map[$int_input]}
elif [[ " ${int_map[@]} " =~ " ${int_input} " ]]; then
    int=$int_input
else
    echo -e "${RED}[!] Invalid selection!${NC}"
    exit 1
fi

# Verify interface exists
if ! check_interface "$int"; then
    exit 1
fi

echo -e "${GREEN}[+] Selected interface: $int${NC}"
echo

# Action selection with animation
PS3=$(echo -e "${YELLOW}Select an option: ${NC}")
options=("Start Monitor Mode" "Stop Monitor Mode" "Exit")
select action in "${options[@]}"; do
    case $action in
        "Start Monitor Mode")
            echo -e "${YELLOW}[~] Killing conflicting processes...${NC}"
            (airmon-ng check kill > /dev/null 2>&1) &
            spinner $!
            echo -e "${GREEN}[✓] Conflicting processes terminated${NC}"
            
            echo -e "${YELLOW}[~] Starting monitor mode on $int...${NC}"
            (airmon-ng start $int > /dev/null 2>&1) &
            spinner $!
            echo -e "${GREEN}[✓] $int is now in monitor mode${NC}"
            
            # Show new interface name if changed
            new_int=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}')
            if [ "$new_int" != "$int" ] && [ ! -z "$new_int" ]; then
                echo -e "${CYAN}[i] Interface renamed to: $new_int${NC}"
            fi
            break
            ;;
        "Stop Monitor Mode")
            echo -e "${YELLOW}[~] Stopping monitor mode on $int...${NC}"
            (airmon-ng stop $int > /dev/null 2>&1) &
            spinner $!
            
            echo -e "${YELLOW}[~] Restoring network services...${NC}"
            (systemctl start wpa_supplicant > /dev/null 2>&1 && \
             systemctl start NetworkManager > /dev/null 2>&1) &
            spinner $!
            
            echo -e "${GREEN}[✓] Monitor mode stopped and services restored${NC}"
            break
            ;;
        "Exit")
            animate "Exiting WiFi Mode Manager. Goodbye!"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid option. Please try again.${NC}"
            ;;
    esac
done

echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    Operation Complete                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
