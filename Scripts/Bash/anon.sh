#!/bin/bash

echo "What do you want to do?"
select action in "Check Anonymous status" "Start Anonymous options" "Stop Anonymous options" "Back" "Exit"; do
     case $action in
        "Check Anonymous status")
	    clear
            kali-whoami --status
	    cd /$PWD/scripts
	    ./anon.sh
            break
            ;;
        "Start Anonymous options")
	    clear
	    kali-whoami --start
	    cd /$PWD/scripts
	    ./anon.sh
            break
            ;;
        "Stop Anonymous options")
	    clear
	    kali-whoami --stop
	    cd /$PWD/scripts
	    ./anon.sh
            break
            ;;
        "Back")
	    /home/kali/CyberSecurity_Lab/main.sh
            break
            ;;
        "Exit")
            echo "[+] Exiting..."
            exit 0
            ;;
        *)
            echo "[?] Invalid option."
            ;;
    esac
done
