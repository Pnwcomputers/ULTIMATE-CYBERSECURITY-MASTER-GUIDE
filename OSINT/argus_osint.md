# Argus Recon Toolkit - Installation Guide

This guide provides a streamlined path for installing and running the [The Argus Recon OSINT Toolkit](https://github.com/jasonxtn/argus) by [Jason13](https://github.com/jasonxtn) on a modern Linux system (Ubuntu/Debian) using Python 3.12+. Argus is a Python-based toolkit for Information Gathering & Reconnaissance

## 🎯 Purpose
Minimal installation guide for the third-party Argus Recon OSINT toolkit on a modern Debian/Ubuntu system, specifically addressing PEP 668's externally-managed-environment restriction that breaks naive `pip install` on recent distros. Distinct from the other OSINT tool references in this folder — this is a single-tool setup guide, not a methodology or command reference.

## ⚙️ Function
Five sequential steps: system prerequisites, repo clone, virtual environment creation (required by PEP 668), dependency installation via the project's own `requirements.txt`, and the launch command.

## 🏆 Goal
Get Argus running from a fresh Ubuntu/Debian install without the common PEP 668 "externally-managed-environment" pip error or import failures from an incomplete manual dependency list.

## 📋 When to Use
- First-time Argus installation on Ubuntu 23.04+/Debian 12+ (where PEP 668 blocks system-wide pip installs)
- Re-launching Argus in a later session (see Quick Start Summary at the bottom)

## Prerequisites
Ensure your system has the necessary build tools and Python development headers installed to prevent compilation errors.
```bash
sudo apt update
sudo apt install python3-full python3-dev build-essential -y
```

## Step-by-Step Setup

### 1. Clone the Repository
Navigate to your desired directory and clone the project:
```bash
git clone https://github.com/jasonxtn/argus.git
cd argus
```

### 2. Create a Virtual Environment
Modern Linux distributions require Python packages to be installed in isolated environments (PEP 668).
```bash
python3 -m venv venv
```

### 3. Activate the Environment
You must activate the virtual environment every time you want to run the tool:
```bash
source venv/bin/activate
```
*(Your terminal prompt should now show `(venv)`)*

### 4. Upgrade Core Build Tools
Before installing dependencies, ensure `pip` and `setuptools` are up to date:
```bash
pip install --upgrade pip setuptools wheel
```

### 5. Install Dependencies
Use the project's own requirements file rather than installing packages manually — Argus depends on 25+ libraries (aiohttp, dnspython, beautifulsoup4, cryptography, ldap3, and more), and a hand-picked subset will fail with import errors once you actually run it:
```bash
pip install -r requirements.txt
```

## Running Argus

Once the setup is complete, launch the toolkit using:
```bash
python3 -m argus
```

## Quick Start Summary
For future sessions, use this shortcut:
```bash
cd ~/argus
source venv/bin/activate
python3 -m argus
```
