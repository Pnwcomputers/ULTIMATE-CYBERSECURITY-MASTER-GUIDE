# Argus Recon Toolkit - Installation Guide

This guide provides a streamlined path for installing and running the [The Argus Recon OSINT Toolkit](https://github.com/jasonxtn/argus) by [Jasonxtn](https://github.com/jasonxtn) on a modern Linux systems (Ubuntu/Debian) using Python 3.12+. Argus is a Python-based toolkit for Information Gathering & Reconnaissance

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
git clone https://github.com/[YOUR_USERNAME]/argus.git
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
Install the required libraries manually to ensure compatibility:
```bash
pip install cmd2 colorama pyperclip requests
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
