# Scripts Directory

This folder contains custom OSINT investigation scripts that integrate with the main playbook.

## Available Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `scammer_audit.sh` | Comprehensive domain/IP investigation | `./scammer_audit.sh -d <domain>` or `-i <ip>` or `-e <email>` |
| `email_audit.sh` | Email address analysis and breach lookup | `./email_audit.sh -e <email>` |
| `phone_audit.sh` | Phone number lookup and validation | `./phone_audit.sh -p <phone>` |
| `full_nmap_scan.sh` | Comprehensive nmap reconnaissance | `./full_nmap_scan.sh <IP_ADDRESS>` |

## Integration

These scripts are automatically detected by `toolkit_integration.sh` and can be run from:

1. **CLI Menu**: `./osint_investigator.sh` → `[6] Integrated Tools`
2. **Direct Command**: `./toolkit_integration.sh --detect`
3. **Standalone**: Run each script directly with its arguments

## Script Details

### scammer_audit.sh
Full domain/IP reconnaissance including:
- theHarvester integration
- CriminalIP, HIBP, LeakLookup, Netlas APIs
- Nmap, RustScan, WhatWeb, Nuclei, Dirsearch scanning
- Master summary report generation

```bash
./scammer_audit.sh -d example.com                    # Domain investigation
./scammer_audit.sh -i 192.168.1.1                    # IP investigation
./scammer_audit.sh -d example.com -e scam@test.com  # Combined
./scammer_audit.sh -q -d example.com                 # Quick mode
```

### email_audit.sh
Email OSINT including:
- HaveIBeenPwned breach checks
- Hunter.io verification
- EmailRep.io reputation
- Gravatar/social media discovery

```bash
./email_audit.sh -e target@example.com               # Single email
./email_audit.sh -e email1@test.com,email2@test.com # Multiple
./email_audit.sh -f emails.txt                       # From file
```

### phone_audit.sh
Phone number intelligence including:
- NumVerify/Veriphone validation
- Carrier and line type detection
- VoIP/virtual number identification
- Leak database checks

```bash
./phone_audit.sh -p +19835551234                     # Single number
./phone_audit.sh -p 19835551234,19835555678         # Multiple
./phone_audit.sh -f phones.txt                       # From file
```

### full_nmap_scan.sh
Comprehensive nmap reconnaissance:
- Basic service detection + default scripts
- Full 65535 port scan
- Aggressive OS detection (requires sudo)
- DNS NSID scripts
- Combined report

```bash
./full_nmap_scan.sh 192.168.1.1                      # Full scan
```

## Adding New Scripts

1. Place your script in this folder
2. Make it executable: `chmod +x your_script.sh`
3. Update `toolkit_integration.sh` to include detection
4. Run `./toolkit_integration.sh --detect` to register

## API Configuration

Scripts read API keys from `~/.config/osint-investigator/api_keys.conf`

Required for full functionality:
- `CRIMINALIP_API_KEY`
- `HAVEIBEENPWNED_API_KEY`
- `HUNTER_API_KEY`
- `LEAKLOOKUP_API_KEY`
- `NETLAS_API_KEY`
- `NUMVERIFY_API_KEY`
- `VERIPHONE_API_KEY`
