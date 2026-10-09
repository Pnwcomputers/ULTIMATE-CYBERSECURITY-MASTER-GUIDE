# Platform Compatibility

## Supported Operating Systems

| Platform | Status | Notes |
|----------|--------|-------|
| Tsurugi Linux | ✅ Fully Tested | Recommended — most OSINT tools pre-installed |
| Kali Linux | ✅ Fully Tested | Excellent apt package coverage |
| Ubuntu 22.04+ | ✅ Tested | Requires manual tool installation |
| Debian 12+ | ✅ Tested | Requires manual tool installation |
| Parrot OS | ✅ Tested | Good tool coverage |
| Arch / Manjaro | ✅ Tested | Use pacman path in installer |
| macOS | ⚠️ Partial | Some tools unavailable (nmap works, holehe/maigret work) |
| Windows (WSL2) | ⚠️ Partial | Run Ubuntu 22.04 WSL2 layer; Docker required for RustScan |

---

## Tool Availability by Platform

| Tool | Kali/Tsurugi | Ubuntu/Debian | Arch | macOS |
|------|:---:|:---:|:---:|:---:|
| nmap | ✅ apt | ✅ apt | ✅ pacman | ✅ brew |
| masscan | ✅ apt | ✅ apt | ✅ pacman | ⚠️ build from source |
| holehe | ✅ pip | ✅ pip | ✅ pip | ✅ pip |
| maigret | ✅ pip | ✅ pip | ✅ pip | ✅ pip |
| h8mail | ✅ pip | ✅ pip | ✅ pip | ✅ pip |
| sherlock | ✅ pip | ✅ pip | ✅ pip | ✅ pip |
| subfinder | ✅ go | ✅ go | ✅ go | ✅ go |
| httpx | ✅ go | ✅ go | ✅ go | ✅ go |
| nuclei | ✅ go | ✅ go | ✅ go | ✅ go |
| theHarvester | ✅ apt/git | ✅ git | ✅ git | ⚠️ git |
| phoneinfoga | ✅ binary | ✅ binary | ✅ binary | ⚠️ binary |
| whois | ✅ apt | ✅ apt | ✅ pacman | ✅ brew |
| wkhtmltopdf | ✅ apt | ✅ apt | ✅ pacman | ⚠️ brew |

---

## Python Version

Requires **Python 3.8+**. Tested on Python 3.10 and 3.11.

```bash
python3 --version
```

---

## Go Version

Requires **Go 1.20+** for ProjectDiscovery tools (subfinder, httpx, nuclei, dnsx).

```bash
go version
```

---

## Known Issues

- **masscan** requires root (`sudo`) for raw packet sending — wrap with `sudo masscan` or run the investigator script as root
- **wkhtmltopdf** on Debian 12+ may require the Qt patch version from the official release page rather than the apt package
- **holehe** may show false negatives on some platforms due to anti-bot measures — results are best-effort
- **theHarvester** from apt on Kali may lag behind the GitHub version; install from source for the latest data sources
- **PhoneInfoga** OSINT scanners (NumVerify, etc.) require API keys; the binary itself installs fine on all platforms
