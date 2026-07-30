# Shells & AV-Bypass Stagers

> ⚠️ **AUTHORIZED USE ONLY.** The code in this folder is offensive tradecraft — reverse
> shells, shellcode stagers, and AV-bypass delivery helpers. Use it strictly against
> systems you own or are explicitly authorized (in writing) to test. Unauthorized use is
> illegal. See the repository [LEGAL.md](../../../LEGAL.md) for the full disclaimer.

## 🎯 Purpose
Source for a small set of classic shell/stager utilities so operators can read, audit, and
build them from source rather than trusting prebuilt binaries. The original prebuilt
`bypass.exe` and `ishell.exe` were removed from version control because compiled binaries
cannot be reviewed, bloat the repository, and are routinely flagged by GitHub and endpoint
AV. Build them yourself from the source below.

## ⚙️ Contents

| File | Language | What it is |
|------|----------|------------|
| `bypass.c` | C (Windows) | Connect-back shellcode stager. Connects to a hard-coded `IP_ADDRESS:PORT`, receives a payload into `RWX` memory, and executes it — a classic AV-bypass reverse-shell stager. |
| `ishell.py` | Python | Interactive command handler (`InteractiveCommand`) that drives an interactive process (e.g., a shell) over a socket. Source for the former `ishell.exe`. |
| `shell.py` | Python | Companion reverse-shell helper. |
| `stealth.go` | Go | Generates Go executables that work with Metasploit's `smb_delivery` / `web_delivery` modules for AV bypass. |
| `insert_encoder.go` | Go | Encoder-insertion helper used alongside `stealth.go`. |

## 🏗️ Building from source

Before building, edit the hard-coded connect-back address/port in the source (e.g.
`IP_ADDRESS` / `PORT` in `bypass.c`, `HOST` / `PORT` in `ishell.py`) to match your
authorized listener.

**`bypass.c` → `bypass.exe`** (cross-compile from Linux/Kali, per the comment in the source):

```bash
# Debian/Kali build environment
sudo apt-get install mingw-w64
# Compile (32-bit):
i686-w64-mingw32-gcc bypass.c -o bypass.exe -lws2_32
```

**`ishell.py` → `ishell.exe`** (optional standalone Windows binary; the original was a
PyInstaller freeze):

```bash
pip install pyinstaller
pyinstaller --onefile ishell.py
# result in dist/ishell.exe
```

The `.py` files also run directly with a Python interpreter — no build step is required to
use them.

**Go helpers:**

```bash
go build stealth.go
go build insert_encoder.go
```

## 📜 Attribution & License
Original C/Python/Go sources are Copyright (c) 2012–2017 Stephen Haywood
(AverageSecurityGuy) and are distributed under a BSD 3-Clause license (see the header of
each source file). Background write-up:
<https://averagesecurityguy.github.io/2017/01/06/bypassing-av-with-golang/>

## 🔗 See also
- [../../README.md](../../README.md) — Scripts index
- [../../../Tradecraft/av-edr-evasion.md](../../../Tradecraft/av-edr-evasion.md) — AV/EDR evasion techniques
- [../../../LEGAL.md](../../../LEGAL.md) — Legal and authorization requirements
