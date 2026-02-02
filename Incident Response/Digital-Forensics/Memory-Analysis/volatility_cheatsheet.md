# 🧠 Volatility 3 Cheatsheet

**Volatility** is the industry-standard framework for memory forensics. This guide focuses on Volatility 3 syntax for analyzing Windows RAM dumps.

---

## 🛠️ Basic Usage

```bash
python3 vol.py -f <IMAGE_FILE> <PLUGIN>
```

---

## 🕵️ Process Analysis

Identify rogue processes running in memory.

| Command | Description |
|---------|-------------|
| `windows.pslist` | List running processes. Look for exited processes. |
| `windows.pstree` | View parent/child relationships (e.g., Word spawning PowerShell). |
| `windows.psscan` | Find unlinked (hidden) processes used by rootkits. |

---

## 🌐 Network Analysis

Find connections that were active at the time of capture.

| Command | Description |
|---------|-------------|
| `windows.netscan` | List active connections (listening ports, established sessions). |
| `windows.netstat` | Similar to netstat command output. |

---

## 💉 Injection & Malware

| Command | Description |
|---------|-------------|
| `windows.malfind` | Scans for code injection (shellcode) in memory regions. |
| `windows.dlllist` | Lists loaded DLLs for a specific PID. |

---

## 📝 Example Workflow

**1. Find the suspicious process:**

```bash
python3 vol.py -f dump.mem windows.pstree
```

**2. Check network connections for that PID:**

```bash
python3 vol.py -f dump.mem windows.netscan | grep <PID>
```

**3. Dump the process executable for analysis:**

```bash
python3 vol.py -f dump.mem windows.pslist --pid <PID> --dump
```

---

*Part of the Incident Response & Log Aggregation Branch*
