# 🪟 Windows Sysmon Configuration

**System Monitor (Sysmon)** is a Windows system service and device driver that logs system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time.

## 📥 Installation
1.  **Download Sysmon:** [Sysinternals Website](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2.  **Download a Configuration:**
    * *Recommended for Beginners:* [SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config)
    * *Advanced:* [Olaf Hartong's Modular Config](https://github.com/olafhartong/sysmon-modular)

## ⚙️ Deployment
Open an Administrator Command Prompt and run:

```cmd
sysmon64.exe -accepteula -i sysmonconfig-export.xml
📝 Key Event IDs to MonitorEvent IDDescriptionWhy it matters1Process CreateShows command line arguments (e.g., powershell.exe -enc <BASE64>).3Network ConnectionLogs outbound connections (C2 callbacks).11FileCreateDropping malware or tools to disk.13RegistryEventPersistence mechanisms (Run keys).🧪 TestingOpen PowerShell.Run whoami.Check Event Viewer: Applications and Services Logs/Microsoft/Windows/Sysmon/Operational.Look for Event ID 1 containing whoami.Part of the Incident Response & Log Aggregation Branch
