
# 💽 Disk Forensics Guide (Autopsy & KAPE)

**Disk forensics** involves the acquisition, analysis, and reporting of data stored on persistent storage media. This guide covers two essential tools: **Autopsy** (a full-featured forensic platform) and **KAPE** (Kroll Artifact Parser and Extractor - a rapid triage collection tool).

Together, these tools enable investigators to quickly collect artifacts and perform deep-dive analysis of compromised systems.

---

## 🎯 Autopsy vs KAPE: When to Use Each

| Scenario | Tool | Reason |
|----------|------|--------|
| Full disk analysis | Autopsy | Complete filesystem examination |
| Rapid triage collection | KAPE | Fast artifact extraction |
| Timeline analysis | Autopsy | Built-in timeline features |
| Remote/live collection | KAPE | Lightweight, portable |
| Malware investigation | Both | KAPE collects, Autopsy analyzes |
| Deleted file recovery | Autopsy | File carving capabilities |
| Registry analysis | Both | Autopsy has viewer, KAPE extracts |
| Browser forensics | Both | Both parse browser artifacts |

### Typical Workflow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Live System    │────▶│     KAPE        │────▶│    Autopsy      │
│  or Disk Image  │     │  (Collection)   │     │   (Analysis)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                              │
                              ▼
                        ┌─────────────────┐
                        │  KAPE Output    │
                        │  (Artifacts +   │
                        │   Parsed Data)  │
                        └─────────────────┘
```

---

# Part A: KAPE (Kroll Artifact Parser and Extractor)

## 📋 KAPE Overview

KAPE is a triage tool designed to:
- **Collect** forensic artifacts from live systems or mounted images
- **Process** collected data using various parsers
- **Output** results in analysis-ready formats

### Key Concepts

| Term | Description |
|------|-------------|
| **Target** | Defines what files/artifacts to collect |
| **Module** | Defines how to process collected artifacts |
| **TKAPE** | Target collection only |
| **MKAPE** | Module processing only |
| **Compound Target** | Multiple targets combined |

---

## 📥 KAPE Installation

### Step 1: Download KAPE

KAPE is free for non-commercial use. Download from:
- [Kroll KAPE Download](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)

### Step 2: Extract and Organize

```powershell
# Extract to a dedicated folder
Expand-Archive -Path "kape.zip" -DestinationPath "C:\Tools\KAPE"

# Directory structure
# C:\Tools\KAPE\
# ├── kape.exe
# ├── Targets\
# ├── Modules\
# └── Documentation\
```

### Step 3: Update Targets and Modules

KAPE uses community-maintained targets and modules:

```powershell
# Clone KapeFiles repository for latest targets/modules
git clone https://github.com/EricZimmerman/KapeFiles.git

# Copy to KAPE directory
Copy-Item -Path "KapeFiles\Targets\*" -Destination "C:\Tools\KAPE\Targets" -Recurse -Force
Copy-Item -Path "KapeFiles\Modules\*" -Destination "C:\Tools\KAPE\Modules" -Recurse -Force
```

### Step 4: Download Module Binaries

Many modules require external tools (Eric Zimmerman tools, etc.):

```powershell
# Run KAPE's module binary sync
cd C:\Tools\KAPE
.\kape.exe --sync
```

Or manually download Eric Zimmerman tools:
- [EZ Tools Download](https://ericzimmerman.github.io/#!index.md)

---

## 🎯 KAPE Targets

### Understanding Target Files

Targets are YAML files defining what to collect:

```yaml
Description: Windows Event Logs
Author: Eric Zimmerman
Version: 1.0
Id: 12345678-1234-1234-1234-123456789abc
RecreateDirectories: true
Targets:
    -
        Name: Event Logs
        Category: EventLogs
        Path: C:\Windows\System32\winevt\Logs\
        FileMask: '*.evtx'
        Recursive: false
```

### Essential Targets for IR

| Target | What It Collects |
|--------|------------------|
| `!SANS_Triage` | Comprehensive IR collection |
| `KapeTriage` | General triage artifacts |
| `EventLogs` | Windows Event Logs |
| `Registry` | Registry hives |
| `FileSystem` | $MFT, $J, $LogFile |
| `Antivirus` | AV logs (Defender, etc.) |
| `WebBrowsers` | All browser artifacts |
| `CloudStorage` | OneDrive, Dropbox, etc. |
| `RemoteAdmin` | RDP, TeamViewer, etc. |
| `PowerShell` | PS history, logs |
| `Prefetch` | Prefetch files |
| `Amcache` | Amcache.hve |
| `SRUM` | System Resource Usage |
| `RecycleBin` | Deleted files info |

### View Available Targets

```powershell
# List all targets
.\kape.exe --tlist

# Search for specific targets
.\kape.exe --tlist | Select-String "Registry"
```

---

## 🔧 KAPE Collection Examples

### Basic Syntax

```powershell
kape.exe --tsource <source> --tdest <destination> --target <target_name>
```

### Example 1: Comprehensive Triage Collection

```powershell
# Collect SANS triage artifacts from C: drive
.\kape.exe --tsource C: --tdest E:\Cases\Case001\Collection --target !SANS_Triage

# With volume shadow copy support
.\kape.exe --tsource C: --tdest E:\Cases\Case001\Collection --target !SANS_Triage --vss
```

### Example 2: Event Logs Only

```powershell
.\kape.exe --tsource C: --tdest E:\Cases\Case001\EventLogs --target EventLogs
```

### Example 3: Registry Hives

```powershell
.\kape.exe --tsource C: --tdest E:\Cases\Case001\Registry --target RegistryHives
```

### Example 4: Browser Artifacts

```powershell
.\kape.exe --tsource C: --tdest E:\Cases\Case001\Browsers --target WebBrowsers
```

### Example 5: Multiple Targets

```powershell
.\kape.exe --tsource C: --tdest E:\Cases\Case001\Collection --target EventLogs,RegistryHives,Prefetch,Amcache
```

### Example 6: Collect from Mounted Image

```powershell
# Mount forensic image as E:
# Then collect
.\kape.exe --tsource E: --tdest F:\Cases\Case001\Collection --target !SANS_Triage
```

### Example 7: Include Volume Shadow Copies

```powershell
.\kape.exe --tsource C: --tdest E:\Cases\Case001\Collection --target !SANS_Triage --vss --vhdx Case001_VSS
```

---

## ⚙️ KAPE Modules

### Understanding Modules

Modules process collected artifacts:

```yaml
Description: Parse Windows Event Logs with EvtxECmd
Category: EventLogs
Author: Eric Zimmerman
Version: 1.0
Id: 87654321-4321-4321-4321-cba987654321
BinaryUrl: https://f001.backblazeb2.com/file/EricZimmermanTools/EvtxECmd.zip
ExportFormat: csv
Processors:
    -
        Executable: EvtxECmd\EvtxECmd.exe
        CommandLine: -d %sourceDirectory% --csv %destinationDirectory%
        ExportFormat: csv
```

### Essential Modules for IR

| Module | What It Processes |
|--------|-------------------|
| `!EZParser` | Run all EZ tools on artifacts |
| `EvtxECmd` | Parse Event Logs to CSV |
| `RECmd` | Parse Registry hives |
| `PECmd` | Parse Prefetch files |
| `LECmd` | Parse LNK files |
| `JLECmd` | Parse Jump Lists |
| `SBECmd` | Parse ShellBags |
| `MFTECmd` | Parse $MFT |
| `AmcacheParser` | Parse Amcache |
| `AppCompatCacheParser` | Parse Shimcache |
| `SrumECmd` | Parse SRUM database |
| `SQLECmd` | Parse SQLite databases |

### View Available Modules

```powershell
# List all modules
.\kape.exe --mlist

# Search for specific modules
.\kape.exe --mlist | Select-String "Registry"
```

---

## 🔄 KAPE Processing Examples

### Basic Module Syntax

```powershell
kape.exe --msource <source> --mdest <destination> --module <module_name>
```

### Example 1: Process All with EZParser

```powershell
.\kape.exe --msource E:\Cases\Case001\Collection --mdest E:\Cases\Case001\Parsed --module !EZParser
```

### Example 2: Parse Event Logs

```powershell
.\kape.exe --msource E:\Cases\Case001\Collection --mdest E:\Cases\Case001\Parsed --module EvtxECmd
```

### Example 3: Parse Registry

```powershell
.\kape.exe --msource E:\Cases\Case001\Collection --mdest E:\Cases\Case001\Parsed --module RECmd_AllRegExecutablesFoundOrRun
```

### Example 4: Full Collection + Processing

```powershell
# Collect AND process in one command
.\kape.exe --tsource C: --tdest E:\Cases\Case001\Collection --target !SANS_Triage --mdest E:\Cases\Case001\Parsed --module !EZParser
```

---

## 📊 KAPE Output Structure

After running KAPE, output is organized:

```
E:\Cases\Case001\
├── Collection\                    # Raw collected artifacts
│   ├── C\                         # Source drive letter
│   │   ├── Windows\
│   │   │   ├── System32\
│   │   │   │   ├── config\        # Registry hives
│   │   │   │   └── winevt\Logs\   # Event logs
│   │   │   └── Prefetch\
│   │   └── Users\
│   │       └── <username>\
│   └── vss\                       # Volume Shadow Copies
│       ├── vss1\
│       └── vss2\
│
└── Parsed\                        # Processed output
    ├── EventLogs\                 # CSV event logs
    ├── Registry\                  # Registry output
    ├── FileSystem\                # $MFT, etc.
    └── ProgramExecution\          # Prefetch, Amcache
```

---

## 🖥️ KAPE GUI (gkape)

KAPE includes a GUI for easier use:

```powershell
# Launch GUI
.\gkape.exe
```

### GUI Features

1. **Target Selection:** Browse and select targets visually
2. **Module Selection:** Browse and select modules
3. **Options:** VSS, VHDX creation, flush settings
4. **Command Preview:** See the command before running

---

# Part B: Autopsy

## 📋 Autopsy Overview

**Autopsy** is an open-source digital forensics platform that provides:
- Disk image analysis
- File system forensics
- Keyword searching
- Timeline analysis
- Hash filtering
- Reporting

---

## 📥 Autopsy Installation

### Step 1: Download Autopsy

Download from [sleuthkit.org/autopsy](https://www.sleuthkit.org/autopsy/download.php)

### Step 2: Install

Run the installer with default settings. Autopsy includes:
- The Sleuth Kit (forensic tools)
- Java Runtime (bundled)
- Various analysis modules

### Step 3: Configure Memory (Optional)

For large cases, increase Java heap:

1. Navigate to Autopsy installation directory
2. Edit `etc\autopsy.conf`
3. Modify: `default_options="-J-Xms4g -J-Xmx16g"`

---

## 🆕 Creating a New Case

### Step 1: Start Autopsy

Launch Autopsy and select **Create New Case**

### Step 2: Case Information

| Field | Example |
|-------|---------|
| Case Name | IR-2024-001 |
| Base Directory | E:\Cases\ |
| Case Type | Single-user |

### Step 3: Optional Information

| Field | Example |
|-------|---------|
| Case Number | IR-2024-001 |
| Examiner | John Smith |
| Organization | PNWC |

---

## 📀 Adding Data Sources

### Supported Data Sources

| Type | Description |
|------|-------------|
| Disk Image | E01, raw (dd), VHD, VMDK |
| Local Disk | Physical drive |
| Logical Files | Folder of files (like KAPE output) |
| Unallocated Space | Raw unallocated space image |
| XRY Text Export | Mobile device export |

### Add Disk Image

1. **Select Data Source Type:** Disk Image or VM File
2. **Browse** to image file (E01, raw, etc.)
3. **Configure Time Zone** (important for timeline accuracy)
4. **Select Ingest Modules** (see below)

### Add KAPE Collection (Logical Files)

1. **Select Data Source Type:** Logical Files
2. **Browse** to KAPE collection folder
3. This allows Autopsy to analyze KAPE-collected artifacts

---

## 🔌 Ingest Modules

Ingest modules automatically analyze data as it's added.

### Essential Modules for IR

| Module | Purpose | Enable? |
|--------|---------|---------|
| **Recent Activity** | Browser, registry, recent docs | ✅ |
| **Hash Lookup** | Compare against known hash sets | ✅ |
| **File Type Identification** | Identify by signature, not extension | ✅ |
| **Extension Mismatch** | Find disguised files | ✅ |
| **Embedded File Extractor** | Extract from archives/docs | ✅ |
| **Keyword Search** | Index for searching | ✅ |
| **Email Parser** | Parse email files | ✅ |
| **Encryption Detection** | Find encrypted files | ✅ |
| **Interesting Files** | Flag suspicious files | ✅ |
| **PhotoRec Carver** | Recover deleted files | Optional |
| **Virtual Machine Extractor** | Extract VM disk images | Optional |
| **Data Source Integrity** | Verify image hash | ✅ |

### Configure Hash Sets

1. **Tools → Options → Hash Sets**
2. Add NSRL (known good) hash set
3. Add known malware hash sets

**Hash Set Sources:**
- [NSRL](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download) (Known good)
- [VirusShare](https://virusshare.com/) (Known bad)
- [Malware Bazaar](https://bazaar.abuse.ch/export/) (Known bad)

### Configure Keyword Lists

1. **Tools → Options → Keyword Lists**
2. Add custom lists for:
   - IP addresses
   - Domain names
   - Email addresses
   - Malware indicators
   - Sensitive data patterns

---

## 🗂️ Navigating Autopsy

### Main Interface Areas

| Area | Purpose |
|------|---------|
| **Tree View (Left)** | Navigate data sources, results |
| **Result Viewer (Top Right)** | List of files/items |
| **Content Viewer (Bottom Right)** | View selected item |

### Tree View Sections

```
Data Sources
├── [Disk Image Name]
│   ├── File Views
│   │   ├── File Types (by extension)
│   │   ├── Deleted Files
│   │   └── File Size
│   └── Data Artifacts
│       ├── Web History
│       ├── Web Downloads
│       ├── Recent Documents
│       └── Installed Programs
│
├── Views
│   ├── File Types
│   └── Deleted Files
│
├── Results
│   ├── Extracted Content
│   │   ├── Web History
│   │   ├── Web Bookmarks
│   │   ├── Web Cookies
│   │   ├── Web Downloads
│   │   └── Recent Documents
│   ├── Keyword Hits
│   ├── Hashset Hits
│   ├── Email Messages
│   └── Interesting Items
│
└── Tags
    ├── Follow Up
    ├── Notable Item
    └── [Custom Tags]
```

---

## 🔍 Analysis Techniques

### File System Analysis

**View All Files:**
1. Expand **Data Sources → [Image] → File Views**
2. Browse by file type, size, or path

**Find Deleted Files:**
1. Navigate to **File Views → Deleted Files**
2. Or use **Views → Deleted Files**

**File Metadata:**
1. Select a file
2. View **File Metadata** tab in Content Viewer
3. Check: Created, Modified, Accessed, Changed times

### Keyword Searching

**Create Search:**
1. Click **Keyword Search** (magnifying glass icon)
2. Enter search term or regex
3. Select **Exact Match**, **Substring**, or **Regex**
4. Click **Search**

**Useful Keywords for IR:**
- `password`, `credential`, `secret`
- `base64`, `powershell -enc`
- `mimikatz`, `procdump`, `psexec`
- IP addresses: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`
- Email: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`

### Timeline Analysis

**Generate Timeline:**
1. **Tools → Timeline**
2. Select time range
3. Choose event types to include

**Timeline Features:**
- Filter by file type, path, event type
- Zoom to specific time periods
- Export events for external analysis

**What to Look For:**
- Cluster of activity around suspected compromise time
- File creations in unusual locations
- Execution artifacts (prefetch) timing
- Gaps in activity (potential log clearing)

### Web Artifact Analysis

**Browser History:**
1. **Results → Extracted Content → Web History**
2. Review URLs, visit times, visit counts

**Downloads:**
1. **Results → Extracted Content → Web Downloads**
2. Look for suspicious downloads

**Cookies:**
1. **Results → Extracted Content → Web Cookies**
2. Identify sites visited, session information

### Registry Analysis

**View Registry:**
1. **Data Artifacts → Operating System Information**
2. Or navigate to registry files in file system
3. Use **Application → Registry Viewer** in Content Viewer

**Key Registry Locations:**
| Location | Information |
|----------|-------------|
| `SAM` | User accounts |
| `SECURITY` | Security settings |
| `SOFTWARE` | Installed software, settings |
| `SYSTEM` | System configuration, services |
| `NTUSER.DAT` | User-specific settings |
| `UsrClass.dat` | User shell settings |

### Hash Analysis

**View Hash Hits:**
1. **Results → Hashset Hits**
2. Review files matching known bad hashes

**Calculate Hash:**
1. Right-click file → **View File in Directory**
2. Check MD5/SHA1/SHA256 in File Metadata

**Search VirusTotal:**
1. Right-click file → **Search Online**
2. Opens VirusTotal search for hash

---

## 🏷️ Tagging and Bookmarking

### Create Tags

1. Right-click item → **Add Tag**
2. Select existing tag or create new
3. Common tags:
   - `Follow Up` - Needs more investigation
   - `Notable Item` - Important finding
   - `Malware` - Confirmed malicious
   - `Exfiltration` - Data theft indicator
   - `Persistence` - Persistence mechanism

### Add Comments

1. Right-click item → **Add Comment**
2. Enter notes about the item
3. Comments appear in reports

---

## 📊 Reporting

### Generate Report

1. **Tools → Generate Report**
2. Select report type:
   - **HTML Report** - Best for sharing
   - **Excel Report** - For data analysis
   - **KML Report** - For geolocation data
   - **Portable Case** - Share case with another analyst

### Report Options

| Option | Description |
|--------|-------------|
| Tagged Results | Only tagged items |
| All Results | Everything found |
| Specific Data Types | Select what to include |

### Export Artifacts

**Export Files:**
1. Right-click file → **Extract File(s)**
2. Choose destination

**Export Timeline:**
1. **Tools → Timeline**
2. **File → Export → CSV**

---

## 🔬 Advanced Autopsy Features

### Data Source Processors

**Add Custom Ingest Module:**
1. **Tools → Options → Ingest**
2. Modules can be added via plugins

### Python Plugins

Autopsy supports Python plugins for custom analysis:

```python
# Example: Custom file analyzer
from org.sleuthkit.autopsy.ingest import IngestModule

class CustomAnalyzer(IngestModule):
    def process(self, file):
        # Custom analysis logic
        pass
```

### Central Repository

For multi-case correlation:

1. **Tools → Options → Central Repository**
2. Enable and configure database
3. Correlates artifacts across cases

### Communication Visualization

1. **Tools → Communications**
2. Visualize email, call, message relationships
3. Useful for understanding connections

---

## 📚 Common Investigation Workflows

### Workflow 1: Malware Investigation

```
1. Create case, add disk image
2. Enable ingest modules (especially hash lookup, interesting files)
3. Check Results → Hashset Hits for known malware
4. Search keywords: malware names, C2 domains
5. Review Extracted Content → Web Downloads
6. Check File Views → Deleted Files for removed malware
7. Timeline analysis around infection time
8. Export malicious files for further analysis
```

### Workflow 2: Data Theft Investigation

```
1. Create case, add disk image
2. Enable Recent Activity module
3. Review Web History and Downloads
4. Search keywords: competitor names, project names
5. Check for cloud storage usage (OneDrive, Dropbox)
6. Review USB device history (registry)
7. Check email artifacts
8. Timeline analysis for data access patterns
```

### Workflow 3: KAPE + Autopsy Combined

```
1. Collect artifacts with KAPE (!SANS_Triage)
2. Process with KAPE modules (!EZParser)
3. Create Autopsy case
4. Add KAPE collection as Logical Files data source
5. Run relevant ingest modules
6. Cross-reference KAPE CSV output with Autopsy findings
7. Generate comprehensive report
```

---

## ❗ Troubleshooting

### Autopsy Won't Start

```powershell
# Check Java version
java -version

# Clear cache (Windows)
Remove-Item -Recurse "$env:APPDATA\.autopsy"
```

### Slow Performance

1. Increase Java heap in `autopsy.conf`
2. Disable unnecessary ingest modules
3. Use SSD for case storage
4. Process large images overnight

### Image Won't Load

1. Verify image integrity (hash)
2. Try different image format
3. Check disk space
4. Mount image externally and add as logical files

### Missing Artifacts

1. Verify ingest modules completed (check progress)
2. Re-run specific ingest modules
3. Check if artifact type is supported
4. Manual navigation to known locations

---

## 📚 Additional Resources

### Documentation

- [Autopsy User Documentation](https://sleuthkit.org/autopsy/docs/user-docs/4.19.3/)
- [KAPE Documentation](https://ericzimmerman.github.io/KapeDocs/)
- [SANS DFIR Resources](https://www.sans.org/blog/dfir-resources/)

### Training

- [Autopsy Training](https://www.autopsy.com/support/training/)
- [SANS FOR500/FOR508](https://www.sans.org/cyber-security-courses/)
- [13Cubed YouTube](https://www.youtube.com/c/13Cubed)

### Tools

- [Eric Zimmerman Tools](https://ericzimmerman.github.io/)
- [Arsenal Image Mounter](https://arsenalrecon.com/products/arsenal-image-mounter)
- [FTK Imager](https://www.exterro.com/ftk-imager)

---

## 🗂️ Quick Reference

### KAPE Commands

| Command | Purpose |
|---------|---------|
| `kape.exe --tlist` | List targets |
| `kape.exe --mlist` | List modules |
| `kape.exe --sync` | Download module binaries |
| `kape.exe --tsource C: --tdest E:\Out --target !SANS_Triage` | Collect triage |
| `kape.exe --msource E:\Out --mdest E:\Parsed --module !EZParser` | Process artifacts |

### KAPE Essential Targets

| Target | Description |
|--------|-------------|
| `!SANS_Triage` | Comprehensive collection |
| `!BasicCollection` | Minimal triage |
| `EventLogs` | Windows Event Logs |
| `RegistryHives` | Registry files |
| `WebBrowsers` | All browsers |
| `FileSystem` | $MFT, $J, etc. |

### Autopsy Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+F` | Find in current view |
| `Ctrl+Shift+F` | Keyword search |
| `Ctrl+T` | Add tag |
| `Ctrl+G` | Generate report |

### Key File Locations (Windows)

| Artifact | Path |
|----------|------|
| Event Logs | `C:\Windows\System32\winevt\Logs\` |
| Registry (System) | `C:\Windows\System32\config\` |
| Registry (User) | `C:\Users\<user>\NTUSER.DAT` |
| Prefetch | `C:\Windows\Prefetch\` |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` |
| Browser (Chrome) | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\` |
| Recent Files | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\` |

---

*Part of the Incident Response & Log Aggregation Branch*
