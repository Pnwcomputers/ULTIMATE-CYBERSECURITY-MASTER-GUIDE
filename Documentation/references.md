# 📖 Security & Networking Reference Guide

## 🎯 Purpose
Quick-reference tables for port numbers (well-known, registered, dynamic), HTTP status codes, and regex patterns used in cybersecurity operations, penetration testing, network administration, and log analysis.

## ⚙️ Function
Three main reference tables: (1) Port numbers organized by service category (file transfer, email, web, database, remote access, security tools, IoT); (2) HTTP status codes by class (2xx success, 3xx redirect, 4xx client error, 5xx server error); (3) Regex patterns for IPs, emails, URLs, credentials, file paths, and common attack signatures.

## 🏆 Goal
Provide a single-file lookup for the most commonly needed port/protocol/regex facts during security assessments — eliminating the need to search IANA tables or MDN docs mid-engagement.

## 📋 When to Use
- Writing Nmap or Nessus scan filters requiring specific port ranges
- Interpreting HTTP response codes in web application pen testing
- Building Suricata/Zeek rules using regex patterns for credential or attack detection
- Quick lookup during log analysis or incident response triage

Quick-reference tables for port numbers, HTTP status codes, and regex patterns commonly used in cybersecurity operations, penetration testing, and network administration.

Part of the **ULTIMATE CYBERSECURITY MASTER GUIDE**

[![Documentation](https://img.shields.io/badge/Documentation-Cybersecurity%20Base-blue?style=for-the-badge&logo=googledocs&logoColor=white)]()
[![Knowledge Base](https://img.shields.io/badge/Category-Reference-green?style=for-the-badge&logo=gitbook&logoColor=white)]()
[![Cybersecurity Ops](https://img.shields.io/badge/Use-Security%20Operations-orange?style=for-the-badge&logo=fortinet&logoColor=white)]()

---

## 📋 Table of Contents
* [Port Numbers](#-port-numbers)
* [HTTP Status Codes](#-http-status-codes)
* [Regex Patterns](#-regex-patterns)
* [Legal Disclaimer](#-legal-disclaimer)

---

## 🔌 Port Numbers

### Well-Known Ports (0–1023)

#### File Transfer & Remote Access
| Port | Protocol | Service | Notes |
| ---: | :---: | :--- | :--- |
| 20 | TCP | FTP Data | Active mode data transfer |
| 21 | TCP | FTP Control | Command channel — often targeted |
| 22 | TCP | SSH | Secure shell — default, change in prod |
| 23 | TCP | Telnet | Cleartext — never use in prod |
| 69 | UDP | TFTP | Trivial FTP — no auth, common in IoT |
| 115 | TCP | SFTP | Simple FTP (not SSH SFTP) |
| 139 | TCP | NetBIOS | SMB over NetBIOS |
| 445 | TCP | SMB | Direct SMB — EternalBlue target |
| 3389 | TCP | RDP | Remote Desktop — high-value attack surface |
| 5900 | TCP | VNC | Remote framebuffer — often unencrypted |

#### Web & Application
| Port | Protocol | Service | Notes |
| ---: | :---: | :--- | :--- |
| 80 | TCP | HTTP | Plaintext web — redirect to 443 in prod |
| 443 | TCP | HTTPS | TLS-encrypted web |
| 8080 | TCP | HTTP Alt | Common dev/proxy port |
| 8443 | TCP | HTTPS Alt | Common alt TLS port |
| 8888 | TCP | HTTP Alt | Jupyter, dev servers |
| 3000 | TCP | HTTP Dev | Node.js, Grafana default |
| 4443 | TCP | HTTPS Alt | Cobalt Strike default listener |
| 9090 | TCP | HTTP | Prometheus, Cockpit |
| 10000 | TCP | Webmin | Web-based sysadmin |

#### Email
| Port | Protocol | Service | Notes |
| ---: | :---: | :--- | :--- |
| 25 | TCP | SMTP | Mail transfer — often blocked by ISPs |
| 110 | TCP | POP3 | Cleartext mail retrieval |
| 143 | TCP | IMAP | Cleartext mail access |
| 465 | TCP | SMTPS | SMTP over SSL |
| 587 | TCP | SMTP Submission | Auth SMTP — preferred for sending |
| 993 | TCP | IMAPS | IMAP over SSL |
| 995 | TCP | POP3S | POP3 over SSL |

#### DNS & Network Services
| Port | Protocol | Service | Notes |
| ---: | :---: | :--- | :--- |
| 53 | TCP/UDP | DNS | UDP for queries, TCP for zone transfers |
| 67 | UDP | DHCP Server | |
| 68 | UDP | DHCP Client | |
| 123 | UDP | NTP | Time sync — spoof/amplification target |
| 161 | UDP | SNMP | Community strings often default |
| 162 | UDP | SNMP Trap | |
| 500 | UDP | IKE | IPsec key exchange |
| 4500 | UDP | IPsec NAT-T | IPsec through NAT |

#### Directory & Authentication
| Port | Protocol | Service | Notes |
| ---: | :---: | :--- | :--- |
| 88 | TCP/UDP | Kerberos | AD authentication — AS-REP roasting target |
| 389 | TCP/UDP | LDAP | Directory services — cleartext |
| 464 | TCP/UDP | Kerberos Change | Password change |
| 636 | TCP | LDAPS | LDAP over SSL |
| 3268 | TCP | Global Catalog | AD GC — LDAP |
| 3269 | TCP | Global Catalog SSL | AD GC over SSL |

---

### Registered Ports (1024–49151) — Security Relevant

| Port | Protocol | Service | Notes |
| ---: | :---: | :--- | :--- |
| 1080 | TCP | SOCKS Proxy | Often abused for tunneling |
| 1194 | UDP | OpenVPN | Default OpenVPN port |
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Oracle database |
| 1723 | TCP | PPTP | VPN — deprecated, weak crypto |
| 2049 | TCP/UDP | NFS | Network File System |
| 2375 | TCP | Docker | Unencrypted Docker API — critical misconfig |
| 2376 | TCP | Docker TLS | Encrypted Docker API |
| 3306 | TCP | MySQL/MariaDB | Database — never expose publicly |
| 4444 | TCP | Metasploit | Default Meterpreter listener |
| 4899 | TCP | Radmin | Remote admin tool |
| 5000 | TCP | Flask/Docker | Common dev port, Docker registry |
| 5432 | TCP | PostgreSQL | Database |
| 5555 | TCP | ADB | Android Debug Bridge |
| 5601 | TCP | Kibana | ELK Stack UI |
| 6379 | TCP | Redis | Often unauthenticated by default |
| 6443 | TCP | Kubernetes API | K8s control plane |
| 7001 | TCP | WebLogic | Oracle WebLogic — frequent CVEs |
| 8009 | TCP | AJP | Apache JServ — Ghostcat (CVE-2020-1938) |
| 8161 | TCP | ActiveMQ Web | ActiveMQ admin console |
| 8500 | TCP | Consul | HashiCorp Consul |
| 9000 | TCP | SonarQube/PHP-FPM | |
| 9200 | TCP | Elasticsearch | Often unauthenticated — data exposure risk |
| 9300 | TCP | Elasticsearch | Node communication |
| 11211 | TCP/UDP | Memcached | Cache — DDoS amplification target |
| 15672 | TCP | RabbitMQ Web | Management console |
| 27017 | TCP | MongoDB | Database — unauthenticated by default historically |
| 47808 | UDP | BACnet | Building automation — ICS/SCADA |
| 50000 | TCP | SAP | SAP application server |
| 51820 | UDP | WireGuard | WireGuard VPN default |

---

### Common C2 & Attack Framework Ports

> ⚠️ These ports are commonly used by attack frameworks — useful for detection rules and firewall analysis.

| Port | Tool / Framework | Direction | Notes |
| ---: | :--- | :--- | :--- |
| 4444 | Metasploit | Inbound | Default Meterpreter reverse shell |
| 5555 | Metasploit | Inbound | Alt Meterpreter |
| 6666 | Various RATs | Inbound | Common RAT listener |
| 1337 | Various | Both | Common "leet" port |
| 4443 | Cobalt Strike | Inbound | Default HTTPS listener |
| 8080 | Cobalt Strike | Inbound | Default HTTP listener |
| 50050 | Cobalt Strike | Inbound | Team server |
| 2222 | Various | Inbound | Alt SSH / shells |
| 31337 | Back Orifice | Inbound | Classic RAT |
| 1604 | Havoc C2 | Inbound | Default Havoc listener |
| 40056 | Sliver C2 | Both | Default Sliver mTLS |

---

### Port Scanning Quick Reference

~~~bash
# Top 1000 ports (default)
nmap <target>

# All 65535 ports
nmap -p- <target>

# Specific ports
nmap -p 22,80,443,3389 <target>

# Service/version detection
nmap -sV -sC <target>

# UDP scan (requires root)
sudo nmap -sU --top-ports 100 <target>

# Fast scan — top 100
nmap -F <target>

# OS detection
sudo nmap -O <target>

# Aggressive (OS + version + scripts + traceroute)
sudo nmap -A <target>

# Through proxychains (TCP connect only)
proxychains4 nmap -sT -Pn <target>
~~~

---

## 🌐 HTTP Status Codes

### 1xx — Informational
| Code | Name | Notes |
| ---: | :--- | :--- |
| 100 | Continue | Server received request headers, client should proceed |
| 101 | Switching Protocols | WebSocket upgrade |
| 102 | Processing | WebDAV — server processing, no response yet |

### 2xx — Success
| Code | Name | Notes |
| ---: | :--- | :--- |
| 200 | OK | Standard success |
| 201 | Created | Resource created (POST/PUT) |
| 202 | Accepted | Request accepted, processing async |
| 204 | No Content | Success, no body (DELETE responses) |
| 206 | Partial Content | Range requests — file download resuming |

### 3xx — Redirection
| Code | Name | Security Notes |
| ---: | :--- | :--- |
| 301 | Moved Permanently | Permanent redirect — watch for open redirects |
| 302 | Found | Temporary redirect — common open redirect vector |
| 303 | See Other | POST → GET redirect after form submit |
| 304 | Not Modified | Cached response — ETag/If-Modified-Since |
| 307 | Temporary Redirect | Preserves HTTP method — use over 302 |
| 308 | Permanent Redirect | Preserves HTTP method — use over 301 |

### 4xx — Client Errors
| Code | Name | Security Notes |
| ---: | :--- | :--- |
| 400 | Bad Request | Malformed request — check for WAF bypass opportunities |
| 401 | Unauthorized | Auth required — credentials not provided |
| 403 | Forbidden | Auth OK, access denied — check for IDOR/path traversal |
| 404 | Not Found | Resource missing — directory brute-force indicator |
| 405 | Method Not Allowed | Try other HTTP verbs (PUT, DELETE, OPTIONS) |
| 406 | Not Acceptable | Content negotiation failure |
| 408 | Request Timeout | |
| 409 | Conflict | State conflict — useful in race condition testing |
| 410 | Gone | Permanently removed |
| 413 | Payload Too Large | File upload size limit — tune for bypass |
| 415 | Unsupported Media Type | Change Content-Type header |
| 418 | I'm a Teapot | Easter egg (RFC 2324) |
| 422 | Unprocessable Entity | Validation error — inspect input handling |
| 425 | Too Early | Early data replay risk |
| 429 | Too Many Requests | Rate limiting — slow down or rotate IPs |

### 5xx — Server Errors
| Code | Name | Security Notes |
| ---: | :--- | :--- |
| 500 | Internal Server Error | Possible injection point — check for stack traces |
| 501 | Not Implemented | HTTP method not supported |
| 502 | Bad Gateway | Upstream failure — proxy/LB misconfiguration |
| 503 | Service Unavailable | Overloaded or maintenance — DoS indicator |
| 504 | Gateway Timeout | Upstream timeout |
| 505 | HTTP Version Not Supported | |

### HTTP Methods Quick Reference
| Method | Purpose | Security Notes |
| :--- | :--- | :--- |
| GET | Retrieve resource | Should be idempotent, no side effects |
| POST | Submit data | CSRF target — check for token |
| PUT | Replace resource | May allow unauthorized file write |
| PATCH | Partial update | Check authorization on partial updates |
| DELETE | Remove resource | Check authorization — IDOR risk |
| OPTIONS | List allowed methods | Information disclosure — enumerate in recon |
| HEAD | GET without body | Useful for stealthy recon |
| TRACE | Echo request | XST attack vector — should be disabled |
| CONNECT | Tunnel (proxy) | Proxy abuse — SSRF pivot |

---

## 🔍 Regex Patterns

### Network & Infrastructure
~~~
# IPv4 address
^(\d{1,3}\.){3}\d{1,3}$

# IPv4 with CIDR
^(\d{1,3}\.){3}\d{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$

# IPv6 address (simplified)
^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$

# MAC address (colon-separated)
^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$

# MAC address (hyphen-separated)
^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$

# Port number (0–65535)
^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$

# Domain name
^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$

# Subdomain extraction
(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}

# URL (http/https)
https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/=]*)

# .onion address (v3)
[a-z2-7]{56}\.onion

# Email address
^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$
~~~

### Credentials & Secrets Detection
~~~
# AWS Access Key ID
AKIA[0-9A-Z]{16}

# AWS Secret Access Key
[0-9a-zA-Z/+]{40}

# Generic API key (common pattern)
[aA][pP][iI]_?[kK][eE][yY].*['"][0-9a-zA-Z]{32,}['"]

# Generic secret/password in config
(secret|password|passwd|pwd|token|api_key)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?

# Base64 encoded string
^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$

# JWT token
^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$

# Private key header
-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----

# MD5 hash
^[a-fA-F0-9]{32}$

# SHA1 hash
^[a-fA-F0-9]{40}$

# SHA256 hash
^[a-fA-F0-9]{64}$

# NTLM hash (LM:NT format)
^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$

# bcrypt hash
^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$
~~~

### Log Analysis & SIEM
~~~
# Syslog timestamp (RFC 3164)
^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}

# ISO 8601 datetime
\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})

# Windows Event ID in logs
EventID\s*[=:]\s*(\d{4})

# Failed login (generic)
(fail|failed|failure|invalid|incorrect|bad)\s+(login|password|credential|auth)

# SQL error strings (potential SQLi indicator)
(SQL syntax|mysql_fetch|ORA-\d{5}|Microsoft OLE DB|ODBC SQL Server|Unclosed quotation)

# XSS indicators in logs
(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)

# Directory traversal attempt
(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)

# Common web shell filenames
(c99|r57|shell|cmd|eval|base64_decode)\.(php|asp|aspx|jsp)

# User-Agent — common scanners
(sqlmap|nikto|nmap|masscan|nessus|openvas|burp|zgrab|nuclei|dirbuster|gobuster)
~~~

### Input Validation (for Secure Coding Reference)
~~~
# Strong password (min 8 chars, upper, lower, digit, special)
^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&\-_])[A-Za-z\d@$!%*?&\-_]{8,}$

# Username (alphanumeric + underscore, 3–32 chars)
^[a-zA-Z0-9_]{3,32}$

# US phone number
^\+?1?\s*\(?[0-9]{3}\)?[\s.\-]?[0-9]{3}[\s.\-]?[0-9]{4}$

# US ZIP code
^\d{5}(-\d{4})?$

# Credit card number (basic Luhn-check pattern, no spaces)
^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$

# SSN (for detection/masking — US)
^\d{3}-\d{2}-\d{4}$

# UUID / GUID
^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$
~~~

### grep / sed / awk Practical One-Liners
~~~bash
# Extract all IPs from a file
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' file.txt | sort -u

# Extract all emails from a file
grep -oE '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}' file.txt | sort -u

# Extract all URLs from a file
grep -oE 'https?://[^ ]+' file.txt | sort -u

# Extract all domains from a file
grep -oE '([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}' file.txt | sort -u

# Find lines with potential API keys
grep -iE '(api_key|apikey|secret|token)\s*[=:]\s*["\x27]?[a-zA-Z0-9]{16,}' file.txt

# Find Base64 blobs in a file
grep -oE '([A-Za-z0-9+/]{40,}={0,2})' file.txt

# Strip ANSI color codes from output
sed 's/\x1b\[[0-9;]*m//g'

# Extract HTTP status codes from access log
awk '{print $9}' access.log | sort | uniq -c | sort -rn

# Count unique IPs in access log
awk '{print $1}' access.log | sort -u | wc -l

# Find top 10 requesting IPs
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10

# Extract failed SSH logins from auth.log
grep "Failed password" /var/log/auth.log | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn
~~~

---

## 📃 Wordlists & Reference Files

| File | Description | Use Case |
| :--- | :--- | :--- |
| [`subdomains.txt`](./subdomains.txt) | Curated subdomain wordlist for enumeration and discovery | Subdomain brute-forcing, recon, attack surface mapping |

### Usage Examples

**With `gobuster`:**
~~~bash
gobuster dns -d target.com -w subdomains.txt -t 50
~~~

**With `ffuf`:**
~~~bash
ffuf -w subdomains.txt -u https://FUZZ.target.com -mc 200,301,302,403
~~~

**With `amass`:**
~~~bash
amass enum -brute -w subdomains.txt -d target.com
~~~

**With `dnsx`:**
~~~bash
dnsx -l subdomains.txt -d target.com -resp
~~~

**With `subfinder` (custom resolvers):**
~~~bash
subfinder -d target.com -w subdomains.txt -o results.txt
~~~

---

## ⚠️ Legal Disclaimer

**IMPORTANT: AUTHORIZED USE ONLY**

This reference material is provided for educational purposes, authorized security assessments, and legitimate network administration.

### 🚫 STRICTLY PROHIBITED:
* Scanning ports or systems without written authorization
* Using credential or secret patterns to harvest unauthorized data
* Applying attack signatures against systems you do not own

> **Legal Note:** Unauthorized port scanning and network reconnaissance may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws in your jurisdiction.

---

## 📚 Resources
* **IANA Port Registry:** [iana.org/assignments/service-names-port-numbers](https://www.iana.org/assignments/service-names-port-numbers)
* **MDN HTTP Status Codes:** [developer.mozilla.org/en-US/docs/Web/HTTP/Status](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)
* **regex101 (tester):** [regex101.com](https://regex101.com)
* **regexr (tester):** [regexr.com](https://regexr.com)
* **NMAP Reference:** [nmap.org/book/man.html](https://nmap.org/book/man.html)

---

## 📊 Document Statistics
* **Last Updated:** June 2026
* **Maintained by:** Pacific Northwest Computers (PNWC)
* **Status:** Active & Growing

---
## Related Files
- [wireshark.md](wireshark.md) — Wireshark filter reference; pairs with port numbers table for targeted captures
- [LinuxCheatSheet.md](LinuxCheatSheet.md) — Linux networking commands that reference the same ports listed here
- [Aircrack-ng_Commands.md](Aircrack-ng_Commands.md) — Uses port/protocol knowledge for identifying captured traffic types

**Use This Knowledge Responsibly: Always Obtain Authorization**
