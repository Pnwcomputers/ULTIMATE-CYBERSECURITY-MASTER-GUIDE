# 🔓 Unauthorized Access Investigation Playbook

This playbook provides step-by-step procedures for investigating unauthorized access incidents, with a focus on **brute force attacks** and **impossible travel alerts**. These are common indicators of credential compromise and account takeover attempts.

---

## 📋 Playbook Overview

| Attribute | Details |
|-----------|---------|
| **Incident Type** | Unauthorized Access |
| **Sub-Types** | Brute Force, Impossible Travel, Credential Stuffing |
| **Severity** | Medium to Critical (context-dependent) |
| **MITRE ATT&CK** | T1110 (Brute Force), T1078 (Valid Accounts) |
| **Typical Sources** | SIEM alerts, Azure AD, Okta, Firewall, VPN logs |

### Scope

This playbook covers:
- Brute force attacks (password spraying, credential stuffing)
- Impossible travel alerts (geographically impossible logins)
- Account compromise indicators
- Investigation and containment procedures

---

## 🚨 Part 1: Alert Triage

### 1.1 Initial Alert Assessment

When an alert fires, gather the following information:

| Field | Description | Example |
|-------|-------------|---------|
| **Alert Type** | Brute force or Impossible travel | `Multiple failed logins` |
| **Target Account** | Username/UPN affected | `jsmith@company.com` |
| **Source IP(s)** | Attacking IP address(es) | `185.234.72.19` |
| **Timestamp** | When the activity occurred | `2024-01-15 14:23:00 UTC` |
| **Authentication Method** | Protocol used | `RDP, OWA, VPN, SSH` |
| **Success/Failure** | Did any attempts succeed? | `47 failures, 1 success` |
| **Target System** | What was being accessed | `VPN Gateway, O365` |

### 1.2 Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| **Critical** | Successful login after failures, privileged account, sensitive system | Immediate |
| **High** | Ongoing attack, multiple accounts targeted, executive account | < 1 hour |
| **Medium** | Failed attempts only, single account, non-sensitive system | < 4 hours |
| **Low** | Known scanner, honeypot trigger, non-production | < 24 hours |

### 1.3 Quick Triage Questions

Answer these to determine priority:

```
□ Did any authentication attempt succeed?
□ Is the targeted account privileged (admin, executive)?
□ Is the attack still ongoing?
□ Are multiple accounts being targeted?
□ Is the source IP internal or external?
□ Does the account have MFA enabled?
□ Has this account been compromised before?
□ Is there any post-authentication suspicious activity?
```

**If YES to any of the first four questions → Escalate immediately**

---

## 🔨 Part 2: Brute Force Investigation

### 2.1 Understanding Brute Force Attacks

| Attack Type | Description | Detection Pattern |
|-------------|-------------|-------------------|
| **Traditional Brute Force** | Many passwords against one account | High failures, single user |
| **Password Spraying** | One password against many accounts | Low failures per user, many users |
| **Credential Stuffing** | Leaked credentials tested | Varied patterns, known breach data |
| **Dictionary Attack** | Common passwords tried | Sequential common passwords |

### 2.2 Data Collection

#### Windows Event Logs

```
Event ID 4625 - Failed logon
Event ID 4624 - Successful logon
Event ID 4771 - Kerberos pre-auth failed
Event ID 4776 - NTLM authentication
Event ID 4768 - Kerberos TGT requested
Event ID 4769 - Kerberos service ticket requested
```

**Splunk Query - Failed Logins:**

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address, Failure_Reason
| where count > 5
| sort -count
```

**Splunk Query - Successful Login After Failures:**

```spl
index=windows sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| transaction Account_Name maxspan=30m
| where eventcount > 5 AND match(EventCode, "4624")
| table _time, Account_Name, Source_Network_Address, eventcount
```

**ELK/KQL Query - Failed Logins:**

```kql
winlog.event_id:4625 
| stats count() by winlog.event_data.TargetUserName, source.ip
| where count > 5
```

**Wazuh Query:**

```
rule.id:18106 OR rule.id:18107
```

#### Azure AD / Entra ID

**Sign-in Logs Location:**
- Azure Portal → Azure Active Directory → Sign-in logs
- Or via Microsoft Graph API

**Key Fields:**
- `userPrincipalName`
- `ipAddress`
- `location`
- `status.errorCode`
- `status.failureReason`
- `clientAppUsed`
- `deviceDetail`

**Azure AD Error Codes:**

| Error Code | Meaning |
|------------|---------|
| 50126 | Invalid username or password |
| 50053 | Account locked |
| 50057 | Account disabled |
| 50055 | Password expired |
| 50074 | MFA required |
| 53003 | Blocked by Conditional Access |
| 50158 | External security challenge (MFA) |

**KQL Query (Azure Sentinel):**

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "50126"
| summarize FailureCount=count(), 
            SuccessCount=countif(ResultType == 0),
            IPAddresses=make_set(IPAddress)
            by UserPrincipalName
| where FailureCount > 10
| sort by FailureCount desc
```

#### Linux/SSH

**Auth Log Location:** `/var/log/auth.log` or `/var/log/secure`

**grep for failed SSH:**

```bash
# Failed SSH attempts
grep "Failed password" /var/log/auth.log | tail -100

# Extract IPs with failure counts
grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Successful logins
grep "Accepted" /var/log/auth.log | tail -50
```

**Splunk Query:**

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, user
| where count > 5
```

### 2.3 Source IP Analysis

For each attacking IP, investigate:

#### Step 1: Geolocation and Reputation

```bash
# Using command line
curl -s "https://ipinfo.io/185.234.72.19" | jq

# Check AbuseIPDB
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=185.234.72.19" \
  -H "Key: YOUR_API_KEY" | jq

# Check VirusTotal
curl -s "https://www.virustotal.com/api/v3/ip_addresses/185.234.72.19" \
  -H "x-apikey: YOUR_API_KEY" | jq
```

**Online Tools:**
- [AbuseIPDB](https://www.abuseipdb.com/)
- [VirusTotal](https://www.virustotal.com/)
- [IPVoid](https://www.ipvoid.com/)
- [Shodan](https://www.shodan.io/)
- [GreyNoise](https://www.greynoise.io/)

#### Step 2: Document IP Intelligence

| Field | Finding |
|-------|---------|
| IP Address | |
| Country/City | |
| ISP/ASN | |
| Known VPN/Proxy? | |
| Known Tor Exit? | |
| Abuse Reports | |
| Threat Intel Match | |
| Historical Activity | |

#### Step 3: Check Internal Activity

Has this IP accessed anything else?

```spl
index=* src_ip="185.234.72.19" OR dest_ip="185.234.72.19"
| stats count by index, sourcetype, action
```

### 2.4 Account Analysis

For each targeted account:

#### Step 1: Account Information

```powershell
# Active Directory
Get-ADUser -Identity jsmith -Properties *

# Azure AD (PowerShell)
Get-AzureADUser -ObjectId jsmith@company.com | Format-List
```

**Document:**
- Account type (standard, admin, service)
- Department / Manager
- Last password change
- MFA status
- Group memberships
- Recent activity

#### Step 2: Check for Successful Compromise

**Did the attacker get in?**

```spl
# Windows - Success after failures from same IP
index=windows sourcetype="WinEventLog:Security" EventCode=4624 
  Account_Name="jsmith" Source_Network_Address="185.234.72.19"
| table _time, Account_Name, Logon_Type, Source_Network_Address
```

```kql
# Azure AD - Success after failures
SigninLogs
| where UserPrincipalName == "jsmith@company.com"
| where ResultType == 0
| where TimeGenerated > ago(24h)
| project TimeGenerated, IPAddress, Location, AppDisplayName, DeviceDetail
```

#### Step 3: Post-Compromise Activity

If successful login detected, investigate:

```spl
# All activity from compromised account
index=* user="jsmith" OR Account_Name="jsmith"
| timechart span=1h count by sourcetype
```

**Check for:**
- [ ] Email forwarding rules created
- [ ] Mailbox delegation changes
- [ ] Password reset attempts
- [ ] MFA changes
- [ ] OAuth app consents
- [ ] File access/downloads
- [ ] Lateral movement attempts
- [ ] Privilege escalation

### 2.5 Brute Force Investigation Checklist

```
INITIAL ASSESSMENT
□ Identify all targeted accounts
□ Determine attack timeframe
□ Identify source IP(s)
□ Check if any attempts succeeded
□ Determine attack type (spray, stuff, traditional)

SOURCE ANALYSIS
□ Geolocate attacking IP(s)
□ Check threat intelligence
□ Identify VPN/Proxy/Tor usage
□ Check for other internal activity from IP
□ Determine if distributed attack (multiple IPs)

ACCOUNT ANALYSIS
□ Review account privileges
□ Check MFA status
□ Verify account owner
□ Check for successful authentication
□ Review post-authentication activity

SCOPE DETERMINATION
□ Are multiple accounts targeted?
□ Is this part of a larger campaign?
□ Are other organizations being hit? (threat intel)
□ How long has this been occurring?
```

---

## 🌍 Part 3: Impossible Travel Investigation

### 3.1 Understanding Impossible Travel

Impossible travel alerts trigger when a user authenticates from two geographic locations in a timeframe that makes physical travel impossible.

**Example:**
- Login from New York at 10:00 AM
- Login from Moscow at 10:30 AM
- Distance: ~4,600 miles
- Time elapsed: 30 minutes
- **Physically impossible**

### 3.2 Alert Context

| Factor | Consideration |
|--------|---------------|
| **Time difference** | How far apart were the logins? |
| **Distance** | How far apart are the locations? |
| **Travel speed required** | Would require > 500 mph? |
| **VPN usage** | Corporate VPN can cause false positives |
| **Proxy/Anonymizer** | User may be using privacy tools |
| **Mobile device** | Could be traveling |
| **Shared account** | Multiple users on one account |

### 3.3 Data Collection

#### Azure AD Impossible Travel

**Azure Portal:**
1. Azure Active Directory → Security → Risky sign-ins
2. Filter by risk type: "Impossible travel"

**KQL Query:**

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskEventTypes_V2 contains "impossibleTravel"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, 
          AppDisplayName, RiskLevelDuringSignIn, RiskDetail
| sort by TimeGenerated desc
```

**Get Full Context:**

```kql
let suspectUser = "jsmith@company.com";
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == suspectUser
| project TimeGenerated, IPAddress, Location, City=tostring(LocationDetails.city),
          Country=tostring(LocationDetails.countryOrRegion),
          AppDisplayName, ClientAppUsed, DeviceDetail, ResultType
| sort by TimeGenerated asc
```

#### Okta Impossible Travel

**Okta System Log Query:**

```
eventType eq "user.session.start" and actor.alternateId eq "jsmith@company.com"
```

**Key Fields:**
- `client.ipAddress`
- `client.geographicalContext`
- `authenticationContext`
- `outcome.result`

#### On-Premises Systems

**VPN Logs:**

```spl
index=vpn user="jsmith"
| table _time, user, src_ip, src_country, action
| sort _time
```

**Correlate with other auth sources:**

```spl
index=* (user="jsmith" OR Account_Name="jsmith") 
  (EventCode=4624 OR action=success OR status=success)
| table _time, index, sourcetype, src_ip, action
| sort _time
```

### 3.4 Investigation Steps

#### Step 1: Map the Timeline

Create a timeline of all authentications:

| Time (UTC) | Location | IP Address | Application | Device | Result |
|------------|----------|------------|-------------|--------|--------|
| 10:00:00 | New York, US | 203.0.113.50 | O365 | Windows/Chrome | Success |
| 10:30:00 | Moscow, RU | 185.234.72.19 | O365 | Unknown | Success |
| 10:32:00 | Moscow, RU | 185.234.72.19 | SharePoint | Unknown | Success |

#### Step 2: Calculate Travel Feasibility

```
Distance between locations: ~4,600 miles
Time between logins: 30 minutes
Required speed: 9,200 mph (impossible)
```

**Online Calculator:** [Distance Calculator](https://www.timeanddate.com/worldclock/distanceresult.html)

#### Step 3: Analyze Each Location

**Location 1 (Expected):**
- Is this the user's normal location?
- Is the IP from corporate network/VPN?
- Is the device known/managed?

**Location 2 (Suspicious):**
- Run IP through threat intelligence
- Check if VPN/Proxy/Tor
- Check device details
- Is this location associated with attacks?

#### Step 4: Contact the User

**Questions to ask:**

```
1. Were you traveling on [date]?
2. Do you use any VPN services (personal or corporate)?
3. Did you share your credentials with anyone?
4. Do you recognize a login from [location] at [time]?
5. Have you received any suspicious emails recently?
6. Did you click on any links or enter credentials anywhere unusual?
```

**Important:** Contact via known-good channel (phone call, in-person), not email.

#### Step 5: Determine Verdict

| Scenario | Verdict | Action |
|----------|---------|--------|
| User confirms using VPN | Benign | Document, tune detection |
| User was traveling with mobile | Benign | Document |
| User denies activity, unknown device | Compromised | Contain immediately |
| Corporate VPN caused both IPs | False Positive | Tune detection |
| User clicked phishing link | Compromised | Contain, investigate phishing |

### 3.5 Impossible Travel Investigation Checklist

```
INITIAL ASSESSMENT
□ Document both login locations and times
□ Calculate distance and required travel speed
□ Identify applications accessed from each location
□ Note device details for each login

LOCATION ANALYSIS
□ Analyze Location 1 (expected location)
  □ Corporate IP/VPN?
  □ Known device?
  □ Normal for this user?
□ Analyze Location 2 (suspicious location)
  □ IP reputation check
  □ VPN/Proxy/Tor?
  □ Device fingerprint
  □ Previous activity from this IP

USER VERIFICATION
□ Contact user via secure channel
□ Verify travel status
□ Confirm VPN usage
□ Review for phishing exposure

VERDICT DETERMINATION
□ Confirmed travel/VPN → False positive
□ Unknown activity, user denies → Compromise
□ User clicked phish → Compromise + phishing IR
```

---

## 🔒 Part 4: Containment

### 4.1 Immediate Actions (Confirmed Compromise)

#### Disable/Reset Account

**Active Directory:**

```powershell
# Disable account immediately
Disable-ADAccount -Identity jsmith

# Reset password
Set-ADAccountPassword -Identity jsmith -Reset -NewPassword (ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force)

# Force password change at next logon
Set-ADUser -Identity jsmith -ChangePasswordAtLogon $true
```

**Azure AD:**

```powershell
# Block sign-in
Set-AzureADUser -ObjectId jsmith@company.com -AccountEnabled $false

# Revoke all refresh tokens
Revoke-AzureADUserAllRefreshToken -ObjectId jsmith@company.com

# Reset password
$newPassword = ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force
Set-AzureADUserPassword -ObjectId jsmith@company.com -Password $newPassword -ForceChangePasswordNextLogin $true
```

**Via Azure Portal:**
1. Azure AD → Users → Select user
2. Click "Revoke sessions"
3. Click "Reset password"
4. Block sign-in if needed

#### Revoke Active Sessions

**Azure AD:**

```powershell
# Revoke all tokens
Revoke-AzureADUserAllRefreshToken -ObjectId jsmith@company.com
```

**On-Premises:**

```powershell
# Check for active sessions
query user /server:SERVER01

# Log off user
logoff <session_id> /server:SERVER01

# Reset Kerberos tickets (force re-auth)
klist purge -li 0x3e7
```

#### Block Attacking IP

**Firewall:**

```bash
# iptables
sudo iptables -A INPUT -s 185.234.72.19 -j DROP

# Windows Firewall
New-NetFirewallRule -DisplayName "Block Attacker" -Direction Inbound -Action Block -RemoteAddress 185.234.72.19
```

**Azure AD Conditional Access:**
1. Create Named Location with attacking IP
2. Create Conditional Access policy blocking that location

### 4.2 Extended Containment

#### Check for Persistence

**Email Rules (Exchange Online):**

```powershell
# Check inbox rules
Get-InboxRule -Mailbox jsmith@company.com | Format-List Name, Description, Enabled, ForwardTo, RedirectTo, DeleteMessage

# Remove suspicious rules
Remove-InboxRule -Mailbox jsmith@company.com -Identity "Suspicious Rule Name"
```

**Mailbox Forwarding:**

```powershell
# Check forwarding
Get-Mailbox -Identity jsmith@company.com | Format-List ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward

# Remove forwarding
Set-Mailbox -Identity jsmith@company.com -ForwardingAddress $null -ForwardingSmtpAddress $null
```

**Mailbox Delegation:**

```powershell
# Check delegation
Get-MailboxPermission -Identity jsmith@company.com | Where-Object {$_.IsInherited -eq $false}

# Check send-as
Get-RecipientPermission -Identity jsmith@company.com

# Check calendar delegation
Get-MailboxFolderPermission -Identity jsmith@company.com:\Calendar
```

**OAuth App Consents:**

```powershell
# List OAuth permissions
Get-AzureADUserOAuth2PermissionGrant -ObjectId jsmith@company.com

# Remove suspicious consent
Remove-AzureADOAuth2PermissionGrant -ObjectId <grant-id>
```

**Azure Portal:**
1. Azure AD → Users → Select user → Applications
2. Review and revoke suspicious app consents

#### MFA Verification

```powershell
# Check MFA status
Get-MsolUser -UserPrincipalName jsmith@company.com | Select-Object DisplayName, StrongAuthenticationRequirements, StrongAuthenticationMethods

# Check authentication methods (Microsoft Graph)
Get-MgUserAuthenticationMethod -UserId jsmith@company.com
```

**If MFA was bypassed, investigate:**
- Was attacker able to register new MFA device?
- Was there SIM swapping involved?
- Was a phishing kit used that captures MFA?

### 4.3 Containment Checklist

```
IMMEDIATE (First 30 minutes)
□ Disable/block compromised account
□ Reset password
□ Revoke all active sessions/tokens
□ Block attacking IP (if applicable)
□ Notify user via secure channel

EXTENDED (First 4 hours)
□ Check and remove email forwarding rules
□ Check and remove mailbox delegation
□ Review OAuth app consents
□ Verify MFA methods
□ Check for lateral movement
□ Review file access/downloads
□ Check for data exfiltration

VERIFICATION
□ Confirm account secured
□ Monitor for re-compromise attempts
□ Prepare account for re-enablement
```

---

## 🔎 Part 5: Post-Compromise Investigation

### 5.1 Determine What Was Accessed

#### Email Access

```powershell
# Exchange Online - Message trace
Get-MessageTrace -SenderAddress jsmith@company.com -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

# Mailbox audit log
Search-MailboxAuditLog -Identity jsmith@company.com -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -ShowDetails
```

**Unified Audit Log:**

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -UserIds jsmith@company.com -RecordType ExchangeItem
```

#### File Access (SharePoint/OneDrive)

```powershell
# Unified Audit Log for file activity
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -UserIds jsmith@company.com -RecordType SharePointFileOperation | Select-Object -ExpandProperty AuditData | ConvertFrom-Json
```

**KQL (Azure Sentinel):**

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where UserId == "jsmith@company.com"
| where RecordType in ("SharePointFileOperation", "OneDriveFileOperation")
| project TimeGenerated, Operation, SourceFileName, Site_Url, ClientIP
| sort by TimeGenerated desc
```

#### Azure/Cloud Resources

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where Caller == "jsmith@company.com"
| project TimeGenerated, OperationName, ResourceGroup, Resource, ActivityStatus
```

### 5.2 Scope Assessment

| Question | Investigation Method |
|----------|---------------------|
| What emails were read? | Mailbox audit log |
| What emails were sent? | Message trace |
| What files were accessed? | SharePoint/OneDrive audit |
| What files were downloaded? | File operation logs |
| Were credentials harvested for other accounts? | Check for internal phishing |
| Was there lateral movement? | Check auth logs for other systems |
| Was data exfiltrated? | DLP logs, network egress |

### 5.3 Impact Assessment Matrix

| Data Type | Accessed | Downloaded | Sent Externally | Impact |
|-----------|----------|------------|-----------------|--------|
| Email | ☐ | ☐ | ☐ | |
| Documents | ☐ | ☐ | ☐ | |
| Customer data | ☐ | ☐ | ☐ | |
| Financial data | ☐ | ☐ | ☐ | |
| Source code | ☐ | ☐ | ☐ | |
| Credentials | ☐ | ☐ | ☐ | |

---

## 🔄 Part 6: Recovery

### 6.1 Account Re-enablement

**Prerequisites before re-enabling:**
- [ ] New strong password set
- [ ] MFA configured/verified
- [ ] Persistence mechanisms removed
- [ ] User security awareness discussion completed
- [ ] Manager notified

**Re-enable Account:**

```powershell
# Active Directory
Enable-ADAccount -Identity jsmith

# Azure AD
Set-AzureADUser -ObjectId jsmith@company.com -AccountEnabled $true
```

### 6.2 User Communication

**Template: Account Compromise Notification**

```
Subject: Security Incident - Account Recovery Required

Dear [User],

Our security team detected suspicious activity on your account on [date]. 
As a precaution, we have:

1. Temporarily disabled your account
2. Reset your password
3. Revoked all active sessions

To regain access:
1. Contact IT Security at [phone/email]
2. Verify your identity
3. You will receive a new temporary password
4. Log in and set a new password
5. Re-enroll in MFA if prompted

Please review your email rules, file sharing, and recent activity 
for anything suspicious.

If you clicked a link or entered credentials somewhere unusual, 
please let us know.

IT Security Team
[Contact Info]
```

### 6.3 Monitoring

Implement enhanced monitoring for 30 days:

**Azure AD:**

```kql
// Alert on any sign-in for this user
SigninLogs
| where UserPrincipalName == "jsmith@company.com"
| project TimeGenerated, IPAddress, Location, AppDisplayName, ResultType
```

**SIEM Alert Rule:**
- Alert on any authentication from previously-compromised account
- Alert on authentication from new locations
- Alert on authentication from new devices

---

## 📊 Part 7: Detection Improvements

### 7.1 Brute Force Detection Rules

**Splunk Alert:**

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count by Account_Name, Source_Network_Address, _time
| where count > 10
| alert
```

**Azure Sentinel Analytics Rule:**

```kql
SigninLogs
| where TimeGenerated > ago(5m)
| where ResultType == "50126"
| summarize FailureCount=count(), Accounts=make_set(UserPrincipalName) by IPAddress
| where FailureCount > 10
```

### 7.2 Impossible Travel Detection

**Azure Sentinel:**

```kql
let timeWindow = 60m;
let speedThreshold = 500; // miles per hour
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, 
          Latitude = toreal(LocationDetails.geoCoordinates.latitude),
          Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName, TimeGenerated asc
| extend prevTime = prev(TimeGenerated, 1),
         prevLat = prev(Latitude, 1),
         prevLon = prev(Longitude, 1),
         prevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == prevUser
| extend timeDiff = datetime_diff('minute', TimeGenerated, prevTime)
| where timeDiff < 60
// Calculate approximate distance (simplified)
| extend distance = sqrt(pow(Latitude - prevLat, 2) + pow(Longitude - prevLon, 2)) * 69
| extend speed = distance / (timeDiff / 60.0)
| where speed > speedThreshold
```

### 7.3 Recommendations

| Control | Recommendation |
|---------|----------------|
| **MFA** | Enforce MFA for all users, especially admins |
| **Conditional Access** | Block legacy auth, require compliant devices |
| **Password Policy** | Minimum 14 chars, ban common passwords |
| **Account Lockout** | 5 failures, 15-minute lockout |
| **Monitoring** | Real-time alerts on auth anomalies |
| **VPN Whitelisting** | Document known VPN IPs to reduce false positives |
| **User Training** | Phishing awareness, credential hygiene |

---

## 📝 Part 8: Reporting

### 8.1 Executive Summary Template

```
INCIDENT SUMMARY
================

Incident ID: IR-2024-0042
Date Detected: January 15, 2024
Date Contained: January 15, 2024
Incident Type: Account Compromise via Brute Force

EXECUTIVE SUMMARY
-----------------
On January 15, 2024, our security monitoring detected a successful 
account compromise affecting [user]. An attacker from [country] 
conducted a password spraying attack and successfully authenticated 
to the user's account.

IMPACT
------
- 1 user account compromised
- [X] emails potentially accessed
- [X] files potentially accessed
- No evidence of data exfiltration
- No lateral movement detected

ACTIONS TAKEN
-------------
1. Account disabled within [X] minutes of detection
2. All sessions revoked
3. Password reset
4. Malicious email rules removed
5. Enhanced monitoring implemented

ROOT CAUSE
----------
User fell victim to phishing attack on [date], exposing credentials.
Account did not have MFA enabled.

RECOMMENDATIONS
---------------
1. Enable MFA for all users (Priority: Critical)
2. Implement Conditional Access policies (Priority: High)
3. Conduct phishing awareness training (Priority: High)

TIMELINE
--------
[Include detailed timeline]
```

### 8.2 Technical Report Template

```
INCIDENT TECHNICAL REPORT
=========================

1. INCIDENT OVERVIEW
   - Incident ID: 
   - Detection Time:
   - Containment Time:
   - Resolution Time:

2. INDICATORS OF COMPROMISE
   - Attacker IP(s):
   - Geolocation:
   - User Agent:
   - Targeted Accounts:

3. ATTACK TIMELINE
   [Detailed timeline with timestamps]

4. FORENSIC FINDINGS
   - Authentication logs analysis
   - Email activity
   - File access
   - Persistence mechanisms

5. IMPACT ASSESSMENT
   - Data accessed
   - Data exfiltrated
   - Systems affected

6. CONTAINMENT ACTIONS
   [List all actions taken]

7. RECOVERY ACTIONS
   [List all recovery steps]

8. LESSONS LEARNED
   - What worked well
   - What could improve
   - Detection gaps

9. RECOMMENDATIONS
   [Prioritized list]

10. APPENDICES
    - Raw log excerpts
    - IOC list
    - Tool output
```

---

## 🗂️ Quick Reference

### Event IDs

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credentials used |
| 4768 | Security | Kerberos TGT requested |
| 4769 | Security | Kerberos service ticket |
| 4771 | Security | Kerberos pre-auth failed |
| 4776 | Security | NTLM credential validation |
| 4740 | Security | Account locked out |

### Azure AD Error Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 50126 | Invalid username/password |
| 50053 | Account locked |
| 50057 | Account disabled |
| 50074 | MFA required |
| 53003 | Blocked by CA |

### Containment Commands

```powershell
# Disable AD account
Disable-ADAccount -Identity username

# Reset AD password
Set-ADAccountPassword -Identity username -Reset

# Disable Azure AD account
Set-AzureADUser -ObjectId user@domain.com -AccountEnabled $false

# Revoke Azure AD sessions
Revoke-AzureADUserAllRefreshToken -ObjectId user@domain.com
```

### Investigation Queries

```spl
# Splunk - Failed logins
index=windows EventCode=4625 | stats count by Account_Name, src_ip

# Splunk - Success after failures
index=windows (EventCode=4625 OR EventCode=4624) | transaction Account_Name
```

```kql
# Azure - Failed logins
SigninLogs | where ResultType == "50126" | summarize count() by UserPrincipalName, IPAddress

# Azure - Impossible travel
SigninLogs | where RiskEventTypes_V2 contains "impossibleTravel"
```

---

*Part of the Incident Response & Log Aggregation Branch*
