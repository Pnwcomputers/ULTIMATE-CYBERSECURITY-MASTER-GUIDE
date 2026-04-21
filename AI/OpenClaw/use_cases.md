# OpenClaw Use Cases & Real-World Examples

A practical guide to getting value out of OpenClaw across personal, professional, IT support, and cybersecurity workflows. These examples assume OpenClaw is running with Telegram or Discord configured as a chat channel so you can interact from anywhere.

---

## Table of Contents

- [Day to Day Personal Life](#day-to-day-personal-life)
- [Work & Business Productivity](#work--business-productivity)
- [IT Support & Field Work](#it-support--field-work)
- [IT Support Business Operations](#it-support-business-operations)
- [Homelab Management](#homelab-management)
- [Blue Team / Defensive Security](#blue-team--defensive-security)
- [Red Team / Offensive Security](#red-team--offensive-security)
- [Purple Team Operations](#purple-team-operations)
- [OSINT & Reconnaissance](#osint--reconnaissance)
- [Model Routing Strategy](#model-routing-strategy)
- [Tips for Getting the Best Results](#tips-for-getting-the-best-results)

---

## Day to Day Personal Life

OpenClaw connected to Telegram means your AI assistant is always in your pocket. These are tasks you'd normally have to sit down at a computer for.

### Morning Briefing
```
"Give me a quick summary of what's on my calendar today, any unread emails that look urgent, 
and today's weather in Vancouver WA"
```
*Requires: Google Calendar skill, Gmail skill, web search*

### Research on the Go
```
"I'm at a client site and they mentioned moving to Azure AD. 
Give me a 5-minute briefing on what that means for a 15-person SMB 
migrating from on-prem AD — costs, gotchas, and what questions I should ask them"
```

### Shopping & Errands
```
"I need to pick up parts for a network install this afternoon. 
Make me a checklist: 8-port managed switch, patch cables cat6, 
keystone jacks, patch panel, rack screws, and velcro ties. 
Estimate cost from Best Buy vs Newegg vs Amazon"
```

### Learning & Study
```
"Explain VLAN trunking to me like I'm prepping for a CompTIA Network+ exam. 
Use an analogy, then give me 5 practice questions."
```

### Health & Fitness
```
"I have 30 minutes and a set of dumbbells. Give me a quick strength circuit 
I can do between service calls. No jumping, I'm in dress clothes."
```

### Home Automation Integration
```
"Check my Home Assistant — is the garage door open? 
Also what's the current temperature inside vs outside?"
```
*Requires: Home Assistant skill or API integration*

---

## Work & Business Productivity

### Email Drafting
```
"Draft a professional follow-up email to a client who hasn't responded 
to my quote for a network upgrade in 2 weeks. Keep it friendly but nudge them. 
My business is Pacific Northwest Computers."
```

### Meeting Prep
```
"I have a discovery call with a new small business client in 20 minutes. 
They're a 12-person dental office. Give me the top 10 questions I should ask 
to scope their IT needs, and common issues dental offices have with IT compliance."
```

### Document Summarization
```
"I'm uploading this 40-page vendor contract. 
Summarize the key terms, flag anything unusual, 
and highlight any auto-renewal clauses or liability caps."
```

### Invoice & Quote Templates
```
"Create a service quote template for a small business network installation. 
Include sections for: labor, hardware (with markup), travel, and ongoing support. 
Format it so I can fill in the blanks quickly on-site."
```

### Knowledge Base Building
```
"I just fixed a weird issue where a client's Windows 11 machine 
kept dropping off the domain after sleep. The fix was disabling 
fast startup and setting the NIC to never sleep in power management. 
Write this up as a KB article I can add to my GitHub repo."
```

---

## IT Support & Field Work

This is where OpenClaw shines for solo technicians. You're on-site, hands full, and need answers fast via Telegram.

### On-Site Diagnostics
```
"Client's printer keeps showing offline even though it's on and connected. 
It's an HP LaserJet Pro M404 on a Windows 10 machine. 
Walk me through a quick diagnostic starting with the most likely causes."
```

```
"Client reports 'slow internet' but speedtest shows 150/20 which matches their plan. 
They say video calls keep dropping. What are the likely causes and 
how do I diagnose this efficiently on-site in under 20 minutes?"
```

### Quick Reference Commands
```
"Give me the PowerShell one-liner to check if Windows Defender 
real-time protection is enabled on a remote machine"
```

```
"What's the command to flush and re-register DNS on Windows 11? 
Also give me the ipconfig release/renew sequence."
```

### Driver & Compatibility Lookups
```
"Client has a Dell OptiPlex 7090 running Windows 11 23H2. 
They bought a new Logitech C920 webcam and it's not being detected. 
What should I check first?"
```

### Client Communication
```
"Write a non-technical explanation I can send to a client explaining 
why their computer is running slow. The actual cause is a failing HDD 
with bad sectors. Don't use jargon — they're a 65-year-old small business owner."
```

### On-the-Fly Training
```
"A client wants to know the difference between their router, 
modem, and the switch I just installed. Give me a simple analogy 
I can use to explain it in under 2 minutes."
```

### Remote Support Prep
```
"I'm about to remote into a Windows Server 2019 machine that 
a client says 'just stopped working.' Give me a first-5-minutes checklist 
of what to check before I start making changes."
```

---

## IT Support Business Operations

### Appointment Management
```
"I have 4 service calls today. Help me route them efficiently: 
- 9am: Battle Ground (PC repair, ~1hr)
- Vancouver downtown (network install, ~3hr) 
- Camas (virus removal, ~1.5hr)
- Vancouver near 78th (printer setup, ~30min)
What order makes the most sense geographically?"
```

### SLA & Response Tracking
```
"I have 8 open tickets. Here's my list: [paste ticket list]. 
Which ones are at risk of breaching a 24hr response SLA 
based on when they were opened? Flag any over 20 hours."
```

### Client Onboarding Documentation
```
"Create a client onboarding checklist for a new small business 
managed services client. Include: network documentation, 
software inventory, backup verification, security assessment, 
and a 90-day check-in schedule."
```

### Pricing & Quoting
```
"A client needs: 
- Replace 3 workstations (mid-range office use)
- New 8-port managed switch
- NAS for file sharing with 10TB usable
- Setup and configuration labor
Give me a rough quote range with parts at retail and 
suggest what markup is typical for MSPs in 2026."
```

### Service Report Generation
```
"I just finished a 3-hour network install at ABC Dental. 
I replaced their unmanaged switch with a UniFi USW-Lite-8-PoE, 
ran 4 new ethernet drops, set up VLANs for guest wifi and office, 
and updated firmware on their router. 
Write a professional service completion report I can email to the client."
```

### Marketing & Social Media
```
"Write 3 social media posts for my IT business (Pacific Northwest Computers) 
promoting our remote support services. 
Target small business owners in Vancouver WA. 
Keep them under 280 characters and avoid tech jargon."
```

---

## Homelab Management

### TrueNAS Health Checks
```
"Check my TrueNAS pools — are they healthy? 
Any scrub errors or degraded drives?"
```
*Requires: TrueNAS skill from ClawHub*

```
"What apps are currently running on my TrueNAS? 
Which ones have updates available?"
```

### Proxmox & VM Management
```
"List all running VMs on my Proxmox cluster and their resource usage. 
Flag anything using over 80% CPU or RAM."
```

### Network Monitoring
```
"Any new unknown devices on my network in the last 24 hours? 
Check NetAlertX for me."
```

### Backup Verification
```
"When did my last TrueNAS replication task run and was it successful? 
Also check if any ZFS snapshots are older than 7 days and should be pruned."
```

### Service Uptime
```
"Quick health check — are all my self-hosted services responding? 
Check: Jellyfin, Frigate, Home Assistant, NPMplus, Ollama"
```

---

## Blue Team / Defensive Security

OpenClaw with appropriate skills becomes a hands-free SOC assistant.

### Log Analysis
```
"I'm going to paste some Wazuh alerts from the last hour. 
Triage them by severity, identify any that look like real threats vs noise, 
and suggest immediate actions for anything critical."
```

```
"Here are 50 lines of auth.log from my SSH server. 
Are there any signs of credential stuffing or brute force? 
Give me the source IPs and recommended firewall rules."
```

### Threat Hunting Queries
```
"Write a Wazuh rule to detect when a new user account is created 
on a Windows machine outside of business hours (8am-6pm PST)"
```

```
"Give me Zeek/Suricata rules to detect DNS tunneling based on 
high-frequency queries, long subdomain strings, and unusual record types"
```

### Incident Response
```
"A Windows workstation on my network made 3,000 DNS queries in 5 minutes 
to random subdomains of a .xyz domain. Walk me through an IR playbook 
for suspected C2 beaconing — what do I contain, collect, and analyze first?"
```

```
"I found this suspicious PowerShell command in my logs: [paste command]. 
Decode it, explain what it does, assess the risk level, 
and tell me what artifacts to look for on the host."
```

### Vulnerability Management
```
"Here's my Nessus scan output for my home network: [paste results]. 
Prioritize the findings by exploitability and suggest a patching order. 
Flag anything with a public exploit."
```

### Security Awareness Training
```
"Write a 5-minute phishing awareness training script 
I can use with a client's non-technical staff. 
Include 3 real-world examples and a quiz at the end."
```

### SIEM Tuning
```
"I'm getting too many false positives from this Wazuh rule: [paste rule]. 
Suggest how to tune it to reduce noise while keeping coverage 
for actual brute force attempts."
```

---

## Red Team / Offensive Security

For authorized penetration testing engagements. Always ensure proper written authorization before any testing.

> ⚠️ These examples are for authorized penetration testing only. Ensure you have written permission before testing any system.

### Recon & Enumeration
```
"I'm starting a pentest engagement on a Windows Active Directory environment. 
Give me a methodology checklist from initial access through domain compromise, 
with the key tools at each stage."
```

```
"What are the current top techniques for AD enumeration without triggering 
common EDR solutions? Focus on living-off-the-land approaches."
```

### Payload & Exploit Research
```
"Explain how Kerberoasting works, why it's effective against service accounts 
with weak passwords, and what defenders typically see in logs when it's performed."
```

```
"I have a shell on a Windows 10 machine as a standard user. 
List the top 5 local privilege escalation techniques I should check, 
ordered by likelihood of success in a corporate environment."
```

### Report Writing
```
"I found an unauthenticated RCE vulnerability in a client's web application 
via an unsanitized file upload endpoint. Write this up as a professional 
pentest finding including: severity rating, technical description, 
proof of concept summary, business impact, and remediation steps."
```

```
"Convert these raw pentest notes into an executive summary 
suitable for a non-technical C-suite audience: [paste notes]. 
Lead with business risk, not technical details."
```

### Tool Reference
```
"Give me the Nmap command to do a full TCP scan with service detection 
and default scripts on a /24 subnet, output to all formats, 
without being too aggressive on timing"
```

```
"What's the Metasploit module for EternalBlue and what are 
the exact prerequisites for it to work? 
What should I check before running it?"
```

### CTF Assistance
```
"I'm stuck on a CTF challenge. Here's what I have so far: [describe challenge]. 
Don't give me the answer — give me hints and point me toward the right technique."
```

---

## Purple Team Operations

Purple team is about blue and red working together to improve defenses. OpenClaw helps coordinate and document this work.

### Detection Engineering
```
"I want to test whether my Wazuh SIEM detects a Pass-the-Hash attack. 
Give me: (1) the exact attack steps to simulate it, 
(2) what log events should fire, 
(3) what a Wazuh rule to detect it should look like, 
and (4) how to verify detection worked"
```

### Atomic Testing
```
"Using Atomic Red Team, which atomics should I run to test detection 
coverage for T1003 (OS Credential Dumping) on Windows? 
Give me the commands and what I should see in Wazuh/Sysmon if detection is working."
```

### Gap Analysis
```
"Here are the MITRE ATT&CK techniques from my last red team engagement: 
[paste technique list]. 
Map these against my current detection stack (Wazuh + Zeek + Sysmon) 
and identify which techniques I have no detection coverage for."
```

### Tabletop Exercise Facilitation
```
"Facilitate a tabletop exercise for a ransomware scenario targeting 
a 20-person dental office. Give me: the scenario narrative, 
inject questions for each phase (initial access, lateral movement, 
encryption, extortion), and what decisions the team needs to make at each stage."
```

### Control Validation
```
"I claimed in a security assessment that our EDR would detect 
Mimikatz credential dumping. Design a test to validate this claim 
that I can run in a lab environment safely."
```

---

## OSINT & Reconnaissance

For legitimate research, due diligence, and authorized investigations.

> ⚠️ OSINT techniques should only be used for lawful purposes. Always comply with applicable laws and platform terms of service.

### Business Intelligence
```
"I'm meeting with a potential client — ABC Manufacturing in Vancouver WA. 
Find what you can about their business: size, industry, any news, 
tech stack hints from their website, LinkedIn presence, 
and any public information about their IT infrastructure."
```

### Domain & Infrastructure Recon
```
"Do passive recon on example.com. 
Find: DNS records, mail servers, any subdomains indexed publicly, 
associated IP ranges, hosting provider, tech stack from headers, 
and any data breach mentions in public sources."
```

### Person of Interest Research (Authorized)
```
"For an authorized background check on a potential employee, 
find publicly available information about [name] in [city]. 
Look for: LinkedIn, professional credentials, any public records, 
and verify their claimed certifications are real."
```

### Threat Actor Research
```
"Summarize what is publicly known about the threat actor group 
tracked as 'BlackCat/ALPHV'. Include: TTPs, typical targets, 
known IOCs, and recent activity."
```

### Breach & Exposure Monitoring
```
"Search HaveIBeenPwned and other public sources for any data breaches 
associated with the domain pnwcomputers.com. 
What credentials or data may be exposed?"
```

### Social Engineering Awareness
```
"I'm doing a security awareness session for a client's staff. 
Using only publicly available information about their company, 
show me what a social engineer could find out in 15 minutes 
to craft a convincing pretexting call. 
This is for defensive awareness — show them what attackers can learn."
```

### Brand Monitoring
```
"Set up a summary: are there any lookalike domains registered 
similar to pnwcomputers.com that could be used for phishing? 
Check for common typosquatting patterns."
```

---

## Model Routing Strategy

Knowing which model to use for which task saves money and gets better results.

| Task Type | Recommended Model | Reason |
|-----------|------------------|--------|
| Quick lookups, commands, checklists | Groq / Llama 3.3 70B | Fast, free, good enough |
| Casual chat, scheduling, reminders | Groq / Llama 3.3 70B | Free tier handles this well |
| Long document analysis | Gemini 3.1 Pro | 1M token context window |
| Web research summaries | Gemini 3.1 Pro | Built-in Google Search integration |
| Complex security analysis | Claude Opus | Best reasoning for nuanced tasks |
| Report writing, professional docs | Claude Haiku or Sonnet | Good quality, lower cost than Opus |
| Sensitive/private tasks | Ollama (local) | Never leaves your network |
| Offline/air-gapped work | Ollama (local) | No internet required |

**In the OpenClaw dashboard:**
- Set **Adaptive** mode to let OpenClaw auto-route based on task complexity
- Or prefix messages with the model name: `@groq what's the ping command for Linux`
- Use `@opus` when you need Claude's best reasoning on a hard problem

---

## Tips for Getting the Best Results

### Be Specific About Context
Instead of: `"Help me fix this network issue"`  
Try: `"Client has a Ubiquiti UniFi setup, USG-3P router, 2 APs, 8-port switch. 
Clients on VLAN 10 can't reach the internet but the gateway ping works. 
What should I check?"`

### Use Role Priming for Specialized Tasks
```
"Act as a senior penetration tester reviewing my methodology. 
Here's my recon phase notes for an engagement: [notes]. 
What am I missing and what would you prioritize next?"
```

```
"Act as a non-technical small business owner. 
Review this security assessment report I wrote and tell me 
what's confusing, what's missing, and what would concern you most."
```

### Chain Tasks Together
```
"1. Find the CVE for the recent Fortinet SSL VPN vulnerability from early 2026
2. Explain the technical details in plain English
3. Write a client advisory email warning them to patch immediately
4. Give me the PowerShell or CLI command to check if their firmware is vulnerable"
```

### Use It as a Second Opinion
```
"I'm about to run this Bash script on a client's production server. 
Review it for anything dangerous, unintended side effects, 
or edge cases I should know about before running it: [paste script]"
```

### Save Recurring Prompts as Skills or Hooks
Set up OpenClaw hooks to run automatically:
- Daily security digest at 8am
- Weekly summary of open service tickets
- Alert when Wazuh fires a critical rule
- Morning weather + calendar brief on weekdays

### Keep Sensitive Data Local
For anything involving:
- Client PII or confidential data
- Internal network diagrams or credentials
- Security assessments with real vulnerability details

...always use `@ollama` to keep it local:
```
"@ollama Review this network diagram and identify security gaps: [diagram details]"
```

---

## Quick Reference: Useful Prompt Patterns for IT Pros

```
# Explain something simply
"Explain [technical concept] to a non-technical client in under 3 sentences"

# Generate a checklist
"Give me a pre-flight checklist before [task] on a production system"

# Write a ticket/report
"Write a service ticket for: [description of issue and resolution]"

# Command lookup
"What's the [Windows/Linux/macOS] command to [task]? Give me the exact syntax."

# Script review
"Review this script for security issues, bugs, or unintended behavior: [script]"

# Incident response
"Walk me through IR steps for: [incident type] on [system type]"

# Client communication
"Write a [friendly/formal/urgent] email to a client explaining: [situation]"

# Cost estimate
"Rough cost estimate for: [hardware/service list] — parts + typical labor"

# Study/cert prep
"Give me 10 practice questions for [certification] on the topic of [topic]"

# Log analysis
"Analyze these logs and tell me if anything looks suspicious: [logs]"
```

---

*Guide written for use with OpenClaw 2026.4.15 deployed on TrueNAS SCALE. All security examples assume authorized testing environments.*
