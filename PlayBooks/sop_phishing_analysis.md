# 🎣 SOP: Phishing Email Analysis

**Severity:** Medium to High
**Trigger:** User reports a suspicious email or SEG (Secure Email Gateway) alert.

## 🎯 Purpose
A short, tier-1-analyst-ready SOP for the single most common SOC ticket type: a user-reported or SEG-flagged phishing email. Designed to be followed start-to-finish in one sitting on a single email.

## ⚙️ Function
Three-stage procedure: (1) immediate triage and containment (isolate the machine if a link was clicked, pull original headers), (2) URL and attachment analysis using specific named tools, (3) closure/escalation decision. Deliberately short — this is the fast-path SOP, not a deep-dive; see `unauth_access.md` for the follow-on investigation if the phishing led to actual account compromise.

## 🏆 Goal
Contain potential compromise within minutes of a report landing, and produce a consistent, minimal evidence trail (headers, URL verdicts, attachment verdicts) for every phishing ticket regardless of which analyst handles it.

## 📋 When to Use
- A user reports a suspicious email via your reporting button/mailbox
- A SEG (Secure Email Gateway) alert fires on an inbound message
- As the entry point before escalating to `unauth_access.md` if the phish resulted in a successful login

---

## 1. 🛑 Triage & Containment
* **Isolate:** If the user clicked a link, disconnect their machine from the network immediately.
* **Header Analysis:** Get the original email headers.
    * *Check:* `Return-Path`, `Received` chain, `X-Originating-IP`.
    * *Tool:* [MxToolbox](https://mxtoolbox.com/EmailHeaders.aspx)

## 2. 🔗 URL & Attachment Analysis
**WARNING:** Never open attachments on your host machine. Use a dedicated sandbox.

### URL Analysis
1.  **Reputation Check:**
    * [VirusTotal](https://www.virustotal.com/)
    * [Urlscan.io](https://urlscan.io/)
2.  **Sandboxing:**
    * Run the URL in a browser inside your isolated **Malware Analysis VM**.
    * Look for credential harvesting forms.

### Attachment Analysis
1.  **Hash It:** Get the MD5/SHA256 hash.
    ```bash
    sha256sum invoice.pdf
    ```
2.  **Detonate:** Upload to an automated sandbox like [Any.Run](https://app.any.run/) or [Hybrid Analysis](https://www.hybrid-analysis.com/).

## 3. 🧹 Remediation
* **Purge:** Delete the email from the user's inbox and searching for it across the organization (Exchange/O365 Search-Mailbox).
* **Block:** Add the sender domain and malicious URL to your firewall/web proxy blocklist.
* **Reset:** Force a password reset for the targeted user.

---
*Part of the Incident Response & Log Aggregation Branch*
