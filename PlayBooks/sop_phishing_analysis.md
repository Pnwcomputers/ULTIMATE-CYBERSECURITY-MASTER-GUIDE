# 🎣 SOP: Phishing Email Analysis

**Severity:** Medium to High
**Trigger:** User reports a suspicious email or SEG (Secure Email Gateway) alert.

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
