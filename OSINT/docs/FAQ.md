# Frequently Asked Questions

## General

**Q: What is PNWC-OSINT for?**
A: It's a toolkit for investigating scam operations, phishing infrastructure, and fraudulent domains. Primary use cases are generating abuse reports for IC3, domain registrars, and hosting providers.

**Q: Is this legal to use?**
A: The toolkit is for authorized security research and fraud investigation only. You must have authorization before scanning any system or using API data for targets. See the Legal Disclaimer in the README.

**Q: Where do I start?**
A: Run `./playbook/osint_investigator.sh` — it's an interactive menu that walks you through creating a case, adding targets, running investigations, and generating reports.

---

## Installation

**Q: What Linux distros are supported?**
A: Tsurugi Linux (recommended), Kali, Ubuntu 22.04+, Debian 12+, Parrot OS, and Arch/Manjaro. See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

**Q: The installer fails on my system — what do I do?**
A: Run `./playbook/osint_investigator.sh --status` to see which tools are missing, then install them manually. The [Installation Guide](docs/INSTALLATION.md) has per-tool instructions.

**Q: Do I need all the tools installed?**
A: No. The scripts gracefully skip tools that aren't installed and warn you. At minimum you need `nmap`, `whois`, `curl`, and `jq` for basic recon. The more tools you have, the richer the output.

---

## API Keys

**Q: Which APIs are required?**
A: None are strictly required — the toolkit degrades gracefully. However, Shodan, VirusTotal, and AbuseIPDB provide the most value and all have free tiers.

**Q: Where do I put my API keys?**
A: Copy `playbook/api_keys.conf` to `~/.config/osint-investigator/api_keys.conf`, fill in your keys, and `chmod 600` the file. Or run `./playbook/osint_investigator.sh --config` for an interactive prompt.

**Q: I'm hitting API rate limits — what should I do?**
A: Use `-q` (quick mode) with `scammer_audit.sh` to reduce API calls. The script already includes 1-second delays between requests. If limits persist, check your API plan tier.

---

## Usage

**Q: What's the difference between `osint_investigator.sh` and `scammer_audit.sh`?**
A: `osint_investigator.sh` is the main interactive playbook — it manages cases, runs all investigation types, and generates reports. `scammer_audit.sh` is a standalone domain/IP audit script you can pipe into other workflows.

**Q: How do I investigate a scam email?**
A: Create a case in `osint_investigator.sh`, add the email under "Email Investigation", and add the sending domain/IP under "Domain" and "IP". Run all investigations, then use Reports → Generate Abuse Report to get a ready-to-submit document.

**Q: Can I scan multiple targets at once?**
A: Yes — use `scammer_audit.sh -i ip1,ip2,ip3 -p` for parallel IP scanning, or add multiple targets in the investigator playbook and use "Run All Investigations."

**Q: Where is the output saved?**
A: Case data saves to `~/OSINT_Cases/<CASE_ID>/`. Raw API/tool output goes in `raw_data/`, processed reports in `reports/`.

---

## Troubleshooting

**Q: `holehe` returns no results for a known email.**
A: Holehe checks account registration via password-reset flows. Many platforms now block or rate-limit these checks. Results are best-effort — a negative result doesn't mean the account doesn't exist.

**Q: `theHarvester` says "Missing API key."**
A: theHarvester reads from `~/.theHarvester/api-keys.yaml`. See [docs/INSTALLATION.md](docs/INSTALLATION.md) for setup instructions.

**Q: nmap scans fail without root.**
A: Some nmap scan types (SYN scan, OS detection) require root. Run with `sudo`, or use the investigator's built-in sudo handling.

**Q: The web interface won't start.**
A: Ensure Flask is installed (`pip3 install flask`), then run `./playbook/osint_investigator.sh --web`. It binds to `http://localhost:5000` by default.

---

## Contact & Support

- **Bugs / Issues**: Open a GitHub issue
- **Security issues**: Email [support@pnwcomputers.com](mailto:support@pnwcomputers.com) — do not open a public issue
- **General support**: [support@pnwcomputers.com](mailto:support@pnwcomputers.com)
