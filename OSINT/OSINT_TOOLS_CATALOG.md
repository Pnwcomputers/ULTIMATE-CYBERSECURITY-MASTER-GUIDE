# 🛠️ Core OSINT Toolkit

## 🎯 Purpose
Comprehensive catalog of core OSINT tools integrated into the OSINT Investigator Playbook - with descriptions, installation, and use cases for each tool.

## ⚙️ Function
Documents each tool in the OSINT toolkit: theHarvester, Maltego, Shodan CLI, Recon-ng, SpiderFoot, OSINT Framework, Sherlock, Holehe, PhotonCrawler, and domain/IP/email/phone-specific tools - with installation commands and primary use cases.

## 🏆 Goal
Serve as the authoritative tool reference for the OSINT Investigator Playbook, ensuring practitioners can install and use each tool correctly within the investigation workflow.

## 📋 When to Use
- Installing the OSINT toolkit on a new system
- Looking up the purpose and usage of a specific OSINT tool
- Deciding which tool to use for a specific data type during an investigation

The playbook integrates the following industry-standard tools for deep reconnaissance:

| Tool | Category | Primary Function |
| :--- | :--- | :--- |
| [**theHarvester**](https://github.com/laramies/theHarvester) | Recon | Email, subdomain, and host harvesting. |
| [**Sherlock**](https://github.com/sherlock-project/sherlock) | Social | Username search across 400+ platforms. |
| [**Xquik**](https://github.com/Xquik-dev/x-twitter-scraper) | Social | X/Twitter search, profile lookup, follower export, and monitoring. |
| [**Recon-ng**](https://github.com/lanmaster53/recon-ng) | Framework | Modular web-reconnaissance and data management. |
| [**Amass**](https://github.com/owasp-amass/amass) | Infrastructure | In-depth DNS enumeration and attack surface mapping. |
| [**SpiderFoot**](https://github.com/smicallef/spiderfoot) | Automation | Automated OSINT collection from 100+ sources. |
| [**Maltego**](https://www.maltego.com/) | Analysis | Visual link analysis and relationship mapping. |
| [**Photon**](https://github.com/s0md3v/Photon) | Crawler | High-speed extraction of URLs, keys, and files. |
| [**H8mail**](https://github.com/khast3x/h8mail) | Breach | Email breach hunting and credential leak analysis. |
| [**Holehe**](https://github.com/megadose/holehe) | Verification | Email-to-account registration enumeration. |
| [**PhoneInfoga**](https://github.com/sundowndev/phoneinfoga) | Phone | Phone number intelligence and carrier tracking. |
| [**Maigret**](https://github.com/soxoj/maigret) | Enumeration | Username search with profile parsing and metadata extraction. |
| [**WhatsMyName**](https://whatsmyname.app/) | Enumeration | Community-maintained username presence checking (web + [data](https://github.com/WebBreacher/WhatsMyName)). |
| [**yt-dlp**](https://github.com/yt-dlp/yt-dlp) | Capture | Video + platform metadata download (TikTok, YouTube, and many others). |
| [**gallery-dl**](https://github.com/mikf/gallery-dl) | Capture | Bulk image/media download across many social platforms. |
| [**Instaloader**](https://instaloader.github.io/) | Capture | Instagram profile and media capture (login required for most targets). |
| [**waybackpy**](https://github.com/akamhy/waybackpy) / [gau](https://github.com/lc/gau) | Recovery | Historical and deleted content recovery via web archives. |
| [**memory.lo**l](https://github.com/travisbrown/memory.lol) | Recovery | X/Twitter handle-history and numeric-ID correlation. |
| [**ExifTool**](https://exiftool.org/) | Metadata | Metadata extraction from downloaded media. |
| [**Argus**](https://github.com/jasonxtn/argus) | Recon | A python-based toolkit for Information Gathering & Reconnaissance |

---

# 🔑 Configuration & APIs
The framework leverages several high-authority databases. Ensure your API keys are configured in `${HOME}/.config/osint-investigator/api_keys.conf`:

## API-Key Providers — _Free Only_

#### SpiderFoot 
Third-party services mainline SpiderFoot (`smicallef/spiderfoot`) can query on a **free** tier — every entry is a module flagged `apikey` whose access model is free. Commercial-only and private/invite providers are excluded. Tags: **key** = free tier needs a key · **key optional** = works without one, a key raises limits.

### 1. INTERNET SCANNING & ATTACK SURFACE
* [**SHODAN**](https://www.shodan.io/): Obtain information from SHODAN about identified IP addresses. *(Free tier · key)*
* [**Censys**](https://censys.com/): Obtain host information from Censys.io. *(Free tier · key)*
* [**BinaryEdge**](https://www.binaryedge.io/): Obtain information on breaches, vulnerabilities, torrents and passive DNS. *(Free tier · key)*
* [**Onyphe**](https://www.onyphe.io): Check Onyphe data (threat list, geo-location, pastries, vulnerabilities)  about a given IP. *(Free tier · key)*
* [**LeakIX**](https://leakix.net/): Search LeakIX for host data leaks, open ports, software and geoip. *(Free · key)*
* [**FullHunt**](https://fullhunt.io/): Identify domain attack surface using FullHunt API. *(Free tier · key)*
* [**NetworksDB**](https://networksdb.io/): Search NetworksDB.io API for IP address and domain information. *(Free tier · key)*
* [**ProjectDiscovery**](https://projectdiscovery.io/): Nuclei & Cloud Automation
* [**Netlas**](https://netlas.io/): Internet Scanning Data

### 2. DNS, DOMAIN, WHOIS & CERTIFICATES
* [**SecurityTrails**](https://securitytrails.com/): Obtain Passive DNS and other information from SecurityTrails. *(Free tier · key)*
* [**DNSDB**](https://www.domaintools.com/products/farsight-dnsdb/): Query Farsight DNSDB for historical and passive DNS data. *(Farsight Security was acquired by DomainTools in 2021; the old farsightsecurity.com domain no longer resolves.)* *(Free tier · key)*
* [**CIRCL.LU**](https://www.circl.lu/): Obtain information from CIRCL.LU's Passive DNS and Passive SSL databases. *(Free · key)*
* [**Microsoft Defender Threat Intelligence**](https://ti.defender.microsoft.com/): Passive DNS and Passive SSL data formerly served by RiskIQ / PassiveTotal. *(RiskIQ was acquired by Microsoft in 2021; the community.riskiq.com portal was retired and its data folded into Defender TI.)* *(Paid · key)*
* [**Host.io**](https://host.io): Obtain information about domain names from host.io. *(Free tier · key)*
* [**Zetalytics**](https://zetalytics.com/): Query the Zetalytics database for hosts on your target domain(s). *(Free tier · key)*
* **ZoneFile.io**: Domain zone-file query API. *(⚠️ Service appears defunct as of 2026-08 — zonefiles.io no longer resolves. For bulk zone-file / newly-registered-domain data, consider [WhoisXML API](https://www.whoisxmlapi.com/) or [Whoisds](https://whoisds.com/newly-registered-domains) instead.)*
* [**CertSpotter**](https://sslmate.com/certspotter/): Gather information about SSL certificates from SSLMate CertSpotter API. *(Free tier · key)*
* [**ViewDNS.info**](https://viewdns.info/): Identify co-hosted websites and perform reverse Whois lookups using ViewDNS.info. *(Free tier · key)*
* [**JsonWHOIS.com**](https://jsonwhois.com): Search JsonWHOIS.com for WHOIS records associated with a domain. *(Free tier · key)*
* [**SpyOnWeb**](http://spyonweb.com/): Search SpyOnWeb for hosts sharing the same IP address, Google Analytics code, or Google Adsense code. *(Free tier · key)*
* [**WhoisXML API**](https://www.whoisxmlapi.com/): WHOIS Data & Domain Research
* [**DNSDumpster**](https://dnsdumpster.com/): DNS Mapping
* [**URLScan.io**](https://urlscan.io/): Website Analysis

### 3. THREAT INTELLIGENCE & IP/DOMAIN REPUTATION
* [**VirusTotal**](https://www.virustotal.com/): Obtain information from VirusTotal about identified IP addresses. *(Free tier · key)*
* [**AbuseIPDB**](https://www.abuseipdb.com): Check if an IP address is malicious according to AbuseIPDB.com blacklist. *(Free tier · key)*
* [**AlienVault OTX**](https://otx.alienvault.com/): Obtain information from AlienVault Open Threat Exchange (OTX). *(Free tier · key)*
* [**GreyNoise**](https://greynoise.io/): Obtain IP enrichment data from GreyNoise. *(Free tier · key)*
* [**GreyNoise Community**](https://greynoise.io/): Obtain IP enrichment data from GreyNoise Community API. *(Free tier · key)*
* [**Pulsedive**](https://pulsedive.com/): Obtain information from Pulsedive's API. *(Free tier · key)*
* [**XForce Exchange**](https://exchange.xforce.ibmcloud.com/): Obtain IP reputation and passive DNS information from IBM X-Force Exchange. *(Free tier · key)*
* [**Fraudguard**](https://fraudguard.io/): Obtain threat information from Fraudguard.io. *(Free tier · key)*
* [**MalwarePatrol**](https://www.malwarepatrol.net/): Searches malwarepatrol.net's database of malicious URLs/IPs. *(Free tier · key)*
* [**MetaDefender**](https://metadefender.opswat.com/): Search MetaDefender API for IP address and domain IP reputation. *(Free tier · key)*
* [**Threat Jammer**](https://threatjammer.com): Check if an IP address is malicious according to ThreatJammer.com. *(Free tier · key)*
* [**Hybrid Analysis**](https://www.hybrid-analysis.com): Search Hybrid Analysis for domains and URLs related to the target. *(Free · key)*
* [**Koodous**](https://koodous.com/apks/): Search Koodous for mobile apps. *(Free tier · key)*
* [**Project Honey Pot**](https://www.projecthoneypot.org/): Query the Project Honey Pot database for IP addresses. *(Free · key)*
* [**BotScout**](https://botscout.com/): Searches BotScout.com's database of spam-bot IP addresses and e-mail addresses. *(Free · key optional)*
* [**Abusix Mail Intelligence**](https://abusix.org/): Check if a netblock or IP address is in the Abusix Mail Intelligence blacklist. *(Free tier · key)*
* [**IPQualityScore**](https://www.ipqualityscore.com/): Determine if target is malicious using IPQualityScore API. *(Free tier · key)*
* [**ZoomEye**](https://www.zoomeye.ai/): Cyberspace Search Engine (the legacy `zoomeye.org` domain is currently returning a server error; `zoomeye.ai` is the actively promoted current domain)
* [**Criminal IP**](https://www.criminalip.io/): CTI & IP Scoring
* [**Google SafeBrowsing**](https://developers.google.com/safe-browsing/v4/lookup-api): Check if the URL is included on any of the Safe Browsing lists. *(Free · key)*

### 4. IP GEOLOCATION & NETWORK DATA
* [**IPInfo.io**](https://ipinfo.io): Identifies the physical location of IP addresses identified using ipinfo.io. *(Free tier · key)*
* [**ipstack**](https://ipstack.com/): Identifies the physical location of IP addresses identified using ipstack.com. *(Free tier · key)*
* [**ipapi.com**](https://ipapi.com/): Queries ipapi.com to identify geolocation of IP Addresses using ipapi.com API. *(Free tier · key)*
* [**ipregistry**](https://ipregistry.co/): Query the ipregistry.co database for reputation and geo-location. *(Free tier · key)*
* [**Focsec**](https://focsec.com/): Look up IP address information from Focsec. *(Free tier · key)*
* [**Google Maps**](https://cloud.google.com/maps-platform/): Identifies potential physical addresses and latitude/longitude coordinates. *(Free tier · key)*

### 5. EMAIL, BREACH & CREDENTIAL INTELLIGENCE
* [**Leak-Lookup**](https://leak-lookup.com/): Searches Leak-Lookup.com's database of breaches. *(Free · key)*
* [**IntelligenceX**](https://intelx.io/): Obtain information from IntelligenceX about identified IP addresses, domains, e-mail addresses and phone numbers. *(Free tier · key)*
* [**PasteBin**](https://pastebin.com/): PasteBin search (via Google Search API) to identify related content. *(Free tier · key)*
* [**Trashpanda**](https://got-hacked.wtf): Queries Trashpanda to gather intelligence about mentions of target in pastesites. *(Free tier · key)*
* [**Grayhat Warfare**](https://buckets.grayhatwarfare.com/): Find bucket names matching the keyword extracted from a domain from Grayhat API. *(Free tier · key)*
* [**Hunter.io**](https://hunter.io/): Check for e-mail addresses and names on hunter.io. *(Free tier · key)*
* [**EmailRep**](https://emailrep.io/): Search EmailRep.io for email address reputation. *(Free tier · key)*
* [**EmailCrawlr**](https://emailcrawlr.com/): Search EmailCrawlr for email addresses and phone numbers associated with a domain. *(Free tier · key)*
* [**Snov**](https://snov.io/): Gather available email IDs from identified domains. *(Free tier · key)*
* [**Clearbit**](https://clearbit.com/): Check for names, addresses, domains and more based on lookups of e-mail addresses on clearbit.com. *(Free tier · key)*
* [**FullContact**](https://www.fullcontact.com): Gather domain and e-mail information from FullContact.com API. *(Free tier · key)*
* [**NameAPI**](https://www.nameapi.org/): Check whether an email is disposable. *(Free tier · key)*
* [**HaveIBeenPwned**](https://haveibeenpwned.com/API/Key): Data Breach Intelligence
* [**Intelligence X**](https://intelx.io/): Deep Web & Archive Search
* [**LeakLookup**](https://leak-lookup.com/): Credential Breach Search

### 6. WEB TECH, COMPANY & SEARCH
* [**BuiltWith**](https://builtwith.com/): Query BuiltWith.com's Domain API for information about your target's web technology stack, e-mail addresses and more. *(Free tier · key)*
* [**WhatCMS**](https://whatcms.org/): Check web technology using WhatCMS.org API. *(Free tier · key)*
* [**Bing**](https://www.bing.com/): Obtain information from bing to identify sub-domains and links. *(Free tier · key)*
* [**Bing (Shared IPs)**](https://www.bing.com/): Search Bing for hosts sharing the same IP. *(Free tier · key)*
* [**Google**](https://developers.google.com/custom-search): Obtain information from the Google Custom Search API to identify sub-domains and links. *(Free tier · key)*
* [**OpenCorporates**](https://opencorporates.com): Look up company information from OpenCorporates. *(Free · key optional)*
* [**StackOverflow**](https://www.stackexchange.com): Search StackOverflow for any mentions of a target domain. Returns potentially related information. *(Free · key optional)*
* [**Ahmia**](https://ahmia.fi/): Search the Tor network for onion services mentioning the target. *(Replaces the defunct Onion.link / "Onion City" Tor2web gateway — most Tor2web services shut down after the Tor Project deprecated Tor2web in 2019.)* *(Free)*

### 7. PHONE NUMBER INTELLIGENCE
* [**numverify**](https://numverify.com/): Lookup phone number location and carrier information from numverify.com. *(Free tier · key)*
* [**Twilio**](https://www.twilio.com/): Obtain information from Twilio about phone numbers. Ensure you have the Caller Name add-on installed in Twilio. *(Free tier · key)*
* [**TextMagic**](https://www.textmagic.com/): Obtain phone number type from TextMagic API. *(Free tier · key)*
* [**NeutrinoAPI**](https://www.neutrinoapi.com/): Search NeutrinoAPI for phone location information, IP address information, and host reputation. *(Free tier · key)*
* [**AbstractAPI**](https://app.abstractapi.com/): Look up domain, phone and IP address information from AbstractAPI. *(Free · key optional)*
* [**Veriphone**](https://veriphone.io/): Global Phone Lookup

### 8. SOCIAL MEDIA & IDENTITY
* [**Social Media Profile Finder**](https://developers.google.com/custom-search): Tries to discover the social media profiles for human names identified. *(Free tier · key)*

### 9. CRYPTOCURRENCY & BLOCKCHAIN
* [**Etherscan**](https://etherscan.io): Queries etherscan.io to find the balance of identified ethereum wallet addresses. *(Free · key optional)*
* [**BitcoinAbuse**](https://www.bitcoinabuse.com/): Check Bitcoin addresses against the bitcoinabuse.com database of suspect/malicious addresses. *(Free · key)*
* [**Bitcoin Who's Who**](https://bitcoinwhoswho.com/): Check for Bitcoin addresses against the Bitcoin Who's Who database of suspect/malicious addresses. *(Free tier · key)*
* [**BlockCypher**](https://www.blockcypher.com/): Multi-chain Crypto Data

### 10. TORRENT, P2P & WIRELESS
* [**Iknowwhatyoudownload.com**](https://iknowwhatyoudownload.com/en/peer/): Check iknowwhatyoudownload.com for IP addresses that have been using torrents. *(Free tier · key)*
* [**WiGLE**](https://wigle.net/): Query WiGLE to identify nearby WiFi access points. *(Free · key)*

---

## Related Files
- [README.md](README.md) - OSINT section index
- [OSINT_CHEATSHEET.md](OSINT_CHEATSHEET.md) - Quick command reference for these tools
- [Playbook/README.md](Playbook/README.md) - Playbook that orchestrates these tools
- [argus_osint.md](argus_osint.md) - Argus toolkit installation
