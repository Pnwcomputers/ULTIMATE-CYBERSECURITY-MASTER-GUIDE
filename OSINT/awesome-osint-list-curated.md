# Awesome OSINT List — curated tools and verification workflows

_Reviewed: 2026-11-03 · Source: [Astrosp/Awesome-OSINT-List](https://github.com/Astrosp/Awesome-OSINT-List), main commit [1fcaaa63](https://github.com/Astrosp/Awesome-OSINT-List/commit/1fcaaa63f64729f563772e4e7ba510c670671e66)._

This guide **selects, classifies and cross-links** useful entries from the large [Awesome OSINT For Everything](https://github.com/Astrosp/Awesome-OSINT-List) directory into PNWC's existing [OSINT guide](OSINT_GUIDE.md), [toolkit catalog](OSINT_TOOLS_CATALOG.md), [social media reference](OSINT_socialmedia.md), and [investigator playbook](Playbook/README.md). Do **not** install or copy the entire upstream list. This curated reference describes public services and stable project entry points; it does **not** certify that every provider, API, plan, jurisdiction or third-party data source is available, accurate or ethical for a specific case.

## Tools by investigation question

| Need | Curated public source | How to use it responsibly |
| --- | --- | --- |
| Historical company identity and links | [ICIJ Offshore Leaks](https://offshoreleaks.icij.org/), [OCCRP Aleph](https://data.occrp.org/), [OpenCorporates](https://opencorporates.com/) | Start with company name/registry number; compare with official company registries; leaked or indexed records may be incomplete or disputed |
| Public map/imagery corroboration | [OpenStreetMap](https://www.openstreetmap.org/), [NASA Worldview](https://worldview.earthdata.nasa.gov/), [Sentinel Hub](https://www.sentinel-hub.com/) | Check timestamps, imagery resolution, map-edit provenance and geospatial uncertainty; avoid precise personal location disclosure |
| Sun/shadow plausibility | [SunCalc](https://www.suncalc.org/) | Use hypothetical date/time/coordinates to evaluate a claim; shadow estimates alone do not prove image place or time |
| Air-traffic or vessel *context* | [ADS-B Exchange](https://globe.adsbexchange.com/), [MarineTraffic](https://www.marinetraffic.com/) | Coverage, blocked/absent transmissions and historical availability vary; absence of a track is **not** proof of absence |
| Visual/clip verification | [TinEye](https://tineye.com/), [InVID/WeVerify](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/), [ExifTool](https://exiftool.org/) | Reverse-search original media; inspect metadata cautiously (can be edited or stripped); preserve hashes and capture times |
| Breach exposure for *owned* identity/domain | [Have I Been Pwned](https://haveibeenpwned.com/), [GreyNoise](https://viz.greynoise.io/) | Use authorized accounts and verified domain ownership; do not download credential dumps or submit plaintext passwords |
| Public infrastructure/background | [crt.sh](https://crt.sh/), [Shodan](https://www.shodan.io/), [Censys](https://search.censys.io/), [SecurityTrails](https://securitytrails.com/) | Public results may be old or incomplete; passive discovery does not authorize active scanning |
| Historic web references | [Wayback Machine](https://web.archive.org/), [Internet Archive](https://archive.org/), [waybackpy](https://pypi.org/project/waybackpy/) | Distinguish capture date from original publication; redact confidential URLs from evidence |
| Web security indicators | [urlscan.io](https://urlscan.io/), [VirusTotal](https://www.virustotal.com/gui/), [Unfurl](https://dfir.blog/unfurl/) | **Submission may share information.** urlscan supports Public, Unlisted and Private visibility; check [visibility documentation](https://docs.urlscan.io/pages/visibility) before submitting confidential URLs. VirusTotal and other public scanners also have data-sharing risks |
| Ethical skill development | [OSINT Dojo](https://www.osintdojo.com/), [Bellingcat Toolkit](https://bellingcat.gitbook.io/toolkit/) | Practice on public challenge datasets; do not try identity enumeration against unwitting individuals |

This list complements, rather than repeats, tools already documented in PNWC: **Sherlock, Maigret, theHarvester, Recon-ng, SpiderFoot, Shodan, Censys, Maltego, Subfinder, Amass, ExifTool and Bellingcat** remain in their existing [tool catalog](OSINT_TOOLS_CATALOG.md). Third-party descriptions are starting points, not verified endorsements.

## Practical, evidence-first workflows

### A. Company and beneficial-ownership research

1. Record scope, inquiry, legitimate purpose and collection date in the [investigation guide](Playbook/investigation_guide.md).
2. Start with an official country/state registry and an exact registration number when possible. Cross-reference the **ICIJ** and **OCCRP Aleph** indexes only for relevant names and contextual links.
3. Write down source URLs, named entities, registry ID, date ranges and jurisdiction; distinguish **reported associations**, ownership claims and independent registry evidence.
4. Record contradictory evidence and unknowns; do not accuse a person solely because a name appears in a leaked database.
5. Preserve a dated note and report the confidence level, not an unsupported conclusion.

### B. Image, video and scene verification

1. Store an authorized copy, calculate `sha256sum source-image.jpg`, retain its original URL and UTC retrieval time.
2. Inspect `exiftool -a -G1 -s source-image.jpg` locally. Missing or conflicting EXIF is not proof of fabrication.
3. Use TinEye or another reverse-image service to find **earlier** appearances. Check whether matches are republications of the same original.
4. Use OpenStreetMap and appropriately dated satellite imagery to assess visible road/building landmarks. Test sun/shadow hypotheses with SunCalc only if time and place are independently plausible.
5. Log alternate explanations; avoid publishing residential coordinates or identifiable private individuals.

### C. Authorized domain/infrastructure profile

1. Confirm the permitted organization's domains and subdomains; record scope.
2. Review **certificate transparency** via crt.sh and passive Internet-exposure sources such as Shodan/Censys. Note that host data may be stale or incomplete.
3. Correlate DNS/registrar data and known asset records before labeling an IP as client-owned; CDNs/shared hosting can mislead.
4. Scan only if explicitly covered by a separate signed testing authorization. For lookup/API use see the [public API catalog](../Documentation/security-public-api-catalog.md).
5. Report source dates, confidence, gaps and recommended verification to the owner.

## Privacy, safety and quality-control rules

- **Do not bulk-import upstream entries.** It mixes reputable research tools with people-search brokers, breach-data resellers, anonymous services, promotional listings, AI tools and obsolete links. Any privacy-invasive service requires a separate legal and accuracy review.
- Never upload client identities, confidential URLs, source documents, leaked credentials, private photos or access tokens to unknown third-party services. For document sanitization, see [Dangerzone](https://github.com/freedomofpress/dangerzone) and [source-protection guidance](../OPSEC/press-freedom/README.md).
- AI-generated OSINT suggestions and entity graphs are **hypotheses**. Verify against original documents and independent evidence.
- A service's free tier, API endpoint and permitted use can change without notice; review each vendor's official terms before use and avoid bypassing rate limits.
- Distinguish **unverified catalog listing**, **web-accessible provider**, **authenticated account/API enabled**, and **operationally tested tool**. Only the first two may be supported by this documentation review.
- Preserve UTC timestamps, content hashes, tool version, exact search query, source URL, interpretation, potential false matches and a minimization/deletion schedule.

## Upstream provenance and maintenance

The inspected source is a **GPL-3.0** GitHub repository with a root LICENSE, last pushed November 3, 2026 (UTC) at the time of review. These are **new PNWC descriptions and links**, not redistributed upstream prose, scripts or datasets. Individual linked services have their own licenses, terms and privacy policies. Pin the source commit above for repeatability; compare future revisions before adding or removing a provider.

**Navigation:** [OSINT hub](README.md) · [OSINT tools catalog](OSINT_TOOLS_CATALOG.md) · [General methodology](OSINT_GUIDE.md) · [Social media](OSINT_socialmedia.md) · [OSINT cheat sheet](OSINT_CHEATSHEET.md) · [Bellingcat source verification](bellingcat-source-verification.md) · [Case playbook](Playbook/README.md) · [Main README](../README.md) · [Source register](../Documentation/upstream-security-projects-register.md).
