# Bellingcat Toolkit and OSINT Source Verification

_Last reviewed: 2026-11-02 (reference review; no live case collection)_

> [!CAUTION]
> Public availability does not authorize harassment, access-control bypass,
> unnecessary personal-data collection or exposing confidential sources.
> Apply [legal terms](../LEGAL.md) and source-protection guidance.

**Prerequisites:** [OSINT hub](README.md) · [Investigator playbook](Playbook/investigation_guide.md) · [OPSEC](../OPSEC/README.md).

## Source context
**Related verified-source directory:** [Awesome OSINT List curation](awesome-osint-list-curated.md) organizes mapping, satellite imagery, image/video provenance and public records; its third-party listings still require independent verification.



[Bellingcat Toolkit 2.0](https://github.com/bellingcat/toolkit) is an actively curated inventory of open-source research tools, with content synced from its online documentation. It can help find tools for page archives, visual verification, geolocation, historical records and media research. A directory listing is **not** an endorsement of the legality, reliability, privacy, continued availability or integrity of each third-party provider.

## A defensible verification workflow

1. Define the question, authority, acceptable data and a minimization plan.
2. Separate research environment and accounts where appropriate. Do not rely on unknown [public proxies](../OPSEC/proxy-reference-froxy.md) to protect identities.
3. Save the original URL, UTC retrieval time, title, platform, claimed origin and content hash. Preserve the original separately from annotations.
4. Seek independent corroboration; repeated syndications of one story are still one underlying source.
5. Test contradictory explanations, publication date, location, image reuse and available file metadata. The absence of EXIF does not mean media is falsified.
6. Label fact vs inference; assign confidence and document unresolved provenance gaps.
7. Protect PII, precise addresses, raw account identifiers and source communications unless strictly necessary.
8. Record reviewer, archive reference, final citation, access permissions and deletion/legal-hold schedule.

| Evidence element | Required note |
| --- | --- |
| Original source | URL and publication or archive attribution |
| Retrieval | UTC timestamp and tool/version |
| Integrity | Hash and preserved original location |
| Verification | Independent corroboration and contradictory evidence |
| Limitations | Authorship, timestamp, location or platform uncertainty |
| Protection | Sensitivity, access list, retention and approval |

## Where it connects

[OSINT Tools Catalog](OSINT_TOOLS_CATALOG.md) provides tool choices;
[Public APIs catalog](../Documentation/security-public-api-catalog.md) covers structured sources; [Investigation Playbook](Playbook/README.md) covers cases; [Press/source protection](../OPSEC/press-freedom/README.md) covers more sensitive investigative work.

## Sources

- [Bellingcat Toolkit repository](https://github.com/bellingcat/toolkit) (GitBook content synchronized upstream).
- [Bellingcat research resources](https://www.bellingcat.com/resources/).
- [OHCHR Berkeley Protocol](https://www.ohchr.org/en/publications/policy-and-methodological-publications/berkeley-protocol-digital-open-source) (open-source evidence practice).

This update supplies a procedure and citations, not scraping, new provider accounts or acquired case data.

---

[OSINT hub](README.md) · [Main guide](../README.md) · [Legal terms](../LEGAL.md)
