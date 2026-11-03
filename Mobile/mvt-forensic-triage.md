# Mobile Verification Toolkit (MVT): Authorized Forensic Triage

_Last reviewed: 2026-11-02 (upstream documentation only; no device analyzed)_

> [!CAUTION]
> Mobile forensic analysis can reveal personal photos, communications,
> location records and confidential sources. Secure informed authorization,
> preserve originals and handle outputs as sensitive evidence.
> See [legal terms](../LEGAL.md).

**Prerequisites:** [Mobile assessment SOP](mobile_pentest_sop.md) · [Mobile security](README.md) · [Press and source safety](../OPSEC/press-freedom/README.md).

## What MVT can and cannot do

[Mobile Verification Toolkit](https://github.com/mvt-project/mvt) is an analysis toolkit for supported iOS/Android forensic artifacts and potential indicators of compromise, with [version-specific official docs](https://docs.mvt.re/). It is **not** a universal spyware detector: available artifacts and collection paths depend on device OS, platform restrictions, backup format and permissions. No finding does not prove a device is safe.

## Consent-first workflow

1. Record device owner, explicit consent, device model/OS, investigator, issue to answer and authorized collection methods.
2. Review upstream MVT documentation for the exact release and supported platform. Do not reuse commands from a different OS/version without checking.
3. Work first against a synthetic test device or owner-supplied test backup.
4. Preserve original encrypted backup/export, hash it and analyze a duplicate offline where feasible. Plan separately for volatile evidence.
5. Record trusted indicator feeds and release dates; indicators are investigative leads, not independent proof.
6. Run supported analysis only within the approved scope, record MVT version, output hashes, timestamps/time zone and processing parameters.
7. Correlate matches with OS behavior, security advisories, independent artifacts and false-positive possibilities.
8. Explain confidence, collection gaps, possible alternatives, risk-reduction measures and specialist referral when appropriate. Protect raw sensitive data and follow retention rules.

| Report field | What to preserve |
| --- | --- |
| Consent and custody | Case, owner authorization, investigator and handlers |
| Device | OS/build, backup type, encryption state |
| Processing | MVT version, platform method, indicator revision |
| Integrity | Original and derived hashes |
| Finding | Artifact/timestamps, corroboration, limitations |
| Outcome | Redacted report, handling and retention decision |

## References

- [MVT GitHub](https://github.com/mvt-project/mvt) and [official docs](https://docs.mvt.re/).
- [Mobile Security index](README.md), [Mobile pentest SOP](mobile_pentest_sop.md) and [Digital Forensics](../IncidentResponse/Digital-Forensics/README.md).

**Status:** source-backed process only; no scan, device connection or user data acquisition.

---

[Mobile hub](README.md) · [Main README](../README.md) · [Legal terms](../LEGAL.md)
