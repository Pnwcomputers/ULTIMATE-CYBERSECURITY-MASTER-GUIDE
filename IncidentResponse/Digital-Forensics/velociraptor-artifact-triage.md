# Velociraptor and ForensicArtifacts: Endpoint Evidence Triage

_Last reviewed: 2026-11-02 (source/API documentation review; no collection executed)_

> [!CAUTION]
> Live endpoint collection can expose personal data, privileged account traces,
> source communications and sensitive client material. Secure written consent,
> minimize collection scope, protect access and chain of custody, and consult
> legal/evidence-retention requirements before starting. Treat acquired data as
> confidential and untrusted.

**Prerequisites:** [Digital Forensics index](README.md) ·
[Live data preservation](LiveData/live_data_collection.md) ·
[Autopsy/KAPE](Disks/autopsy_kape.md).

## Project roles

- [Velociraptor](https://github.com/Velocidex/velociraptor): endpoint visibility
  and targeted collection via artifacts and Velociraptor Query Language (VQL).
  Its [official docs](https://docs.velociraptor.app/) define supported deployment,
  artifact, authorization and retention models.
- [ForensicArtifacts/artifacts](https://github.com/ForensicArtifacts/artifacts):
  a standardized catalogue of operating-system forensic artifact definitions,
  useful for mapping artifacts to data sources and selecting a proportionate
  collection set; not an endpoint execution agent.
- [Volatility 3](Memory/volatility_cheatsheet.md): memory analysis, complementary
  to disk/live endpoint collection; does not substitute for it.

## Controlled deployment and triage

1. Write the investigative question (e.g., suspicious persistence, lateral
   movement, unusual process launch) and define the authorized hosts,
   available credentials and retention deadline.
2. Confirm legal hold and imaging priority. For a volatile device, document
   acquisition order and the effect of running collection software on evidence.
3. In a **disposable local lab**, study
   [Velociraptor's offline GUI workflow](https://docs.velociraptor.app/)
   and artifact explorer before considering a production server/client rollout.
4. For a customer environment, choose a deployment approved by that customer,
   apply agent enrollment and role-based access controls, secure server TLS and
   isolate evidence storage.
5. Build an artifact selection matrix: investigative question → OS version →
   collection artifact → expected event timestamps and file paths → privacy
   sensitivity → estimated data volume.
6. Execute a **minimal** targeted collection, not every artifact. Record
   endpoint identity, system time/time zone, collector version, artifact
   definition/commit, query parameters, operator and result hashes.
7. Normalize timestamps and corroborate with memory, event logs, disk and
   network evidence. Distinguish a lack of an artifact from proof of absence.
8. Export only necessary findings; store raw evidence access-controlled and
   encrypted, record access, and rehearse restoration/disposal according to
   legal retention obligations.

## Evidence capture worksheet

| Item | Expected record |
| --- | --- |
| Consent | Case ID, owner, signed authorization, time window |
| Endpoint | Host ID, OS/build, time zone, clock skew, collection agent |
| Artifact | Source name + version, collection parameter set |
| Integrity | Collection hash, transport/storage checksum, receipt time |
| Analysis | Timestamps, hypothesis, source log comparison, confidence |
| Custody | Person/system handling evidence, encrypted storage location |
| Retention | Preservation order, disposal/review date and restoration plan |

## Practical safety checks

Never enroll an unmanaged/customer device or use remote endpoint execution
without documented approval. Review artifact collection SQL/VQL before running:
even a "read-only" query can collect secrets, sensitive user files or large
volumes. Avoid broad memory dumps unless justified and consented. Handle the
Velociraptor server like a privileged administrative service.

**Integration status:** source-backed runbook only; no agent installation,
client deployment, cloud connection, collection or VQL execution.

## Sources

- [Velociraptor](https://github.com/Velocidex/velociraptor) /
  [documentation](https://docs.velociraptor.app/).
- [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts)
  (Apache-2.0).
- [Tsurugi Bento](tsurugi-bento-portable-dfir-guide.md) ·
  [Sysmon](../Endpoint-Visibility/Windows/sysmon.md) ·
  [Osquery](../Endpoint-Visibility/Linux/osquery.md).

---

[DFIR index](README.md) · [Incident Response](../README.md) ·
[Main guide](../../README.md)
