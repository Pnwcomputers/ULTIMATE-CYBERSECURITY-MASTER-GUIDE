# Evidence, Privacy & Integrity

[Cyberdeck Home](../README.md) · [Offline Helper](../tools/evidence_manifest.py) · [Example Metadata](../templates/EVIDENCE_RECORD.example.json)

## Local-First Handling

Use one authorized case directory per engagement **outside** source control. Protect it with actual encryption-at-rest, least-privilege access, documented backups and pre-agreed retention. Raw captures, signed agreements and customer identifiers **never** belong in this public repository.

| Field | Reason |
| --- | --- |
| Case identifier | Separate client evidence without disclosing names in public source control |
| Collector and exact version | Reproduce conditions and qualify tool support |
| Actual acquisition origin/vantage | Distinguish outside-in, onsite, passive wireless and local-only observations |
| Target and method approval reference | Verify that collection fell inside signed scope |
| UTC acquisition time | Reconstruct sequence while documenting clock/offset limitations |
| Original byte count and SHA-256 | Detect later file changes |
| Independent review state | Separate raw observation, unconfirmed candidate and validated finding |
| Derivative/redaction hash | Keep disclosure-safe report copies traceable without overwriting originals |

## Offline SHA-256 Example

The [manifest helper](../tools/evidence_manifest.py) recursively inventories **existing** regular local files beneath a selected folder and generates a JSON manifest with relative paths, sizes and hashes. It skips symlinks, refuses to write into the input tree and refuses to overwrite an existing output path. It has no network access or collection features.

```bash
python Cyberdeck/tools/evidence_manifest.py \
  --input Cyberdeck/examples/synthetic-evidence \
  --output /tmp/pnwc-synthetic-manifest.json
```

A SHA-256 match indicates a particular file's bytes match the recorded digest. **It does not authenticate who acquired the material, validate the accuracy of source timestamps, establish legal custody or certify safe handling.** For formal evidence, independently protect logs, identities, signed manifests and transfer records.

## Public Release Review

Before publishing even a sample, remove or replace customer names, addresses, infrastructure identifiers, file paths, VPN names, public/private IP assignments, SSIDs, client MACs, service URLs, tokens, scan exports, internal reports, signatures and metadata embedded in images. A private Git history can retain old secrets even after deletion; use a **fresh** repository or curated tree rather than toggling a confidential repository to public.

Use [publication and release checklist](PUBLISHING_AND_RELEASE.md) before moving any material from a confidential source.

## Verify a Saved Inventory

Use [verify_manifest.py](../tools/verify_manifest.py) with `--input` pointing at the evidence folder and `--manifest` pointing at a saved manifest outside it. See the [runbook](BUILD_AND_OPERATIONS.md) for cross-platform commands and exit codes. Verification reports added, missing and changed regular files without modifying evidence or the manifest. It validates the v1 inventory fields and rejects duplicate or unsafe relative paths.

Both utilities exclude symlinks and are intended for quiescent, trusted local evidence copies. They are not filesystem snapshots or protection against hostile concurrent changes. An empty inventory may be valid but proves no collection occurred. A directory traversal error aborts creation rather than silently omitting an unreadable directory. The manifest creation timestamp is hashing time, not acquisition time.

Preserve the baseline separately under access control. Compare after transfer and restore; keep mismatch records and investigate without overwriting originals. The original baseline and a derivative/redacted inventory are separate artifacts. Neither utility signs the manifest, validates case metadata, enforces retention or verifies encryption.
