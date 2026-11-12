# Public Reference to Private Implementation

[Cyberdeck Home](../README.md) · [Field Device Workflow](PORTABLE_WIRELESS_FIELD_DEVICES.md) · [Acceptance Matrix](ACCEPTANCE_TESTS.md) · [Publication Boundary](PUBLISHING_AND_RELEASE.md)

Use this public section as a design and qualification contract for the private setup. Public documentation can describe interfaces, expected behavior and synthetic examples without publishing private application code, live configurations or customer material. This roadmap does not assert access to or inspection of the private repository.

## Milestones in Dependency Order

| Milestone | Public deliverable | Work in the private setup | Definition of done |
| --- | --- | --- | --- |
| M0: Reproducible baseline | Runbook, policy matrix and qualification template | Inventory actual models, firmware, port map, operating system and revision | Another operator can reconstruct the lab; unresolved assumptions are listed |
| M1: Reliable evidence | Offline manifest creation and verification | Provision encrypted vault, protected baseline, identities, backup and restore | Q06, Q07 and Q13 pass on synthetic cases |
| M2: Manual case workflow | Engagement and report templates | Case lifecycle, unique IDs, scope revisions, private evidence references and review states | A synthetic case goes from intake to close with an auditable record |
| M3: Proven network boundary | Zone objectives and visibility caveats | Actual firewall policy, cabling, IPv4/IPv6 checks and recovery | Q01–Q05 pass for enabled paths and sensors |
| M4: Supervised tool execution | Method and output contracts described below | Scope gate, bounded inputs, timeout, process tracking, cancel, export review | Q08 and Q12 pass; failures cannot silently become successful findings |
| M5: Portable reliability | Power and enclosure worksheet | Measured load, runtime reserve, thermal test, low-space and restart behavior | Q09 and Q10 pass within a documented operating envelope |
| M6: Optional integrations | [Flipper/Pineapple/Bruce/Marauder field workflows](PORTABLE_WIRELESS_FIELD_DEVICES.md), synthetic adapter examples and limitations | Device-specific manual import first; separately qualify any live control | Each integration has tests, provenance, stop behavior and supported versions; Q15–Q18 as relevant |
| M7: Optional external origin | Vantage requirements | Separately controlled runner, authenticated transport and case isolation | Source is independently verified; scope, cancellation and transfer gates pass |

M0–M3 make a useful manual platform. M4, M6 and M7 add complexity and should not block documentation or offline evidence work. No task here authorizes exploitation, radio transmission or client testing.

## Private Data and Interface Contracts

| Record | Minimum fields | Invariant |
| --- | --- | --- |
| Case | Case ID, owner reference, state, scope revision, operator, timestamps | State transitions record who changed what and why |
| Scope | Approved assets, sources, methods, exclusions, UTC window, approval reference | Missing, expired or ambiguous approval prevents execution |
| Tool run | Run ID, case/scope revision, actual source, tool/version, structured arguments, start/end, exit status | Operator text is not evaluated as shell code; cancellation is recorded |
| Evidence | Artifact ID, case/run reference, acquisition time and source, size/hash, custody reference | Original bytes remain distinct from reviewed derivatives |
| Finding | Claim, affected asset, evidence references, confidence, impact, reviewer, remediation | Candidate observations cannot become confirmed findings without review |
| Integration | Supported device/firmware, permitted method, input/output contract, failure/stop states | Unsupported hardware and malformed exports fail explicitly |

These contracts are design requirements, not a claim that the existing private prototype implements them. Store paths, credentials and identifiers privately. The public JSON example is illustrative; it is not a validated database schema or a custody system.

## Case and Run State

Suggested case progression: `DRAFT → SCOPE_REVIEW → APPROVED → COLLECTING → REVIEW → DELIVERED → CLOSED`. Record rejection, scope changes and stop events explicitly. A case label alone is insufficient: revalidate the current window, method, target and source immediately before each run. Scope amendments should invalidate stale execution approvals until reviewed.

Suggested run outcomes: `QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, `TIMED_OUT`. Preserve partial outputs with their actual outcome. A process exit code of zero is not proof of a security finding, complete collection or trustworthy evidence. A portal stop control must track child processes and independent devices; demonstrate what it can and cannot stop.

## Next Private Development Tasks

1. Compare these contracts with the current private implementation and mark each requirement implemented, partial or absent with a source revision and test reference.
2. Complete M0 and M1 with one synthetic case before adding device automation.
3. Complete the manual M2 case end to end, including a deliberately failed collection, a redacted derivative, a restore and a skipped-test report entry.
4. Qualify M3 on owned fixtures. Fix unexpected paths before enabling any client interface.
5. Add one bounded integration at a time only after its milestone gates pass. Keep an operator review step before reports or external delivery.

Keep public and private issue lists separate. Public issues may reference milestone IDs and generic behavior; private issues carry actual configurations, customer identifiers, implementation details and qualification artifacts. Promote only independently reviewed synthetic examples back to this repository. Choose licensing separately; expanding these docs does not change the existing publication terms.
