# Legal and Responsible Use Notice

> **Informational notice; not legal advice or a contract.** This page summarizes general
> considerations for reading a cybersecurity reference repository. It does not create
> a binding agreement, determine whether any particular activity is lawful, or replace
> advice from a qualified lawyer familiar with the relevant facts and jurisdiction.

## What this repository contains

The repository includes defensive references, lab exercises, scripts, hardware
projects, and descriptions of security testing techniques. Some material can affect
systems, networks, radio services, accounts, credentials, or personal data when used.
A guide's presence here does not establish that a command is safe for every environment,
current for every tool version, or authorized for a particular target.

## Authorization and scope

Before active testing, confirm you have authority for the exact system, account,
network, device, data, technique, time window, and expected effects. Use the form of
approval required by the system owner, contract, policy, and applicable law. Keep
written scope where appropriate and preserve any exclusions, stop conditions,
emergency contacts, and data-handling rules.

Stop if ownership, consent, scope, service rules, or potential impact is unclear.
Do not test third-party systems, credentials, communications, or radio services just
because a tool is available or a device is nearby. A lab, simulator, test account,
or shielded enclosure can reduce some risks, but does not automatically provide legal
authorization or guarantee containment.

## Legal requirements depend on the activity

The law can depend on the specific conduct, intent, authorization, data, affected
service, jurisdiction, and other facts. Similar words such as “access,” “interception,”
“damage,” “credential,” or “transmission” can have different definitions under
different statutes and rules. A warning elsewhere in the repository is not a legal
finding about a particular situation.

### Computer access and damage

In the United States, the [Computer Fraud and Abuse Act, 18 U.S.C. § 1030](https://uscode.house.gov/us/usc/119-118/t18/s1030/)
contains several distinct offenses, each with its own elements and penalties. Whether
the statute applies depends on the subsection and facts; there is no single penalty
that applies to every unauthorized or out-of-policy computer activity. The Supreme
Court's [Van Buren decision](https://www.supremecourt.gov/opinions/20pdf/19-783_k53l.pdf)
and the [Department of Justice charging policy](https://www.justice.gov/jm/jm-9-48000-computer-fraud)
provide additional context. State, territorial, tribal, and other national laws may
also apply.

### Communications and personal data

Network monitoring, packet capture, account research, and collection of identifiers
may involve privacy, interception, wiretap, data-protection, or sector-specific rules.
Consent requirements and exceptions differ across jurisdictions and contexts. Collect
only data approved for the engagement, minimize retention, protect evidence, and do
not assume that “read-only” collection is automatically lawful.

### Radio-frequency and satellite activity

Radio requirements are service- and band-specific. In the United States, some devices
may operate under [FCC Part 15](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15)
subject to technical conditions, including rules against harmful interference.
Satellite earth-station operations may require separate authority; see, for example,
[47 CFR § 25.115](https://www.ecfr.gov/current/title-47/section-25.115). Other services,
locations, and countries have different requirements. Do not transmit, jam, spoof, or
interfere with a real service unless the operation is specifically authorized and
compliant with the applicable rules. A shielded enclosure is a risk-reduction measure,
not a universal legal safe harbor.

### Payment, identity, and export-controlled material

Payment credentials, identity documents, health information, and other sensitive data
may be subject to additional statutes, contracts, network rules, or privacy duties.
Use synthetic data and issuer-provided test credentials unless the engagement
specifically authorizes other handling. Export-control requirements may apply to
some technology, software, hardware, or destinations; check the applicable rules
before transfer.

## Possible consequences

Depending on the facts and jurisdiction, misuse can result in service disruption,
data exposure, contractual or employment consequences, civil claims, regulatory
action, or criminal investigation. Charges, remedies, and penalties are determined
under the applicable law and by the relevant authorities or courts. This notice does
not predict a sentence, fine, extradition, professional sanction, or other outcome.

## Responsible use checklist

- Identify the owner and responsible contact for each target.
- Confirm the authorization, exact scope, approved methods, time window, and stop conditions.
- Prefer isolated labs, synthetic data, and non-production systems.
- Use bounded, low-impact methods; avoid destructive, disruptive, or privacy-invasive actions unless specifically authorized and planned.
- Protect credentials, collected data, logs, and evidence; retain only what the approved purpose requires.
- Stop and report unexpected impact, out-of-scope access, or accidental data collection through the agreed channel.
- Verify tool versions, documentation, and environment-specific effects before use.

## Repository content and distribution

The material is provided for education, defensive work, and authorized testing. It may
be incomplete, outdated, or unsuitable for a particular environment. Review the
source, dependencies, and effects before running code or following a procedure.
Use of this repository does not grant permission to access systems, accounts, data,
or radio services.

This notice is informational and does not replace a separately reviewed license,
contract, or terms-of-use agreement. To the extent permitted by applicable law, the
repository content is provided without warranty. Nothing in this paragraph waives
rights or responsibilities that cannot legally be waived.

## Reporting an issue

For corrections to repository content, open an issue or pull request with the affected
file and a source that supports the proposed correction. For a security issue involving
a repository-maintained artifact, use the repository's published security reporting
channel. Do not submit personal data, secrets, or third-party vulnerability details
that you are not authorized to disclose.
