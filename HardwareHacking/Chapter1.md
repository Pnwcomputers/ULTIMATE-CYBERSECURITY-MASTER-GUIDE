# Chapter 1: Threat Modeling for Hardware Security

## 🎯 Purpose
A framework for scoping hardware security risks by identifying assets, reachable interfaces, attacker capabilities, lifecycle conditions, controls, and residual risk.

## ⚙️ Function
Applies threat-modeling questions to embedded systems, including physical access, debug interfaces, firmware, side channels, fault injection, supply chain, and manufacturing or service states.

## 🏆 Goal
Produce a documented, evidence-based threat model that guides authorized assessment and practical design or operational controls.

## 📋 When to Use
- Scoping an authorized hardware security review
- Designing or procuring an embedded product
- Reviewing a device lifecycle, debug, update, service, or recovery process
- Prioritizing controls against a stated attacker capability

> *Part of the [Hardware Hacking Guide](./README.md) - [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

---

### Why Hardware Threat Modeling Differs

Hardware threat models include device-specific physical access, manufacturing, service, firmware, electrical, and side-channel conditions alongside ordinary software and network threats. Physical possession can create additional opportunities, but it does not by itself provide memory access, debug privileges, key extraction, or a successful bypass. Those outcomes depend on the design, lifecycle state, configuration, attacker capability, and evidence.

Treat interfaces such as JTAG, SWD, UART, boot ROM, and external flash as possible exposure points to verify. Their presence does not establish that they are enabled, reachable, unauthenticated, or able to access protected assets.

![Conceptual hardware threat-model flow from defined capability and reachable interfaces to controls, residual risk, and evidence](../assets/diagrams/hardware-threat-model-capability-flow.svg)

### Attacker Profiles

Describe capabilities directly instead of assigning universal cost or skill bands. Two useful scenarios for the same device may differ in access time, tools, expertise, allowed teardown, supply-chain access, and ability to retain or replace a device.

| Capability dimension | Questions to document |
|----------------------|-----------------------|
| Access | Remote, local, brief physical possession, prolonged possession, service access, or supply-chain access? |
| Resources | What equipment, facilities, budget, and replacement devices are available? |
| Expertise | Which hardware, firmware, cryptographic, or manufacturing skills are in scope? |
| Time and scale | One device or a fleet? How much access time, repetition, and preparation? |
| Constraints | Can the attacker open, modify, damage, or return the device? What detection or legal limits apply? |
| Objective | Data access, service disruption, cloning, unauthorized updates, or compromise of a specific trust boundary? |

Use named profiles only as shorthand for an explicit set of assumptions. Do not infer a device's required defense level solely from broad labels such as hobbyist or nation-state.

### Assets

Hardware assets differ from software assets because they are often **physical objects** whose compromise has physical consequences.

#### Asset Categories

| Category | Examples | Sensitivity |
|----------|---------|------------|
| **Cryptographic keys** | Root keys, device identity keys, session keys | Critical - disclosure often irrecoverable |
| **Firmware / IP** | Proprietary algorithms, product firmware | High - enables cloning, piracy, vulnerability research |
| **Configuration / fuses** | Security state bits, feature enables, calibration | High - manipulation enables bypass |
| **Runtime data** | PINs, passwords, intermediate crypto values | High - transient but frequently targeted |
| **Physical device** | PCB, chips, interfaces | Medium - extraction enables all other attacks |
| **Manufacturing data** | Test modes, debug interfaces, factory keys | High - often left active in production |

#### Asset-Attack Surface Mapping

Map each asset to its location, uses, trust boundaries, and potential observations or modification paths. A path is a hypothesis to validate, not a claim that the asset is practically extractable.

| Asset example | Questions to investigate |
|----------------|--------------------------|
| Cryptographic key | Where is it generated, stored, used, backed up, and erased? Which components can access it? What documented debug or side-channel controls apply? |
| Firmware or configuration | Which boot, update, recovery, and service paths can read or modify it? How are authorization and integrity checked? |
| Runtime secret | Is it exposed in logs, memory, peripheral buses, crash dumps, or physical observables? For how long? |
| Manufacturing or service data | Which factory modes, test interfaces, credentials, and lifecycle transitions exist, and how are they disabled or restricted in production? |

For example, a device may store a key in a secure element and use it through a cryptographic API. A power side channel, debug interface, or fault path is in scope only if the relevant access and device behavior are established for that target.

### Objectives

Translate each objective into a testable scenario with a defined precondition, asset, interface, security property, and observable success criterion.

| Objective | Candidate paths to assess | Conditions and evidence |
|-----------|---------------------------|-------------------------|
| Firmware confidentiality or integrity | Debug, boot, update, recovery, or external storage paths | Verify interface state, authorization, signature checks, and whether altered firmware is accepted |
| Key protection | Key-management API, debug state, power/EM leakage, backup or zeroization path | Establish key location, permitted operations, threat model, and independently verified leakage or exposure |
| Authentication integrity | Protocol, firmware, debug, or fault-resilience paths | Test only a scoped development target; a fault or unexpected output alone is not proof of an authentication bypass |
| Service availability | Power, clock, update, or physical tamper paths | Define recovery behavior, safe limits, and authorized disruption conditions |
| Supply-chain assurance | Manufacturing access, component substitution, signing and provisioning systems | Identify trust anchors, custody steps, and available verification evidence |

Avoid writing an attack path as a guaranteed result. For instance, a debug port or fault-injection method does not imply that a security fuse can be bypassed.

### Countermeasures

Select controls for the documented threat model and verify them on the target design and lifecycle. No single physical, silicon, or firmware control covers every fault, probing, leakage, update, or supply-chain scenario.

#### Silicon and Platform Controls

| Control | Potential contribution | Limits to assess |
|---------|------------------------|------------------|
| Debug authorization and lifecycle state | Restricts debug access on supported devices | Verify production provisioning, authenticated access, recovery, and failure behavior |
| Secure boot and measured boot | Detects or blocks unauthorized firmware changes when correctly rooted | Does not by itself protect secrets in a running system or guarantee safe update/recovery |
| Voltage, clock, and tamper monitoring | May detect specified abnormal conditions and trigger a response | Coverage depends on sensor thresholds, placement, response path, and tested fault models |
| Redundant or diverse checks | Can detect some incorrect computation before acting | Common-mode faults, compiler behavior, and shared inputs can undermine redundancy |
| Memory encryption | Protects specified data in particular memory or bus exposure scenarios | Does not automatically protect keys while in use, debug paths, or all physical attacks |
| Side-channel-resistant implementation | Constant-time code, masking, or hiding may reduce selected leakage | Requires implementation-specific analysis; no technique guarantees absence of all leakage |

A TRNG provides random values for designs that consume them; its presence alone does not randomize execution or prevent power-analysis leakage.

#### Firmware and Key Management

- **Authenticated updates and recovery:** Verify signatures, authorization, rollback policy, and recovery behavior across all update paths.
- **Lifecycle-aware debug policy:** Restrict production debug access while preserving documented and controlled service or recovery mechanisms.
- **Key isolation and provisioning:** Limit key use through defined interfaces; protect provisioning, backup, rotation, and zeroization.
- **Constant-time cryptographic operations:** Use vetted implementations and review the full call path, compiler output, and target environment where relevant.
- **Fault-aware checks:** Validate important results and fail safely, then assess the design against scoped fault models and common-mode behavior.
- **Secure diagnostics:** Avoid exposing secrets or security state in logs, crash reports, test interfaces, or service tools.

#### Physical and Operational Controls

| Control | Potential contribution | Limits to assess |
|---------|------------------------|------------------|
| Tamper-evident seals | May indicate that a device was opened or altered | Evidence can be missed, forged, or separated from device custody |
| Potting, shields, and enclosure design | Can raise effort or obstruct some access paths | Do not treat as proof that probing, optical access, or fault coupling is prevented |
| Intrusion sensing and response | May detect selected enclosure or environmental changes | Validate sensor coverage, bypass resistance, response timing, and false alarms |
| Board and package design | Can reduce exposed test points or add protection layers | Adds cost and does not replace secure firmware, lifecycle controls, or verification |
| Supply-chain and service procedures | Protects provisioning, components, credentials, and repair paths | Depends on custody, vendor controls, auditability, and key-management practices |

### Threat Model Template

For each target, record:

```
TARGET:
  Device/model/revision:
  Owner and authorized assessment scope:
  Deployment and lifecycle state:
  Safety, legal, and operational constraints:

ATTACKER CAPABILITIES:
  Access, time, equipment, expertise, scale:
  Explicitly excluded assumptions:

ASSETS AND TRUST BOUNDARIES:
  Asset / sensitivity / location / authorized users:
  Data and control paths:
  External interfaces and reachable states:

SCENARIOS:
  ID / objective / preconditions / path / expected observable:
  Likelihood rationale / impact / evidence confidence:

CONTROLS:
  Prevent / limit / detect / respond / recover:
  Implementation and verification status:
  Known gaps and common-mode considerations:

RESIDUAL RISK:
  Accepted or treated risk / owner / rationale / review date:
  Evidence retained and limitations:
```

Keep assumptions separate from observations. Mark an interface as reachable, a key as exposed, or a control as effective only when supported by target-specific documentation or authorized test evidence.

## Related Files
- [Hardware Security Case Studies](../CaseStudies/README.md) - Onity, Unsaflok, Tesla key-fob and EUCLEAK research to inform physical-access threat models
- [Chapter2.md](Chapter2.md) - Electrical fundamentals: the physical layer knowledge underlying every threat in this model
- [JTAGulator.md](JTAGulator.md) - Primary tool for exploiting the JTAG/UART debug-interface threat identified in threat models
- [T48_TL866-3G.md](T48_TL866-3G.md) - IC programmer for the firmware extraction threat vector
- [Chapter3.md](Chapter3.md) - Fault injection: one of the key hardware attacks this chapter helps scope
- [Chapter4.md](Chapter4.md) - Side-channel: the passive observation threat class this chapter introduces

---

<div align="center">

**Next:** [Chapter 2 - Electrical Fundamentals →](./Chapter2.md)

[← Back to Hardware Hacking README](./README.md)

</div>
