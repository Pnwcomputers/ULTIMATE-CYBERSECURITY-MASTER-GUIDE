# Ethical CTF, research and professional assessment training pathways

_2026-11-03 · [PlayBooks](README.md) · [Main guide](../README.md)._

The following education paths are drawn from [Awesome-Hacking](https://github.com/Hack-with-Github/Awesome-Hacking), [h4cker](https://github.com/The-Art-of-Hacking/h4cker), and [Awesome-Hacking-Resources](https://github.com/vitalysim/Awesome-Hacking-Resources). A training environment is not permission to run exploits on a client system.

| Level | Public learning resource | Competency and evidence |
| --- | --- | --- |
| Foundations | [OverTheWire](https://overthewire.org/wargames/), [picoCTF](https://picoctf.org/), [Hopper's Roppers](https://www.hoppersroppers.org/) | Bash, protocols, encodings; create concise solution notes |
| Web and API | [PortSwigger Web Security Academy](https://portswigger.net/web-security), [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [WebGoat](https://github.com/WebGoat/WebGoat) | Practice request/response validation, auth and access-control defense |
| Cryptography/reversing | [Cryptopals](https://cryptopals.com/), [crackmes.one](https://crackmes.one/), [RPISEC MBE](https://github.com/RPISEC/MBE) | Distinguish encoding vs encryption; document samples safely |
| Network detection and DFIR | [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/), [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) | Analyze **provided PCAP fixtures**; detection hypothesis and false-positive review |
| Isolated systems lab | [h4cker lab resources](https://github.com/The-Art-of-Hacking/h4cker/tree/master/build-your-own-lab), [Vulhub](https://github.com/vulhub/vulhub), [Metasploitable3](https://github.com/rapid7/metasploitable3) | Segmented virtual network, snapshots, mock reports, restoration |
| AI model assessment | [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/), [Promptfoo](https://github.com/promptfoo/promptfoo), [PyRIT](https://github.com/Azure/PyRIT) | Repeatable guardrail, leakage and prompt-injection testing on authorized apps |

## Standard report for each exercise

1. Record legal right to run the test, scope, challenge version and expected behavior.
2. Isolate test VM/network; snapshot, disable public access to intentionally vulnerable systems and use dummy identities.
3. Note a hypothesis and controlled steps; preserve input/output, commands, versions, UTC time and file hashes.
4. Explain *why* the behavior occurred, expected safeguards and the relevant defensive control.
5. Validate the fix or compensating detection, including false-positive or coverage caveats.
6. Restore/tear down the lab, confirm exposed ports are closed and remove credentials or test datasets.

For transition to PNWC customer work, follow [staged client assessments](assessment-service-integration-map.md), [findings lifecycle](assessment-findings-lifecycle.md), and the [Proxmox sensor visibility checklist](../Homelab/proxmox-security-monitoring-visibility.md).

**Status:** Educational source integration, no labs executed here. Provider prices, course versions and training terms change; check each official website before teaching.

[Source map](../Documentation/awesome-hacking-collections-integration.md) · [START HERE](../START_HERE.md) · [Legal](../LEGAL.md).
