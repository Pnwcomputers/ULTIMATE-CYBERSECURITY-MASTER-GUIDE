# 📦 Container & Kubernetes Security

<div align="center">

**Threat model, attack surface, and hardening for containers and Kubernetes**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Focus](https://img.shields.io/badge/Focus-Container_Security-blue?style=for-the-badge)
![Kubernetes](https://img.shields.io/badge/Orchestration-Kubernetes-orange?style=for-the-badge)
![Use](https://img.shields.io/badge/Use-Authorized_Only-red?style=for-the-badge)

</div>

---

## 🎯 Purpose
Dedicated home for container and Kubernetes security - the image/runtime attack
surface, container escape, the Kubernetes threat model, and hardening for both.

## ⚙️ Function
Indexes the Container Security section: cross-cutting fundamentals and tooling
(this file), container/image security and escape techniques
([containers.md](./containers.md)), and Kubernetes security - RBAC, Pod Security
Standards, secrets, network policy, attack paths, and hardening
([kubernetes.md](./kubernetes.md)) - each pairing offense with defense.

## 🏆 Goal
Give practitioners a single reference for how containerized and orchestrated
workloads are attacked and how to harden them, complementing the
[Cloud](../Cloud/README.md) section.

## 📋 When to Use
- Assessing or hardening a container image, runtime, or Kubernetes cluster
- Looking up container-escape vectors or Kubernetes attack paths
- Selecting scanning/runtime-security tooling
- Reviewing a cluster against the CIS Kubernetes Benchmark

---

## 📋 Table of Contents

- [Overview](#-overview)
- [The Container Threat Model](#-the-container-threat-model)
- [Tooling](#-tooling)
- [Folder Contents](#-folder-contents)
- [Security & Legal Disclaimer](#-security--legal-disclaimer)
- [Resources](#-resources)

---

## 🎯 Overview

Containers and Kubernetes are now the default way applications ship and run, and
they add attack surface at several layers - the image, the container runtime, the
host, and the orchestrator. This section consolidates container security
(previously scattered across the master guides) into fundamentals plus depth on
containers and Kubernetes.

Like [Cloud](../Cloud/) and [Tradecraft](../Tradecraft/), the material is
**dual-use**: each guide pairs the offensive view (how workloads are attacked and
escaped) with hardening and detection.

---

## 🎯 The Container Threat Model

Attack surface spans four layers:

| Layer | Example risks |
|-------|---------------|
| **Image** | Vulnerable packages, embedded secrets, untrusted base images, no signing |
| **Runtime** | Privileged containers, over-broad capabilities, mounted `docker.sock`, `hostPath` |
| **Host** | Container **escape** to the node; shared kernel; weak isolation |
| **Orchestrator (K8s)** | Over-permissive RBAC, exposed API server, weak Pod Security, flat networking |

The defining property: **containers share the host kernel**, so isolation is
weaker than a VM - a misconfiguration or kernel vulnerability can lead to escape.

---

## 🛠️ Tooling

| Tool | Role |
|------|------|
| [Trivy](https://github.com/aquasecurity/trivy) | Image, filesystem, and IaC vulnerability + misconfiguration scanning |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS Kubernetes Benchmark checks |
| [kubescape](https://github.com/kubescape/kubescape) | Cluster risk analysis, misconfiguration, and compliance scanning |
| [Falco](https://github.com/falcosecurity/falco) | Runtime threat detection (syscall-based); CNCF |
| [Docker Bench for Security](https://github.com/docker/docker-bench-security) | CIS Docker Benchmark checks |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | Cluster penetration-testing scanner (authorized use) |

---

## 📂 Folder Contents

| File | Description | Status |
|------|-------------|--------|
| **[containers.md](./containers.md)** | Image and runtime security, container escape vectors, and hardening (Docker/OCI) | ✅ Complete |
| **[kubernetes.md](./kubernetes.md)** | RBAC, Pod Security Standards, secrets, network policy, attack paths, and hardening | ✅ Complete |

---

## ⚠️ Security & Legal Disclaimer

> [!CAUTION]
> **Authorized use only.** The techniques here are for authorized assessment,
> education, and defensive research. Test only clusters and images you own or have
> **explicit written permission** to assess - and where the cluster runs on a cloud
> provider, follow that provider's penetration-testing policy too. See
> [LEGAL.md](../LEGAL.md).

---

## 📚 Resources

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) / [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NSA/CISA Kubernetes Hardening Guidance](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-152a)
- [Kubernetes Security documentation](https://kubernetes.io/docs/concepts/security/)
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)

---

<div align="center">

**⚠️ USE THIS REPO RESPONSIBLY AND LEGALLY ⚠️**

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

</div>

---

## Related Files
- [containers.md](containers.md) - Container image & runtime security
- [kubernetes.md](kubernetes.md) - Kubernetes security
- [../Cloud/README.md](../Cloud/README.md) - Cloud security (managed K8s: EKS/AKS/GKE)
- [../LEGAL.md](../LEGAL.md) - Legal notice and authorized-use terms
