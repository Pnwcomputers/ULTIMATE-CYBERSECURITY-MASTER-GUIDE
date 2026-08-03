# ☸️ Kubernetes Security

> [!CAUTION]
> **Authorized use only.** The techniques below are for authorized assessment,
> education, and defensive research. Test only clusters you own or have **explicit
> written permission** to assess (and follow the cloud provider's pentest policy
> for managed clusters). See [LEGAL.md](../LEGAL.md).

## 🎯 Purpose
Kubernetes security reference - the cluster attack surface, RBAC and Pod Security,
common attack paths, and hardening.

## ⚙️ Function
Covers the K8s components and trust boundaries, RBAC, **Pod Security Standards**
(the replacement for the removed PodSecurityPolicy), secrets, network policy,
common attack paths, and a hardening baseline mapped to the CIS Kubernetes
Benchmark and NSA/CISA guidance.

## 🏆 Goal
Let a reader assess a Kubernetes cluster methodically and recommend concrete
hardening.

## 📋 When to Use
- Authorized assessment or hardening of a Kubernetes cluster
- Looking up K8s attack paths (RBAC abuse, privileged pods, exposed API/kubelet)
- Building a cluster hardening baseline

---

## 📋 Table of Contents

- [Cluster Attack Surface](#cluster-attack-surface)
- [RBAC](#rbac)
- [Pod Security Standards (PSP is Removed)](#pod-security-standards-psp-is-removed)
- [Secrets & Network Policy](#secrets--network-policy)
- [Common Attack Paths](#common-attack-paths)
- [Hardening & Detection](#hardening--detection)
- [Resources](#-resources)

---

## Cluster Attack Surface

- **API server** - the front door; exposed or weakly authenticated API servers are
  a critical risk.
- **etcd** - stores all cluster state (incl. secrets); must be encrypted and
  access-restricted.
- **kubelet** - the node agent; an exposed/anonymous kubelet API can allow command
  execution in pods.
- **Workloads** - over-privileged pods and service accounts.
- **Supply chain** - images and admission (see [containers.md](containers.md)).

---

## RBAC

Role-Based Access Control governs who can do what. Common problems:

- **Over-permissive roles** - `cluster-admin` bindings, wildcard verbs/resources.
- **Dangerous permissions** - `create pods` (+ a privileged pod), `create` on
  `pods/exec`, `secrets get/list`, `escalate`/`bind` on roles, `impersonate`.
- **Default service-account tokens** auto-mounted into pods that don't need them.

```bash
# Enumerate what the current identity can do (authorized)
kubectl auth can-i --list
kubectl auth can-i create pods
```

**Defend:** least-privilege roles; no wildcard `cluster-admin`; disable
auto-mounting of service-account tokens where unused (`automountServiceAccountToken:
false`); audit RBAC (kubescape / `kubectl-who-can`).

---

## Pod Security Standards (PSP is Removed)

> [!IMPORTANT]
> **PodSecurityPolicy (PSP) was deprecated in Kubernetes 1.21 and removed in 1.25.**
> Guides that still tell you to configure PSPs are out of date. The built-in
> replacement is **Pod Security Admission (PSA)**, which enforces the **Pod Security
> Standards (PSS)**.

The three Pod Security Standards levels:

- **Privileged** - unrestricted (avoid for workloads).
- **Baseline** - blocks known privilege escalations; a sensible minimum.
- **Restricted** - hardened best practice (non-root, no privilege escalation,
  dropped capabilities, seccomp).

Apply per-namespace via labels (`pod-security.kubernetes.io/enforce: restricted`).
For policy beyond PSA, use an admission controller like **OPA/Gatekeeper** or
**Kyverno**.

---

## Secrets & Network Policy

- **Secrets** are only base64-encoded at rest by default - enable **etcd encryption
  at rest**, restrict `get/list secrets` via RBAC, and prefer an external secrets
  manager (cloud KMS, Vault).
- **Networking is flat by default** - any pod can reach any pod. Apply
  **NetworkPolicies** (default-deny, then allow-list) to segment workloads and limit
  lateral movement.

---

## Common Attack Paths

For authorized testing, the recurring paths:

- **Exposed API server / dashboard** without auth → cluster control.
- **Anonymous or exposed kubelet** (`:10250`) → exec into pods.
- **RBAC → pod creation** → schedule a privileged pod that mounts the host or reads
  node credentials (a node/cloud-credential escalation).
- **Readable secrets** → cloud credentials or app secrets → pivot.
- **Container escape** from a workload to the node (see [containers.md](containers.md)).
- Scanners: `kube-hunter` (pentest), `kubescape`, `kube-bench` (benchmark).

---

## Hardening & Detection

- **Access:** strong API-server authn/authz; no anonymous auth; least-privilege
  RBAC; protect the kubelet.
- **Workloads:** enforce **Restricted** Pod Security where feasible; non-root,
  read-only FS, dropped capabilities, seccomp; admission control (Gatekeeper/Kyverno).
- **Data:** etcd encryption at rest; tight secret RBAC; external secret stores.
- **Network:** default-deny NetworkPolicies; segment namespaces.
- **Supply chain:** scan images (Trivy); require signed images at admission.
- **Detection:** audit logging enabled and shipped to a
  [SIEM](../IncidentResponse/SIEM/README.md); runtime detection with
  [Falco](https://github.com/falcosecurity/falco).
- **Benchmark:** [kube-bench](https://github.com/aquasecurity/kube-bench) against the
  [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes); review
  the [NSA/CISA Kubernetes Hardening Guidance](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-152a).

---

## 📚 Resources

- [Kubernetes Security docs](https://kubernetes.io/docs/concepts/security/) / [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) / [kube-bench](https://github.com/aquasecurity/kube-bench)
- [kubescape](https://github.com/kubescape/kubescape) / [Falco](https://github.com/falcosecurity/falco)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [MITRE ATT&CK Containers](https://attack.mitre.org/matrices/enterprise/containers/)

---

## Related Files
- [README.md](README.md) - Container & Kubernetes Security section index
- [containers.md](containers.md) - container image & runtime security
- [../Cloud/README.md](../Cloud/README.md) - managed Kubernetes (EKS/AKS/GKE) sits in the cloud section
