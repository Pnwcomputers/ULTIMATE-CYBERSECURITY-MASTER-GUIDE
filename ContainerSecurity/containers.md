# 🐳 Container Image & Runtime Security

> [!CAUTION]
> **Authorized use only.** The techniques below are for authorized assessment,
> education, and defensive research. Test only images and hosts you own or have
> **explicit written permission** to assess. See [LEGAL.md](../LEGAL.md).

## 🎯 Purpose
Container (Docker/OCI) security reference - image and runtime risks, container
escape vectors, and hardening.

## ⚙️ Function
Covers image security (base images, vulnerabilities, secrets, signing), runtime
misconfigurations, the main **container escape** vectors, and a hardening baseline
mapped to the CIS Docker Benchmark.

## 🏆 Goal
Let a reader assess a containerized workload for the common issues and recommend
concrete hardening.

## 📋 When to Use
- Reviewing a container image or runtime configuration
- Looking up container-escape vectors during an authorized test
- Building a container hardening baseline

---

## 📋 Table of Contents

- [Image Security](#image-security)
- [Runtime Misconfigurations](#runtime-misconfigurations)
- [Container Escape Vectors](#container-escape-vectors)
- [Hardening](#hardening)
- [Resources](#-resources)

---

## Image Security

- **Vulnerabilities:** base images and packages carry known CVEs; scan every image
  in CI and before deploy (`trivy image IMAGE`).
- **Secrets in images:** credentials baked into layers or `ENV` persist in history -
  never bake secrets; use build secrets / runtime injection; scan with Trivy/git-secrets.
- **Untrusted base images:** prefer minimal, official, or distroless bases; pin by
  digest, not floating tags.
- **Provenance:** sign images and verify signatures (Cosign / Sigstore); enforce at
  admission.

```bash
# Scan an image for vulnerabilities and misconfigurations (authorized)
trivy image --severity HIGH,CRITICAL myorg/app:1.2.3
```

---

## Runtime Misconfigurations

The high-risk runtime settings (each is also an escape enabler):

- **`--privileged`** - disables most isolation; near-equivalent to root on the host.
- **Mounted Docker socket** (`-v /var/run/docker.sock:...`) - control of the socket
  is control of the daemon, hence the host.
- **Excessive capabilities** - especially `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`,
  `CAP_NET_ADMIN`; drop all and add back only what is needed.
- **`hostPath` / host namespaces** (`--pid=host`, `--net=host`) - break isolation.
- **Running as root** inside the container; no read-only root filesystem.

---

## Container Escape Vectors

For authorized testing, the classic escape checks:

```bash
# Am I in a container? What privileges?
ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup | grep -i docker
capsh --print                       # enumerate capabilities
mount | grep -i docker.sock         # mounted daemon socket?
```

Common escape paths:

- **Privileged container** - mount the host filesystem or abuse cgroups to run code
  on the node.
- **Mounted `docker.sock`** - `docker -H unix:///var/run/docker.sock run --privileged
  --pid=host ... nsenter` onto the host.
- **`CAP_SYS_ADMIN`** - enables mounts and several escape techniques.
- **Kernel/runtime vulnerabilities** - e.g. historical runc CVEs (keep the runtime patched).

*(These are illustrative checks; only run them against systems you are authorized to test.)*

---

## Hardening

- **Least privilege:** `--cap-drop=ALL` then add only what is needed; never
  `--privileged`; run as a non-root `USER`; `--read-only` root FS with explicit
  writable mounts.
- **No host exposure:** don't mount `docker.sock`, host namespaces, or sensitive
  `hostPath`s; use user namespaces where possible.
- **Images:** minimal/distroless base, pinned by digest, scanned in CI, signed and
  verified.
- **Resources:** set CPU/memory limits to contain abuse.
- **Runtime detection:** [Falco](https://github.com/falcosecurity/falco) for
  anomalous syscalls; ship events to a [SIEM](../IncidentResponse/SIEM/README.md).
- Benchmark with [Docker Bench for Security](https://github.com/docker/docker-bench-security)
  against the [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).

---

## 📚 Resources

- [Trivy](https://github.com/aquasecurity/trivy) - image/IaC scanning
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) / [Docker Bench](https://github.com/docker/docker-bench-security)
- [Docker security documentation](https://docs.docker.com/engine/security/)
- [Sigstore / Cosign](https://www.sigstore.dev/) - image signing & verification
- [MITRE ATT&CK Containers](https://attack.mitre.org/matrices/enterprise/containers/)

---

## Related Files
- [README.md](README.md) - Container & Kubernetes Security section index
- [kubernetes.md](kubernetes.md) - Kubernetes security
- [../Cloud/README.md](../Cloud/README.md) - Cloud security
