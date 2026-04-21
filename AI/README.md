# 🤖 AI Cybersecurity Resources

<div align="center">

**AI, Machine Learning, and Generative Intelligence resources applied to cybersecurity**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![AI Agents](https://img.shields.io/badge/AI_Agents-OpenClaw_|_AnythingLLM-red?style=for-the-badge)]()
[![LLM Providers](https://img.shields.io/badge/LLM_Providers-Anthropic_|_Gemini_|_Groq_|_Ollama-purple?style=for-the-badge)]()
[![Deployment](https://img.shields.io/badge/Deployment-Self--Hosted_|_TrueNAS_SCALE-blue?style=for-the-badge)]()
[![Use Cases](https://img.shields.io/badge/Use_Cases-Blue_Team_|_Red_Team_|_OSINT-green?style=for-the-badge)]()

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Folder Contents](#folder-contents)
- [Resource Categories](#resource-categories)
- [How to Use These Resources](#how-to-use-these-resources)
- [Security & Legal Disclaimer](#security--legal-disclaimer)
- [Contributing](#contributing)
- [Resources](#resources)

---

## 🎯 Overview

This directory contains **resources, configurations, guides, and methodologies** focused on the intersection of artificial intelligence (AI), machine learning (ML), generative AI (GenAI), and cybersecurity — with an emphasis on **self-hosted, privacy-respecting deployments** that keep your data on your own hardware.

**What You'll Find Here:**
- Self-hosted AI agent frameworks (OpenClaw, AnythingLLM) with full setup guides for TrueNAS SCALE
- Multi-provider LLM routing — Anthropic Claude, Google Gemini, Groq, and local Ollama models
- AI-powered workflows for blue team, red team, purple team, OSINT, and IT support operations
- Prompt engineering cheat sheets and templates for security practitioners
- AgentFlow configurations for automating incident response, OSINT collection, and security audits
- Offline/air-gapped LLM deployment guides for sensitive environments

### Purpose

These resources are designed to:
- Provide **practical, deployable configurations** for integrating AI into cybersecurity workflows — not just theory
- Enable **cost-effective AI operations** using free tiers (Groq, Gemini) and local inference (Ollama) while reserving paid APIs for complex tasks
- Offer **reusable agent personas and skill configurations** for IT support, pentesting, and SOC work
- Encourage **responsible and privacy-conscious** use of AI with self-hosted infrastructure
- Serve as **training and reference material** for cybersecurity practitioners expanding into AI/ML

---

## 📂 Folder Contents

| File/Folder | Description |
|-------------|-------------|
| **[offline-llm.md](offline-llm.md)** | Create a completely offline LLM system — hardware selection, model deployment, air-gapped setup, and operational security for sensitive environments |
| **[ai_prompts.md](ai_prompts.md)** | Master resource and cheat sheet for high-performance AI prompting — templates, patterns, and techniques for security and IT workflows |
| **[AnythingLLM/](AnythingLLM/)** | Generative AI configuration and AgentFlows for automating incident response, OSINT data collection, and security audits using a self-hosted AnythingLLM instance |
| **[OpenClaw/](OpenClaw/)** | Complete setup guide and configurations for deploying OpenClaw on TrueNAS SCALE — multi-provider LLM routing, homelab integration, and cybersecurity agent workflows |
| └ [README.md](OpenClaw/README.md) | TrueNAS SCALE installation guide — ixVolume setup, provider config, NPMplus HTTPS proxy, device pairing, and troubleshooting |
| └ [use_cases.md](OpenClaw/use_cases.md) | Real-world prompt examples for IT support, blue team, red team, purple team, OSINT, homelab, and business operations |
| └ [agent_skill_config.md](OpenClaw/agent_skill_config.md) | Pre-built agent personas, skill configurations, cron jobs, and multi-agent workflow setups |

---

## 🗂️ Resource Categories

### 1. 🦞 Self-Hosted AI Agent Frameworks

**Purpose**: Deploy persistent AI agents on your own hardware that connect to messaging platforms, tools, and services.

**What's included:**
- **OpenClaw on TrueNAS SCALE** — Full deployment guide for a multi-provider AI agent framework running as a TrueNAS community app. Connects to Telegram, Discord, Slack, and 50+ channels. Routes tasks automatically between Anthropic, Gemini, Groq, and local Ollama models based on cost and capability.
- **AnythingLLM AgentFlows** — Custom automation flows for incident response, OSINT collection, log analysis, and security audits running inside a self-hosted AnythingLLM instance.

**Key capabilities:**
- Run 24/7 on your homelab with no cloud dependency
- Free inference via Groq (Llama 3.3 70B) and Gemini free tiers
- Fully local/private inference via Ollama for sensitive data
- Scheduled automations, cron jobs, and event-driven hooks

---

### 2. 🧠 GenAI / LLM Applications for Security

**Purpose**: Apply large language models to security operations tasks — report generation, log analysis, threat hunting, and SOC automation.

**Key focus areas:**
- Prompt engineering for security workflows — triage, IR, pentest reporting
- RAG (retrieval-augmented generation) for threat intelligence and knowledge bases
- Multi-agent workflows for complex security assessments
- Model routing strategy — knowing when to use local vs. cloud models

**Included resources:**
- `ai_prompts.md` — Comprehensive prompt cheat sheet organized by security domain
- OpenClaw `use_cases.md` — 50+ real-world example prompts covering blue team, red team, OSINT, IT support, and business ops
- OpenClaw `agent_skill_config.md` — Pre-built agent personas for field tech, security analyst, pentester, OSINT researcher, and homelab monitor roles

---

### 3. 📴 Offline & Air-Gapped AI Deployment

**Purpose**: Run AI inference in environments where internet connectivity is restricted or prohibited — classified networks, air-gapped labs, sensitive client engagements.

**Key focus areas:**
- Hardware selection for local inference (GPU/CPU requirements by model size)
- Ollama deployment for offline model serving
- Air-gapped setup and model transfer procedures
- OPSEC considerations for AI in sensitive environments

**Included resources:**
- `offline-llm.md` — Complete guide to building a fully offline LLM system

---

### 4. 🔴 Red Team / Offensive AI Applications

**Purpose**: Use AI to enhance authorized penetration testing and offensive security research.

**Key capabilities (authorized engagements only):**
- Methodology assistance and attack chain planning
- Report writing and finding documentation
- OSINT automation and passive recon
- Payload research and exploit documentation
- CTF assistance and lab environment support

**Included resources:**
- OpenClaw Rex agent config — Pentest-focused persona with scope guardrails
- OpenClaw Oliver agent config — OSINT-focused research assistant
- `use_cases.md` red team and OSINT sections

---

### 5. 🔵 Blue Team / Defensive AI Applications

**Purpose**: Augment defensive security operations with AI-assisted detection, analysis, and response.

**Key capabilities:**
- Log analysis and alert triage
- SIEM rule and detection engineering (Wazuh/Sigma)
- Threat intelligence summarization
- Incident response playbook generation
- Security awareness training content

**Included resources:**
- OpenClaw Blaine agent config — Blue team analyst persona with MITRE ATT&CK awareness
- OpenClaw daily security digest cron job — Automated CVE and threat briefings
- `use_cases.md` blue team section

---

### 6. 📊 Assessment & Governance

**Purpose**: Ensure AI/ML components in security are deployed responsibly and effectively.

**Key focus areas:**
- Model risk assessment and validation
- Data privacy and bias mitigation
- Monitoring, drift detection, and retraining
- Ethical and legal compliance for AI in security contexts

---

## 📖 How to Use These Resources

### For IT & Security Practitioners
1. Start with **OpenClaw README.md** to deploy a self-hosted AI agent on TrueNAS SCALE
2. Once running, apply the **agent_skill_config.md** configurations for your role (IT support, blue team, red team, etc.)
3. Use **use_cases.md** as a daily reference for prompts relevant to your current work
4. Reference **ai_prompts.md** for prompt engineering techniques to improve output quality

### For Blue Teamers & SOC Analysts
- Deploy the Blaine (blue team analyst) agent persona from `agent_skill_config.md`
- Set up the daily security digest cron job for automated CVE and threat briefings
- Use the log analysis and SIEM rule writing prompts in `use_cases.md`
- Connect OpenClaw to Telegram for mobile alert notifications

### For Penetration Testers
- Deploy the Rex (pentester) and Oliver (OSINT) agent personas
- Use the multi-agent pentest workflow in `agent_skill_config.md` for end-to-end engagement support
- Reference `use_cases.md` red team section for methodology, reporting, and tool reference
- Use local Ollama models (`@ollama`) for sensitive engagement data

### For Sensitive / Air-Gapped Environments
- Follow `offline-llm.md` for fully offline deployment
- Use Ollama as the sole inference backend — no data leaves the machine
- Apply the `agent_skill_config.md` homelab agent (Homer) for infrastructure management

### Customization Tips
- **Adapt agent personas**: Edit the `instructions` field in agent configs to match your business name, client base, and tooling
- **Adjust model routing**: Change `primary`/`fallback` model assignments per agent based on your API budget
- **Modify cron schedules**: Update cron expressions in `agent_skill_config.md` to match your timezone and preferred timing
- **Extend skill prompts**: Each skill's prompt template is plain text — customize it to reference your specific environment

---

## ⚠️ Security & Legal Disclaimer

> These resources are provided for **authorized, ethical, and supervised use only.**
>
> Unauthorized use, misuse, or deployment of AI in security testing or operations without proper authorization, governance, and oversight is strictly prohibited.

Always comply with:
- ✅ Written authorization for all security engagements
- ✅ Local, state, federal, and international laws
- ✅ Ethical guidelines for AI usage in security contexts
- ✅ Your organization's governance, privacy, and data-handling standards
- ✅ Platform terms of service for all AI providers used

---

## 🤝 Contributing

### To Submit New Resources:
1. Fork the repository
2. Add your document, configuration, or guide in the appropriate subfolder
3. Update this README's Folder Contents table with your new file
4. Submit a pull request with a description of the contribution

### Good Contributions Include:
- ✅ Clear naming and consistent file structure
- ✅ Purpose statement and description at the top of each file
- ✅ Reusable and modular configurations/templates
- ✅ Governance and ethical sections where relevant
- ✅ Version history (e.g., `v1.0 – 2026-04-21 – JP`)
- ✅ Tested configurations — note the version/environment it was tested on

---

## 📚 Resources

**AI Frameworks & Tools:**
- **OpenClaw** — https://openclaw.ai
- **AnythingLLM** — https://anythingllm.com
- **Ollama** — https://ollama.ai
- **Hugging Face Models** — https://huggingface.co/models

**AI Security Research:**
- **MITRE ATLAS** (AI threat matrix) — https://atlas.mitre.org
- **NIST AI Risk Management Framework** — https://www.nist.gov/ai/risk-management-framework
- **OWASP LLM Top 10** — https://owasp.org/www-project-top-10-for-large-language-model-applications

**LLM Providers (Free Tiers Available):**
- **Groq** (Llama 3.3 70B, free tier) — https://console.groq.com
- **Google Gemini** (1M context, free tier) — https://aistudio.google.com
- **Anthropic Claude** — https://console.anthropic.com

---

## 🔗 Quick Links

- [🏠 Main Repository](../README.md)
- [🔍 OSINT Resources](../OSINT/OSINT_GUIDE.md)
- [📑 PDF Library](../PDF/)
- [📋 Checklists](../Checklists/)

---

<div align="center">

**🧠 Harness AI with a Security Mindset**
*Advance responsibly, stay ethical, stay effective.*

Maintained by **[Pacific Northwest Computers (PNWC)](https://pnwcomputers.com)**
⭐ If you find these resources useful, please star the repo ⭐

</div>
