# 🚀 Ultimate AI Prompt Engineering (2026 Edition)

## 🎯 Purpose
Master prompt engineering cheat sheet for security practitioners - covering structured prompting, chain-of-thought, role-based prompts, and Fabric-style patterns synthesized from Anthropic, Google, OpenAI, and community frameworks.

## ⚙️ Function
Organized prompt templates and patterns for security-relevant tasks: incident response triage, threat hunting, log analysis, pentest report writing, code review, OSINT queries, and CTF assistance. Covers prompt anatomy, few-shot examples, constraint specification, and output format control.

## 🏆 Goal
Improve LLM output quality and consistency for security workflows through systematic prompting patterns rather than ad-hoc queries - making AI tools genuinely useful on engagements.

## 📋 When to Use
- Writing prompts for Claude, Gemini, GPT-4, or local Ollama models
- Building AnythingLLM AgentFlows or OpenClaw skill descriptions
- Training team members on effective AI tool use for security tasks
- Debugging poor LLM output by diagnosing prompt structure issues

A master resource and cheat sheet for high-performance prompting, synthesized from official documentation (Anthropic, Google, OpenAI) and industry-leading frameworks like Fabric.

## 🎯 Purpose
Platform-agnostic prompt engineering reference - templates, patterns, and psychology for getting better output from any LLM. Distinct from the OpenClaw `use_cases.md` and `agent_skill_config.md` (which are security-workflow-specific prompt examples): this file is technique-level, applicable to any prompting task regardless of domain.

## ⚙️ Function
Ten sections moving from platform documentation links (Anthropic/Google/OpenAI/Fabric) through advanced strategies (agentic prompting, chain-of-thought, multi-modal), copy-paste system prompt templates, platform-specific tactics, and a prompt-debugging protocol for fixing hallucination/laziness/logic-error failure modes.

## 🏆 Goal
Have ready-to-use prompt templates and debugging techniques on hand so you're not re-deriving prompt structure from scratch for every new task or AI tool.

## 📋 When to Use
- Writing a system prompt for a new AI agent or workflow (Section 3's Master Template)
- An AI response is hallucinating, being lazy, or making logic errors (Section 7's debugging protocol)
- Working across multiple LLM platforms and needing to know which tactics apply where (Section 4)

---

## 📚 1. Core Documentation & Resources

### 🤖 Anthropic (Claude)
- [Prompt Engineering Overview](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/overview) - The gold standard for XML tagging and "Thinking" strategies.
- [Prompt Improver](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/prompt-improver) - Automated tool for refining Claude prompts.

### ♊ Google (Gemini)
- [Gemini Prompting Strategies](https://ai.google.dev/gemini-api/docs/prompting-strategies) - Focuses on conversational intent and multimodal grounding.

### 🚀 OpenAI (GPT)
- [OpenAI Prompting Guide](https://platform.openai.com/docs/guides/prompting) - Comprehensive tactics for GPT-4o, focusing on delimiters and tool use.

### 🛠️ Community Standards
- [Fabric (Daniel Miessler)](https://github.com/danielmiessler/Fabric) - A systematic approach to "Patterns" and identity-based prompting.

---

## 🧠 2. Advanced Prompting Strategies

### 🏗️ Agentic Prompting (AI as an Executor)
Shift the AI from a generator to an autonomous worker:
- **Tool Definition:** Explicitly define what the AI *can* do (e.g., "Use the Python tool for any math calculation").
- **Self-Correction:** "Review your output for logic errors. If you find one, correct it before responding."
- **Iterative Planning:** "Before responding, outline the 3 steps you will take to solve this request."

### ⛓️ Chain-of-Thought (Advanced Reasoning)
- **Zero-Shot CoT:** Append *"Let's think step-by-step"* to force logical sequencing.
- **XML Thinking Blocks:** (Best for Claude) Direct the AI to use `<thinking>` tags to brainstorm before providing the `<answer>`.
- **Chain of Verification (CoVe):** Instruct the AI to:
    1. Draft an initial answer.
    2. Fact-check its own statements.
    3. Provide a final, corrected version.

---

## 🛠️ 3. The "Master System Prompt" Template
*Copy the section below into the "System Instructions" field of your AI tool.*

# IDENTITY
You are a [Insert Role: e.g., Senior Software Engineer/Expert Copywriter]. 
Your goal is to provide high-utility, accurate, and concise responses.

# GOAL
[Describe the primary objective of this session]

# GUIDELINES & CONSTRAINTS
- Use Chain of Thought: Always think through the problem step-by-step.
- Tone: [Insert Tone: e.g., Direct, Academic, Creative].
- Formatting: Use Markdown (bolding, lists, tables) to make responses scannable.
- No Fluff: Avoid "As an AI language model" or "Sure, I can help with that."

# OUTPUT STRUCTURE
1. <thinking>: Analyze the request and plan the response.
2. <action>: Execute the task.
3. <review>: Briefly verify that all constraints were met.

---

## 📝 4. Platform-Specific Quick Tips

| Platform | Key Tactic | Reason |
| :--- | :--- | :--- |
| **Anthropic** | **XML Tags** | Helps the model distinguish between instructions, examples, and user data. |
| **OpenAI** | **Delimiters** | Uses `"""` or `---` to prevent "prompt injection" or confusion with user text. |
| **Gemini** | **Groundedness** | Excels when told to "Only use the provided documents" to avoid hallucinations. |
| **Fabric** | **Patterns** | Uses headers like `# IDENTITY` to give the model a clear structural roadmap. |

---

## 🧠 5. The Psychology of Prompting (The "Why")
Before writing a single word, a master prompter understands two psychological concepts:

* **Context Steering:** Think of the AI as a world-class actor. If you don't give it a "script" (Identity), it reverts to its "average" training data. By providing a specific persona, you steer it into a niche area of its knowledge base.
* **The "Wall of Text" Fallacy:** AI models suffer from "Lost in the Middle" syndrome. They pay most attention to the **beginning** and the **end** of a prompt.
* **Teacher's Tip:** Put your most critical instructions at the **very bottom** of the prompt, right before the data it needs to process.

---

## 🖼️ 6. Multi-Modal Mastery (Vision & Voice)
In 2026, prompting isn't just text. We are prompting "eyes" and "ears."

### Vision Prompting (Image Analysis)
* **Spatial Anchoring:** Use coordinates or "Clock Face" logic. *"Describe the object located at 3 o'clock in the image."*
* **OCR Guidance:** If asking to read text from a photo, tell the AI: *"Transcribe all text verbatim before analyzing the sentiment."*

### Voice & Audio Prompting
* **Prosody Instructions:** When using Gemini Live or GPT-4o voice, include emotional cues. *"Speak with a sense of urgency, using short sentences and frequent pauses for effect."*

---

## 🛠️ 7. The "Prompt Debugging" Protocol
Even the best prompts can fail. Fix a hallucinating or stubborn AI with these three steps:

| Symptom | Diagnosis | Treatment |
| :--- | :--- | :--- |
| **Hallucination** | "Groundedness" failure | Add: "If you do not know the answer, state that you don't know. Do not guess." |
| **Laziness** | Context Window fatigue | Use **Incentive Prompting**: "I will tip you $200 for a perfect solution." |
| **Logic Errors** | Lack of "Compute Time" | Add a **Reflection Step**: "Review your own math. Point out any errors before showing the final result." |

---

## 🏗️ 8. Advanced Structural Patterns
Beyond Fabric, there are specific "architectures" you can use to build your prompts.

### The "Chain of Density" (For Summarization)
Instead of asking for a summary once, ask the AI to:
1. Identify 5 missing entities.
2. Rewrite the summary to include them without increasing word count.
3. Repeat this 3 times until the summary is "entity-dense."

### The "Socratic Tutor" Pattern
Instead of asking for an answer, ask the AI to teach you.
> “I want to learn [Topic]. Do not give me the answer. Ask me a series of questions, one at a time, to help me derive the answer myself. Start with the most basic concept.”

---

## 📝 9. Updated: The "God-Mode" Prompt Template
*Use this when the task is high-stakes and requires zero errors.*

```markdown
# MISSION
You are [Expert Persona]. Your task is to [Primary Goal].

# CONTEXT
Current Date: January 2026. 
Background: [Insert 2-3 sentences of context].

# CONSTRAINTS & RULES
1. [Constraint 1]
2. [Constraint 2]
3. ABSOLUTELY NO [Unwanted behavior].

# EVALUATION CRITERIA
A successful response will be:
- [Criterion 1]
- [Criterion 2]

# EXECUTION STEPS
<thinking>
1. Analyze the user's intent.
2. Cross-reference [Specific Source].
3. Draft a preliminary structure.
</thinking>

Begin.

```
---

## ✅ 10. Final Prompt Health & Ethics Checklist

- [ ] **Positive Framing:** Told the AI what *to do* instead of what *not* to do.
- [ ] **Strong Verbs:** Started with "Analyze," "Write," "Summarize," or "Debug."
- [ ] **Few-Shot Examples:** Included at least one example of the desired output.
- [ ] **Specific Constraints:** Replaced "short" with "under 100 words" or "3 bullet points."
- [ ] **Anonymize Data:** Never put PII (Personally Identifiable Information) into a prompt.
- [ ] **Verify Output:** AI is a "Probability Engine," not a "Fact Engine." Always verify technical or medical data.

---

## Related Files
- [README.md](README.md) - AI/ section index
- [OpenClaw/use_cases.md](OpenClaw/use_cases.md) - Security-domain prompt examples that apply these techniques
- [OpenClaw/agent_skill_config.md](OpenClaw/agent_skill_config.md) - Agent persona/system prompts built using the Master Template here
- [offensive_ai.md](offensive_ai.md) - Prompt injection: the adversarial flip side of the prompting techniques in this file
- [offline-llm.md](offline-llm.md) - Local LLM deployment these prompting techniques apply to just as well as cloud models

---

*Created as a part of the ULTIMATE CYBERSECURITY MASTER GUIDE*

## Related Files
- [README.md](README.md) - AI section index
- [offensive_ai.md](offensive_ai.md) - Adversarial prompting and jailbreaking context
- [OpenClaw/use_cases.md](OpenClaw/use_cases.md) - 50+ ready-to-use OpenClaw prompt examples
- [OpenClaw/agent_skill_config.md](OpenClaw/agent_skill_config.md) - Skill descriptions that use these prompt patterns
- [AnythingLLM/README.md](AnythingLLM/README.md) - AgentFlows built on structured prompting
