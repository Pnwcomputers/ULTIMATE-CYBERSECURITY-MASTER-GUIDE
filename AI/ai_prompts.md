# 🚀 Ultimate AI Prompt Engineering

A master resource and cheat sheet for high-performance prompting, synthesized from official documentation (Anthropic, Google, OpenAI) and industry-leading frameworks like Fabric.

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
- [Fabric (Daniel Miessler)](https://github.com/danielmiessler/Fabric/blob/main/data/patterns/improve_prompt/system.md) - A systematic approach to "Patterns" and identity-based prompting.

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

## 📚 5. Prompt Library (Quick-Start Examples)

| Use Case | Prompt Pattern Fragment |
| :--- | :--- |
| **Code Refactoring** | "Analyze this code for O(n) efficiency. Rewrite it using standard libraries only. Explain each change." |
| **Summarization** | "Extract the 5 most important 'Action Items' and 'Key Decisions' from these meeting notes. Format as a table." |
| **Creative Writing** | "Write a story intro in the style of [Author]. Do not use clichés. Focus on sensory details (smell/touch)." |
| **Data Extraction** | "Extract all names, dates, and prices from the text below. Return strictly as a valid JSON object." |
| **Strategic Planning** | "I want to [Goal]. Perform a SWOT analysis and identify the 3 highest-risk blockers to this plan." |

---

## ✅ 6. Final Prompt Health Checklist
- [ ] **Positive Framing:** Told the AI what *to do* instead of what *not* to do.
- [ ] **Strong Verbs:** Started with "Analyze," "Write," "Summarize," or "Debug."
- [ ] **Few-Shot Examples:** Included at least one example of the desired output.
- [ ] **Specific Constraints:** Replaced "short" with "under 100 words" or "3 bullet points."

---
*Created for the Prompt Engineering Resource Hub (2026).*
