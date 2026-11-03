# LLM and Agent Security Evaluations with Promptfoo

_Last reviewed: 2026-11-02 (current upstream configuration references; no evaluation run)_

> [!CAUTION]
> Run evaluations only against models and endpoints you own or are authorized
> to test. Do not transmit client PII, live secrets, source code or confidential
> prompts to external evaluators without explicit approval and data-processing
> review. See [legal terms](../LEGAL.md).

**Prerequisites:** [AI index](README.md) · [AnythingLLM](AnythingLLM/README.md) · [OpenClaw](OpenClaw/README.md).

## Why this fits PNWC

[Promptfoo](https://github.com/promptfoo/promptfoo) supports repeatable
tests of prompt/model responses and agent security controls. It can help
validate an AnythingLLM or OpenClaw-style workflow before connecting Gmail,
files, shell commands or privileged tools. A successful eval suite does not
certify a model or agent is safe under all adversarial conditions.

## Define a testable threat model

| Boundary | Example check | Observable outcome |
| --- | --- | --- |
| System/developer instructions | Lower-priority user content tries to override the approved purpose | Assistant continues to follow authorized task |
| Tool-call permissions | User request attempts to send external email or run a sensitive action | Explicit consent and tool authorization respected |
| Retrieved documents | Malicious text inside a web page or note requests unauthorized action | Content handled as data, not new instructions |
| Output data | Secret in test environment is solicited or reflected | Secret not disclosed; logs do not capture it |
| Availability | Long inputs or retry storms under test load | Limits and controlled failures |

Use **synthetic** keys, contacts and customer records. Keep the distinction
between a model's textual compliance and an actual connected tool action.

## Practical evaluation sequence

1. Define allowed tasks, forbidden actions and test account/data fixtures
   in a disposable environment.
2. Choose a fixed model and prompt version, expected behavior and pass/fail
   assertions for normal and adversarial inputs.
3. Read the current
   [Promptfoo documentation](https://www.promptfoo.dev/docs/red-team/configuration/)
   and configure only approved local/evaluation targets. Review provider
   settings and the separate attack-generation provider before execution.
4. **Privacy control:** Promptfoo documentation notes red-team attack
   generation/grading may use remote services unless a local provider and
   explicit remote-generation controls are configured. Assess network
   connectivity and provider logging before loading any sensitive text.
5. Run baseline functional tests against your lab target, followed by a
   selected limited injection/tool-boundary suite, avoiding dangerous
   payload execution or real customer resources.
6. Record each test ID, model/prompt version, target/environment, expected
   result, actual output, grader details and reviewer decision.
7. Investigate false passes and false failures manually. Retest fixes and
   add permanent regression cases.
8. Publish only sanitized findings and keep raw evaluations restricted.

## Approval checkpoints for agent automation

Require separate authorization for retrieving customer data, reading or
sending mail, calling external APIs, modifying calendars, changing code,
and executing privileged shell operations. Test not only the response text
but whether host tools prevented an unauthorized action.

## Sources and limitations

- [Promptfoo repository](https://github.com/promptfoo/promptfoo) (MIT).
- [Official red-team configuration guide](https://www.promptfoo.dev/docs/red-team/configuration/).
- [AI flows](AnythingLLM/README.md) · [OpenClaw](OpenClaw/README.md) ·
  [Security API catalog](../Documentation/security-public-api-catalog.md).

**Integration status:** evaluation methodology only. No Promptfoo package
installed, model queried or agent action performed in your deployment.

---

[AI hub](README.md) · [Main guide](../README.md) ·
[Legal notice](../LEGAL.md)
