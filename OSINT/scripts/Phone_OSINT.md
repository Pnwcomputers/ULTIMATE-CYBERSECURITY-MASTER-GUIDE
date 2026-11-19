# Phone OSINT Investigation

> **Retired example:** The copied implementation formerly on this page placed provider API keys in URL query strings, where they could appear in process arguments, shell history, proxy logs, and provider logs. Do not copy or run that implementation.

Use the maintained [Phone OSINT audit script](../Playbook/scripts/phone_audit.sh) instead. It routes credentials through curl's standard-input configuration and now creates case output with owner-only permissions. Review the script and provider requirements before use. Only investigate numbers within an authorized case and in accordance with each provider's terms.

Keep keys in a protected local configuration file, never in a command line, URL pasted into a terminal, or a committed file. The script's output may contain personal information; preserve its restrictive permissions and handle it as case evidence.

For procedure and scope guidance, see the [OSINT investigation guide](../Playbook/investigation_guide.md).