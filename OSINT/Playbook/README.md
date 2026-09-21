# OSINT Investigator Playbook — prototype

## Purpose

This folder contains a manual [investigation guide](investigation_guide.md) and
an experimental Bash menu, `osint_investigator.sh`. Use the manual guide for
investigations; the menu is a case-directory prototype.

## Implemented functionality

- Creates a case directory under `~/OSINT_Cases` and writes basic case metadata.
- Creates a local API-key configuration template.
- Contains a DNS/WHOIS helper that is not connected to the menu.

Case loading, the investigation menu, and settings are placeholders. Email,
phone, IP, username, and crypto modules, evidence hashing, chain-of-custody logs,
and report generation are **not implemented**. The script does not support
`--config` or `--install` flags. Its outputs are not a verified evidence package.

## Try the prototype

Run as a regular user in a disposable lab with Bash and Python 3:

```bash
bash osint_investigator.sh
```

The broad `install_dependencies.sh` installer supports tools discussed by the
manual guide; it is not required to create a case directory. Review its package
changes before running it. Only investigate systems and data within your authority.

## Development priorities

Add tested case persistence and input validation before connecting investigation
modules. Define evidence integrity and reporting requirements before advertising
those capabilities. Do not assume directories named `evidence` or `reports`
contain an automatically verified record.

[Manual workflow](investigation_guide.md) · [OSINT index](../README.md)
