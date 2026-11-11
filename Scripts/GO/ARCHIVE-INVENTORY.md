# Historical Scripts: Provenance, Syntax & Disposition

_Review date: November 11, 2026 · Coverage: all 39 archived Python files under `Scripts/GO/` · 21 Python 3 AST parser failures (not execution failures)._

## Scope & Safety

This directory is an **archival, mixed-language research collection**, not a working Go module or maintained Python 3 package. The list below records header attribution and current static Python 3 parser compatibility; **no program below has been executed or given a safety/production approval by this audit**. An AST pass proves syntax only; imports, dependency versions, API contracts, network effects, actual behavior, and terms have not been certified.

A copyright or redistribution header indicates a notice exists in that file; it is **not** proof the repository owns the code or that all bundled dependencies may be reused. For unattributed items, provenance/license requires independent investigation. Preserve original copyright and license text when retaining files.

## Disposition Definitions

| Decision | Meaning |
|---|---|
| **Historical Only** | Retain as research reference, never recommend as installation-ready or invoke from automation |
| **Modernize Only With Fixtures** | May be worth a separate isolated Python 3 rewrite from reviewed source; require provenance, sanitized input/expected output, error-path tests and license compliance first |
| **Retire From Active Index** | Preserve archival history, but do not route users to this as a working attack/credential/exploit/scanning tool; any educational replacement must undergo a new safety and maintenance review |

The manifest is maintained at [archive_manifest.json](archive_manifest.json); a regression test checks file coverage and the 21 parser classifications. It does **not** run archived scripts.

## Per-File Review

| Archived Python File | Source Header Attribution | Python 3 AST | Disposition |
|---|---|---|---|
| [`bruteforce/brute_http_basic.py`](bruteforce/brute_http_basic.py) | AverageSecurityGuy | Legacy syntax — fails | Retire From Active Index |
| [`bruteforce/brute_http_form.py`](bruteforce/brute_http_form.py) | AverageSecurityGuy | Legacy syntax — fails | Retire From Active Index |
| [`bruteforce/brute_http_ntlm.py`](bruteforce/brute_http_ntlm.py) | AverageSecurityGuy | Legacy syntax — fails | Retire From Active Index |
| [`bruteforce/brute_ssh_keyboard.py`](bruteforce/brute_ssh_keyboard.py) | Unattributed in file header | Syntax parsed; runtime untested | Retire From Active Index |
| [`bruteforce/cassbrute.py`](bruteforce/cassbrute.py) | Unattributed in file header | Syntax parsed; runtime untested | Retire From Active Index |
| [`bruteforce/firewarebf.py`](bruteforce/firewarebf.py) | AverageSecurityGuy | Legacy syntax — fails | Retire From Active Index |
| [`bruteforce/multi_ssh.py`](bruteforce/multi_ssh.py) | Unattributed in file header | Legacy syntax — fails | Retire From Active Index |
| [`bruteforce/sw_ike.py`](bruteforce/sw_ike.py) | Unattributed in file header | Legacy syntax — fails | Retire From Active Index |
| [`database/mysql_search.py`](database/mysql_search.py) | Unattributed in file header | Syntax parsed; runtime untested | Historical Only |
| [`enumeration/ad_self_service_miner.py`](enumeration/ad_self_service_miner.py) | Unattributed in file header | Legacy syntax — fails | Retire From Active Index |
| [`enumeration/dnsbrute.py`](enumeration/dnsbrute.py) | Unattributed in file header | Syntax parsed; runtime untested | Historical Only |
| [`enumeration/resolve.py`](enumeration/resolve.py) | Unattributed in file header | Syntax parsed; runtime untested | Historical Only |
| [`enumeration/resolve_mt.py`](enumeration/resolve_mt.py) | Unattributed in file header | Syntax parsed; runtime untested | Historical Only |
| [`enumeration/smtp_enum.py`](enumeration/smtp_enum.py) | LCI Technology Group | Syntax parsed; runtime untested | Historical Only |
| [`enumeration/texttable.py`](enumeration/texttable.py) | Tenable Network Security | Legacy syntax — fails | Modernize Only With Fixtures |
| [`enumeration/usernames.py`](enumeration/usernames.py) | LCI Technology Group | Syntax parsed; runtime untested | Historical Only |
| [`exploit/ssh_pwn.py`](exploit/ssh_pwn.py) | AverageSecurityGuy | Legacy syntax — fails | Retire From Active Index |
| [`exploit/ssh_super_virus.py`](exploit/ssh_super_virus.py) | AverageSecurityGuy | Legacy syntax — fails | Retire From Active Index |
| [`osint/gravatar.py`](osint/gravatar.py) | LCI Technology Group | Legacy syntax — fails | Historical Only |
| [`osint/shodan_ip.py`](osint/shodan_ip.py) | Unattributed in file header | Syntax parsed; runtime untested | Historical Only |
| [`passwords/passfilter.py`](passwords/passfilter.py) | AverageSecurityGuy | Legacy syntax — fails | Modernize Only With Fixtures |
| [`passwords/type7.py`](passwords/type7.py) | Unattributed in file header | Legacy syntax — fails | Historical Only |
| [`passwords/weak_passwords.py`](passwords/weak_passwords.py) | AverageSecurityGuy | Syntax parsed; runtime untested | Historical Only |
| [`scan/do_proxy_chains.py`](scan/do_proxy_chains.py) | LCI Technology Group | Syntax parsed; runtime untested | Historical Only |
| [`scan/do_ssh_proxy.py`](scan/do_ssh_proxy.py) | LCI Technology Group | Syntax parsed; runtime untested | Historical Only |
| [`scan/gnmap2md.py`](scan/gnmap2md.py) | AverageSecurityGuy | Legacy syntax — fails | Modernize Only With Fixtures |
| [`scan/lhf.py`](scan/lhf.py) | AverageSecurityGuy | Syntax parsed; runtime untested | Historical Only |
| [`scan/masscan_parse.py`](scan/masscan_parse.py) | LCI Technology Group | Syntax parsed; runtime untested | Modernize Only With Fixtures |
| [`scan/plugin.py`](scan/plugin.py) | AverageSecurityGuy | Syntax parsed; runtime untested | Historical Only |
| [`scan/scan.py`](scan/scan.py) | LCI Technology Group | Legacy syntax — fails | Retire From Active Index |
| [`shells/ishell.py`](shells/ishell.py) | AverageSecurityGuy | Syntax parsed; runtime untested | Retire From Active Index |
| [`shells/shell.py`](shells/shell.py) | AverageSecurityGuy | Syntax parsed; runtime untested | Retire From Active Index |
| [`webapp/dirb.py`](webapp/dirb.py) | LCI Technology Group | Legacy syntax — fails | Retire From Active Index |
| [`webapp/discover.py`](webapp/discover.py) | AverageSecurityGuy | Legacy syntax — fails | Retire From Active Index |
| [`webapp/http_upload.py`](webapp/http_upload.py) | LCI Technology Group | Legacy syntax — fails | Retire From Active Index |
| [`webapp/rails_find.py`](webapp/rails_find.py) | Unattributed in file header | Legacy syntax — fails | Retire From Active Index |
| [`webapp/rails_secret_token.py`](webapp/rails_secret_token.py) | Unattributed in file header | Legacy syntax — fails | Retire From Active Index |
| [`webapp/servers_to_burp.py`](webapp/servers_to_burp.py) | Unattributed in file header | Legacy syntax — fails | Historical Only |
| [`webapp/web_discover.py`](webapp/web_discover.py) | LCI Technology Group | Syntax parsed; runtime untested | Retire From Active Index |

## Critical Compatibility & Risk Notes

- The **21 syntax-failing files** contain Python 2 patterns such as print statements; modernizing print alone is insufficient when libraries like `Queue`, `urllib2`, `BaseHTTPServer` or byte/string semantics changed. Python 2 is end-of-life and is not a recommended mitigation.
- Historical credential testing, active enumeration, exploitation, remote shells and file-serving examples must **not** run on customer networks merely because their source is present. `enumeration/ad_self_service_miner.py` explicitly disables certificate verification; do not treat that as a safe default.
- `osint/shodan_ip.py` contains an empty API key placeholder. Do not embed real secrets in this public repository. Live providers and billing/terms remain unverified.
- `cloud/s3browse.go` is also an unfinished Go sketch; it is not covered by the Python-only count.
- The practical upgrade path is to **write a separate supported Python 3 utility** with tests and explicit scope rather than mechanically converting or executing old, poorly understood attack tools. No untested operational replacement was introduced in this review.

## What Counts As Closing An Individual Modernization

1. Verify the exact upstream origin, complete file license and intended use; record unsupported license cases.
2. Define a narrow, authorized, non-invasive use case and a sanitized offline fixture.
3. Port independently, pin/install supported dependencies, test positive/error/malformed cases and compare expected versus observed output.
4. Record interpreter/runtime versions, no-network defaults, rollback and review date in a scoped PR. Keep the original archive untouched unless there is a documented preservation reason to change it.
5. Add the new maintained path to the appropriate canonical index only after CI and human review.

---

[Archive Overview](README.md) · [Scripts Index](../README.md) · [Verification Protocol](../../Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md)
