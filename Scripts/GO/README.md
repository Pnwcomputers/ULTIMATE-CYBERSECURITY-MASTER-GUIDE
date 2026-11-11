# Historical Script Collection

This directory contains archived examples in several languages, despite its name.
It is not a supported Go module or a maintained Python 3 application. Dependencies
and tool APIs have not been validated for current runtimes.

The November 11, 2026 static inventory flagged **21 Python files** in this archived directory with Python 3 AST syntax failures, predominantly legacy Python 2 print syntax. This is a *parse incompatibility count*, not a runtime test or a declaration that the original scripts are malicious. See [Quality Inventory](../../tools/repository_quality_audit.py) and [Maintenance Operations](../../Documentation/REPOSITORY-MAINTENANCE-OPERATIONS.md). 

Python 2 print syntax remains in several examples. `cloud/s3browse.go` is an
unfinished sketch (including an incomplete search function), not a runnable tool.
Do not treat these examples as installation-ready utilities or install obsolete
interpreters to run them. Port and test an individual example in an isolated lab
before considering it for use. Only test systems you own or are authorized to assess.

See the [per-file legacy archive disposition](ARCHIVE-INVENTORY.md) for all 39 Python examples, source-header attribution, Python 2 syntax classification, and safe preservation/retirement decisions. It is based on source inspection and AST inventory only, not execution or complete license validation.

See the [script index](../README.md) and [archived review](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/de8f58798d20db4fb07f5a9e996ec41ce8f86d6a/REVIEW_2026-09-21.md).
