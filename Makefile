PYTHON ?= python3

.PHONY: help audit audit-strict docs tests links verify

help:
	@printf '%s\n' 'make audit        - inventory non-executing code syntax and Markdown review candidates' 'make audit-strict - require maintained Python and shell syntax to parse' 'make docs         - run existing numbered-list and duplicate-section checks' 'make tests        - run isolated hardening and tool regression tests' 'make links        - offline Markdown file and anchor check (requires lychee)' 'make verify       - audit-strict, docs and tests (not a live/hardware certification)'

audit:
	$(PYTHON) -B tools/repository_quality_audit.py --max-items 120

audit-strict:
	$(PYTHON) -B tools/repository_quality_audit.py --strict-syntax --max-items 40

docs:
	$(PYTHON) -B tools/check_duplicate_sections.py
	$(PYTHON) -B tools/check_markdown_numbered_lists.py

tests:
	$(PYTHON) -B -m unittest discover -s tests/hardening -v
	$(PYTHON) -B -m unittest discover -s tools/tests -v

links:
	@command -v lychee >/dev/null || { echo 'Install the lychee link checker first (see .github/workflows/link-check.yml)' >&2; exit 2; }
	lychee --offline --include-fragments --no-progress './**/*.md'

verify: audit-strict docs tests
