# Curated Technical Documentation and Documentation-Authoring Resources

_Last reviewed: 2026-11-02 (source-index and relevance review; individual upstream pages and version-specific steps may change)_

**[Beautiful Docs](https://github.com/matheusfelipeog/beautiful-docs)** is an
MIT-licensed community list of noteworthy developer documentation. This page
selects only the material relevant to the security guide, its scripting
examples, API documentation, homelab and data-engineering topics.

[Documentation index](README.md) · [Repository style guide](../STYLE_GUIDE.md) ·
[Main README](../README.md) · [START_HERE](../START_HERE.md)

> [!NOTE]
> These are **links to upstream documents**, not third-party content copied
> into this repository. An author's inclusion in Beautiful Docs is a qualitative
> recommendation, not confirmation that every endpoint, release or CLI example
> still works. Consult the linked maintainers' current versioned documentation.

## Documentation examples by cybersecurity workflow

| Topic in this repository | Recommended upstream document | Why it is useful |
| --- | --- | --- |
| Git workflows, code review, incident-response automation | [GitHub Docs](https://docs.github.com/en) | GitHub Actions, secure collaboration, pull requests, REST and token scope documentation |
| Version control fundamentals | [Atlassian Git Tutorials](https://www.atlassian.com/git/) | Clear tutorials for branching, rebasing and historical investigation |
| BSD networking and system hardening | [FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/) | Maintained OS/network administration reference for BSD-based environments |
| Python APIs and security labs | [FastAPI documentation](https://fastapi.tiangolo.com/) | Request validation and API configuration examples; apply [OWASP API Security](https://owasp.org/API-Security/) separately |
| Python web services | [Django documentation](https://docs.djangoproject.com/en/) | Authentication, configuration and framework security reference |
| Backend/ingestion data stores | [PostgreSQL documentation](https://www.postgresql.org/docs/current/) | SQL, roles, backups, transactions and indexing semantics |
| Caching, queues and telemetry pipelines | [Redis documentation](https://redis.io/docs/latest/) | Key-value operations and deployment behavior; review its security separately |
| Reproducible lab infrastructure | [HashiCorp Packer documentation](https://developer.hashicorp.com/packer/docs) | Machine-image build concepts and repeatability |
| Development tools and scripts | [Go by Example](https://gobyexample.com/) | Accessible Go language patterns for verified local tools |
| Cloud/Linux deployment | [Linode/Akamai documentation](https://www.linode.com/docs/) | Infrastructure tutorials; check product-specific availability and versions |

Most links above were selected from the [Beautiful Docs directory](https://github.com/matheusfelipeog/beautiful-docs).
The **OWASP API Security** entry is an additional primary security reference,
not an item claimed to be in the upstream curated list.

## Writing and maintaining better guides

| Reference from Beautiful Docs | Good application in this repository |
| --- | --- |
| [Diátaxis](https://diataxis.fr/) | Separate tutorials, task-based how-tos, explanations and command references without repeating the same content |
| [Google Developer Documentation Style Guide](https://developers.google.com/style) | Consistent technical language, code references and interface terminology |
| [Write the Docs](https://www.writethedocs.org/) | Documentation maintenance, review workflow and contributor practices |
| [Writing Great Documentation](https://jacobian.org/series/great-documentation/) | Information architecture and troubleshooting-oriented writing |
| [MkDocs](https://www.mkdocs.org/) | Publish versioned Markdown as a searchable documentation website if desired |
| [Sphinx](https://www.sphinx-doc.org/) | Python API/code documentation and cross-references |
| [Read the Docs](https://about.readthedocs.com/) | Hosted publishing and searchable versioned documentation |

**Suggested PNWC workflow:** preserve the existing GitHub-first Markdown and
[style guide](../STYLE_GUIDE.md). Use Diátaxis to decide *what* a new page is,
then link it from the nearest README and maintain one authoritative page per
procedure. Prefer references to official vendor and standard sources rather
than reproducing pages from this directory.

A documentation generator or hosted service is a **future option** only: none
has been installed, configured, connected or deployed as part of this change.

## Reading paths in this repository

- [Programming / Python](./python.md) → FastAPI and Django for controlled API labs.
- [Web application security](../WebAppSecurity/README.md) → the OWASP API Security
  reference plus framework documentation.
- [Data engineering](../Data-Engineering/README.md) → PostgreSQL and Redis.
- [Cloud security](../Cloud/README.md) → infrastructure and API documentation.
- [Homelab](../Homelab/README.md) → Packer and reproducible lab approaches.
- [Scripts](../Scripts/README.md) → GitHub and Git documentation for reviewing changes.
- [Technical writing conventions](../STYLE_GUIDE.md) → Diátaxis and Google's style guide.

## Attribution and limits

Source index: **matheusfelipeog/beautiful-docs**,
[GitHub repository](https://github.com/matheusfelipeog/beautiful-docs),
[MIT license](https://github.com/matheusfelipeog/beautiful-docs/blob/master/LICENSE).

This document provides original short descriptions and links to independent
upstream documentation. Those upstream publishers control their content and
licenses. Verify command compatibility against installed versions before
applying a linked how-to in production.

---

[Documentation index](README.md) · [Main guide](../README.md) ·
[Legal terms](../LEGAL.md)
