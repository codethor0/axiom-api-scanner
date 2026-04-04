# Security

## Supported versions

Only the **latest commit on `main`** is actively maintained for public development. Published tags are listed in [CHANGELOG.md](CHANGELOG.md) (e.g. **`v0.1.0-rc.1`**). General scope questions: [docs/faq.md](docs/faq.md).

## Reporting a vulnerability

Please **do not** open a public issue for unfixed security vulnerabilities in Axiom itself (the scanner product or its dependencies as shipped in this repository).

Instead, contact the maintainers **privately**:

1. Open a **GitHub Security Advisory** on [codethor0/axiom-api-scanner](https://github.com/codethor0/axiom-api-scanner) if you have access, **or**
2. Email or DM the repository owner (**codethor0**) with:
   - Description and impact
   - Affected component (API, storage, rules loader, etc.)
   - Steps to reproduce
   - Optional patch or mitigation idea

We aim to acknowledge reasonable reports quickly and coordinate a fix and disclosure timeline.

## Scope notes

- Findings about **your own applications** discovered **using** Axiom are normal operational output, not vulnerabilities in Axiom.
- **Unauthorized scanning** of third-party systems is **out of scope** for this policy and may violate law or GitHub’s rules; Axiom is intended for **authorized** testing only (see [README.md](README.md)).
