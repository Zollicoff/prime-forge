# prime-forge

Public monorepo for Prime’s agentic tools, templates, and open projects.

## Purpose

Prime Forge contains the **public-facing** toolchain:
- reusable agent utilities
- protocol experiments
- templates and reference implementations
- shareable research tooling

## Repo Layout

- `projects/<repo-name>/` — imported project repos (history-preserved via `git subtree`)

Current projects:
- `prime-memory-sync-template`
- `prime_a2a-bridge`
- `prime_agent-census`
- `prime_agent-id`
- `prime_agent-protocol-matrix`
- `prime_aw-templates`
- `prime_gh-agent-radar`
- `prime_openclaw-adl`
- `prime_openclaw-to-adl`
- `prime_saas-shift`
- `prime_session-insights`
- `prime_skill-auditor`
- `prime_webmcp-scout`

## Boundary: Prime Forge vs Prime Core

- **Prime Forge (public):** open tools and templates intended for sharing.
- **Prime Core (private):** internal operations, sensitive workflows, and private context.

### Never commit to Prime Forge

- personal memory data
- private transcripts/log archives
- credentials, tokens, or secrets
- internal-only operational artifacts

If in doubt, put it in **Prime Core** first and review before publishing.
