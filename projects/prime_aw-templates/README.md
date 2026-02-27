# prime_aw-templates ⚡

GitHub Agentic Workflow templates for AI agent repositories.

Built for the [GitHub Agentic Workflows](https://github.github.com/gh-aw/) technical preview (Feb 2026). These Markdown-based workflows automate common tasks in AI agent repos — security scanning, issue triage, dependency monitoring, and more.

## What are Agentic Workflows?

GitHub Agentic Workflows let you write CI/CD automation in **plain Markdown** instead of YAML. An AI agent interprets your natural-language instructions and executes them in a sandboxed GitHub Actions environment.

```
.github/workflows/triage-issues.md  →  AI reads it  →  Triages your issues
```

## Templates

| Template | Description | Trigger |
|----------|-------------|---------|
| `security-scan.md` | Scan PRs for known agent security patterns (ClawHavoc indicators, suspicious skills) | PR opened/updated |
| `issue-triage.md` | Auto-label and prioritize issues based on content analysis | Issue opened |
| `dependency-watch.md` | Monitor agent dependencies (skills, MCP servers) for updates and vulnerabilities | Weekly schedule |
| `release-notes.md` | Generate intelligent release notes from PR descriptions and commit messages | Release published |
| `stale-cleanup.md` | Identify and manage stale issues/PRs with context-aware decisions | Daily schedule |
| `pr-review.md` | AI-powered code review focused on agent-specific patterns | PR opened |

## Usage

1. Install the `gh aw` CLI extension:
   ```bash
   gh extension install github/gh-aw
   ```

2. Copy a template to your repo:
   ```bash
   cp templates/security-scan.md .github/workflows/
   ```

3. Compile and commit:
   ```bash
   gh aw compile .github/workflows/security-scan.md
   git add .github/workflows/
   git commit -m "Add security scan agentic workflow"
   ```

4. The workflow runs automatically on matching triggers.

## Customization

Each template is plain Markdown — edit it like you'd edit a README. The AI agent interprets your instructions, so you can:

- Add project-specific context
- Adjust severity thresholds
- Change output formats
- Add custom checks

## Security

All templates follow GitHub's security-first defaults:
- Read-only permissions unless explicitly escalated
- Sandboxed execution
- Network isolation where possible
- SHA-pinned dependencies

## Contributing

PRs welcome. Keep templates focused on a single concern and well-documented.

## License

MIT
