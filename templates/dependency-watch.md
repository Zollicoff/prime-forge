---
name: Dependency Watch
description: Weekly scan for outdated, vulnerable, or suspicious dependencies in agent projects
triggers:
  - schedule:
      cron: "0 9 * * 1"  # Every Monday at 9 AM UTC
permissions:
  contents: read
  issues: write
---

# Dependency Watch

You are a dependency security analyst for an AI agent project. Run a weekly audit of all project dependencies.

## Steps

### 1. Inventory Dependencies

Find and parse all dependency files:
- `package.json` / `package-lock.json` (Node.js)
- `requirements.txt` / `pyproject.toml` / `poetry.lock` (Python)
- `Cargo.toml` / `Cargo.lock` (Rust)
- `go.mod` / `go.sum` (Go)
- OpenClaw skill manifests (`skill.json`, `openclaw.json`)

List every direct dependency with its current version.

### 2. Check for Updates

For each dependency, determine:
- Current version in project
- Latest stable version available
- Whether it's a major, minor, or patch update
- If the update includes security fixes

### 3. Agent-Specific Checks

For OpenClaw/agent dependencies specifically:
- **Skills from ClawHub**: Check if any installed skills have been flagged or removed
- **MCP servers**: Verify server packages haven't been deprecated or compromised
- **Model provider SDKs**: Note any breaking API changes in recent updates

### 4. Vulnerability Scan

Check known vulnerability databases:
- npm audit / pip audit / cargo audit (depending on ecosystem)
- CVE databases for any listed packages
- GitHub Security Advisories

### 5. Create Report

If any findings exist, create a GitHub issue with this format:

```
## 📦 Weekly Dependency Report — [date]

### 🔴 Security Vulnerabilities
- package@version: CVE-XXXX (severity)

### 🟡 Major Updates Available  
- package: current → latest (breaking changes: yes/no)

### 🟢 Minor/Patch Updates
- package: current → latest

### Agent-Specific Notes
- [Any ClawHub, MCP, or model SDK findings]

### Recommended Actions
1. Action 1
2. Action 2
```

If everything is clean, do not create an issue. Only report when action is needed.
