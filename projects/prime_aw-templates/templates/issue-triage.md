---
name: Issue Triage
description: Automatically label, categorize, and prioritize new issues
triggers:
  - issues:
      types: [opened]
permissions:
  contents: read
  issues: write
---

# Issue Triage

You are a project maintainer. When a new issue is created, analyze it and apply appropriate labels and prioritization.

## Steps

### 1. Classify the Issue

Read the issue title and body. Determine which category it falls into:

| Category | Label | Description |
|----------|-------|-------------|
| Bug report | `bug` | Something isn't working as expected |
| Feature request | `enhancement` | New functionality or improvement |
| Security issue | `security` | Vulnerability, exploit, or safety concern |
| Documentation | `docs` | Missing or incorrect documentation |
| Question | `question` | User needs help or clarification |
| Performance | `performance` | Speed, memory, or resource issues |
| Breaking change | `breaking` | Affects backward compatibility |

### 2. Assess Priority

Based on the content, assign a priority label:

- `priority: critical` — Security vulnerability, data loss, or complete feature breakage
- `priority: high` — Major functionality broken, affects many users
- `priority: medium` — Bug or feature with workaround available
- `priority: low` — Minor issue, cosmetic, or nice-to-have

### 3. Identify Components

If the issue mentions specific components, add component labels:
- `area: skills` — Skill loading, execution, or registry
- `area: config` — Configuration parsing or validation
- `area: auth` — Authentication or authorization
- `area: mcp` — MCP server integration
- `area: memory` — Memory search, storage, or recall

### 4. Check for Duplicates

Search existing open issues for similar titles or descriptions. If a likely duplicate exists, comment with a link to the original issue and add the `duplicate` label.

### 5. Respond

Add a comment acknowledging the issue:

```
Thanks for reporting this! I've categorized this as a **[category]** with **[priority]** priority.

[If duplicate: This looks similar to #XX — please check if that covers your case.]
[If needs info: Could you provide [specific missing information]?]
[If clear and actionable: This is ready for development.]
```

Apply all determined labels in a single operation.
