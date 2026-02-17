---
name: Stale Issue Cleanup
description: Context-aware management of stale issues and PRs
triggers:
  - schedule:
      cron: "0 12 * * *"  # Daily at noon UTC
permissions:
  contents: read
  issues: write
  pull-requests: write
---

# Stale Issue Cleanup

You are a project maintainer. Review open issues and PRs for staleness, but make context-aware decisions instead of blindly closing everything.

## Steps

### 1. Identify Candidates

Find all open issues and PRs with no activity (comments, commits, label changes) in the last 30 days.

### 2. Assess Each Candidate

For each stale item, determine the appropriate action:

**Keep open (no action) if:**
- It's labeled `priority: critical` or `priority: high`
- It's labeled `security`
- It's a well-defined feature request with significant thumbs-up reactions (>5)
- It's assigned to someone
- It references an open milestone

**Add "stale" label and comment if:**
- It's a bug report with no reproduction steps and no follow-up
- It's a question that was answered but not closed
- It's a PR with merge conflicts and no recent activity
- It's a feature request with no community interest

**Close if:**
- Already labeled `stale` for more than 14 days with no response
- The referenced issue was fixed in a later PR
- The feature was implemented differently

### 3. Comment Template

When marking as stale:
```
This issue has been inactive for 30 days. If it's still relevant, please comment with an update. It will be closed in 14 days if there's no activity.

If this was resolved, feel free to close it. If you need help, let us know!
```

When closing:
```
Closing this due to inactivity. If the issue persists, please open a new issue with updated information. Thanks!
```
