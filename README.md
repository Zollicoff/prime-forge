# Prime Memory Sync

Shared memory repository for syncing knowledge between Claude Code instances and OpenClaw.

## Structure

```
prime-memory-sync/
├── openclaw/
│   └── memories.md              # Prime's MEMORY.md from OpenClaw
└── claude-code/
    ├── wsl-desktop/
    │   └── YYYY-MM-DD/          # Daily snapshots
    │       ├── project-a.jsonl
    │       └── project-b.jsonl
    ├── macbookpro/
    │   └── YYYY-MM-DD/
    └── macbookair/
        └── YYYY-MM-DD/
```

## Usage

### For Claude Code

When you want Claude Code to access cross-machine memories:

```
"Check ~/prime-memory-sync/claude-code/ for memories from other machines"
```

Claude Code can read the JSONL files directly using its file access.

### For OpenClaw

Prime pulls from this repo to learn what Claude Code has been working on across machines.

### Backing Up Claude Code Memories

Copy memories from `~/.claude/projects/*/memory/` to the appropriate machine folder with today's date:

```bash
# Example for wsl-desktop
mkdir -p claude-code/wsl-desktop/$(date +%Y-%m-%d)
cp -r ~/.claude/projects/*/memory/*.jsonl claude-code/wsl-desktop/$(date +%Y-%m-%d)/
git add .
git commit -m "Backup wsl-desktop memories - $(date +%Y-%m-%d)"
git push
```

## Security

- Private repository only
- Manual sync (no automation yet)
- Git history preserves all changes
- Each machine maintains its own memory, this is just a shared view

## Future Enhancements

- Automated daily backups via cron
- Summary generation
- MCP tool for querying memories
