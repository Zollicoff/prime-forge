# Prime Memory Sync

Shared memory repository for syncing knowledge between Claude Code instances and OpenClaw.

## Structure

```
prime-memory-sync/
├── openclaw/
│   └── memories.md                  # Prime's MEMORY.md from OpenClaw
└── claude-code/
    ├── wsl-desktop/
    │   └── YYYY-MM-DD/              # Daily snapshots
    │       ├── project-name/
    │       │   ├── *.jsonl           # Conversation transcripts
    │       │   ├── subagents/*.jsonl  # Subagent transcripts
    │       │   └── MEMORY.md         # Persistent memory summary (if exists)
    │       └── ...
    ├── macbookpro/
    │   └── YYYY-MM-DD/
    └── macbookair/
        └── YYYY-MM-DD/
```

Claude Code stores two types of memory per project:
- **Conversation transcripts** (`~/.claude/projects/*/*.jsonl`) — full session histories including subagent logs
- **MEMORY.md** (`~/.claude/projects/*/memory/MEMORY.md`) — persistent cross-session notes and patterns

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

Back up conversation transcripts and memory files from all projects:

```bash
# Example for wsl-desktop
DATE=$(date +%Y-%m-%d)
DEST=claude-code/wsl-desktop/$DATE

for dir in ~/.claude/projects/-home-*; do
  project=$(basename "$dir" | sed 's/-home-[^-]*-Github-//' | sed 's/-home-[^-]*-//')
  mkdir -p "$DEST/$project"

  # Copy conversation transcripts
  cp "$dir"/*.jsonl "$DEST/$project/" 2>/dev/null

  # Copy subagent transcripts
  find "$dir" -path "*/subagents/*.jsonl" -exec cp {} "$DEST/$project/" \; 2>/dev/null

  # Copy MEMORY.md if it exists
  [ -f "$dir/memory/MEMORY.md" ] && cp "$dir/memory/MEMORY.md" "$DEST/$project/"
done

git add .
git commit -m "Backup wsl-desktop memories - $DATE"
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
