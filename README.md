# Prime Memory Sync

A shared memory repository for syncing knowledge between Claude Code instances and OpenClaw agents across multiple machines.

## Why This Exists

When you work with AI coding assistants across multiple machines (desktop, laptop, cloud workstations), each instance has its own isolated memory. This repo provides a structured way to sync:

1. **Conversation transcripts** - Full session histories from Claude Code projects
2. **Persistent memory** - MEMORY.md files that carry context across sessions
3. **Agent memory** - OpenClaw's MEMORY.md for cross-tool awareness

## Structure

```
prime-memory-sync/
├── openclaw/
│   └── memories.md                  # OpenClaw agent's MEMORY.md
└── claude-code/
    ├── machine-1/
    │   └── YYYY-MM-DD/              # Daily snapshots
    │       ├── project-name/
    │       │   ├── *.jsonl           # Conversation transcripts
    │       │   ├── subagents/*.jsonl  # Subagent transcripts
    │       │   └── MEMORY.md         # Persistent memory summary (if exists)
    │       └── ...
    ├── machine-2/
    │   └── YYYY-MM-DD/
    └── machine-3/
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

OpenClaw agents can pull from this repo to learn what Claude Code has been working on across machines.

### Backing Up Claude Code Memories

Back up conversation transcripts and memory files from all projects:

```bash
#!/bin/bash
# backup-claude-memories.sh

MACHINE_NAME="your-machine-name"  # e.g., "wsl-desktop", "macbook-pro"
DATE=$(date +%Y-%m-%d)
DEST="claude-code/$MACHINE_NAME/$DATE"

for dir in ~/.claude/projects/*; do
  [ -d "$dir" ] || continue
  
  # Extract clean project name
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
git commit -m "Backup $MACHINE_NAME memories - $DATE"
git push
```

### Backing Up OpenClaw Memory

```bash
# From your OpenClaw workspace
cp ~/.openclaw/workspace/MEMORY.md ~/prime-memory-sync/openclaw/memories.md
cd ~/prime-memory-sync
git add openclaw/memories.md
git commit -m "Sync OpenClaw MEMORY.md - $(date +%Y-%m-%d)"
git push
```

## Setup

1. **Create a private repository** (your memories contain sensitive project info!)

```bash
gh repo create prime-memory-sync --private
cd prime-memory-sync
mkdir -p openclaw claude-code
touch openclaw/.gitkeep claude-code/.gitkeep
git add .
git commit -m "Initial setup"
git push -u origin main
```

2. **Clone on each machine**

```bash
git clone git@github.com:yourusername/prime-memory-sync.git ~/prime-memory-sync
```

3. **Set up daily backups** (optional - cron job)

```bash
# Add to crontab: backup at 3 AM daily
0 3 * * * cd ~/prime-memory-sync && bash backup-claude-memories.sh
```

## Security

- ⚠️ **Keep this repo PRIVATE** — conversation transcripts may contain sensitive code, API keys, or personal information
- Git history preserves all changes — useful for tracking memory evolution
- Each machine maintains its own memory; this is just a shared view
- Consider adding `.credentials`, `.env`, or other sensitive files to `.gitignore`

## Use Cases

### Cross-Machine Project Continuity
Work on a project on your desktop, then pick it up on your laptop with full context from previous sessions.

### Multi-Agent Collaboration
OpenClaw can read what Claude Code has been working on and vice versa, enabling better tool suggestions and context awareness.

### Memory Archaeology
Search through past conversations to find "how did I solve X last month?"

### Pattern Recognition
AI agents can analyze conversation histories to learn your preferences, coding patterns, and decision-making style.

## Future Enhancements

- Automated daily backups via cron
- Summary generation (daily digest of work across all machines)
- MCP tool for querying memories
- Semantic search across all conversations
- Memory conflict resolution (when same project edited on multiple machines)

## Credits

Created for syncing memory between [OpenClaw](https://openclaw.ai) agents and [Claude Code](https://code.anthropic.com) instances. Useful for any multi-machine AI assistant workflow.

## License

MIT - Use this structure for your own memory sync setup!
