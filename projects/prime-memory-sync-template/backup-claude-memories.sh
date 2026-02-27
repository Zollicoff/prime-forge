#!/bin/bash
# backup-claude-memories.sh
# 
# Backs up Claude Code conversation transcripts and MEMORY.md files
# to the prime-memory-sync repository.
#
# Usage:
#   1. Set MACHINE_NAME to identify this machine (e.g., "wsl-desktop", "macbook-pro")
#   2. Run manually or add to crontab for daily backups
#   3. Ensure you're in the prime-memory-sync directory

MACHINE_NAME="${MACHINE_NAME:-$(hostname)}"  # Default to hostname if not set
DATE=$(date +%Y-%m-%d)
DEST="claude-code/$MACHINE_NAME/$DATE"

echo "Backing up Claude Code memories from $MACHINE_NAME..."

# Create destination directory
mkdir -p "$DEST"

# Find all Claude Code project directories
for dir in ~/.claude/projects/*; do
  [ -d "$dir" ] || continue
  
  # Extract clean project name (remove hostname/path prefixes)
  project=$(basename "$dir" | sed 's/-home-[^-]*-Github-//' | sed 's/-home-[^-]*-//')
  
  echo "  Processing: $project"
  mkdir -p "$DEST/$project"

  # Copy main conversation transcripts
  if ls "$dir"/*.jsonl 1> /dev/null 2>&1; then
    cp "$dir"/*.jsonl "$DEST/$project/" 2>/dev/null
    echo "    ✓ Copied conversation transcripts"
  fi

  # Copy subagent transcripts
  if find "$dir" -path "*/subagents/*.jsonl" -print -quit | grep -q .; then
    find "$dir" -path "*/subagents/*.jsonl" -exec cp {} "$DEST/$project/" \; 2>/dev/null
    echo "    ✓ Copied subagent transcripts"
  fi

  # Copy MEMORY.md if it exists
  if [ -f "$dir/memory/MEMORY.md" ]; then
    cp "$dir/memory/MEMORY.md" "$DEST/$project/"
    echo "    ✓ Copied MEMORY.md"
  fi
done

# Commit and push
git add .
git commit -m "Backup $MACHINE_NAME memories - $DATE" || echo "No changes to commit"
git push

echo "✓ Backup complete!"
