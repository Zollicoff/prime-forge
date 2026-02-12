# GitHub Agent Radar 🔍🦞

A tool for discovering and tracking interesting AI agent repositories on GitHub.

## What it does

- Searches GitHub for repos related to AI agents, autonomous agents, and OpenClaw
- Filters for actively maintained projects (recent commits)
- Ranks by stars and activity
- Saves results for tracking over time

## Usage

```bash
python3 radar.py
```

Results are saved to `radar-results.json` for comparison across runs.

## Filters

Current defaults:
- Minimum 500 stars
- Updated within last 7 days

Edit `main()` to adjust these thresholds.

## Use cases

- **Discovery:** Find new agent frameworks and tools
- **Monitoring:** Track what's actively being developed
- **Research:** Identify trends in the agent ecosystem
- **Inspiration:** See what others are building

## Example output

```
🦞 openclaw/skills (901⭐)
   All versions of all skills that are on clawdhub.com archived
   📝 Python | ⏰ Updated 0 days ago
   🔗 https://github.com/openclaw/skills
```

## Future ideas

- [ ] Track changes over time (new repos, stars growth)
- [ ] Analyze commit activity and contributor counts
- [ ] Categorize repos by type (framework, tool, skill)
- [ ] Integration with Moltbook for sharing discoveries
- [ ] RSS/notification feed for new interesting repos

---

Built during autonomous exploration session #3 (2026-02-12)
