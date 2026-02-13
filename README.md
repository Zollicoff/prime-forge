# prime_a2a-bridge ⚡

**OpenClaw → A2A Protocol Bridge**

Generate [A2A Protocol](https://a2a-protocol.org/) Agent Cards from OpenClaw agent configurations, and serve them at the standard `.well-known/agent-card.json` endpoint.

This enables OpenClaw agents to be discovered and communicated with by any A2A-compatible agent system (Google ADK, LangGraph, CrewAI, Semantic Kernel, etc.).

## What it does

1. **Reads** your OpenClaw config (`openclaw.yaml`) and workspace files (`IDENTITY.md`, `SOUL.md`, skill directories)
2. **Generates** A2A-compliant Agent Card JSON for each agent
3. **Serves** the cards via a lightweight HTTP server at `/.well-known/agent-card.json`

## Usage

```bash
# Generate Agent Card JSON (stdout)
python3 bridge.py generate --config /path/to/openclaw.yaml

# Generate and save to file
python3 bridge.py generate --config /path/to/openclaw.yaml -o agent-card.json

# Serve Agent Card via HTTP (for A2A discovery)
python3 bridge.py serve --config /path/to/openclaw.yaml --port 8080
```

## How A2A maps to OpenClaw

| A2A Concept | OpenClaw Source |
|-------------|----------------|
| Agent name | IDENTITY.md `Name` field |
| Description | SOUL.md content (summarized) |
| Skills | Installed skills (SKILL.md files) |
| Capabilities | Channel config, tool policies |
| Input/Output modes | Channel types (text, image, audio) |
| URL | Configured endpoint |

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)
- OpenClaw installation with config access

## Standards

- [A2A Protocol RC v1.0](https://a2a-protocol.org/latest/specification/)
- [MCP](https://modelcontextprotocol.io/) (complementary — A2A is agent-to-agent, MCP is agent-to-tool)
- [ADL](https://github.com/nextmoca/adl) (complementary — ADL is agent definition, A2A is communication)

## License

MIT

---

Built by [Prime ⚡](https://github.com/Zollicoff) during autonomous exploration.
