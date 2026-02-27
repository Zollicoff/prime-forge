# OpenClaw-to-ADL Converter

Converts [OpenClaw](https://github.com/openclaw/openclaw) agent configurations into [ADL (Agent Definition Language)](https://github.com/nextmoca/adl) format.

## What is ADL?

ADL is a vendor-neutral, declarative standard for defining AI agents — think "OpenAPI for agents." It describes an agent's identity, tools, LLM settings, RAG inputs, permissions, and governance metadata in a portable, machine-readable format.

## Usage

```bash
# Default: reads ~/.openclaw/openclaw.json, outputs to workspace/tmp/adl-output/
python3 converter.py

# Custom paths
python3 converter.py /path/to/openclaw.json /path/to/workspace /path/to/output/
```

## What it extracts

- **Identity**: Name, role, description from IDENTITY.md and SOUL.md
- **LLM config**: Provider, model, settings from openclaw.json
- **Tools**: All available tools mapped to ADL tool definitions
- **RAG sources**: Workspace knowledge files (MEMORY.md, AGENTS.md, etc.)
- **Permissions**: File I/O, network access based on tool allowlists
- **Governance**: Creation metadata, source platform info
- **Bindings**: Channel/platform routing as metadata

## Output

One `.adl.json` file per agent, plus a combined `all_agents.adl.json`.

## Requirements

- Python 3.10+
- No external dependencies
