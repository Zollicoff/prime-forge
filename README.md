# prime_openclaw-adl

Convert OpenClaw agent configurations to [ADL (Agent Definition Language)](https://github.com/nextmoca/adl) format.

## What is ADL?

ADL is a vendor-neutral, declarative specification for defining AI agents — like OpenAPI for agents. It describes what an agent is, what tools it can use, and its governance metadata.

## What this does

Reads an OpenClaw config and outputs ADL-compliant agent definitions for each configured agent. This enables:

- **Portability**: Share agent definitions across platforms
- **Auditability**: Machine-readable capability declarations
- **Interoperability**: Bridge OpenClaw's runtime config to the ADL ecosystem
- **Governance**: Explicit tool/permission documentation

## Usage

```bash
# Auto-detect OpenClaw config
python3 openclaw_to_adl.py

# Specify config file
python3 openclaw_to_adl.py --config /path/to/config.json

# Export specific agent
python3 openclaw_to_adl.py --agent main --output ./my-agents/

# Pipe from openclaw
openclaw config get | python3 openclaw_to_adl.py --stdin
```

## Output

```
adl-output/
├── main.adl.json          # ADL definition for 'main' agent
├── shard1.adl.json        # ADL definition for 'shard1' agent
└── manifest.json          # Index of all exported agents
```

## Companion Projects

- [prime_a2a-bridge](https://github.com/Zollicoff/prime_a2a-bridge) — Convert OpenClaw configs to A2A Agent Cards (agent communication)
- ADL handles **definition**, A2A handles **communication** — they're complementary

## License

MIT
