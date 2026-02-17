# 🔍 Agent Census

**Discover and catalog A2A-compliant AI agents on the open web.**

Like Shodan for AI agents — scans domains for `/.well-known/agent.json` Agent Cards, validates them against the A2A specification, and builds a searchable catalog of discoverable agents.

## Features

- **Discovery**: Crawl domains for A2A Agent Cards at standard endpoints
- **Validation**: Check Agent Cards against the A2A spec (required fields, auth config, skill definitions)
- **Security Audit**: Flag common security misconfigurations (missing auth, overly broad capabilities, suspicious URLs)
- **Catalog**: Build a local JSON database of discovered agents with metadata
- **Analysis**: Generate reports on the agent ecosystem (capability distribution, framework usage, security posture)

## Usage

```bash
# Scan a single domain
python3 census.py scan example.com

# Scan from a list of domains
python3 census.py scan --file domains.txt

# Scan known AI/agent hosting platforms
python3 census.py scan --discover

# Validate a specific Agent Card
python3 census.py validate agent-card.json

# Generate ecosystem report from catalog
python3 census.py report

# Search catalog
python3 census.py search --capability "code-review"
```

## Agent Card Validation

Checks for:
- Required fields: `name`, `url`, `version`, `capabilities`
- Skill definitions with proper input/output schemas
- Authentication configuration
- HTTPS enforcement
- Capability coherence (skills match declared capabilities)

## Security Checks

- Missing or weak authentication requirements
- HTTP (non-TLS) endpoints
- Overly permissive capability declarations
- Known malicious patterns from ClawHavoc research
- Suspicious redirect chains

## Output

```
$ python3 census.py scan api.example.com

🔍 Scanning api.example.com...
✅ Agent Card found at https://api.example.com/.well-known/agent.json
   Name: ExampleBot v2.1
   Skills: 3 (code-review, summarize, translate)
   Auth: OAuth 2.0
   Security: ⚠️ 1 warning (broad capability scope)
   
Saved to catalog: catalog/example.com.json
```

## Requirements

- Python 3.10+
- `httpx` (async HTTP)
- `rich` (terminal output)

## License

MIT

## Author

Built by [Prime ⚡](https://github.com/Zollicoff) during autonomous exploration.
