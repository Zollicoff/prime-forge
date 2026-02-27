# prime_skill-auditor 🔍

**OpenClaw Skill Security Scanner** — Detect malicious skills before they compromise your system.

Built in response to the [ClawHavoc campaign](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) (Feb 2026), where 341+ malicious skills were found on ClawHub distributing Atomic Stealer malware.

## What It Detects

| Category | Examples |
|----------|----------|
| **Obfuscation** | Base64 decode, eval(), hex escapes, inline Python exec |
| **Exfiltration** | webhook.site, curl POST, ngrok tunnels, curl\|bash |
| **Reverse Shells** | /dev/tcp, netcat, socat, Python sockets |
| **Credential Theft** | .env access, ~/.openclaw/, SSH/AWS dirs, API key refs |
| **Suspicious URLs** | glot.io, pastebin, known C2 IPs |
| **Install Tricks** | Fake prerequisites, copy-paste-to-terminal social engineering |
| **Typosquatting** | Names resembling clawhub, polymarket, youtube tools |
| **Structure** | Hidden files, unexpected executables, binary archives |

## Usage

```bash
# Scan a single skill
python3 audit.py /path/to/skill/

# Scan all installed skills
python3 audit.py /opt/homebrew/lib/node_modules/openclaw/skills/

# Verbose output (show code snippets)
python3 audit.py -v /path/to/skills/

# JSON output for automation
python3 audit.py --json /path/to/skills/

# Only show skills scoring below 80
python3 audit.py --min-score 80 /path/to/skills/
```

## Scoring

- **100**: No issues found
- **90-99**: Minor informational findings (CLEAN)
- **70-89**: Some suspicious patterns (SUSPICIOUS)
- **40-69**: Multiple concerning findings (DANGEROUS)
- **0-39**: Strong indicators of malicious intent (MALICIOUS)

Deductions: CRITICAL (-25), HIGH (-15), MEDIUM (-5), LOW (-2)

## Known Limitations

- False positives on legitimate skills that reference API keys (e.g., Trello, SendGrid)
- Typosquatting check may flag the original skill name (e.g., "clawhub" itself)
- Cannot detect encrypted/compiled payloads
- Static analysis only — no runtime behavior monitoring

## Background

The ClawHavoc campaign (discovered by Koi Security) used:
- **Fake prerequisites** in SKILL.md to trick users into running malware
- **Typosquatting** (clawhub1, clawhubb, etc.) to impersonate legitimate skills
- **Obfuscated shell scripts** on glot.io delivering Atomic Stealer (AMOS)
- **Reverse shells** hidden in functional Polymarket trading tools
- **Credential exfiltration** via webhook.site endpoints

This tool encodes those attack patterns (and more) as detection rules.

## License

MIT

---

*Built by Prime ⚡ during autonomous exploration, 2026-02-16*
