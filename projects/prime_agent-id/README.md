# prime_agent-id 🪪

**NIST-Aligned Agent Identity Toolkit**

Generate, validate, and audit AI agent identity documents following the [NIST AI Agent Standards Initiative](https://www.nist.gov/caisi/ai-agent-standards-initiative) framework (Feb 2026).

As AI agents increasingly operate autonomously in enterprise environments, robust identity and authorization becomes critical. This toolkit helps agent developers and deployers create standardized identity artifacts.

## Features

### 1. Agent Identity Document (AID) Generator
Creates structured identity documents for AI agents following NIST NCCoE guidelines:
- Agent metadata (name, version, capabilities, operator)
- Authorization scope declarations
- Delegation chains (human → agent accountability)
- Ephemeral vs persistent identity modes

### 2. Authorization Policy Validator
Validates agent configurations against zero-trust principles:
- Least privilege analysis
- Scope creep detection
- Human-in-the-loop requirements
- OAuth 2.0/SPIFFE readiness assessment

### 3. Audit Trail Analyzer
Reviews agent action logs for compliance:
- Non-repudiation verification
- Prompt injection indicators
- Privilege escalation patterns
- Data provenance tracking

## NIST Framework Alignment

Based on the NCCoE concept paper "Accelerating the Adoption of Software and AI Agent Identity and Authorization" (Feb 5, 2026):

| NIST Area | Toolkit Coverage |
|-----------|-----------------|
| Identification | AID generation with metadata |
| Authentication | Key management readiness check |
| Authorization | Zero-trust policy validation |
| Access Delegation | Delegation chain modeling |
| Logging/Transparency | Audit trail analysis |
| Prompt Injection | Configuration hardening score |

## Usage

```bash
# Generate an Agent Identity Document
python3 agent_id.py generate --config agent.yaml

# Validate an OpenClaw config against NIST guidelines
python3 agent_id.py validate --config ~/.openclaw/config.yaml

# Audit agent action logs
python3 agent_id.py audit --logs session.jsonl

# Score overall NIST readiness
python3 agent_id.py score --config ~/.openclaw/config.yaml
```

## Why This Matters

The NIST AI Agent Standards Initiative (announced Feb 18, 2026) establishes three pillars:
1. Industry-led agent standards development
2. Open source protocol development
3. Research in agent security and identity

This toolkit is an early open-source contribution to pillar 2, providing practical tools before formal standards are finalized. Comments on the NIST concept paper are due **April 2, 2026**.

## Context

Built during the "SaaSpocalypse" of early 2026, where AI agents replacing human workers created an urgent need for agent identity infrastructure. As enterprises deploy agents that access sensitive systems, NIST-grade identity controls move from "nice-to-have" to "critical infrastructure."

## License

MIT
