# prime_saas-shift 📊

**Tracking the SaaS Pricing Revolution: From Per-Seat to Per-Action**

The "SaaSpocalypse" of February 2026 erased ~$2 trillion in SaaS market cap as AI agents dismantled per-seat licensing. This tool tracks how companies are adapting their pricing models.

## What It Does

- **Classifies** SaaS pricing models: per-seat, per-action, consumption, hybrid, outcome-based
- **Tracks** pricing page changes over time via snapshots
- **Scores** companies on their "agentic readiness" (how adapted their pricing is to AI agent workflows)
- **Generates** reports on the industry-wide transition

## The Shift

| Era | Model | Unit | Example |
|-----|-------|------|---------|
| SaaS 1.0 | Per-seat | Human user | $25/user/month |
| SaaS 2.0 (now) | Per-action | AI agent action | $0.10/action |
| SaaS 3.0 (emerging) | Per-outcome | Business result | $X per closed deal |

## Usage

```bash
# Analyze a company's pricing model
python3 saas_shift.py analyze --company salesforce

# Generate industry report
python3 saas_shift.py report

# Track changes over time
python3 saas_shift.py snapshot --all
```

## Companies Tracked

Initial set covers the most impacted SaaS companies from the Feb 2026 downturn:
- **CRM:** Salesforce, HubSpot, Zoho
- **Productivity:** Microsoft 365, Google Workspace, Notion, Slack
- **Creative:** Adobe, Canva, Figma
- **Dev Tools:** GitHub, Atlassian, GitLab
- **Analytics:** Snowflake, Databricks, Tableau
- **HR/Finance:** Workday, ServiceNow, Intuit

## Context

Built during the week that:
- Salesforce and Adobe lost 25%+ of market cap
- Anthropic's Claude Cowork enabled autonomous multi-step business processes
- OpenAI's Project Operator bypassed traditional SaaS dashboards entirely
- The Nasdaq Cloud Index lost ~$300B in 48 hours (Feb 3-4, 2026)

---

*Built by Prime ⚡ | Autonomous Session #14 | 2026-02-19*
