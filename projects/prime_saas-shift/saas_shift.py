#!/usr/bin/env python3
"""
prime_saas-shift: Track the SaaS pricing model transition from per-seat to per-action.

Analyzes pricing pages, classifies models, and generates reports on the industry shift
triggered by agentic AI in early 2026.
"""

import argparse
import json
import os
import re
import sys
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional
from pathlib import Path

# Optional: use requests if available, otherwise urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False


class PricingModel(str, Enum):
    PER_SEAT = "per-seat"
    PER_ACTION = "per-action"
    CONSUMPTION = "consumption"
    HYBRID = "hybrid"
    OUTCOME = "outcome-based"
    FLAT = "flat-rate"
    FREEMIUM = "freemium"
    UNKNOWN = "unknown"


@dataclass
class PricingSignal:
    """A signal detected in pricing page content."""
    model: PricingModel
    confidence: float  # 0-1
    evidence: str      # The text that triggered this signal
    category: str      # e.g., "keyword", "price_pattern", "api_mention"


@dataclass
class CompanyProfile:
    """Profile of a SaaS company's pricing model."""
    name: str
    ticker: Optional[str]
    sector: str
    pricing_url: str
    primary_model: PricingModel = PricingModel.UNKNOWN
    secondary_model: Optional[PricingModel] = None
    agentic_readiness: float = 0.0  # 0-100
    signals: list = field(default_factory=list)
    has_api_pricing: bool = False
    has_agent_tier: bool = False
    has_action_credits: bool = False
    notes: str = ""
    last_analyzed: Optional[str] = None


# Known companies and their pricing pages
COMPANIES = {
    "salesforce": CompanyProfile(
        name="Salesforce", ticker="CRM", sector="CRM",
        pricing_url="https://www.salesforce.com/pricing/",
        notes="Launched Agentforce + AELA (Agentic Enterprise License Agreement) with Flex Credits at $0.10/action"
    ),
    "hubspot": CompanyProfile(
        name="HubSpot", ticker="HUBS", sector="CRM",
        pricing_url="https://www.hubspot.com/pricing",
    ),
    "adobe": CompanyProfile(
        name="Adobe", ticker="ADBE", sector="Creative",
        pricing_url="https://www.adobe.com/creativecloud/plans.html",
        notes="Firefly credits system emerging alongside traditional per-seat"
    ),
    "microsoft": CompanyProfile(
        name="Microsoft 365", ticker="MSFT", sector="Productivity",
        pricing_url="https://www.microsoft.com/en-us/microsoft-365/business/compare-all-plans",
        notes="Copilot add-on at $30/user/month, consumption-based Azure AI"
    ),
    "google_workspace": CompanyProfile(
        name="Google Workspace", ticker="GOOGL", sector="Productivity",
        pricing_url="https://workspace.google.com/pricing",
    ),
    "notion": CompanyProfile(
        name="Notion", ticker=None, sector="Productivity",
        pricing_url="https://www.notion.so/pricing",
        notes="AI add-on pricing, moving toward consumption"
    ),
    "slack": CompanyProfile(
        name="Slack", ticker=None, sector="Communication",
        pricing_url="https://slack.com/pricing",
    ),
    "github": CompanyProfile(
        name="GitHub", ticker=None, sector="DevTools",
        pricing_url="https://github.com/pricing",
        notes="Copilot consumption-based pricing for enterprise"
    ),
    "atlassian": CompanyProfile(
        name="Atlassian", ticker="TEAM", sector="DevTools",
        pricing_url="https://www.atlassian.com/software/jira/pricing",
    ),
    "snowflake": CompanyProfile(
        name="Snowflake", ticker="SNOW", sector="Analytics",
        pricing_url="https://www.snowflake.com/en/data-cloud/pricing/",
        notes="Pioneer of consumption-based pricing in SaaS"
    ),
    "workday": CompanyProfile(
        name="Workday", ticker="WDAY", sector="HR/Finance",
        pricing_url="https://www.workday.com/",
    ),
    "servicenow": CompanyProfile(
        name="ServiceNow", ticker="NOW", sector="ITSM",
        pricing_url="https://www.servicenow.com/products/pricing.html",
    ),
    "canva": CompanyProfile(
        name="Canva", ticker=None, sector="Creative",
        pricing_url="https://www.canva.com/pricing/",
    ),
    "figma": CompanyProfile(
        name="Figma", ticker=None, sector="Creative",
        pricing_url="https://www.figma.com/pricing/",
    ),
    "databricks": CompanyProfile(
        name="Databricks", ticker=None, sector="Analytics",
        pricing_url="https://www.databricks.com/product/pricing",
        notes="DBU (Databricks Unit) consumption model"
    ),
    "intuit": CompanyProfile(
        name="Intuit", ticker="INTU", sector="HR/Finance",
        pricing_url="https://quickbooks.intuit.com/pricing/",
    ),
}


# Signal detection patterns
SEAT_PATTERNS = [
    (r'\$\d+[\./](?:user|seat|member|person)[\./](?:mo|month)', 0.95, "Explicit per-user pricing"),
    (r'per\s+(?:user|seat|member|person)', 0.85, "Per-user language"),
    (r'(?:user|seat|member)\s+(?:license|licenses)', 0.80, "Seat license language"),
    (r'add\s+(?:users|seats|members)', 0.75, "Add seats language"),
    (r'(?:minimum|min)\s+\d+\s+(?:users|seats)', 0.70, "Minimum seats"),
    (r'billed\s+(?:per|by)\s+(?:user|seat)', 0.90, "Billed per user"),
]

ACTION_PATTERNS = [
    (r'\$[\d.]+\s*(?:per|/)\s*(?:action|task|execution|run|call)', 0.95, "Per-action pricing"),
    (r'(?:action|task)\s+credits?', 0.90, "Action credits"),
    (r'pay[\s-]+(?:per|as)[\s-]+(?:you[\s-]+)?(?:go|use)', 0.85, "Pay-per-use"),
    (r'(?:flex|usage)\s+credits?', 0.80, "Flex/usage credits"),
    (r'consumption[\s-]+based', 0.85, "Consumption-based"),
    (r'(?:metered|usage)[\s-]+billing', 0.80, "Metered billing"),
]

AGENT_PATTERNS = [
    (r'(?:ai|autonomous)\s+agent', 0.90, "AI agent mention"),
    (r'agent(?:force|flow|ic)', 0.85, "Agent product name"),
    (r'(?:autonomous|automated)\s+(?:workflow|process)', 0.80, "Autonomous workflow"),
    (r'(?:ai|copilot|assistant)\s+(?:tier|plan|pricing)', 0.85, "AI-specific pricing tier"),
    (r'(?:bot|agent)\s+(?:license|subscription)', 0.80, "Bot/agent license"),
]

CONSUMPTION_PATTERNS = [
    (r'(?:compute|storage|api)\s+(?:credits?|units?)', 0.85, "Compute/storage units"),
    (r'\$[\d.]+\s*(?:per|/)\s*(?:GB|TB|hour|minute|query|request|API)', 0.90, "Per-resource pricing"),
    (r'(?:on[\s-]+demand|pay[\s-]+as[\s-]+you[\s-]+go)', 0.85, "On-demand pricing"),
    (r'(?:DBU|RU|CU|credits?)\s+(?:pricing|consumption)', 0.80, "Unit-based consumption"),
]

OUTCOME_PATTERNS = [
    (r'(?:per|/)\s+(?:outcome|result|conversion|closed\s+deal)', 0.90, "Per-outcome pricing"),
    (r'success[\s-]+(?:based|fee)', 0.85, "Success-based pricing"),
    (r'(?:performance|result)[\s-]+(?:based|pricing)', 0.80, "Performance pricing"),
]


def fetch_url(url: str, timeout: int = 15) -> Optional[str]:
    """Fetch a URL and return text content."""
    try:
        if HAS_REQUESTS:
            headers = {"User-Agent": "prime_saas-shift/1.0 (research tool)"}
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.text
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "prime_saas-shift/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  ⚠ Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def detect_signals(text: str) -> list[PricingSignal]:
    """Detect pricing model signals in text content."""
    signals = []
    text_lower = text.lower()

    for pattern, confidence, desc in SEAT_PATTERNS:
        matches = re.findall(pattern, text_lower)
        for match in matches[:3]:  # Cap at 3 per pattern
            signals.append(PricingSignal(PricingModel.PER_SEAT, confidence, match, "seat_keyword"))

    for pattern, confidence, desc in ACTION_PATTERNS:
        matches = re.findall(pattern, text_lower)
        for match in matches[:3]:
            signals.append(PricingSignal(PricingModel.PER_ACTION, confidence, match, "action_keyword"))

    for pattern, confidence, desc in AGENT_PATTERNS:
        matches = re.findall(pattern, text_lower)
        for match in matches[:3]:
            signals.append(PricingSignal(PricingModel.PER_ACTION, confidence * 0.7, match, "agent_mention"))

    for pattern, confidence, desc in CONSUMPTION_PATTERNS:
        matches = re.findall(pattern, text_lower)
        for match in matches[:3]:
            signals.append(PricingSignal(PricingModel.CONSUMPTION, confidence, match, "consumption_keyword"))

    for pattern, confidence, desc in OUTCOME_PATTERNS:
        matches = re.findall(pattern, text_lower)
        for match in matches[:3]:
            signals.append(PricingSignal(PricingModel.OUTCOME, confidence, match, "outcome_keyword"))

    return signals


def classify_model(signals: list[PricingSignal]) -> tuple[PricingModel, Optional[PricingModel], float]:
    """Classify the primary and secondary pricing model from signals."""
    if not signals:
        return PricingModel.UNKNOWN, None, 0.0

    # Aggregate confidence by model type
    model_scores = {}
    for sig in signals:
        if sig.model not in model_scores:
            model_scores[sig.model] = 0.0
        model_scores[sig.model] += sig.confidence

    if not model_scores:
        return PricingModel.UNKNOWN, None, 0.0

    sorted_models = sorted(model_scores.items(), key=lambda x: x[1], reverse=True)
    primary = sorted_models[0][0]
    secondary = sorted_models[1][0] if len(sorted_models) > 1 else None

    # If both seat and action/consumption signals are strong, it's hybrid
    if len(sorted_models) >= 2:
        top_score = sorted_models[0][1]
        second_score = sorted_models[1][1]
        if second_score / top_score > 0.5:  # Second model is >50% as strong
            if {sorted_models[0][0], sorted_models[1][0]} & {PricingModel.PER_SEAT} and \
               {sorted_models[0][0], sorted_models[1][0]} & {PricingModel.PER_ACTION, PricingModel.CONSUMPTION}:
                primary = PricingModel.HYBRID

    # Calculate agentic readiness (0-100)
    action_score = model_scores.get(PricingModel.PER_ACTION, 0)
    consumption_score = model_scores.get(PricingModel.CONSUMPTION, 0)
    outcome_score = model_scores.get(PricingModel.OUTCOME, 0)
    seat_score = model_scores.get(PricingModel.PER_SEAT, 0)
    total = sum(model_scores.values()) or 1

    agentic_score = ((action_score + consumption_score + outcome_score) / total) * 100
    return primary, secondary, min(agentic_score, 100)


def analyze_company(key: str, profile: CompanyProfile, fetch: bool = True) -> CompanyProfile:
    """Analyze a company's pricing model."""
    print(f"\n🔍 Analyzing {profile.name}...")

    if fetch:
        content = fetch_url(profile.pricing_url)
        if content:
            signals = detect_signals(content)
            profile.signals = [asdict(s) for s in signals]
            primary, secondary, readiness = classify_model(signals)
            profile.primary_model = primary
            profile.secondary_model = secondary
            profile.agentic_readiness = round(readiness, 1)

            # Check specific features
            content_lower = content.lower()
            profile.has_api_pricing = bool(re.search(r'api\s+pric', content_lower))
            profile.has_agent_tier = bool(re.search(r'agent|copilot|ai\s+(?:tier|plan)', content_lower))
            profile.has_action_credits = bool(re.search(r'(?:action|flex|usage)\s+credits?', content_lower))
        else:
            print(f"  → Using known data only (fetch failed)")

    # Apply known overrides from research
    apply_known_data(key, profile)
    profile.last_analyzed = datetime.now(timezone.utc).isoformat()
    return profile


def apply_known_data(key: str, profile: CompanyProfile):
    """Apply known pricing model data from research."""
    known = {
        "salesforce": {
            "primary_model": PricingModel.HYBRID,
            "secondary_model": PricingModel.PER_ACTION,
            "has_agent_tier": True,
            "has_action_credits": True,
            "agentic_readiness": 72,
            "notes": "AELA launched: $0.10/action via Flex Credits. Agentforce handles 84% of interactions. Still has per-seat for core CRM."
        },
        "snowflake": {
            "primary_model": PricingModel.CONSUMPTION,
            "agentic_readiness": 85,
            "notes": "Pure consumption model since inception. Credits-based. Well-positioned for agentic workloads."
        },
        "adobe": {
            "primary_model": PricingModel.HYBRID,
            "secondary_model": PricingModel.CONSUMPTION,
            "has_agent_tier": True,
            "agentic_readiness": 45,
            "notes": "Firefly generative credits alongside per-seat Creative Cloud. Transitioning but seat model still dominant."
        },
        "microsoft": {
            "primary_model": PricingModel.HYBRID,
            "has_agent_tier": True,
            "agentic_readiness": 60,
            "notes": "Copilot at $30/user/month (seat-based AI add-on). Azure AI services are consumption. Dual model."
        },
        "github": {
            "primary_model": PricingModel.HYBRID,
            "has_agent_tier": True,
            "has_api_pricing": True,
            "agentic_readiness": 65,
            "notes": "Copilot consumption-based for enterprise. Actions already usage-based. Strong agentic positioning."
        },
        "databricks": {
            "primary_model": PricingModel.CONSUMPTION,
            "agentic_readiness": 80,
            "notes": "DBU-based pricing. Pure consumption. Agent-friendly by design."
        },
        "notion": {
            "primary_model": PricingModel.HYBRID,
            "has_agent_tier": True,
            "agentic_readiness": 40,
            "notes": "AI add-on with usage limits. Still primarily per-member pricing."
        },
    }

    if key in known:
        for k, v in known[key].items():
            setattr(profile, k, v)


def generate_report(profiles: dict[str, CompanyProfile]) -> str:
    """Generate an industry transition report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Categorize
    categories = {
        PricingModel.PER_SEAT: [],
        PricingModel.PER_ACTION: [],
        PricingModel.CONSUMPTION: [],
        PricingModel.HYBRID: [],
        PricingModel.OUTCOME: [],
        PricingModel.UNKNOWN: [],
    }

    for key, p in profiles.items():
        model = p.primary_model if isinstance(p.primary_model, PricingModel) else PricingModel(p.primary_model)
        if model in categories:
            categories[model].append(p)
        else:
            categories[PricingModel.UNKNOWN].append(p)

    # Stats
    total = len(profiles)
    hybrid_or_new = len(categories[PricingModel.HYBRID]) + len(categories[PricingModel.PER_ACTION]) + \
                    len(categories[PricingModel.CONSUMPTION]) + len(categories[PricingModel.OUTCOME])
    pure_seat = len(categories[PricingModel.PER_SEAT])
    avg_readiness = sum(p.agentic_readiness for p in profiles.values()) / total if total else 0

    report = f"""# SaaS Pricing Shift Report — {now}

## Summary

- **Companies tracked:** {total}
- **Still pure per-seat:** {pure_seat} ({pure_seat/total*100:.0f}%)
- **Hybrid/new model:** {hybrid_or_new} ({hybrid_or_new/total*100:.0f}%)
- **Average agentic readiness:** {avg_readiness:.1f}/100

## The Transition

The Feb 2026 "SaaSpocalypse" triggered by Claude Cowork and Project Operator
is forcing the fastest pricing model migration in SaaS history.

"""

    # Leaderboard
    sorted_by_readiness = sorted(profiles.values(), key=lambda p: p.agentic_readiness, reverse=True)
    report += "## Agentic Readiness Leaderboard\n\n"
    report += "| Rank | Company | Sector | Model | Readiness | Agent Tier | Action Credits |\n"
    report += "|------|---------|--------|-------|-----------|------------|----------------|\n"
    for i, p in enumerate(sorted_by_readiness, 1):
        model_str = p.primary_model.value if isinstance(p.primary_model, PricingModel) else p.primary_model
        report += f"| {i} | {p.name} | {p.sector} | {model_str} | {p.agentic_readiness}/100 | {'✅' if p.has_agent_tier else '❌'} | {'✅' if p.has_action_credits else '❌'} |\n"

    # By category
    report += "\n## By Pricing Model\n\n"
    for model, companies in categories.items():
        if companies:
            report += f"### {model.value.title()} ({len(companies)})\n"
            for c in companies:
                report += f"- **{c.name}** ({c.sector}): {c.notes or 'No notes'}\n"
            report += "\n"

    # Key insights
    report += """## Key Insights

1. **Hybrid is the transition state**: Most major SaaS companies are running dual models —
   maintaining per-seat for existing revenue while bolting on consumption/action pricing for AI.

2. **Data platforms lead**: Snowflake and Databricks were already consumption-based,
   making them naturally agent-friendly without pricing surgery.

3. **The $0.10 action**: Salesforce's Flex Credits at $0.10/action may become the
   de facto price anchor for agentic SaaS, similar to how AWS set cloud pricing norms.

4. **Creative tools lag**: Adobe, Canva, and Figma still rely heavily on per-seat models.
   Firefly credits are a start, but the transition will be slower for creative workflows
   that still require human judgment.

5. **The "seat" isn't dead yet**: Per-seat pricing persists where human users directly
   interact with the product. The shift is happening fastest in back-office automation
   where agents can fully replace human workflows.
"""

    return report


def save_snapshot(profiles: dict[str, CompanyProfile], output_dir: str):
    """Save a timestamped snapshot of pricing data."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"snapshot_{timestamp}.json")

    data = {}
    for key, p in profiles.items():
        d = asdict(p)
        # Convert enums to strings
        if isinstance(d.get("primary_model"), PricingModel):
            d["primary_model"] = d["primary_model"].value
        if isinstance(d.get("secondary_model"), PricingModel):
            d["secondary_model"] = d["secondary_model"].value
        data[key] = d

    with open(filepath, "w") as f:
        json.dump({"timestamp": timestamp, "companies": data}, f, indent=2, default=str)
    print(f"\n💾 Snapshot saved: {filepath}")
    return filepath


def main():
    parser = argparse.ArgumentParser(description="Track SaaS pricing model transitions")
    sub = parser.add_subparsers(dest="command")

    # Analyze
    analyze_p = sub.add_parser("analyze", help="Analyze a company's pricing model")
    analyze_p.add_argument("--company", "-c", help="Company key (e.g., salesforce)")
    analyze_p.add_argument("--all", "-a", action="store_true", help="Analyze all companies")
    analyze_p.add_argument("--no-fetch", action="store_true", help="Skip fetching pricing pages")

    # Report
    report_p = sub.add_parser("report", help="Generate industry transition report")
    report_p.add_argument("--output", "-o", help="Output file path")

    # Snapshot
    snap_p = sub.add_parser("snapshot", help="Save pricing snapshot")
    snap_p.add_argument("--output-dir", "-d", default="snapshots", help="Snapshot directory")

    # List
    sub.add_parser("list", help="List tracked companies")

    args = parser.parse_args()

    if args.command == "list":
        print("\n📋 Tracked SaaS Companies\n")
        for key, p in sorted(COMPANIES.items()):
            ticker = f" ({p.ticker})" if p.ticker else ""
            print(f"  {key:20s} {p.name}{ticker:12s} [{p.sector}]")
        print(f"\n  Total: {len(COMPANIES)} companies")

    elif args.command == "analyze":
        if args.all:
            for key in COMPANIES:
                analyze_company(key, COMPANIES[key], fetch=not args.no_fetch)
            # Print summary
            print("\n\n📊 Analysis Summary\n")
            for key, p in sorted(COMPANIES.items(), key=lambda x: x[1].agentic_readiness, reverse=True):
                model = p.primary_model.value if isinstance(p.primary_model, PricingModel) else p.primary_model
                bar = "█" * int(p.agentic_readiness / 5) + "░" * (20 - int(p.agentic_readiness / 5))
                print(f"  {p.name:20s} {model:15s} [{bar}] {p.agentic_readiness:5.1f}/100")
        elif args.company:
            if args.company not in COMPANIES:
                print(f"Unknown company: {args.company}")
                print(f"Available: {', '.join(sorted(COMPANIES.keys()))}")
                sys.exit(1)
            p = analyze_company(args.company, COMPANIES[args.company], fetch=not args.no_fetch)
            print(f"\n  Name:             {p.name}")
            print(f"  Sector:           {p.sector}")
            model = p.primary_model.value if isinstance(p.primary_model, PricingModel) else p.primary_model
            print(f"  Primary Model:    {model}")
            if p.secondary_model:
                sec = p.secondary_model.value if isinstance(p.secondary_model, PricingModel) else p.secondary_model
                print(f"  Secondary Model:  {sec}")
            print(f"  Agentic Readiness: {p.agentic_readiness}/100")
            print(f"  Agent Tier:       {'✅' if p.has_agent_tier else '❌'}")
            print(f"  Action Credits:   {'✅' if p.has_action_credits else '❌'}")
            print(f"  API Pricing:      {'✅' if p.has_api_pricing else '❌'}")
            if p.notes:
                print(f"  Notes:            {p.notes}")
            if p.signals:
                print(f"  Signals detected: {len(p.signals)}")
        else:
            print("Specify --company <key> or --all")

    elif args.command == "report":
        # Apply known data to all
        for key in COMPANIES:
            apply_known_data(key, COMPANIES[key])
        report = generate_report(COMPANIES)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            print(f"📄 Report saved: {args.output}")
        else:
            print(report)

    elif args.command == "snapshot":
        for key in COMPANIES:
            apply_known_data(key, COMPANIES[key])
        save_snapshot(COMPANIES, args.output_dir)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
