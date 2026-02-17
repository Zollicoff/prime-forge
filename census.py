#!/usr/bin/env python3
"""
Agent Census — Discover and catalog A2A-compliant AI agents on the open web.

Scans domains for /.well-known/agent.json Agent Cards, validates them,
checks for security issues, and builds a searchable catalog.
"""

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    print("Install httpx: pip3 install httpx")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# --- Constants ---

AGENT_CARD_PATHS = [
    "/.well-known/agent.json",
    "/.well-known/agent-card.json",
    "/agent.json",
    "/a2a/agent.json",
]

REQUIRED_FIELDS = ["name", "url", "version"]
RECOMMENDED_FIELDS = ["description", "capabilities", "skills", "authentication"]

CATALOG_DIR = Path(__file__).parent / "catalog"
REPORT_DIR = Path(__file__).parent / "reports"

# Known agent hosting platforms to discover
DISCOVERY_DOMAINS = [
    "api.langchain.com",
    "agents.google.com",
    "api.openai.com",
    "api.anthropic.com",
    "moltbook.com",
    "a2a-protocol.org",
    "kimi.com",
    "agent.dev",
    "agentprotocol.ai",
    "clawhub.com",
]


# --- Data Models ---

@dataclass
class SecurityFinding:
    severity: str  # "critical", "warning", "info"
    category: str
    message: str
    detail: str = ""


@dataclass
class ValidationResult:
    valid: bool
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    info: list = field(default_factory=list)


@dataclass
class AgentRecord:
    domain: str
    url: str
    card: dict
    discovered_at: str
    validation: dict = field(default_factory=dict)
    security: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# --- Validation ---

def validate_agent_card(card: dict) -> ValidationResult:
    """Validate an A2A Agent Card against the specification."""
    result = ValidationResult(valid=True)

    # Check required fields
    for f in REQUIRED_FIELDS:
        if f not in card or not card[f]:
            result.errors.append(f"Missing required field: '{f}'")
            result.valid = False

    # Check recommended fields
    for f in RECOMMENDED_FIELDS:
        if f not in card:
            result.warnings.append(f"Missing recommended field: '{f}'")

    # Validate URL format
    if "url" in card:
        parsed = urlparse(card["url"])
        if not parsed.scheme:
            result.errors.append("'url' missing scheme (http/https)")
            result.valid = False
        if parsed.scheme == "http":
            result.warnings.append("'url' uses HTTP instead of HTTPS")

    # Validate version format
    if "version" in card:
        v = card["version"]
        if not isinstance(v, str) or not any(c.isdigit() for c in v):
            result.warnings.append(f"Version '{v}' doesn't follow semver convention")

    # Validate skills
    if "skills" in card:
        skills = card["skills"]
        if not isinstance(skills, list):
            result.errors.append("'skills' must be an array")
            result.valid = False
        else:
            for i, skill in enumerate(skills):
                if not isinstance(skill, dict):
                    result.errors.append(f"Skill [{i}] must be an object")
                    continue
                if "id" not in skill and "name" not in skill:
                    result.warnings.append(f"Skill [{i}] missing 'id' or 'name'")
                if "description" not in skill:
                    result.info.append(f"Skill [{i}] missing 'description'")

    # Validate capabilities
    if "capabilities" in card:
        caps = card["capabilities"]
        if not isinstance(caps, dict):
            result.errors.append("'capabilities' must be an object")
        else:
            known_caps = {"streaming", "pushNotifications", "stateTransitionHistory"}
            for cap in caps:
                if cap not in known_caps:
                    result.info.append(f"Non-standard capability: '{cap}'")

    # Validate authentication
    if "authentication" in card:
        auth = card["authentication"]
        if isinstance(auth, dict):
            if "schemes" not in auth and "type" not in auth:
                result.warnings.append("Authentication config missing 'schemes' or 'type'")
        elif isinstance(auth, list):
            for scheme in auth:
                if isinstance(scheme, dict) and "type" not in scheme:
                    result.warnings.append("Auth scheme missing 'type'")

    return result


# --- Security Analysis ---

def analyze_security(card: dict, domain: str) -> list[SecurityFinding]:
    """Check an Agent Card for security issues."""
    findings = []

    # No authentication
    if "authentication" not in card or not card["authentication"]:
        findings.append(SecurityFinding(
            severity="critical",
            category="auth",
            message="No authentication configured",
            detail="Agent accepts unauthenticated requests. Any agent can invoke skills."
        ))

    # HTTP endpoint
    url = card.get("url", "")
    if url.startswith("http://"):
        findings.append(SecurityFinding(
            severity="critical",
            category="transport",
            message="HTTP endpoint (no TLS)",
            detail=f"Agent card URL uses plaintext HTTP: {url}"
        ))

    # URL mismatch (card URL doesn't match discovered domain)
    if url:
        card_domain = urlparse(url).hostname
        if card_domain and card_domain != domain:
            findings.append(SecurityFinding(
                severity="warning",
                category="identity",
                message="Domain mismatch",
                detail=f"Card URL domain ({card_domain}) differs from discovery domain ({domain})"
            ))

    # Overly broad capabilities
    skills = card.get("skills", [])
    if len(skills) > 50:
        findings.append(SecurityFinding(
            severity="warning",
            category="scope",
            message=f"Excessive skill count ({len(skills)})",
            detail="Agents with many skills have a larger attack surface"
        ))

    # Check for suspicious patterns in skill descriptions
    suspicious_patterns = [
        "execute", "shell", "system", "eval", "exec(", "subprocess",
        "rm -rf", "sudo", "admin", "root", "password", "credential"
    ]
    for skill in skills:
        desc = json.dumps(skill).lower()
        for pattern in suspicious_patterns:
            if pattern in desc:
                findings.append(SecurityFinding(
                    severity="warning",
                    category="skill_content",
                    message=f"Suspicious pattern in skill: '{pattern}'",
                    detail=f"Skill: {skill.get('name', skill.get('id', 'unknown'))}"
                ))
                break

    # Missing description (identity spoofing risk)
    if "description" not in card or not card.get("description"):
        findings.append(SecurityFinding(
            severity="info",
            category="identity",
            message="No description provided",
            detail="Missing description makes it harder to verify agent identity"
        ))

    # Check for known malicious domains (from ClawHavoc research)
    malicious_indicators = [
        "91.92.242.", "webhook.site", "glot.io", "pastebin.com",
        "clawhub1.", "clawhubb.", "openclaw-agent.zip"
    ]
    card_str = json.dumps(card).lower()
    for indicator in malicious_indicators:
        if indicator in card_str:
            findings.append(SecurityFinding(
                severity="critical",
                category="malicious",
                message=f"Known malicious indicator: '{indicator}'",
                detail="Matches pattern from ClawHavoc supply chain attack research"
            ))

    return findings


# --- Discovery & Scanning ---

async def fetch_agent_card(client: httpx.AsyncClient, domain: str) -> Optional[tuple[str, dict]]:
    """Try to fetch an Agent Card from a domain."""
    for path in AGENT_CARD_PATHS:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}{path}"
            try:
                resp = await client.get(url, follow_redirects=True, timeout=10)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or path.endswith(".json"):
                        try:
                            card = resp.json()
                            if isinstance(card, dict) and ("name" in card or "skills" in card or "capabilities" in card):
                                return (str(resp.url), card)
                        except json.JSONDecodeError:
                            continue
            except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout, Exception):
                continue
    return None


async def scan_domains(domains: list[str], verbose: bool = False) -> list[AgentRecord]:
    """Scan multiple domains for Agent Cards."""
    records = []
    
    async with httpx.AsyncClient(
        headers={"User-Agent": "AgentCensus/1.0 (https://github.com/Zollicoff/prime_agent-census)"},
        verify=False,  # Some agent endpoints have self-signed certs
    ) as client:
        tasks = [fetch_agent_card(client, d) for d in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for domain, result in zip(domains, results):
            if isinstance(result, Exception):
                if verbose:
                    print(f"  ❌ {domain}: {type(result).__name__}")
                continue
            
            if result is None:
                if verbose:
                    print(f"  ➖ {domain}: No Agent Card found")
                continue
            
            url, card = result
            validation = validate_agent_card(card)
            security = analyze_security(card, domain)
            
            record = AgentRecord(
                domain=domain,
                url=url,
                card=card,
                discovered_at=datetime.now(timezone.utc).isoformat(),
                validation={
                    "valid": validation.valid,
                    "errors": validation.errors,
                    "warnings": validation.warnings,
                    "info": validation.info,
                },
                security=[asdict(f) for f in security],
            )
            records.append(record)
            
            # Print result
            name = card.get("name", "Unknown")
            skill_count = len(card.get("skills", []))
            sec_critical = sum(1 for f in security if f.severity == "critical")
            sec_warn = sum(1 for f in security if f.severity == "warning")
            
            status = "✅" if validation.valid else "❌"
            sec_status = ""
            if sec_critical > 0:
                sec_status = f"🔴 {sec_critical} critical"
            elif sec_warn > 0:
                sec_status = f"⚠️ {sec_warn} warnings"
            else:
                sec_status = "🟢 clean"
            
            print(f"  {status} {domain}")
            print(f"     Name: {name}")
            print(f"     Skills: {skill_count}")
            print(f"     Security: {sec_status}")
            print()
    
    return records


# --- Catalog Management ---

def save_to_catalog(records: list[AgentRecord]):
    """Save discovered agents to the catalog."""
    CATALOG_DIR.mkdir(parents=True, exist_ok=True)
    
    for record in records:
        safe_domain = record.domain.replace("/", "_").replace(":", "_")
        path = CATALOG_DIR / f"{safe_domain}.json"
        with open(path, "w") as f:
            json.dump(record.to_dict(), f, indent=2)
    
    # Update index
    index_path = CATALOG_DIR / "index.json"
    index = {}
    if index_path.exists():
        with open(index_path) as f:
            index = json.load(f)
    
    for record in records:
        index[record.domain] = {
            "name": record.card.get("name", "Unknown"),
            "url": record.url,
            "skills": len(record.card.get("skills", [])),
            "valid": record.validation.get("valid", False),
            "security_issues": len(record.security),
            "discovered_at": record.discovered_at,
        }
    
    with open(index_path, "w") as f:
        json.dump(index, f, indent=2)
    
    print(f"💾 Saved {len(records)} records to {CATALOG_DIR}/")


def load_catalog() -> dict:
    """Load the catalog index."""
    index_path = CATALOG_DIR / "index.json"
    if not index_path.exists():
        return {}
    with open(index_path) as f:
        return json.load(f)


# --- Reports ---

def generate_report():
    """Generate an ecosystem report from the catalog."""
    catalog = load_catalog()
    
    if not catalog:
        print("📊 No agents in catalog. Run 'scan' first.")
        return
    
    total = len(catalog)
    valid = sum(1 for v in catalog.values() if v.get("valid"))
    total_skills = sum(v.get("skills", 0) for v in catalog.values())
    with_issues = sum(1 for v in catalog.values() if v.get("security_issues", 0) > 0)
    
    print()
    print("=" * 60)
    print("  🔍 Agent Census — Ecosystem Report")
    print("=" * 60)
    print()
    print(f"  Total Agents Discovered: {total}")
    print(f"  Valid Agent Cards:       {valid} ({valid/total*100:.0f}%)" if total else "")
    print(f"  Total Skills:            {total_skills}")
    print(f"  With Security Issues:    {with_issues} ({with_issues/total*100:.0f}%)" if total else "")
    print()
    
    # Top agents by skill count
    sorted_agents = sorted(catalog.items(), key=lambda x: x[1].get("skills", 0), reverse=True)
    print("  Top Agents by Skill Count:")
    for domain, info in sorted_agents[:10]:
        print(f"    {info.get('name', domain):30s} — {info.get('skills', 0)} skills")
    
    print()
    print("=" * 60)


# --- Search ---

def search_catalog(query: str, capability: str = None):
    """Search the catalog."""
    catalog = load_catalog()
    results = []
    
    for domain, info in catalog.items():
        if query and query.lower() in json.dumps(info).lower():
            results.append((domain, info))
        elif capability:
            # Load full record to check skills
            path = CATALOG_DIR / f"{domain.replace('/', '_').replace(':', '_')}.json"
            if path.exists():
                with open(path) as f:
                    record = json.load(f)
                skills_str = json.dumps(record.get("card", {}).get("skills", [])).lower()
                if capability.lower() in skills_str:
                    results.append((domain, info))
    
    if not results:
        print(f"No agents found matching '{query or capability}'")
        return
    
    print(f"\n🔍 Found {len(results)} agents:\n")
    for domain, info in results:
        print(f"  {info.get('name', domain)} — {domain}")
        print(f"    Skills: {info.get('skills', 0)} | Security: {'⚠️' if info.get('security_issues') else '✅'}")
        print()


# --- Validate local file ---

def validate_file(path: str):
    """Validate a local Agent Card JSON file."""
    with open(path) as f:
        card = json.load(f)
    
    print(f"\n📋 Validating: {path}\n")
    
    validation = validate_agent_card(card)
    domain = urlparse(card.get("url", "")).hostname or "unknown"
    security = analyze_security(card, domain)
    
    # Validation results
    if validation.valid:
        print("  ✅ Agent Card is VALID")
    else:
        print("  ❌ Agent Card is INVALID")
    
    if validation.errors:
        print(f"\n  Errors ({len(validation.errors)}):")
        for e in validation.errors:
            print(f"    🔴 {e}")
    
    if validation.warnings:
        print(f"\n  Warnings ({len(validation.warnings)}):")
        for w in validation.warnings:
            print(f"    ⚠️ {w}")
    
    if validation.info:
        print(f"\n  Info ({len(validation.info)}):")
        for i in validation.info:
            print(f"    ℹ️ {i}")
    
    # Security results
    if security:
        print(f"\n  Security Findings ({len(security)}):")
        for f_item in security:
            icon = {"critical": "🔴", "warning": "⚠️", "info": "ℹ️"}.get(f_item.severity, "•")
            print(f"    {icon} [{f_item.category}] {f_item.message}")
            if f_item.detail:
                print(f"      {f_item.detail}")
    else:
        print("\n  🟢 No security issues found")
    
    print()


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        description="Agent Census — Discover and catalog A2A-compliant AI agents"
    )
    sub = parser.add_subparsers(dest="command")
    
    # scan
    scan_p = sub.add_parser("scan", help="Scan domains for Agent Cards")
    scan_p.add_argument("domains", nargs="*", help="Domains to scan")
    scan_p.add_argument("--file", "-f", help="File with domains (one per line)")
    scan_p.add_argument("--discover", action="store_true", help="Scan known agent platforms")
    scan_p.add_argument("--verbose", "-v", action="store_true")
    
    # validate
    val_p = sub.add_parser("validate", help="Validate a local Agent Card file")
    val_p.add_argument("file", help="Path to Agent Card JSON")
    
    # report
    sub.add_parser("report", help="Generate ecosystem report from catalog")
    
    # search
    search_p = sub.add_parser("search", help="Search the catalog")
    search_p.add_argument("query", nargs="?", default="")
    search_p.add_argument("--capability", "-c", help="Search by capability")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        domains = list(args.domains) if args.domains else []
        if args.file:
            with open(args.file) as f:
                domains.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
        if args.discover:
            domains.extend(DISCOVERY_DOMAINS)
        
        if not domains:
            print("No domains specified. Use --discover or provide domains.")
            return
        
        domains = list(dict.fromkeys(domains))  # dedupe preserving order
        print(f"\n🔍 Agent Census — Scanning {len(domains)} domains...\n")
        
        records = asyncio.run(scan_domains(domains, verbose=args.verbose))
        
        if records:
            save_to_catalog(records)
            print(f"✨ Discovered {len(records)} agent(s) out of {len(domains)} scanned")
        else:
            print("No Agent Cards found.")
    
    elif args.command == "validate":
        validate_file(args.file)
    
    elif args.command == "report":
        generate_report()
    
    elif args.command == "search":
        search_catalog(args.query, args.capability)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
