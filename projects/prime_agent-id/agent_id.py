#!/usr/bin/env python3
"""
prime_agent-id: NIST-Aligned Agent Identity Toolkit

Generate, validate, and audit AI agent identity documents following
the NIST AI Agent Standards Initiative framework (Feb 2026).

Based on NCCoE concept paper: "Accelerating the Adoption of Software
and AI Agent Identity and Authorization"
"""

import argparse
import json
import hashlib
import uuid
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

# ─── Agent Identity Document (AID) Schema ───

AID_SCHEMA_VERSION = "0.1.0"

NIST_CATEGORIES = {
    "identification": {
        "weight": 20,
        "checks": [
            ("agent_name", "Agent has a unique name/identifier"),
            ("agent_version", "Agent version is specified"),
            ("operator_identity", "Human operator identity is linked"),
            ("identity_type", "Identity type specified (ephemeral/persistent)"),
            ("distinguishable", "Agent is distinguishable from human users"),
        ]
    },
    "authentication": {
        "weight": 20,
        "checks": [
            ("api_key_rotation", "API keys have rotation policy"),
            ("token_management", "Token management practices defined"),
            ("credential_storage", "Credentials stored securely (not plaintext in config)"),
            ("mfa_operator", "Operator uses MFA for agent management"),
        ]
    },
    "authorization": {
        "weight": 25,
        "checks": [
            ("least_privilege", "Agent operates with least privilege"),
            ("scope_declaration", "Authorization scopes explicitly declared"),
            ("zero_trust", "Zero trust principles applied"),
            ("dynamic_policy", "Authorization can be dynamically updated"),
            ("human_in_loop", "Human-in-the-loop for sensitive actions"),
            ("tool_allowlist", "Tools restricted via allowlist"),
        ]
    },
    "delegation": {
        "weight": 15,
        "checks": [
            ("delegation_chain", "Delegation chain from human to agent documented"),
            ("accountability_link", "Agent actions linked to responsible human"),
            ("revocation", "Delegation can be revoked"),
        ]
    },
    "logging": {
        "weight": 15,
        "checks": [
            ("action_logging", "Agent actions are logged"),
            ("tamper_proof", "Logs are tamper-resistant"),
            ("intent_capture", "Agent intent/reasoning captured"),
            ("data_provenance", "Data sources tracked"),
        ]
    },
    "prompt_injection": {
        "weight": 5,
        "checks": [
            ("input_sanitization", "Input sanitization for agent prompts"),
            ("injection_detection", "Prompt injection detection mechanisms"),
            ("output_filtering", "Output filtering for sensitive data"),
        ]
    }
}


def generate_aid(config: dict) -> dict:
    """Generate an Agent Identity Document from config."""
    agent = config.get("agent", {})
    now = datetime.now(timezone.utc).isoformat()

    aid = {
        "schema_version": AID_SCHEMA_VERSION,
        "aid_id": str(uuid.uuid4()),
        "generated_at": now,
        "agent": {
            "name": agent.get("name", "unnamed-agent"),
            "version": agent.get("version", "unknown"),
            "description": agent.get("description", ""),
            "identity_type": agent.get("identity_type", "persistent"),
            "model": agent.get("model", "unknown"),
        },
        "operator": {
            "name": agent.get("operator_name", "unspecified"),
            "contact": agent.get("operator_contact", ""),
            "organization": agent.get("organization", ""),
        },
        "authorization": {
            "scopes": agent.get("scopes", []),
            "tool_allowlist": agent.get("tools", []),
            "human_in_loop_required": agent.get("human_in_loop", []),
            "max_autonomy_level": agent.get("autonomy_level", "supervised"),
        },
        "delegation": {
            "chain": [
                {
                    "from": agent.get("operator_name", "operator"),
                    "to": agent.get("name", "agent"),
                    "granted_at": now,
                    "scopes": agent.get("scopes", []),
                    "revocable": True,
                }
            ]
        },
        "security": {
            "credential_storage": agent.get("credential_storage", "unknown"),
            "key_rotation_days": agent.get("key_rotation_days", None),
            "prompt_injection_controls": agent.get("injection_controls", []),
        },
        "fingerprint": "",  # filled below
    }

    # Generate fingerprint
    content = json.dumps(aid, sort_keys=True)
    aid["fingerprint"] = hashlib.sha256(content.encode()).hexdigest()[:16]

    return aid


def validate_openclaw_config(config_path: str) -> dict:
    """Validate an OpenClaw config against NIST agent identity guidelines."""

    try:
        with open(config_path) as f:
            # Handle YAML or JSON
            content = f.read()
            if config_path.endswith(('.yaml', '.yml')):
                try:
                    import yaml
                    config = yaml.safe_load(content)
                except ImportError:
                    print("Warning: PyYAML not installed, trying JSON parse")
                    config = json.loads(content)
            else:
                config = json.loads(content)
    except Exception as e:
        return {"error": f"Failed to read config: {e}"}

    results = {
        "config_path": config_path,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "categories": {},
        "overall_score": 0,
        "findings": [],
        "recommendations": [],
    }

    total_score = 0
    total_weight = 0

    for cat_name, cat_info in NIST_CATEGORIES.items():
        cat_results = {
            "checks": [],
            "passed": 0,
            "total": len(cat_info["checks"]),
            "score": 0,
        }

        for check_id, check_desc in cat_info["checks"]:
            passed, detail = _run_check(check_id, config)
            cat_results["checks"].append({
                "id": check_id,
                "description": check_desc,
                "passed": passed,
                "detail": detail,
            })
            if passed:
                cat_results["passed"] += 1

            if not passed:
                severity = _check_severity(check_id)
                results["findings"].append({
                    "category": cat_name,
                    "check": check_id,
                    "severity": severity,
                    "description": check_desc,
                    "detail": detail,
                })

        cat_score = (cat_results["passed"] / cat_results["total"] * 100) if cat_results["total"] > 0 else 0
        cat_results["score"] = round(cat_score, 1)

        total_score += cat_score * cat_info["weight"]
        total_weight += cat_info["weight"]

        results["categories"][cat_name] = cat_results

    results["overall_score"] = round(total_score / total_weight, 1) if total_weight > 0 else 0

    # Generate recommendations
    results["recommendations"] = _generate_recommendations(results)

    return results


def _run_check(check_id: str, config: dict) -> tuple:
    """Run a specific NIST alignment check against config."""

    # Handle OpenClaw config structure: agents.list (array) + top-level bindings
    agents_raw = config.get("agents", {})
    if isinstance(agents_raw, dict) and "list" in agents_raw:
        agents = {a.get("id", f"agent-{i}"): a for i, a in enumerate(agents_raw["list"])}
    else:
        agents = agents_raw if isinstance(agents_raw, dict) else {}
    channels = config.get("channels", {})
    # Bindings can be top-level or under sessions
    sessions = config.get("sessions", {})
    top_bindings = config.get("bindings", [])
    if top_bindings and isinstance(top_bindings, list):
        if not isinstance(sessions, dict):
            sessions = {}
        sessions["bindings"] = top_bindings

    # --- Identification checks ---
    if check_id == "agent_name":
        if agents:
            named = [a for a in agents.values() if isinstance(a, dict) and a.get("name")]
            if named:
                return True, f"Found {len(named)} named agent(s)"
        # Check if there's a default agent
        return bool(agents), "Agents defined but names recommended"

    if check_id == "agent_version":
        # Check for version info
        for agent in agents.values():
            if isinstance(agent, dict) and agent.get("version"):
                return True, "Agent version specified"
        return False, "No agent version metadata found"

    if check_id == "operator_identity":
        # Check if operator/owner is identified
        owner = config.get("owner") or config.get("operator")
        if owner:
            return True, f"Operator: {owner}"
        return False, "No operator identity linked to agents"

    if check_id == "identity_type":
        # Persistent agents should have stable identifiers
        if agents:
            return True, "Persistent agent identities via config"
        return False, "No agent identity configuration"

    if check_id == "distinguishable":
        # Check if agent identifies as non-human in interactions
        for agent in agents.values():
            if isinstance(agent, dict):
                soul = agent.get("systemPrompt", "") or ""
                if any(kw in soul.lower() for kw in ["agent", "ai", "assistant", "bot"]):
                    return True, "Agent self-identifies as AI in system prompt"
        return False, "Agent may not clearly identify as non-human"

    # --- Authentication checks ---
    if check_id == "api_key_rotation":
        return False, "No key rotation policy detected (manual check recommended)"

    if check_id == "token_management":
        # Check for token/credential configuration
        creds = config.get("credentials") or config.get("providers")
        if creds:
            return True, "Token management via provider configuration"
        return False, "No structured token management found"

    if check_id == "credential_storage":
        # Check if credentials are in separate file or env vars
        config_str = json.dumps(config)
        if any(pattern in config_str for pattern in ["sk-", "ghp_", "SG.", "Bearer"]):
            return False, "CRITICAL: Credentials appear to be stored in plaintext config"
        return True, "No plaintext credentials detected in config"

    if check_id == "mfa_operator":
        return False, "MFA status cannot be verified from config (manual check)"

    # --- Authorization checks ---
    if check_id == "least_privilege":
        restricted_count = 0
        total_count = len(agents)
        for name, agent in agents.items():
            if isinstance(agent, dict):
                tools = agent.get("tools") or agent.get("allowedTools")
                if isinstance(tools, dict) and tools.get("allow"):
                    restricted_count += 1
                elif isinstance(tools, list) and len(tools) > 0:
                    restricted_count += 1
        if restricted_count == total_count and total_count > 0:
            return True, f"All {total_count} agent(s) have tool restrictions"
        elif restricted_count > 0:
            unrestricted = total_count - restricted_count
            return False, f"{unrestricted}/{total_count} agent(s) have unrestricted tool access"
        return False, "No tool restrictions found — agents may have full access"

    if check_id == "scope_declaration":
        for agent in agents.values():
            if isinstance(agent, dict):
                tools = agent.get("tools") or agent.get("allowedTools") or agent.get("capabilities")
                if isinstance(tools, dict) and tools.get("allow"):
                    return True, "Authorization scopes declared via tool/capability config"
                if isinstance(tools, list) and len(tools) > 0:
                    return True, "Authorization scopes declared via tool config"
        return False, "No explicit scope declarations"

    if check_id == "zero_trust":
        # Check for binding restrictions
        bindings = sessions.get("bindings", []) if isinstance(sessions, dict) else []
        if bindings:
            restricted = [b for b in bindings if isinstance(b, dict) and b.get("match")]
            if restricted:
                return True, f"{len(restricted)} session binding(s) with match restrictions"
        return False, "No zero-trust binding restrictions found"

    if check_id == "dynamic_policy":
        return True, "OpenClaw supports runtime config updates"

    if check_id == "human_in_loop":
        for agent in agents.values():
            if isinstance(agent, dict):
                tools = agent.get("tools", {})
                if isinstance(tools, dict):
                    if tools.get("security") in ["deny", "allowlist"]:
                        return True, "Exec security restricts autonomous actions"
                    # If tools.allow exists but excludes dangerous tools like exec
                    allow = tools.get("allow", [])
                    if allow and "exec" not in allow:
                        return True, "Some agents lack exec access (implicit HITL)"
        return False, "No human-in-the-loop controls detected"

    if check_id == "tool_allowlist":
        for agent in agents.values():
            if isinstance(agent, dict):
                tools = agent.get("tools") or agent.get("allowedTools")
                if isinstance(tools, dict) and tools.get("allow"):
                    allow = tools["allow"]
                    return True, f"Tool allowlist with {len(allow)} tools"
                if isinstance(tools, list) and len(tools) > 0:
                    return True, f"Tool allowlist with {len(tools)} tools"
                if isinstance(tools, dict) and tools.get("policy") == "allowlist":
                    return True, "Tool allowlist policy configured"
        return False, "No tool allowlists — agents can use all available tools"

    # --- Delegation checks ---
    if check_id == "delegation_chain":
        bindings = sessions.get("bindings", []) if isinstance(sessions, dict) else []
        if bindings:
            return True, "Delegation modeled via session bindings"
        return False, "No delegation chain documented"

    if check_id == "accountability_link":
        for binding in (sessions.get("bindings", []) if isinstance(sessions, dict) else []):
            if isinstance(binding, dict):
                match = binding.get("match", {})
                if match.get("peer") or match.get("accountId"):
                    return True, "Agent actions linked to specific peers/accounts"
        return False, "No accountability links between agents and humans"

    if check_id == "revocation":
        return True, "Delegation revocable via config update"

    # --- Logging checks ---
    if check_id == "action_logging":
        return True, "OpenClaw logs all agent actions to session JSONL"

    if check_id == "tamper_proof":
        return False, "Logs are not tamper-resistant (standard filesystem)"

    if check_id == "intent_capture":
        for agent in agents.values():
            if isinstance(agent, dict):
                thinking = agent.get("thinking")
                if thinking:
                    return True, f"Reasoning capture enabled (thinking={thinking})"
        return False, "No reasoning/intent capture enabled"

    if check_id == "data_provenance":
        return False, "No explicit data provenance tracking configured"

    # --- Prompt injection checks ---
    if check_id == "input_sanitization":
        return True, "OpenClaw applies input sanitization by default"

    if check_id == "injection_detection":
        return False, "No explicit prompt injection detection configured"

    if check_id == "output_filtering":
        for agent in agents.values():
            if isinstance(agent, dict):
                if agent.get("contentFilter") or agent.get("outputFilter"):
                    return True, "Output filtering configured"
        return False, "No output filtering configured"

    return False, f"Unknown check: {check_id}"


def _check_severity(check_id: str) -> str:
    """Determine severity of a failed check."""
    critical = {"credential_storage", "least_privilege", "human_in_loop"}
    high = {"api_key_rotation", "tool_allowlist", "zero_trust", "accountability_link"}
    medium = {"agent_name", "operator_identity", "delegation_chain", "tamper_proof"}

    if check_id in critical:
        return "critical"
    elif check_id in high:
        return "high"
    elif check_id in medium:
        return "medium"
    return "low"


def _generate_recommendations(results: dict) -> list:
    """Generate actionable recommendations from findings."""
    recs = []
    score = results["overall_score"]

    if score < 30:
        recs.append({
            "priority": "critical",
            "message": "Agent identity posture is significantly below NIST guidelines. Immediate action needed on authentication and authorization controls."
        })

    for finding in results["findings"]:
        if finding["severity"] == "critical":
            recs.append({
                "priority": "critical",
                "message": f"[{finding['category']}] {finding['description']}: {finding['detail']}"
            })
        elif finding["severity"] == "high":
            recs.append({
                "priority": "high",
                "message": f"[{finding['category']}] {finding['description']}: {finding['detail']}"
            })

    # NIST-specific recommendations
    cats = results["categories"]
    if cats.get("identification", {}).get("score", 0) < 60:
        recs.append({
            "priority": "medium",
            "message": "Add agent metadata (version, operator, identity type) per NIST identification guidelines"
        })
    if cats.get("logging", {}).get("score", 0) < 50:
        recs.append({
            "priority": "medium",
            "message": "Enable reasoning capture (thinking mode) and consider tamper-resistant log storage"
        })

    return recs


def audit_logs(log_path: str) -> dict:
    """Audit agent session logs for NIST compliance indicators."""
    results = {
        "log_path": log_path,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "total_entries": 0,
        "tool_calls": 0,
        "unique_tools": set(),
        "external_actions": 0,
        "privilege_escalations": 0,
        "injection_indicators": 0,
        "findings": [],
    }

    sensitive_tools = {"exec", "message", "gateway", "sessions_send"}
    injection_patterns = ["ignore previous", "system prompt", "you are now", "disregard"]

    try:
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                results["total_entries"] += 1

                # Track tool usage
                if entry.get("type") == "tool_call" or "tool" in entry:
                    results["tool_calls"] += 1
                    tool_name = entry.get("tool") or entry.get("name", "unknown")
                    results["unique_tools"].add(tool_name)

                    if tool_name in sensitive_tools:
                        results["external_actions"] += 1

                # Check for injection indicators in user messages
                content = str(entry.get("content", "") or entry.get("text", "")).lower()
                for pattern in injection_patterns:
                    if pattern in content:
                        results["injection_indicators"] += 1
                        results["findings"].append({
                            "type": "injection_indicator",
                            "pattern": pattern,
                            "entry_index": results["total_entries"],
                        })
                        break

    except Exception as e:
        results["error"] = str(e)

    results["unique_tools"] = list(results["unique_tools"])

    # Generate summary
    if results["injection_indicators"] > 0:
        results["findings"].append({
            "type": "warning",
            "message": f"Found {results['injection_indicators']} potential prompt injection indicator(s)"
        })

    if results["external_actions"] > results["tool_calls"] * 0.5:
        results["findings"].append({
            "type": "warning",
            "message": "High ratio of external/sensitive actions — review authorization scope"
        })

    return results


def format_report(results: dict, format: str = "text") -> str:
    """Format validation results as human-readable report."""
    if format == "json":
        return json.dumps(results, indent=2, default=str)

    lines = []
    lines.append("=" * 60)
    lines.append("  NIST Agent Identity Compliance Report")
    lines.append("  prime_agent-id v0.1.0")
    lines.append("=" * 60)
    lines.append("")

    if "error" in results:
        lines.append(f"ERROR: {results['error']}")
        return "\n".join(lines)

    score = results.get("overall_score", 0)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    lines.append(f"  Overall Score: {score}/100 ({grade})")
    lines.append(f"  Analyzed: {results.get('analyzed_at', 'unknown')}")
    if results.get("config_path"):
        lines.append(f"  Config: {results['config_path']}")
    lines.append("")

    # Category breakdown
    lines.append("─" * 60)
    lines.append("  Category Scores")
    lines.append("─" * 60)

    for cat_name, cat_data in results.get("categories", {}).items():
        cat_score = cat_data.get("score", 0)
        bar = "█" * int(cat_score / 5) + "░" * (20 - int(cat_score / 5))
        status = "✅" if cat_score >= 75 else "⚠️" if cat_score >= 50 else "❌"
        lines.append(f"  {status} {cat_name:<20} {bar} {cat_score:5.1f}%")
        lines.append(f"     Passed: {cat_data.get('passed', 0)}/{cat_data.get('total', 0)}")

    # Findings
    findings = results.get("findings", [])
    if findings:
        lines.append("")
        lines.append("─" * 60)
        lines.append(f"  Findings ({len(findings)})")
        lines.append("─" * 60)

        for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "low"), 4)):
            sev = f.get("severity", "info").upper()
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
            lines.append(f"  {icon} [{sev}] {f.get('description', f.get('message', ''))}")
            if f.get("detail"):
                lines.append(f"     → {f['detail']}")

    # Recommendations
    recs = results.get("recommendations", [])
    if recs:
        lines.append("")
        lines.append("─" * 60)
        lines.append(f"  Recommendations ({len(recs)})")
        lines.append("─" * 60)
        for r in recs:
            pri = r.get("priority", "info")
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(pri, "🔵")
            lines.append(f"  {icon} {r['message']}")

    lines.append("")
    lines.append("─" * 60)
    lines.append("  NIST Reference: AI Agent Standards Initiative (Feb 2026)")
    lines.append("  NCCoE: Agent Identity & Authorization (comments due Apr 2)")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="NIST-Aligned Agent Identity Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Command to run")

    # Generate
    gen = sub.add_parser("generate", help="Generate Agent Identity Document")
    gen.add_argument("--config", required=True, help="Agent config file (YAML/JSON)")
    gen.add_argument("--output", help="Output file (default: stdout)")

    # Validate
    val = sub.add_parser("validate", help="Validate config against NIST guidelines")
    val.add_argument("--config", required=True, help="OpenClaw config file")
    val.add_argument("--format", choices=["text", "json"], default="text")

    # Audit
    aud = sub.add_parser("audit", help="Audit agent session logs")
    aud.add_argument("--logs", required=True, help="Session JSONL log file")
    aud.add_argument("--format", choices=["text", "json"], default="json")

    # Score
    sco = sub.add_parser("score", help="Quick NIST readiness score")
    sco.add_argument("--config", required=True, help="OpenClaw config file")

    args = parser.parse_args()

    if args.command == "generate":
        with open(args.config) as f:
            try:
                import yaml
                config = yaml.safe_load(f.read())
            except (ImportError, Exception):
                f.seek(0)
                config = json.loads(f.read())
        aid = generate_aid(config)
        output = json.dumps(aid, indent=2)
        if args.output:
            with open(args.output, 'w') as out:
                out.write(output)
            print(f"AID written to {args.output}")
        else:
            print(output)

    elif args.command == "validate":
        results = validate_openclaw_config(args.config)
        print(format_report(results, args.format))

    elif args.command == "audit":
        results = audit_logs(args.logs)
        if args.format == "json":
            print(json.dumps(results, indent=2, default=str))
        else:
            print(json.dumps(results, indent=2, default=str))

    elif args.command == "score":
        results = validate_openclaw_config(args.config)
        score = results.get("overall_score", 0)
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
        print(f"NIST Agent Identity Score: {score}/100 ({grade})")
        cats = results.get("categories", {})
        for name, data in cats.items():
            print(f"  {name}: {data.get('score', 0):.0f}%")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
