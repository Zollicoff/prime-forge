#!/usr/bin/env python3
"""
openclaw_to_adl.py - Convert OpenClaw agent configs to ADL (Agent Definition Language) format.

Usage:
    python3 openclaw_to_adl.py [--config PATH] [--agent AGENT_ID] [--output PATH]
    python3 openclaw_to_adl.py --stdin --output ./adl-output/
"""

import json
import sys
import os
import uuid
import argparse
from datetime import datetime, timezone


# Known OpenClaw tool metadata
TOOL_CATALOG = {
    "read": ("Read file contents from the filesystem", "File Operations"),
    "write": ("Create or overwrite files", "File Operations"),
    "edit": ("Make precise edits to existing files", "File Operations"),
    "exec": ("Execute shell commands", "System"),
    "process": ("Manage background execution sessions", "System"),
    "web_search": ("Search the web using Brave Search API", "Web"),
    "web_fetch": ("Fetch and extract readable content from URLs", "Web"),
    "browser": ("Control web browser for automation", "Web"),
    "message": ("Send messages via channel plugins", "Communication"),
    "cron": ("Manage scheduled jobs and wake events", "Scheduling"),
    "memory_search": ("Semantic search across memory files", "Memory"),
    "memory_get": ("Read snippets from memory files", "Memory"),
    "image": ("Analyze images with vision models", "Vision"),
    "tts": ("Convert text to speech", "Audio"),
    "nodes": ("Discover and control paired nodes/devices", "IoT"),
    "canvas": ("Present and control UI canvases", "UI"),
    "gateway": ("Manage the OpenClaw gateway daemon", "System"),
    "sessions_spawn": ("Spawn background sub-agent sessions", "Multi-Agent"),
    "sessions_send": ("Send messages to other sessions", "Multi-Agent"),
    "sessions_list": ("List active sessions", "Multi-Agent"),
    "sessions_history": ("Fetch session message history", "Multi-Agent"),
    "session_status": ("Show session status and usage", "Multi-Agent"),
}

ALL_TOOL_NAMES = set(TOOL_CATALOG.keys())


def load_config(config_path=None, from_stdin=False):
    if from_stdin:
        return json.load(sys.stdin)
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            return json.load(f)
    for p in [
        os.path.expanduser("~/.openclaw/openclaw.json"),
        os.path.expanduser("~/.openclaw/config.json"),
    ]:
        if os.path.exists(p):
            with open(p) as f:
                return json.load(f)
    raise FileNotFoundError("Could not find OpenClaw config.")


def get_allowed_tools(agent_cfg):
    """Determine which tools an agent has access to."""
    tools = agent_cfg.get("tools", {})
    if isinstance(tools, dict) and "allow" in tools:
        return set(tools["allow"])
    return ALL_TOOL_NAMES  # full access by default


def build_adl_tools(tool_names):
    result = []
    for name in sorted(tool_names):
        desc, cat = TOOL_CATALOG.get(name, (f"OpenClaw tool: {name}", "Other"))
        result.append({
            "name": name,
            "description": desc,
            "category": cat,
            "parameters": [],
        })
    return result


def agent_to_adl(agent_id, agent_cfg, defaults):
    """Convert one OpenClaw agent to ADL."""
    # Resolve model
    model_cfg = agent_cfg.get("model", defaults.get("model", {}))
    if isinstance(model_cfg, dict):
        model_str = model_cfg.get("primary", "anthropic/claude-sonnet-4-5")
    else:
        model_str = str(model_cfg)

    provider = model_str.split("/")[0] if "/" in model_str else "unknown"

    allowed = get_allowed_tools(agent_cfg)
    identity = agent_cfg.get("identity", {})

    adl = {
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"openclaw:agent:{agent_id}")),
        "version": 1,
        "name": identity.get("name", agent_id),
        "description": f"OpenClaw agent '{agent_id}' — {len(allowed)} tools enabled, model: {model_str}",
        "role": "Assistant",
        "llm": provider,
        "llm_settings": {"temperature": 1.0, "max_tokens": 16384},
        "owner": "openclaw",
        "rag": [],
        "tools": build_adl_tools(allowed),
        "x_openclaw": {
            "agent_id": agent_id,
            "model": model_str,
            "workspace": agent_cfg.get("workspace", defaults.get("workspace")),
            "channels": [],  # populated below
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "permissions": {
                "file_read": "read" in allowed,
                "file_write": "write" in allowed or "edit" in allowed,
                "shell": "exec" in allowed,
                "network": any(t in allowed for t in ["web_search", "web_fetch", "browser"]),
                "messaging": "message" in allowed,
            }
        }
    }
    return adl


def convert(config, agent_filter=None):
    agents_section = config.get("agents", {})
    defaults = agents_section.get("defaults", {})
    agent_list = agents_section.get("list", [])
    bindings = config.get("bindings", [])

    if not agent_list:
        # Single agent config
        return [agent_to_adl("default", config, {})]

    results = []
    for agent_entry in agent_list:
        aid = agent_entry.get("id", "unknown")
        if agent_filter and aid != agent_filter:
            continue

        adl = agent_to_adl(aid, agent_entry, defaults)

        # Enrich with binding info
        agent_bindings = [b for b in bindings if b.get("agentId") == aid]
        channels = set()
        for b in agent_bindings:
            m = b.get("match", {})
            ch = m.get("channel", "unknown")
            if m.get("peer", {}).get("kind") == "dm":
                channels.add(f"{ch}:dm")
            elif m.get("guildId"):
                channels.add(f"{ch}:guild:{m['guildId']}")
            else:
                channels.add(ch)
        adl["x_openclaw"]["channels"] = sorted(channels)

        results.append(adl)

    return results


def main():
    parser = argparse.ArgumentParser(description="Convert OpenClaw configs to ADL format")
    parser.add_argument("--config", help="Path to OpenClaw config JSON")
    parser.add_argument("--agent", help="Export specific agent ID only")
    parser.add_argument("--output", default="./adl-output", help="Output directory")
    parser.add_argument("--stdin", action="store_true", help="Read config from stdin")
    args = parser.parse_args()

    config = load_config(args.config, args.stdin)
    adl_agents = convert(config, args.agent)

    if not adl_agents:
        print("No agents found.", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    for adl in adl_agents:
        path = os.path.join(args.output, f"{adl['x_openclaw']['agent_id']}.adl.json")
        with open(path, "w") as f:
            json.dump(adl, f, indent=2)
        print(f"✓ {adl['x_openclaw']['agent_id']} → {path} ({len(adl['tools'])} tools)")

    manifest = {
        "adl_version": "1.0",
        "source": "openclaw",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "agents": [{"id": a["id"], "name": a["name"], "role": a["role"]} for a in adl_agents],
    }
    mpath = os.path.join(args.output, "manifest.json")
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"✓ manifest → {mpath}")
    print(f"\nExported {len(adl_agents)} agent(s).")


if __name__ == "__main__":
    main()
