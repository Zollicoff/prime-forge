#!/usr/bin/env python3
"""
OpenClaw-to-ADL Converter

Converts OpenClaw agent configurations (openclaw.json + workspace files)
into ADL (Agent Definition Language) format.

ADL spec: https://github.com/nextmoca/adl
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime, timezone


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_text(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def extract_agent_identity(workspace: str) -> dict:
    """Extract identity from IDENTITY.md, SOUL.md, USER.md."""
    identity = {}
    
    identity_md = load_text(os.path.join(workspace, "IDENTITY.md"))
    if identity_md:
        for line in identity_md.splitlines():
            if line.startswith("- **Name:**"):
                identity["name"] = line.split(":**")[1].strip()
            elif line.startswith("- **Creature:**"):
                identity["creature"] = line.split(":**")[1].strip()
            elif line.startswith("- **Vibe:**"):
                identity["vibe"] = line.split(":**")[1].strip()
            elif line.startswith("- **Emoji:**"):
                identity["emoji"] = line.split(":**")[1].strip()
    
    soul_md = load_text(os.path.join(workspace, "SOUL.md"))
    if soul_md:
        # Extract first meaningful paragraph as description
        paragraphs = [p.strip() for p in soul_md.split("\n\n") if p.strip() and not p.strip().startswith("#") and not p.strip().startswith("_")]
        if paragraphs:
            identity["soul_summary"] = paragraphs[0][:500]
    
    return identity


def extract_tools_from_config(agent_config: dict, defaults: dict) -> list[dict]:
    """Extract tool definitions from agent config."""
    tools = []
    
    # Get tool allow list
    tool_allow = None
    if "tools" in agent_config and "allow" in agent_config["tools"]:
        tool_allow = agent_config["tools"]["allow"]
    
    # Map OpenClaw tools to ADL tool definitions
    tool_descriptions = {
        "read": ("read_file", "Read contents of files in the workspace"),
        "write": ("write_file", "Create or overwrite files"),
        "edit": ("edit_file", "Make precise edits to existing files"),
        "exec": ("execute_command", "Run shell commands"),
        "web_search": ("web_search", "Search the web using Brave Search API"),
        "web_fetch": ("web_fetch", "Fetch and extract content from URLs"),
        "browser": ("browser_control", "Control web browser for automation"),
        "message": ("send_message", "Send messages via channel plugins (Discord, etc.)"),
        "image": ("analyze_image", "Analyze images with vision models"),
        "memory_search": ("memory_search", "Search agent memory files"),
        "memory_get": ("memory_get", "Read snippets from memory files"),
        "session_status": ("session_status", "Check session status and usage"),
        "cron": ("cron_jobs", "Manage scheduled tasks and reminders"),
        "tts": ("text_to_speech", "Convert text to speech audio"),
        "canvas": ("canvas_control", "Present and control canvas UI"),
        "nodes": ("node_control", "Discover and control paired nodes/devices"),
        "gateway": ("gateway_manage", "Manage the OpenClaw gateway process"),
        "sessions_spawn": ("spawn_subagent", "Spawn background sub-agent sessions"),
        "sessions_send": ("send_to_session", "Send messages to other sessions"),
        "sessions_list": ("list_sessions", "List active sessions"),
        "sessions_history": ("session_history", "Fetch session message history"),
        "agents_list": ("list_agents", "List available agent IDs"),
        "process": ("process_manage", "Manage background exec sessions"),
    }
    
    for tool_key, (name, desc) in tool_descriptions.items():
        if tool_allow is None or tool_key in tool_allow:
            tools.append({
                "name": name,
                "description": desc,
                "parameters": [],
                "invocation": {"type": "openclaw_builtin", "source": tool_key}
            })
    
    return tools


def extract_permissions(agent_config: dict, defaults: dict) -> dict:
    """Extract permission boundaries."""
    perms = {
        "file_read": True,
        "file_write": True,
        "network": True,
        "env_vars": False,
    }
    
    # If tools are restricted, adjust permissions
    if "tools" in agent_config and "allow" in agent_config["tools"]:
        allowed = agent_config["tools"]["allow"]
        perms["file_write"] = "write" in allowed or "edit" in allowed
        perms["network"] = "web_search" in allowed or "web_fetch" in allowed or "browser" in allowed
    
    return perms


def extract_rag(workspace: str) -> list[dict]:
    """Extract RAG/knowledge sources from workspace."""
    rag = []
    
    knowledge_files = {
        "MEMORY.md": "Long-term curated memory",
        "AGENTS.md": "Agent behavior guidelines",
        "SOUL.md": "Agent personality and values",
        "USER.md": "User profile and preferences",
        "TOOLS.md": "Tool configuration notes",
        "IDENTITY.md": "Agent identity definition",
        "HEARTBEAT.md": "Periodic check configuration",
    }
    
    for filename, desc in knowledge_files.items():
        filepath = os.path.join(workspace, filename)
        if os.path.exists(filepath):
            rag.append({
                "name": filename.lower().replace(".md", ""),
                "type": "markdown",
                "description": desc,
                "path": filename,
            })
    
    # Check for memory directory
    mem_dir = os.path.join(workspace, "memory")
    if os.path.isdir(mem_dir):
        rag.append({
            "name": "daily_memory",
            "type": "directory",
            "description": "Daily session logs and memories",
            "path": "memory/",
        })
    
    return rag


def convert_agent(agent_config: dict, defaults: dict, workspace: str, bindings: list) -> dict:
    """Convert a single OpenClaw agent to ADL format."""
    agent_id = agent_config.get("id", "unknown")
    agent_workspace = agent_config.get("workspace", defaults.get("workspace", workspace))
    
    # Identity
    identity = extract_agent_identity(agent_workspace)
    agent_name = identity.get("name", agent_config.get("name", agent_id))
    
    # Model config
    model_config = agent_config.get("model", defaults.get("model", {}))
    primary_model = model_config.get("primary", "anthropic/claude-sonnet-4-5")
    provider, model = primary_model.split("/", 1) if "/" in primary_model else ("unknown", primary_model)
    
    # Build ADL
    adl = {
        "adl_version": "1.0.0",
        "name": agent_name.lower().replace(" ", "_").replace("-", "_"),
        "display_name": agent_name,
        "description": identity.get("soul_summary", f"OpenClaw agent: {agent_id}"),
        "role": identity.get("vibe", "AI Assistant"),
        "version": "1.0.0",
        "llm": provider,
        "llm_settings": {
            "model": model,
            "temperature": 0,
            "max_tokens": 8192,
        },
        "tools": extract_tools_from_config(agent_config, defaults),
        "rag": extract_rag(agent_workspace),
        "permissions": extract_permissions(agent_config, defaults),
        "dependencies": [],
        "governance": {
            "created_by": "openclaw-to-adl-converter",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_platform": "openclaw",
            "source_agent_id": agent_id,
        },
        "metadata": {
            "openclaw": {
                "agent_id": agent_id,
                "is_default": agent_config.get("default", False),
                "compaction_mode": defaults.get("compaction", {}).get("mode"),
                "max_concurrent": defaults.get("maxConcurrent"),
            }
        }
    }
    
    # Add identity extras
    if identity.get("emoji"):
        adl["metadata"]["emoji"] = identity["emoji"]
    if identity.get("creature"):
        adl["metadata"]["creature"] = identity["creature"]
    
    # Add channel bindings as metadata
    agent_bindings = [b for b in bindings if b.get("agentId") == agent_id]
    if agent_bindings:
        adl["metadata"]["openclaw"]["bindings"] = []
        for b in agent_bindings:
            match = b.get("match", {})
            binding_info = {"channel": match.get("channel", "unknown")}
            if "guildId" in match:
                binding_info["guild_id"] = match["guildId"]
            if "peer" in match:
                binding_info["peer"] = match["peer"]
            adl["metadata"]["openclaw"]["bindings"].append(binding_info)
    
    return adl


def convert_openclaw_config(config_path: str, workspace: str = None) -> list[dict]:
    """Convert full OpenClaw config to ADL definitions."""
    config = load_json(config_path)
    
    agents_section = config.get("agents", {})
    defaults = agents_section.get("defaults", {})
    agent_list = agents_section.get("list", [])
    bindings = config.get("bindings", [])
    
    if workspace is None:
        workspace = defaults.get("workspace", ".")
    
    adl_agents = []
    for agent in agent_list:
        adl = convert_agent(agent, defaults, workspace, bindings)
        adl_agents.append(adl)
    
    return adl_agents


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/.openclaw/openclaw.json")
    workspace = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/.openclaw/workspace")
    output_dir = sys.argv[3] if len(sys.argv) > 3 else os.path.join(workspace, "tmp/adl-output")
    
    if not os.path.exists(config_path):
        print(f"Error: Config not found at {config_path}")
        sys.exit(1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    agents = convert_openclaw_config(config_path, workspace)
    
    for agent in agents:
        filename = f"{agent['name']}.adl.json"
        output_path = os.path.join(output_dir, filename)
        with open(output_path, "w") as f:
            json.dump(agent, f, indent=2)
        print(f"✅ Generated: {output_path}")
    
    # Also write combined file
    combined_path = os.path.join(output_dir, "all_agents.adl.json")
    with open(combined_path, "w") as f:
        json.dump(agents, f, indent=2)
    print(f"📦 Combined: {combined_path}")
    
    print(f"\n🔧 Converted {len(agents)} agent(s) to ADL format")


if __name__ == "__main__":
    main()
