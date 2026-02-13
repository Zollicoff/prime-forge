#!/usr/bin/env python3
"""
prime_a2a-bridge: OpenClaw → A2A Protocol Bridge

Generates A2A-compliant Agent Cards from OpenClaw configurations,
enabling discovery by any A2A-compatible agent system.
"""

import argparse
import json
import os
import re
import sys
import uuid
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------

def load_config(config_path: str) -> dict:
    """Load OpenClaw config (YAML or JSON)."""
    path = Path(config_path)
    if not path.exists():
        print(f"Error: Config not found at {config_path}", file=sys.stderr)
        sys.exit(1)
    
    text = path.read_text()
    
    if path.suffix in ('.yaml', '.yml'):
        if yaml is None:
            # Fallback: try simple YAML-like parsing or suggest install
            print("Warning: PyYAML not installed. Trying JSON fallback.", file=sys.stderr)
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                print("Error: Install PyYAML (`pip install pyyaml`) for YAML support.", file=sys.stderr)
                sys.exit(1)
        return yaml.safe_load(text)
    else:
        return json.loads(text)


def read_markdown_file(workspace: str, filename: str) -> str | None:
    """Read a markdown file from the workspace."""
    path = Path(workspace) / filename
    if path.exists():
        return path.read_text()
    return None


def extract_identity(workspace: str) -> dict:
    """Extract agent identity from IDENTITY.md."""
    content = read_markdown_file(workspace, "IDENTITY.md")
    if not content:
        return {"name": "OpenClaw Agent", "description": "An OpenClaw-powered AI agent"}
    
    identity = {}
    
    # Extract name
    name_match = re.search(r'\*\*Name:\*\*\s*(.+)', content)
    if name_match:
        identity["name"] = name_match.group(1).strip()
    
    # Extract creature/type
    creature_match = re.search(r'\*\*Creature:\*\*\s*(.+)', content)
    if creature_match:
        identity["creature"] = creature_match.group(1).strip()
    
    # Extract vibe/description
    vibe_match = re.search(r'\*\*Vibe:\*\*\s*(.+)', content)
    if vibe_match:
        identity["description"] = vibe_match.group(1).strip()
    
    # Extract emoji
    emoji_match = re.search(r'\*\*Emoji:\*\*\s*(.+)', content)
    if emoji_match:
        identity["emoji"] = emoji_match.group(1).strip()
    
    return identity


def discover_skills(workspace: str, config: dict) -> list[dict]:
    """Discover installed OpenClaw skills and convert to A2A AgentSkill format."""
    skills = []
    
    # Check common skill locations
    skill_dirs = [
        Path(workspace) / "skills",
        Path("/opt/homebrew/lib/node_modules/openclaw/skills"),
        Path(os.path.expanduser("~/.openclaw/skills")),
    ]
    
    # Also check config for skill paths
    agents = config.get("agents", {})
    agent_list = agents.get("list", []) if isinstance(agents, dict) else []
    for agent_cfg in (agent_list if isinstance(agent_list, list) else []):
        if not isinstance(agent_cfg, dict):
            continue
        agent_skills = agent_cfg.get("skills", [])
        for s in (agent_skills if isinstance(agent_skills, list) else []):
            if isinstance(s, str):
                skill_dirs.append(Path(s))
    
    seen = set()
    for skill_dir in skill_dirs:
        if not skill_dir.exists() or not skill_dir.is_dir():
            continue
        
        for entry in skill_dir.iterdir():
            skill_md = entry / "SKILL.md" if entry.is_dir() else None
            if skill_md and skill_md.exists() and entry.name not in seen:
                seen.add(entry.name)
                content = skill_md.read_text()
                
                # Extract description from first meaningful paragraph
                lines = [l.strip() for l in content.split('\n') 
                         if l.strip() and not l.startswith('#') and not l.startswith('---') 
                         and not l.startswith('```') and ':' not in l[:20] and len(l.strip()) > 10]
                desc = lines[0] if lines else f"Skill: {entry.name}"
                
                # Extract tags from content
                tags = [entry.name]
                if "weather" in entry.name.lower():
                    tags.append("weather")
                if "github" in entry.name.lower():
                    tags.extend(["github", "code", "git"])
                if "image" in entry.name.lower():
                    tags.extend(["image", "generation"])
                
                skills.append({
                    "id": entry.name,
                    "name": entry.name.replace("-", " ").title(),
                    "description": desc[:200],
                    "tags": tags,
                    "examples": [],
                    "inputModes": ["text/plain"],
                    "outputModes": ["text/plain"],
                })
    
    return skills


def detect_capabilities(config: dict) -> dict:
    """Detect A2A capabilities from OpenClaw config."""
    caps = {
        "streaming": False,
        "pushNotifications": False,
        "extensions": [],
    }
    
    channels = config.get("channels", {})
    
    # If has any real-time channel, mark streaming
    if any(ch in channels for ch in ("discord", "telegram", "slack")):
        caps["streaming"] = True
    
    return caps


def detect_modes(config: dict) -> tuple[list[str], list[str]]:
    """Detect supported input/output modes from config."""
    input_modes = ["text/plain"]
    output_modes = ["text/plain"]
    
    # Check for image capabilities
    agents = config.get("agents", {})
    agent_list = agents.get("list", []) if isinstance(agents, dict) else []
    for agent_cfg in (agent_list if isinstance(agent_list, list) else []):
        if not isinstance(agent_cfg, dict):
            continue
        tools = agent_cfg.get("tools", {})
        if isinstance(tools, dict):
            if tools.get("image") or tools.get("browser"):
                input_modes.append("image/png")
                output_modes.append("image/png")
    
    return input_modes, output_modes


# ---------------------------------------------------------------------------
# A2A Agent Card generation
# ---------------------------------------------------------------------------

def generate_agent_card(
    config: dict,
    workspace: str,
    agent_id: str = "main",
    url: str = "http://localhost:8080",
) -> dict:
    """Generate an A2A-compliant Agent Card from OpenClaw config."""
    
    identity = extract_identity(workspace)
    skills = discover_skills(workspace, config)
    capabilities = detect_capabilities(config)
    input_modes, output_modes = detect_modes(config)
    
    # Get agent-specific config
    agents = config.get("agents", {})
    agent_list = agents.get("list", []) if isinstance(agents, dict) else []
    agent_cfg = {}
    for a in (agent_list if isinstance(agent_list, list) else []):
        if isinstance(a, dict) and a.get("id") == agent_id:
            agent_cfg = a
            break
    defaults = agents.get("defaults", {}) if isinstance(agents, dict) else {}
    model_cfg = agent_cfg.get("model", defaults.get("model", {}))
    model = model_cfg.get("primary", "unknown") if isinstance(model_cfg, dict) else str(model_cfg)
    
    # Build the card
    card = {
        "name": identity.get("name", "OpenClaw Agent"),
        "description": identity.get("description", "An AI agent powered by OpenClaw"),
        "url": url,
        "version": "1.0.0",
        "defaultInputModes": input_modes,
        "defaultOutputModes": output_modes,
        "capabilities": capabilities,
        "skills": skills,
        "supportsAuthenticatedExtendedCard": False,
        # Extensions for OpenClaw-specific metadata
        "extensions": [
            {
                "uri": "urn:openclaw:agent-metadata",
                "type": "AgentMetadata",
                "required": False,
                "data": {
                    "agentId": agent_id,
                    "model": model,
                    "creature": identity.get("creature", ""),
                    "emoji": identity.get("emoji", ""),
                    "framework": "openclaw",
                }
            }
        ],
    }
    
    # Add provider info if available
    soul = read_markdown_file(workspace, "SOUL.md")
    if soul:
        # Summarize SOUL.md into a provider description
        soul_lines = [l.strip() for l in soul.split('\n') 
                      if l.strip() and not l.startswith('#') and not l.startswith('_') and not l.startswith('-')]
        if soul_lines:
            card["description"] = soul_lines[0][:300]
    
    return card


# ---------------------------------------------------------------------------
# HTTP Server for serving Agent Card
# ---------------------------------------------------------------------------

class A2ACardHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves the Agent Card at .well-known/agent-card.json"""
    
    card_json: str = "{}"
    
    def do_GET(self):
        if self.path == "/.well-known/agent-card.json" or self.path == "/agent-card.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(self.card_json.encode())
        elif self.path == "/":
            # Simple landing page
            html = f"""<!DOCTYPE html>
<html><head><title>A2A Agent</title></head>
<body>
<h1>🤖 A2A Agent Card</h1>
<p>This agent supports the <a href="https://a2a-protocol.org">A2A Protocol</a>.</p>
<p>Agent Card: <a href="/.well-known/agent-card.json">/.well-known/agent-card.json</a></p>
<pre>{self.card_json}</pre>
</body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        print(f"[A2A] {args[0]}")


def serve_card(card: dict, port: int = 8080):
    """Start HTTP server serving the Agent Card."""
    A2ACardHandler.card_json = json.dumps(card, indent=2)
    
    server = HTTPServer(("0.0.0.0", port), A2ACardHandler)
    print(f"🚀 A2A Agent Card server running at http://localhost:{port}")
    print(f"   Card endpoint: http://localhost:{port}/.well-known/agent-card.json")
    print(f"   Agent: {card.get('name', 'Unknown')}")
    print(f"   Skills: {len(card.get('skills', []))}")
    print()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="OpenClaw → A2A Protocol Bridge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate A2A Agent Card JSON")
    gen_parser.add_argument("--config", "-c", default="openclaw.yaml",
                           help="Path to OpenClaw config file")
    gen_parser.add_argument("--workspace", "-w", default=".",
                           help="Path to agent workspace directory")
    gen_parser.add_argument("--agent", "-a", default="main",
                           help="Agent ID to generate card for")
    gen_parser.add_argument("--url", "-u", default="http://localhost:8080",
                           help="Agent's A2A endpoint URL")
    gen_parser.add_argument("--output", "-o", default=None,
                           help="Output file (default: stdout)")
    
    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Serve Agent Card via HTTP")
    serve_parser.add_argument("--config", "-c", default="openclaw.yaml",
                             help="Path to OpenClaw config file")
    serve_parser.add_argument("--workspace", "-w", default=".",
                             help="Path to agent workspace directory")
    serve_parser.add_argument("--agent", "-a", default="main",
                             help="Agent ID to serve card for")
    serve_parser.add_argument("--port", "-p", type=int, default=8080,
                             help="HTTP port (default: 8080)")
    serve_parser.add_argument("--url", "-u", default=None,
                             help="Agent's public URL (default: http://localhost:<port>)")
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    
    if args.command == "generate":
        card = generate_agent_card(config, args.workspace, args.agent, args.url)
        output = json.dumps(card, indent=2)
        
        if args.output:
            Path(args.output).write_text(output)
            print(f"Agent Card written to {args.output}", file=sys.stderr)
        else:
            print(output)
    
    elif args.command == "serve":
        url = args.url or f"http://localhost:{args.port}"
        card = generate_agent_card(config, args.workspace, args.agent, url)
        serve_card(card, args.port)


if __name__ == "__main__":
    main()
