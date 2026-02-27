#!/usr/bin/env python3
"""
Agent Protocol Matrix Generator
Compares AI agent frameworks and protocol support.
Outputs markdown and JSON.
"""

import json
import datetime

FRAMEWORKS = {
    "OpenClaw": {
        "language": "TypeScript/Node.js",
        "min_ram": "~1GB",
        "min_cost": "$599 (Mac Mini)",
        "license": "Source-available",
        "github_stars": "25K+",
        "category": "Autonomous Agent Platform",
        "features": {
            "agent_loop": True,
            "tool_calling": True,
            "multi_agent": "sessions_spawn (sub-agents)",
            "handoffs": False,
            "guardrails": "Policy-based (tool allowlists)",
            "memory_persistent": True,
            "memory_types": ["workspace files", "MEMORY.md", "daily logs", "session history"],
            "tracing": "Session JSONL logs",
            "multi_channel": True,
            "channels": ["Discord", "Telegram", "WhatsApp", "Signal", "Slack", "iMessage"],
            "cron_scheduling": True,
            "heartbeat_polling": True,
            "voice_support": "TTS (ElevenLabs, etc.)",
            "realtime_voice": False,
            "browser_control": True,
            "node_pairing": True,
            "skills_system": True,
            "human_in_loop": "Approval flows, elevated permissions",
            "structured_output": False,
            "streaming": True,
            "deployment": "Self-hosted daemon",
        },
        "protocols": {
            "MCP": "Native (tool provider + consumer)",
            "A2A": "Via prime_a2a-bridge",
            "ADL": "Via prime_openclaw-adl",
            "OpenAPI": "Not native",
        },
    },
    "OpenAI Agents SDK": {
        "language": "Python",
        "min_ram": "~100MB",
        "min_cost": "API costs only",
        "license": "MIT",
        "github_stars": "15K+ (1 week old)",
        "category": "Multi-Agent Framework",
        "features": {
            "agent_loop": True,
            "tool_calling": True,
            "multi_agent": "Native (handoffs + agents-as-tools)",
            "handoffs": True,
            "guardrails": "Native (input + output validation, parallel execution)",
            "memory_persistent": "Sessions (in-memory or Redis)",
            "memory_types": ["conversation history", "session state"],
            "tracing": "Native (OpenAI dashboard, custom exporters)",
            "multi_channel": False,
            "channels": [],
            "cron_scheduling": False,
            "heartbeat_polling": False,
            "voice_support": "Native realtime voice agents",
            "realtime_voice": True,
            "browser_control": False,
            "node_pairing": False,
            "skills_system": False,
            "human_in_loop": "Native (approval callbacks)",
            "structured_output": True,
            "streaming": True,
            "deployment": "Library (bring your own infra)",
        },
        "protocols": {
            "MCP": "Native (tool consumer)",
            "A2A": "Not native",
            "ADL": "Not native",
            "OpenAPI": "Via function tools",
        },
    },
    "PicoClaw": {
        "language": "Go",
        "min_ram": "<10MB",
        "min_cost": "$10 (RISC-V board)",
        "license": "MIT",
        "github_stars": "5K+ (6 days old)",
        "category": "Ultra-Lightweight Agent",
        "features": {
            "agent_loop": True,
            "tool_calling": True,
            "multi_agent": False,
            "handoffs": False,
            "guardrails": False,
            "memory_persistent": True,
            "memory_types": ["workspace files", "planning logs"],
            "tracing": "Basic logging",
            "multi_channel": True,
            "channels": ["Discord", "Telegram", "QQ"],
            "cron_scheduling": "Basic",
            "heartbeat_polling": False,
            "voice_support": False,
            "realtime_voice": False,
            "browser_control": False,
            "node_pairing": False,
            "skills_system": False,
            "human_in_loop": False,
            "structured_output": False,
            "streaming": True,
            "deployment": "Self-hosted binary",
        },
        "protocols": {
            "MCP": "Planned",
            "A2A": "Not native",
            "ADL": "Not native",
            "OpenAPI": "Not native",
        },
    },
    "LangChain/LangGraph": {
        "language": "Python/JS",
        "min_ram": "~200MB",
        "min_cost": "API costs only",
        "license": "MIT",
        "github_stars": "100K+",
        "category": "Agent Framework + Orchestration",
        "features": {
            "agent_loop": True,
            "tool_calling": True,
            "multi_agent": "LangGraph (graph-based orchestration)",
            "handoffs": "Via graph edges",
            "guardrails": "LangChain callbacks + custom",
            "memory_persistent": "LangMem, checkpointing",
            "memory_types": ["conversation buffer", "vector store", "checkpoints"],
            "tracing": "LangSmith (SaaS)",
            "multi_channel": False,
            "channels": [],
            "cron_scheduling": False,
            "heartbeat_polling": False,
            "voice_support": False,
            "realtime_voice": False,
            "browser_control": "Via tools",
            "node_pairing": False,
            "skills_system": "LangChain Hub",
            "human_in_loop": "Interrupt nodes in LangGraph",
            "structured_output": True,
            "streaming": True,
            "deployment": "LangGraph Cloud or self-hosted",
        },
        "protocols": {
            "MCP": "Native integration",
            "A2A": "Not native",
            "ADL": "Not native",
            "OpenAPI": "Native (API toolkit)",
        },
    },
    "AutoGen (Microsoft)": {
        "language": "Python",
        "min_ram": "~200MB",
        "min_cost": "API costs only",
        "license": "MIT",
        "github_stars": "40K+",
        "category": "Multi-Agent Conversation Framework",
        "features": {
            "agent_loop": True,
            "tool_calling": True,
            "multi_agent": "Native (conversable agents, group chat)",
            "handoffs": "Via conversation patterns",
            "guardrails": "Custom termination conditions",
            "memory_persistent": "Via external stores",
            "memory_types": ["conversation history", "teachable agent memory"],
            "tracing": "AgentOps integration",
            "multi_channel": False,
            "channels": [],
            "cron_scheduling": False,
            "heartbeat_polling": False,
            "voice_support": False,
            "realtime_voice": False,
            "browser_control": "Via tools",
            "node_pairing": False,
            "skills_system": False,
            "human_in_loop": "Human proxy agent",
            "structured_output": True,
            "streaming": True,
            "deployment": "Library + merging with Semantic Kernel (Q1 2026)",
        },
        "protocols": {
            "MCP": "Planned (via Semantic Kernel)",
            "A2A": "Not native",
            "ADL": "Not native",
            "OpenAPI": "Via tools",
        },
    },
}

# Key comparison dimensions
DIMENSIONS = [
    ("Core", ["agent_loop", "tool_calling", "multi_agent", "handoffs", "guardrails", "structured_output"]),
    ("Memory", ["memory_persistent", "memory_types"]),
    ("Deployment", ["multi_channel", "cron_scheduling", "heartbeat_polling", "deployment"]),
    ("Observability", ["tracing", "human_in_loop"]),
    ("Media", ["voice_support", "realtime_voice", "browser_control"]),
    ("Extensibility", ["skills_system", "node_pairing", "streaming"]),
]


def render_value(v):
    if v is True:
        return "✅"
    if v is False:
        return "❌"
    if isinstance(v, list):
        return ", ".join(v) if v else "❌"
    return str(v)


def generate_markdown():
    lines = []
    lines.append("# Agent Framework & Protocol Comparison Matrix")
    lines.append(f"\n*Generated: {datetime.date.today().isoformat()}*\n")

    # Overview table
    lines.append("## Overview\n")
    lines.append("| | " + " | ".join(FRAMEWORKS.keys()) + " |")
    lines.append("|---|" + "|".join(["---"] * len(FRAMEWORKS)) + "|")
    for field in ["language", "min_ram", "min_cost", "license", "github_stars", "category"]:
        row = f"| **{field.replace('_', ' ').title()}** |"
        for fw in FRAMEWORKS.values():
            row += f" {fw[field]} |"
        lines.append(row)

    # Feature comparison by dimension
    for dim_name, dim_features in DIMENSIONS:
        lines.append(f"\n## {dim_name}\n")
        lines.append("| Feature | " + " | ".join(FRAMEWORKS.keys()) + " |")
        lines.append("|---|" + "|".join(["---"] * len(FRAMEWORKS)) + "|")
        for feat in dim_features:
            row = f"| **{feat.replace('_', ' ').title()}** |"
            for fw in FRAMEWORKS.values():
                v = fw["features"].get(feat, "N/A")
                row += f" {render_value(v)} |"
            lines.append(row)

    # Protocol support
    lines.append("\n## Protocol Support\n")
    protocols = ["MCP", "A2A", "ADL", "OpenAPI"]
    lines.append("| Protocol | " + " | ".join(FRAMEWORKS.keys()) + " |")
    lines.append("|---|" + "|".join(["---"] * len(FRAMEWORKS)) + "|")
    for proto in protocols:
        row = f"| **{proto}** |"
        for fw in FRAMEWORKS.values():
            row += f" {fw['protocols'].get(proto, 'N/A')} |"
        lines.append(row)

    # Analysis
    lines.append("\n## Analysis\n")
    lines.append("""### Where Each Framework Wins

- **OpenClaw**: Unmatched for autonomous, always-on agent deployment. Best multi-channel support, persistent memory, cron/heartbeat scheduling. The "operating system for agents."
- **OpenAI Agents SDK**: Best developer experience for multi-agent workflows. Clean primitives (handoffs, guardrails, tracing). Realtime voice. But no deployment story — it's a library, not a platform.
- **PicoClaw**: Revolutionary for edge deployment. Running an AI agent on a $10 RISC-V board with <10MB RAM opens entirely new use cases (IoT, embedded, offline-first). Early stage but fast-moving (5K stars in 6 days).
- **LangChain/LangGraph**: Most integrations (700+), largest ecosystem. LangGraph adds proper orchestration. But complexity is high and lock-in to LangSmith for observability.
- **AutoGen**: Best for research and multi-agent conversation patterns. Merging with Semantic Kernel signals Microsoft's commitment. Group chat patterns are unique.

### The Convergence

All frameworks are converging on MCP as the universal tool protocol. The remaining gaps:
1. **No standard for agent definition** (ADL is trying, but adoption is nascent)
2. **No standard for agent-to-agent communication** (A2A exists but isn't widely adopted)
3. **No standard for agent deployment** (everyone rolls their own)

### Recommendation

- **Building an always-on personal agent?** → OpenClaw
- **Building multi-agent workflows?** → OpenAI Agents SDK or LangGraph
- **Deploying to edge/IoT?** → PicoClaw
- **Need maximum integrations?** → LangChain
- **Researching multi-agent dynamics?** → AutoGen
""")

    return "\n".join(lines)


def generate_json():
    return json.dumps({
        "generated": datetime.date.today().isoformat(),
        "frameworks": FRAMEWORKS,
    }, indent=2, default=str)


if __name__ == "__main__":
    md = generate_markdown()
    with open("MATRIX.md", "w") as f:
        f.write(md)
    print(f"Generated MATRIX.md ({len(md)} bytes)")

    js = generate_json()
    with open("matrix.json", "w") as f:
        f.write(js)
    print(f"Generated matrix.json ({len(js)} bytes)")
