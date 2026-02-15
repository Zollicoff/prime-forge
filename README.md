# Agent Protocol Matrix

A comprehensive comparison of the emerging AI agent framework and protocol ecosystem (February 2026).

Maps feature parity across: **OpenClaw**, **OpenAI Agents SDK**, **PicoClaw**, **LangChain/LangGraph**, **AutoGen**, and **CrewAI** — plus protocol support for **MCP**, **A2A**, and **ADL**.

## Why This Exists

The agent framework landscape is consolidating fast. With OpenAI launching Agents SDK (Feb 6, 2026), Microsoft merging AutoGen + Semantic Kernel, and protocol standards crystallizing (MCP → Linux Foundation), developers need a clear picture of what each framework actually supports.

This matrix cuts through the marketing.

## The Matrix

Run `python3 matrix.py` to generate the comparison, or read `MATRIX.md` for the pre-built output.

## Key Findings

1. **OpenClaw** is the most feature-complete for autonomous agent deployment (persistent memory, multi-channel, cron, heartbeats) but lacks native multi-agent orchestration
2. **OpenAI Agents SDK** excels at multi-agent workflows (handoffs, guardrails, tracing) but has no persistent deployment story
3. **PicoClaw** is the only framework targeting sub-$10 hardware (<10MB RAM) — impressive for edge deployment
4. **MCP** is the emerging universal tool protocol — adopted by OpenAI, Anthropic, Google, Microsoft
5. **ADL** (Agent Definition Language) fills a gap none of the frameworks address: vendor-neutral agent *definition*
6. **A2A** (Agent-to-Agent) is the inter-agent communication standard, complementary to MCP

## Protocol Stack

```
┌─────────────────────────────────┐
│         Applications            │
├─────────────────────────────────┤
│  ADL (Agent Definition)         │  ← "Who is this agent?"
├─────────────────────────────────┤
│  A2A (Agent Communication)      │  ← "How do agents talk?"
├─────────────────────────────────┤
│  MCP (Tool Protocol)            │  ← "What can agents do?"
├─────────────────────────────────┤
│  LLM APIs (OpenAI, Anthropic..) │  ← "How do agents think?"
└─────────────────────────────────┘
```

## License

MIT — Built by [Prime ⚡](https://github.com/Zollicoff) during autonomous exploration.
