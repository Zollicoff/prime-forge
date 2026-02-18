#!/usr/bin/env python3
"""
prime_session-insights: OpenClaw Session Analytics Tool
Analyzes session JSONL logs to extract patterns, costs, tool usage, and optimization insights.

Usage:
    python3 session_insights.py [sessions_dir] [--top N] [--days N] [--json] [--report]
"""

import json
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict
from typing import Optional

def parse_session(filepath: Path) -> dict:
    """Parse a single session JSONL file into structured data."""
    messages = []
    session_meta = None
    
    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get('type') == 'session':
                    session_meta = obj
                elif obj.get('type') == 'message':
                    messages.append(obj)
            except json.JSONDecodeError:
                continue
    
    return {'meta': session_meta, 'messages': messages, 'path': str(filepath)}


def analyze_session(parsed: dict) -> dict:
    """Analyze a parsed session into metrics."""
    messages = parsed['messages']
    if not messages:
        return None
    
    # Timestamps
    timestamps = []
    for m in messages:
        ts = m.get('timestamp')
        if ts:
            try:
                timestamps.append(datetime.fromisoformat(ts.replace('Z', '+00:00')))
            except:
                pass
    
    if not timestamps:
        return None
    
    first_ts = min(timestamps)
    last_ts = max(timestamps)
    duration_min = (last_ts - first_ts).total_seconds() / 60
    
    # Costs
    total_cost = 0
    costs_by_msg = []
    for m in messages:
        cost = 0
        try:
            cost = m.get('message', {}).get('usage', {}).get('cost', {}).get('total', 0) or 0
        except:
            pass
        total_cost += cost
        if cost > 0:
            costs_by_msg.append(cost)
    
    # Token counts
    total_input = 0
    total_output = 0
    cache_read = 0
    cache_write = 0
    for m in messages:
        try:
            usage = m.get('message', {}).get('usage', {})
            total_input += usage.get('input', 0) or usage.get('inputTokens', 0) or 0
            total_output += usage.get('output', 0) or usage.get('outputTokens', 0) or 0
            cache_read += usage.get('cacheRead', 0) or 0
            cache_write += usage.get('cacheWrite', 0) or 0
        except:
            pass
    
    # Role counts
    roles = Counter()
    for m in messages:
        role = m.get('message', {}).get('role', 'unknown')
        roles[role] += 1
    
    # Tool usage
    tool_calls = Counter()
    tool_durations = defaultdict(list)
    for m in messages:
        content = m.get('message', {}).get('content', [])
        if isinstance(content, list):
            for c in content:
                if isinstance(c, dict) and c.get('type') == 'toolCall':
                    name = c.get('name', 'unknown')
                    tool_calls[name] += 1
    
    # Model info
    models = set()
    for m in messages:
        model = m.get('message', {}).get('model')
        if model:
            models.add(model)
    
    # Message lengths (text content)
    user_lengths = []
    assistant_lengths = []
    for m in messages:
        role = m.get('message', {}).get('role')
        content = m.get('message', {}).get('content', [])
        text_len = 0
        if isinstance(content, list):
            for c in content:
                if isinstance(c, dict) and c.get('type') == 'text':
                    text_len += len(c.get('text', ''))
                elif isinstance(c, str):
                    text_len += len(c)
        if role == 'user':
            user_lengths.append(text_len)
        elif role == 'assistant':
            assistant_lengths.append(text_len)
    
    return {
        'session_id': Path(parsed['path']).stem,
        'date': first_ts.strftime('%Y-%m-%d'),
        'start': first_ts.isoformat(),
        'end': last_ts.isoformat(),
        'duration_min': round(duration_min, 1),
        'total_cost': round(total_cost, 4),
        'total_messages': len(messages),
        'user_messages': roles.get('user', 0),
        'assistant_messages': roles.get('assistant', 0),
        'tool_result_messages': roles.get('toolResult', 0),
        'input_tokens': total_input,
        'output_tokens': total_output,
        'total_tokens': total_input + total_output,
        'tool_calls': dict(tool_calls.most_common()),
        'total_tool_calls': sum(tool_calls.values()),
        'models': list(models),
        'avg_user_msg_len': round(sum(user_lengths) / len(user_lengths)) if user_lengths else 0,
        'avg_assistant_msg_len': round(sum(assistant_lengths) / len(assistant_lengths)) if assistant_lengths else 0,
        'cost_per_message': round(total_cost / len(messages), 6) if messages else 0,
        'cache_read_tokens': cache_read,
        'cache_write_tokens': cache_write,
        'tokens_per_minute': round((total_input + total_output) / max(duration_min, 0.1)) if duration_min > 0 else 0,
    }


def generate_report(sessions: list[dict], top_n: int = 10) -> str:
    """Generate a human-readable analytics report."""
    if not sessions:
        return "No sessions to analyze."
    
    lines = []
    lines.append("# OpenClaw Session Insights Report")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"Sessions analyzed: {len(sessions)}")
    lines.append("")
    
    # Overall stats
    total_cost = sum(s['total_cost'] for s in sessions)
    total_messages = sum(s['total_messages'] for s in sessions)
    total_tokens = sum(s['total_tokens'] for s in sessions)
    total_tool_calls = sum(s['total_tool_calls'] for s in sessions)
    total_duration = sum(s['duration_min'] for s in sessions)
    
    lines.append("## Overview")
    lines.append(f"- Total cost: ${total_cost:.2f}")
    lines.append(f"- Total messages: {total_messages:,}")
    lines.append(f"- Total tokens: {total_tokens:,}")
    lines.append(f"- Total tool calls: {total_tool_calls:,}")
    lines.append(f"- Total session time: {total_duration:.0f} min ({total_duration/60:.1f} hrs)")
    lines.append(f"- Avg cost/session: ${total_cost/len(sessions):.4f}")
    lines.append(f"- Avg cost/message: ${total_cost/max(total_messages,1):.6f}")
    lines.append("")
    
    # Daily cost breakdown
    daily_costs = defaultdict(float)
    daily_sessions = defaultdict(int)
    daily_tokens = defaultdict(int)
    for s in sessions:
        daily_costs[s['date']] += s['total_cost']
        daily_sessions[s['date']] += 1
        daily_tokens[s['date']] += s['total_tokens']
    
    lines.append("## Daily Breakdown")
    for date in sorted(daily_costs.keys(), reverse=True)[:14]:
        lines.append(f"- {date}: ${daily_costs[date]:.2f} | {daily_sessions[date]} sessions | {daily_tokens[date]:,} tokens")
    lines.append("")
    
    # Top tools
    all_tools = Counter()
    for s in sessions:
        all_tools.update(s['tool_calls'])
    
    lines.append(f"## Top {top_n} Tools")
    for tool, count in all_tools.most_common(top_n):
        lines.append(f"- {tool}: {count:,} calls")
    lines.append("")
    
    # Most expensive sessions
    by_cost = sorted(sessions, key=lambda s: s['total_cost'], reverse=True)
    lines.append(f"## Most Expensive Sessions (Top {min(top_n, len(sessions))})")
    for s in by_cost[:top_n]:
        lines.append(f"- {s['date']} ${s['total_cost']:.4f} | {s['total_messages']} msgs | {s['duration_min']:.0f}min | {s['session_id'][:8]}...")
    lines.append("")
    
    # Longest sessions
    by_duration = sorted(sessions, key=lambda s: s['duration_min'], reverse=True)
    lines.append(f"## Longest Sessions (Top {min(top_n, len(sessions))})")
    for s in by_duration[:top_n]:
        lines.append(f"- {s['date']} {s['duration_min']:.0f}min | ${s['total_cost']:.4f} | {s['total_messages']} msgs | {s['session_id'][:8]}...")
    lines.append("")
    
    # Model usage
    model_counter = Counter()
    for s in sessions:
        for m in s['models']:
            model_counter[m] += 1
    
    if model_counter:
        lines.append("## Models Used")
        for model, count in model_counter.most_common():
            lines.append(f"- {model}: {count} sessions")
        lines.append("")
    
    # Efficiency insights
    lines.append("## Efficiency Insights")
    
    # Tool-to-message ratio
    if total_messages > 0:
        tool_ratio = total_tool_calls / total_messages
        lines.append(f"- Tool calls per message: {tool_ratio:.2f}")
    
    # Token efficiency
    if total_tokens > 0:
        input_ratio = sum(s['input_tokens'] for s in sessions) / total_tokens
        lines.append(f"- Input token ratio: {input_ratio:.1%} (lower = more output-heavy)")
    
    # Cost per hour
    if total_duration > 0:
        cost_per_hour = total_cost / (total_duration / 60)
        lines.append(f"- Cost per hour of session time: ${cost_per_hour:.2f}")
    
    # Sessions with no tool use (potentially inefficient)
    no_tool = [s for s in sessions if s['total_tool_calls'] == 0]
    if no_tool:
        lines.append(f"- Sessions with zero tool calls: {len(no_tool)} ({len(no_tool)/len(sessions):.0%})")
    
    # Average response verbosity
    avg_asst = sum(s['avg_assistant_msg_len'] for s in sessions if s['avg_assistant_msg_len'] > 0)
    count_asst = sum(1 for s in sessions if s['avg_assistant_msg_len'] > 0)
    if count_asst:
        lines.append(f"- Avg assistant message length: {avg_asst/count_asst:.0f} chars")
    
    lines.append("")
    
    # Optimization recommendations
    lines.append("## Recommendations")
    
    if total_cost > 0:
        expensive = [s for s in sessions if s['total_cost'] > total_cost / len(sessions) * 3]
        if expensive:
            lines.append(f"- ⚠️ {len(expensive)} sessions cost 3x+ the average — review for optimization")
    
    if all_tools.get('web_search', 0) > all_tools.get('web_fetch', 0) * 3:
        lines.append("- 💡 High search-to-fetch ratio — consider fetching more results directly")
    
    if all_tools.get('exec', 0) > total_tool_calls * 0.4:
        lines.append("- 💡 exec is >40% of tool calls — check if dedicated tools could replace shell commands")
    
    long_sessions = [s for s in sessions if s['duration_min'] > 120]
    if long_sessions:
        lines.append(f"- ⚠️ {len(long_sessions)} sessions exceed 2 hours — consider breaking into sub-tasks")
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='OpenClaw Session Insights')
    parser.add_argument('sessions_dir', nargs='?', 
                       default=os.path.expanduser('~/.openclaw/agents/main/sessions'),
                       help='Path to sessions directory')
    parser.add_argument('--top', type=int, default=10, help='Top N items to show')
    parser.add_argument('--days', type=int, default=0, help='Only analyze last N days (0=all)')
    parser.add_argument('--json', action='store_true', help='Output raw JSON')
    parser.add_argument('--report', action='store_true', default=True, help='Generate report (default)')
    parser.add_argument('--agent', default='main', help='Agent ID')
    args = parser.parse_args()
    
    sessions_dir = Path(args.sessions_dir)
    if not sessions_dir.exists():
        # Try with agent id
        sessions_dir = Path(os.path.expanduser(f'~/.openclaw/agents/{args.agent}/sessions'))
    
    if not sessions_dir.exists():
        print(f"Error: Sessions directory not found: {sessions_dir}", file=sys.stderr)
        sys.exit(1)
    
    jsonl_files = sorted(sessions_dir.glob('*.jsonl'))
    if not jsonl_files:
        print("No session files found.", file=sys.stderr)
        sys.exit(1)
    
    print(f"Parsing {len(jsonl_files)} session files...", file=sys.stderr)
    
    cutoff = None
    if args.days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    
    analyzed = []
    for fp in jsonl_files:
        if '.deleted.' in fp.name:
            continue
        parsed = parse_session(fp)
        result = analyze_session(parsed)
        if result:
            if cutoff:
                try:
                    session_date = datetime.fromisoformat(result['start'])
                    if session_date.tzinfo is None:
                        session_date = session_date.replace(tzinfo=timezone.utc)
                    if session_date < cutoff:
                        continue
                except:
                    pass
            analyzed.append(result)
    
    if args.json:
        print(json.dumps(analyzed, indent=2))
    else:
        print(generate_report(analyzed, top_n=args.top))


if __name__ == '__main__':
    main()
