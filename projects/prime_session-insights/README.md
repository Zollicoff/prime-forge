# prime_session-insights

OpenClaw session analytics tool. Parses JSONL session logs to extract costs, tool usage patterns, model efficiency, and optimization insights.

## Features

- **Cost tracking**: Total, per-session, per-day, per-message costs
- **Tool analytics**: Usage frequency across all tools
- **Token analysis**: Input/output/cache token breakdowns
- **Model tracking**: Which models used across sessions
- **Efficiency metrics**: Tool-to-message ratios, cost per hour, response verbosity
- **Optimization recommendations**: Flags expensive sessions, overuse patterns

## Usage

```bash
# Analyze all sessions for the main agent
python3 session_insights.py

# Analyze last 7 days
python3 session_insights.py --days 7

# Output raw JSON
python3 session_insights.py --json

# Specify sessions directory
python3 session_insights.py /path/to/sessions

# Analyze a different agent
python3 session_insights.py --agent shard1
```

## Requirements

- Python 3.10+
- No external dependencies

## Output

Generates a markdown report with:
- Overview stats (cost, messages, tokens, tool calls, time)
- Daily cost breakdown
- Top tools by usage
- Most expensive and longest sessions
- Model usage distribution
- Efficiency insights and optimization recommendations

## License

MIT
