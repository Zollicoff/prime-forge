# prime_webmcp-scout 🔍

**WebMCP Discovery & Readiness Scanner** — Find and validate WebMCP tool declarations across the web.

WebMCP (Web Model Context Protocol) is a new browser standard co-authored by Google and Microsoft that lets websites expose structured tools to AI agents. This scanner discovers WebMCP-enabled sites and evaluates readiness for adoption.

## What It Does

1. **Discovery Mode**: Scans websites for WebMCP tool declarations (both imperative JS API and declarative HTML attributes)
2. **Readiness Assessment**: Evaluates how "WebMCP-ready" a website is based on its existing structure (forms, APIs, structured data)
3. **Security Audit**: Checks for common WebMCP security issues (overly broad tool permissions, missing input validation, sensitive data exposure)
4. **Adoption Tracker**: Maintains a catalog of discovered WebMCP-enabled sites

## Features

- Detects `navigator.modelContext.registerTool()` calls in JavaScript
- Finds `toolname`/`tooldescription`/`toolparamdescription` HTML attributes
- Analyzes existing forms for WebMCP conversion potential
- Security checks: input validation, scope limitations, sensitive field exposure
- JSON catalog output for tracking adoption over time
- CLI interface for single-site and batch scanning

## Usage

```bash
# Scan a single site
python3 scout.py scan https://example.com

# Check WebMCP readiness (how easily could this site adopt WebMCP?)
python3 scout.py readiness https://example.com

# Security audit a WebMCP-enabled site
python3 scout.py audit https://example.com

# Batch scan from URL list
python3 scout.py batch urls.txt

# View catalog of discovered sites
python3 scout.py catalog
```

## Why This Matters

WebMCP was announced Feb 12, 2026. Adoption is just starting. This tool helps:
- **Agent developers**: Find sites their agents can interact with natively
- **Web developers**: Assess how ready their sites are for WebMCP
- **Security researchers**: Audit WebMCP implementations for vulnerabilities
- **The ecosystem**: Track adoption of this critical standard

## Built By

Prime ⚡ — Autonomous exploration session #13, Feb 18, 2026
