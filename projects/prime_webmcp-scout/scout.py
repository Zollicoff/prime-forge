#!/usr/bin/env python3
"""
prime_webmcp-scout: WebMCP Discovery & Readiness Scanner
Scans websites for WebMCP tool declarations and evaluates adoption readiness.

Author: Prime ⚡ (Autonomous Session #13, 2026-02-18)
"""

import argparse
import json
import re
import sys
import os
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from pathlib import Path

try:
    import urllib.request
    import urllib.error
    import ssl
except ImportError:
    pass

# ── Constants ──────────────────────────────────────────────────────────────

CATALOG_FILE = Path(__file__).parent / "catalog.json"

# WebMCP detection patterns
IMPERATIVE_PATTERNS = [
    r'navigator\.modelContext\.registerTool\s*\(',
    r'navigator\.modelContext\.registerResource\s*\(',
    r'navigator\.modelContext\.registerPrompt\s*\(',
    r'modelContext\.registerTool\s*\(',
    r'\.registerTool\s*\(\s*\{[^}]*name\s*:',
]

DECLARATIVE_ATTRS = [
    'toolname',
    'tooldescription', 
    'toolparamdescription',
    'toolresource',
]

# Security-sensitive form fields that shouldn't be exposed via WebMCP
SENSITIVE_FIELDS = [
    'password', 'passwd', 'pass', 'pwd',
    'ssn', 'social_security', 'social-security',
    'credit_card', 'card_number', 'cc_number', 'ccnum',
    'cvv', 'cvc', 'security_code',
    'secret', 'token', 'api_key', 'apikey',
    'pin', 'otp', 'mfa', '2fa',
]

# ── Helpers ────────────────────────────────────────────────────────────────

def fetch_page(url: str, timeout: int = 15) -> tuple[str, int]:
    """Fetch a page and return (html, status_code)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(url, headers={
        'User-Agent': 'prime_webmcp-scout/1.0 (WebMCP adoption scanner)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
    })
    
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        html = resp.read().decode('utf-8', errors='replace')
        return html, resp.status
    except urllib.error.HTTPError as e:
        return '', e.code
    except Exception as e:
        return '', 0


def find_imperative_tools(html: str) -> list[dict]:
    """Find navigator.modelContext.registerTool() calls."""
    tools = []
    for pattern in IMPERATIVE_PATTERNS:
        matches = list(re.finditer(pattern, html))
        for m in matches:
            # Try to extract tool name from nearby context
            context = html[m.start():m.start()+500]
            name_match = re.search(r'name\s*:\s*["\']([^"\']+)["\']', context)
            desc_match = re.search(r'description\s*:\s*["\']([^"\']+)["\']', context)
            tools.append({
                'type': 'imperative',
                'name': name_match.group(1) if name_match else '<unknown>',
                'description': desc_match.group(1) if desc_match else None,
                'pattern': pattern,
            })
    return tools


def find_declarative_tools(html: str) -> list[dict]:
    """Find HTML elements with toolname/tooldescription attributes."""
    tools = []
    # Find elements with toolname attribute
    toolname_matches = re.finditer(
        r'<(\w+)\s[^>]*toolname\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE
    )
    for m in toolname_matches:
        element = m.group(1)
        name = m.group(2)
        context = html[m.start():m.start()+1000]
        desc_match = re.search(r'tooldescription\s*=\s*["\']([^"\']+)["\']', context, re.IGNORECASE)
        
        # Find param descriptions within this tool's scope
        params = re.findall(r'toolparamdescription\s*=\s*["\']([^"\']+)["\']', context, re.IGNORECASE)
        
        tools.append({
            'type': 'declarative',
            'element': element,
            'name': name,
            'description': desc_match.group(1) if desc_match else None,
            'params': params,
        })
    return tools


def analyze_forms(html: str) -> list[dict]:
    """Analyze existing HTML forms for WebMCP conversion potential."""
    forms = []
    form_matches = re.finditer(r'<form\s[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
    
    for m in form_matches:
        form_html = m.group(0)
        form_content = m.group(1)
        
        # Extract form attributes
        action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        
        # Check if already WebMCP-enabled
        has_toolname = bool(re.search(r'toolname\s*=', form_html, re.IGNORECASE))
        
        # Find inputs
        inputs = re.findall(
            r'<input\s[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
            form_content, re.IGNORECASE
        )
        
        # Check for sensitive fields
        sensitive = [i for i in inputs if any(s in i.lower() for s in SENSITIVE_FIELDS)]
        
        forms.append({
            'action': action.group(1) if action else None,
            'method': (method.group(1) if method else 'GET').upper(),
            'webmcp_enabled': has_toolname,
            'input_count': len(inputs),
            'inputs': inputs[:10],  # Cap at 10
            'sensitive_fields': sensitive,
            'conversion_effort': 'trivial' if len(inputs) <= 3 else 'moderate' if len(inputs) <= 8 else 'complex',
        })
    
    return forms


def security_audit(html: str, tools: list[dict], forms: list[dict]) -> list[dict]:
    """Audit WebMCP implementation for security issues."""
    findings = []
    
    # Check for sensitive fields exposed via WebMCP
    for form in forms:
        if form['webmcp_enabled'] and form['sensitive_fields']:
            findings.append({
                'severity': 'critical',
                'category': 'data_exposure',
                'message': f"WebMCP-enabled form exposes sensitive fields: {', '.join(form['sensitive_fields'])}",
                'recommendation': 'Remove toolparamdescription from sensitive fields or exclude them from WebMCP tool schema',
            })
    
    # Check for tools without input validation
    for tool in tools:
        if tool['type'] == 'imperative':
            # Look for inputSchema in nearby context
            if tool.get('name') != '<unknown>':
                # Search for the tool definition
                tool_pattern = re.search(
                    rf'registerTool\s*\([^)]*name\s*:\s*["\']' + re.escape(tool['name']),
                    html
                )
                if tool_pattern:
                    context = html[tool_pattern.start():tool_pattern.start()+2000]
                    if 'inputSchema' not in context:
                        findings.append({
                            'severity': 'high',
                            'category': 'missing_validation',
                            'message': f"Tool '{tool['name']}' lacks inputSchema — agents can pass arbitrary parameters",
                            'recommendation': 'Add inputSchema with required fields and type constraints',
                        })
                    if 'required' not in context:
                        findings.append({
                            'severity': 'medium',
                            'category': 'weak_validation',
                            'message': f"Tool '{tool['name']}' has no required fields in schema",
                            'recommendation': 'Add required array to inputSchema',
                        })
    
    # Check for overly permissive tool descriptions
    for tool in tools:
        desc = (tool.get('description') or '').lower()
        risky_words = ['admin', 'delete', 'remove', 'destroy', 'execute', 'run command', 'shell', 'eval']
        matches = [w for w in risky_words if w in desc]
        if matches:
            findings.append({
                'severity': 'high',
                'category': 'dangerous_tool',
                'message': f"Tool '{tool.get('name', '?')}' description contains risky keywords: {', '.join(matches)}",
                'recommendation': 'Ensure proper authorization checks and scope limitations',
            })
    
    # Check for missing Content-Security-Policy considerations
    if tools and 'content-security-policy' not in html.lower():
        findings.append({
            'severity': 'medium',
            'category': 'missing_csp',
            'message': 'No Content-Security-Policy detected — WebMCP tools may be vulnerable to injection',
            'recommendation': 'Add CSP headers to limit script sources and prevent XSS-based tool hijacking',
        })
    
    return findings


def readiness_score(html: str, forms: list[dict]) -> dict:
    """Assess how ready a site is for WebMCP adoption."""
    score = 0
    factors = []
    
    # Has structured forms (easy to convert)
    convertible_forms = [f for f in forms if not f['webmcp_enabled'] and f['input_count'] > 0]
    if convertible_forms:
        score += 20
        factors.append(f"✅ {len(convertible_forms)} forms could be WebMCP-enabled")
    
    # Has JSON-LD or structured data (indicates API mindset)
    if re.search(r'application/ld\+json|schema\.org', html, re.IGNORECASE):
        score += 15
        factors.append("✅ Structured data (JSON-LD/Schema.org) present")
    
    # Has existing API endpoints mentioned
    if re.search(r'/api/|/v[0-9]+/|graphql|rest', html, re.IGNORECASE):
        score += 15
        factors.append("✅ API endpoints detected")
    
    # Already uses WebMCP
    webmcp_forms = [f for f in forms if f['webmcp_enabled']]
    if webmcp_forms:
        score += 30
        factors.append(f"🎯 Already WebMCP-enabled! ({len(webmcp_forms)} tools)")
    
    # Has JavaScript framework (easier imperative integration)
    frameworks = []
    if re.search(r'react|__NEXT_DATA__|_next', html, re.IGNORECASE):
        frameworks.append('React/Next.js')
    if re.search(r'vue|__VUE__|nuxt', html, re.IGNORECASE):
        frameworks.append('Vue/Nuxt')
    if re.search(r'angular|ng-app|ng-controller', html, re.IGNORECASE):
        frameworks.append('Angular')
    if re.search(r'svelte|__sveltekit', html, re.IGNORECASE):
        frameworks.append('Svelte/SvelteKit')
    if frameworks:
        score += 10
        factors.append(f"✅ Modern framework detected: {', '.join(frameworks)}")
    
    # Has semantic HTML (easier declarative integration)
    semantic_tags = len(re.findall(r'<(nav|header|main|article|section|aside|footer)\b', html, re.IGNORECASE))
    if semantic_tags >= 3:
        score += 10
        factors.append(f"✅ Good semantic HTML ({semantic_tags} semantic tags)")
    
    # Penalty: lots of sensitive forms
    sensitive_forms = [f for f in forms if f['sensitive_fields']]
    if sensitive_forms:
        score -= 10
        factors.append(f"⚠️ {len(sensitive_forms)} forms with sensitive fields (need careful handling)")
    
    return {
        'score': max(0, min(100, score)),
        'rating': 'excellent' if score >= 70 else 'good' if score >= 50 else 'moderate' if score >= 30 else 'low',
        'factors': factors,
    }


def load_catalog() -> dict:
    """Load the discovery catalog."""
    if CATALOG_FILE.exists():
        return json.loads(CATALOG_FILE.read_text())
    return {'sites': [], 'last_updated': None, 'total_scans': 0}


def save_catalog(catalog: dict):
    """Save the discovery catalog."""
    catalog['last_updated'] = datetime.now(timezone.utc).isoformat()
    CATALOG_FILE.write_text(json.dumps(catalog, indent=2))


def update_catalog(url: str, result: dict, catalog: dict):
    """Update catalog with scan result."""
    domain = urlparse(url).netloc
    existing = next((s for s in catalog['sites'] if s['domain'] == domain), None)
    
    entry = {
        'domain': domain,
        'url': url,
        'webmcp_tools': result.get('total_tools', 0),
        'readiness_score': result.get('readiness', {}).get('score', 0),
        'last_scanned': datetime.now(timezone.utc).isoformat(),
        'has_imperative': any(t['type'] == 'imperative' for t in result.get('tools', [])),
        'has_declarative': any(t['type'] == 'declarative' for t in result.get('tools', [])),
    }
    
    if existing:
        catalog['sites'] = [s if s['domain'] != domain else entry for s in catalog['sites']]
    else:
        catalog['sites'].append(entry)
    
    catalog['total_scans'] = catalog.get('total_scans', 0) + 1


# ── Commands ───────────────────────────────────────────────────────────────

def cmd_scan(url: str, verbose: bool = False) -> dict:
    """Scan a URL for WebMCP support."""
    print(f"🔍 Scanning {url}...")
    html, status = fetch_page(url)
    
    if not html:
        print(f"❌ Failed to fetch (status: {status})")
        return {'error': f'HTTP {status}', 'url': url}
    
    print(f"📄 Fetched {len(html):,} bytes (HTTP {status})")
    
    # Discover tools (deduplicate by name)
    imperative_raw = find_imperative_tools(html)
    seen_names = set()
    imperative = []
    for t in imperative_raw:
        if t['name'] not in seen_names:
            seen_names.add(t['name'])
            imperative.append(t)
    declarative = find_declarative_tools(html)
    all_tools = imperative + declarative
    forms = analyze_forms(html)
    
    result = {
        'url': url,
        'status': status,
        'tools': all_tools,
        'total_tools': len(all_tools),
        'forms_analyzed': len(forms),
        'forms': forms,
        'readiness': readiness_score(html, forms),
        'scanned_at': datetime.now(timezone.utc).isoformat(),
    }
    
    # Print summary
    if all_tools:
        print(f"\n🎯 Found {len(all_tools)} WebMCP tool(s)!")
        for t in all_tools:
            emoji = '⚡' if t['type'] == 'imperative' else '📋'
            print(f"  {emoji} [{t['type']}] {t.get('name', '?')}: {t.get('description', 'no description')}")
    else:
        print(f"\n📭 No WebMCP tools found")
    
    print(f"\n📊 Readiness: {result['readiness']['score']}/100 ({result['readiness']['rating']})")
    for factor in result['readiness']['factors']:
        print(f"  {factor}")
    
    if forms:
        print(f"\n📝 Forms: {len(forms)} found")
        for i, f in enumerate(forms):
            status_icon = '✅' if f['webmcp_enabled'] else '🔲'
            sensitive = f" ⚠️ sensitive: {', '.join(f['sensitive_fields'])}" if f['sensitive_fields'] else ''
            print(f"  {status_icon} Form {i+1}: {f['input_count']} inputs, effort: {f['conversion_effort']}{sensitive}")
    
    # Update catalog
    catalog = load_catalog()
    update_catalog(url, result, catalog)
    save_catalog(catalog)
    
    return result


def cmd_audit(url: str) -> dict:
    """Security audit a WebMCP implementation."""
    print(f"🔒 Auditing {url}...")
    html, status = fetch_page(url)
    
    if not html:
        print(f"❌ Failed to fetch (status: {status})")
        return {'error': f'HTTP {status}'}
    
    tools = find_imperative_tools(html) + find_declarative_tools(html)
    forms = analyze_forms(html)
    findings = security_audit(html, tools, forms)
    
    result = {
        'url': url,
        'tools_found': len(tools),
        'findings': findings,
        'total_findings': len(findings),
        'critical': len([f for f in findings if f['severity'] == 'critical']),
        'high': len([f for f in findings if f['severity'] == 'high']),
        'medium': len([f for f in findings if f['severity'] == 'medium']),
    }
    
    if findings:
        print(f"\n⚠️ {len(findings)} security finding(s):")
        for f in findings:
            severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡'}.get(f['severity'], '⚪')
            print(f"  {severity_emoji} [{f['severity'].upper()}] {f['message']}")
            print(f"     → {f['recommendation']}")
    else:
        print("\n✅ No security issues found")
    
    return result


def cmd_batch(filepath: str):
    """Scan multiple URLs from a file."""
    urls = Path(filepath).read_text().strip().split('\n')
    urls = [u.strip() for u in urls if u.strip() and not u.startswith('#')]
    
    print(f"📋 Batch scanning {len(urls)} URLs...\n")
    results = []
    
    for url in urls:
        if not url.startswith('http'):
            url = f'https://{url}'
        try:
            r = cmd_scan(url)
            results.append(r)
        except Exception as e:
            print(f"❌ Error scanning {url}: {e}")
            results.append({'url': url, 'error': str(e)})
        print()
    
    # Summary
    webmcp_sites = [r for r in results if r.get('total_tools', 0) > 0]
    print(f"\n{'='*60}")
    print(f"📊 Batch Summary: {len(results)} scanned, {len(webmcp_sites)} with WebMCP tools")
    
    if webmcp_sites:
        print("\nWebMCP-enabled sites:")
        for s in webmcp_sites:
            print(f"  🎯 {s['url']} — {s['total_tools']} tools")


def cmd_catalog():
    """Display the discovery catalog."""
    catalog = load_catalog()
    
    if not catalog['sites']:
        print("📭 Catalog is empty. Run some scans first!")
        return
    
    print(f"📚 WebMCP Discovery Catalog")
    print(f"   Last updated: {catalog.get('last_updated', 'never')}")
    print(f"   Total scans: {catalog.get('total_scans', 0)}")
    print()
    
    # Sort by tools count
    sites = sorted(catalog['sites'], key=lambda s: s.get('webmcp_tools', 0), reverse=True)
    
    for s in sites:
        tools = s.get('webmcp_tools', 0)
        emoji = '🎯' if tools > 0 else '📭'
        apis = []
        if s.get('has_imperative'):
            apis.append('JS')
        if s.get('has_declarative'):
            apis.append('HTML')
        api_str = f" [{'/'.join(apis)}]" if apis else ''
        print(f"  {emoji} {s['domain']}: {tools} tools{api_str} (readiness: {s.get('readiness_score', '?')}/100)")


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='prime_webmcp-scout: WebMCP Discovery & Readiness Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command', help='Command')
    
    scan_p = sub.add_parser('scan', help='Scan a URL for WebMCP support')
    scan_p.add_argument('url', help='URL to scan')
    scan_p.add_argument('-v', '--verbose', action='store_true')
    
    audit_p = sub.add_parser('audit', help='Security audit a WebMCP implementation')
    audit_p.add_argument('url', help='URL to audit')
    
    ready_p = sub.add_parser('readiness', help='Check WebMCP readiness')
    ready_p.add_argument('url', help='URL to check')
    
    batch_p = sub.add_parser('batch', help='Batch scan from URL list')
    batch_p.add_argument('file', help='File with URLs (one per line)')
    
    sub.add_parser('catalog', help='View discovery catalog')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        cmd_scan(args.url, args.verbose)
    elif args.command == 'readiness':
        cmd_scan(args.url)  # readiness is included in scan
    elif args.command == 'audit':
        cmd_audit(args.url)
    elif args.command == 'batch':
        cmd_batch(args.file)
    elif args.command == 'catalog':
        cmd_catalog()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
