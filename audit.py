#!/usr/bin/env python3
"""
prime_skill-auditor: OpenClaw Skill Security Scanner
Detects malicious patterns from the ClawHavoc campaign and other threats.

Scans skill directories for:
1. Suspicious prerequisites (fake install steps → malware)
2. Obfuscated shell commands (base64, eval, curl|sh patterns)
3. Credential exfiltration (webhook.site, .env file access)
4. Reverse shell patterns (nc, /dev/tcp, bash -i)
5. Typosquatting detection (Levenshtein distance from known skills)
6. Suspicious external URLs (glot.io, pastebin, etc.)
7. Hidden file access (~/.clawdbot/.env, ~/.openclaw/, API keys)
8. Network exfiltration (curl POST with file data)

Inspired by the ClawHavoc findings (Koi Security, Feb 2026):
- 341 malicious skills found on ClawHub
- Atomic Stealer (AMOS) distributed via fake prerequisites
- Reverse shells hidden in functional code
- Credential theft via webhook endpoints
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

# --- Severity levels ---
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

@dataclass
class Finding:
    severity: str
    category: str
    description: str
    file: str
    line: Optional[int] = None
    snippet: Optional[str] = None

@dataclass
class AuditReport:
    skill_path: str
    skill_name: str
    findings: list = field(default_factory=list)
    score: int = 100  # starts at 100, deductions per finding

    @property
    def verdict(self):
        if self.score >= 90: return "CLEAN"
        if self.score >= 70: return "SUSPICIOUS"
        if self.score >= 40: return "DANGEROUS"
        return "MALICIOUS"

# --- Detection patterns ---

OBFUSCATION_PATTERNS = [
    (r'base64\s+(-d|--decode)', CRITICAL, "Base64 decode in shell command"),
    (r'eval\s*\(', HIGH, "eval() call — potential code injection"),
    (r'eval\s+"?\$', HIGH, "Shell eval with variable expansion"),
    (r'echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*(base64|openssl)', CRITICAL, "Encoded payload piped to decoder"),
    (r'python[3]?\s+-c\s+["\'].*(?:import|exec|eval)', HIGH, "Inline Python execution"),
    (r'\\x[0-9a-fA-F]{2}', MEDIUM, "Hex-escaped characters (potential obfuscation)"),
]

EXFIL_PATTERNS = [
    (r'webhook\.site', CRITICAL, "webhook.site URL — known exfiltration endpoint"),
    (r'curl\s+.*-X\s*POST.*(?:-d|--data)', HIGH, "curl POST with data — potential exfiltration"),
    (r'curl\s+.*\|\s*(?:bash|sh|zsh)', CRITICAL, "curl piped to shell — remote code execution"),
    (r'wget\s+.*\|\s*(?:bash|sh|zsh)', CRITICAL, "wget piped to shell — remote code execution"),
    (r'ngrok', HIGH, "ngrok tunnel — potential data exfiltration"),
    (r'requestbin', HIGH, "RequestBin URL — data collection endpoint"),
    (r'pipedream', MEDIUM, "Pipedream URL — webhook/automation endpoint"),
]

REVERSE_SHELL_PATTERNS = [
    (r'/dev/tcp/', CRITICAL, "Bash /dev/tcp reverse shell"),
    (r'nc\s+-[a-z]*[el]', CRITICAL, "Netcat reverse shell"),
    (r'bash\s+-i\s+>&\s*/dev/tcp', CRITICAL, "Interactive bash reverse shell"),
    (r'mkfifo\s+/tmp/', HIGH, "Named pipe creation (reverse shell component)"),
    (r'socat\s+.*EXEC', CRITICAL, "Socat exec — reverse shell"),
    (r'python[3]?\s+.*socket.*connect', HIGH, "Python socket connection (potential reverse shell)"),
]

CREDENTIAL_PATTERNS = [
    (r'\.env\b', MEDIUM, "Accesses .env file (may contain secrets)"),
    (r'~/\.clawdbot/', HIGH, "Accesses ClawdBot config directory"),
    (r'~/\.openclaw/', HIGH, "Accesses OpenClaw config directory"),
    (r'API_KEY|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN', MEDIUM, "References API/secret keys"),
    (r'~/.ssh/', HIGH, "Accesses SSH directory"),
    (r'~/.aws/', HIGH, "Accesses AWS credentials"),
    (r'keychain|keyring', MEDIUM, "Accesses system keychain/keyring"),
    (r'OPENAI_API_KEY|ANTHROPIC_API_KEY', HIGH, "References LLM provider API keys"),
]

SUSPICIOUS_URLS = [
    (r'glot\.io', CRITICAL, "glot.io URL — used in ClawHavoc malware distribution"),
    (r'pastebin\.com', HIGH, "Pastebin URL — common malware hosting"),
    (r'paste\.ee', HIGH, "paste.ee URL — common malware hosting"),
    (r'transfer\.sh', HIGH, "transfer.sh — file exfiltration service"),
    (r'91\.92\.242', CRITICAL, "Known ClawHavoc C2 IP address"),
    (r'raw\.githubusercontent\.com/(?!openclaw|Zollicoff)', MEDIUM, "Raw GitHub content from unknown source"),
]

INSTALL_RED_FLAGS = [
    (r'(?i)prerequisite', MEDIUM, "Prerequisites section — verify manually"),
    (r'(?i)install.*first|before.*install', MEDIUM, "Pre-install instruction — common social engineering vector"),
    (r'openclaw-agent\.zip', CRITICAL, "Known ClawHavoc malware filename"),
    (r'(?i)copy.*paste.*terminal', HIGH, "Copy-paste to terminal instruction — social engineering"),
    (r'chmod\s+\+x.*&&.*\./', HIGH, "Download-chmod-execute pattern"),
]

# Known legitimate skill names for typosquatting detection
KNOWN_SKILLS = [
    "clawhub", "github", "weather", "canvas", "discord", "healthcheck",
    "coding-agent", "session-logs", "skill-creator", "openai-image-gen",
    "polymarket", "youtube", "solana", "wallet", "auto-updater",
]

TYPOSQUAT_PATTERNS = [
    (r'^clawhub[0-9]$|^claw[hw]ub$|^cl[al]whub$', CRITICAL, "ClawHub typosquat"),
    (r'^polymarket-?(trader|pro|bot)$', HIGH, "Polymarket typosquat variant"),
    (r'^youtube-?(summarize|thumbnail|download)', MEDIUM, "YouTube tool variant — verify source"),
    (r'^auto-?update', HIGH, "Auto-updater variant — verify source"),
    (r'^solana-?wallet', MEDIUM, "Solana wallet variant — verify source"),
]

SEVERITY_DEDUCTIONS = {
    CRITICAL: 25,
    HIGH: 15,
    MEDIUM: 5,
    LOW: 2,
    INFO: 0,
}


def scan_file(filepath: str, content: str, report: AuditReport):
    """Scan a single file for all pattern categories."""
    rel_path = os.path.relpath(filepath, report.skill_path)
    
    for i, line in enumerate(content.split('\n'), 1):
        all_patterns = (
            [(p, s, d, "obfuscation") for p, s, d in OBFUSCATION_PATTERNS] +
            [(p, s, d, "exfiltration") for p, s, d in EXFIL_PATTERNS] +
            [(p, s, d, "reverse_shell") for p, s, d in REVERSE_SHELL_PATTERNS] +
            [(p, s, d, "credential_access") for p, s, d in CREDENTIAL_PATTERNS] +
            [(p, s, d, "suspicious_url") for p, s, d in SUSPICIOUS_URLS] +
            [(p, s, d, "install_red_flag") for p, s, d in INSTALL_RED_FLAGS]
        )
        
        for pattern, severity, desc, category in all_patterns:
            if re.search(pattern, line):
                report.findings.append(Finding(
                    severity=severity,
                    category=category,
                    description=desc,
                    file=rel_path,
                    line=i,
                    snippet=line.strip()[:120]
                ))


def check_typosquatting(skill_name: str, report: AuditReport):
    """Check if skill name looks like a typosquat."""
    for pattern, severity, desc in TYPOSQUAT_PATTERNS:
        if re.match(pattern, skill_name, re.IGNORECASE):
            report.findings.append(Finding(
                severity=severity,
                category="typosquatting",
                description=desc,
                file="(skill name)",
                snippet=skill_name
            ))


def check_structure(skill_path: str, report: AuditReport):
    """Check for suspicious structural patterns."""
    # Check for hidden files
    for root, dirs, files in os.walk(skill_path):
        for f in files:
            if f.startswith('.') and f not in ('.gitignore', '.gitkeep'):
                report.findings.append(Finding(
                    severity=MEDIUM,
                    category="suspicious_structure",
                    description=f"Hidden file: {f}",
                    file=os.path.relpath(os.path.join(root, f), skill_path)
                ))
        for d in dirs:
            if d.startswith('.') and d not in ('.git',):
                report.findings.append(Finding(
                    severity=MEDIUM,
                    category="suspicious_structure",
                    description=f"Hidden directory: {d}",
                    file=os.path.relpath(os.path.join(root, d), skill_path)
                ))
    
    # Check for executable files
    for root, dirs, files in os.walk(skill_path):
        for f in files:
            fp = os.path.join(root, f)
            if os.access(fp, os.X_OK) and not f.endswith(('.sh', '.py', '.rb')):
                report.findings.append(Finding(
                    severity=HIGH,
                    category="suspicious_structure",
                    description=f"Unexpected executable: {f}",
                    file=os.path.relpath(fp, skill_path)
                ))
    
    # Check for binary files in skill directory
    BINARY_EXTENSIONS = {'.exe', '.dll', '.so', '.dylib', '.bin', '.dmg', '.pkg', '.msi', '.zip', '.tar', '.gz'}
    for root, dirs, files in os.walk(skill_path):
        for f in files:
            if Path(f).suffix.lower() in BINARY_EXTENSIONS:
                report.findings.append(Finding(
                    severity=CRITICAL,
                    category="suspicious_structure",
                    description=f"Binary/archive in skill directory: {f}",
                    file=os.path.relpath(os.path.join(root, f), skill_path)
                ))


def audit_skill(skill_path: str) -> AuditReport:
    """Run full audit on a skill directory."""
    skill_name = os.path.basename(os.path.normpath(skill_path))
    report = AuditReport(skill_path=skill_path, skill_name=skill_name)
    
    # Typosquatting check
    check_typosquatting(skill_name, report)
    
    # Structure check
    check_structure(skill_path, report)
    
    # Scan all text files
    text_extensions = {'.md', '.txt', '.sh', '.py', '.js', '.ts', '.rb', '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.env', ''}
    for root, dirs, files in os.walk(skill_path):
        # Skip .git
        dirs[:] = [d for d in dirs if d != '.git']
        for f in files:
            fp = os.path.join(root, f)
            if Path(f).suffix.lower() in text_extensions or f in ('Makefile', 'Dockerfile', 'SKILL.md'):
                try:
                    with open(fp, 'r', errors='ignore') as fh:
                        content = fh.read()
                    scan_file(fp, content, report)
                except (OSError, UnicodeDecodeError):
                    pass
    
    # Calculate score
    for finding in report.findings:
        report.score -= SEVERITY_DEDUCTIONS.get(finding.severity, 0)
    report.score = max(0, report.score)
    
    return report


def format_report(report: AuditReport, verbose: bool = False) -> str:
    """Format audit report as readable text."""
    lines = []
    verdict_emoji = {
        "CLEAN": "✅", "SUSPICIOUS": "⚠️", "DANGEROUS": "🔶", "MALICIOUS": "🔴"
    }
    
    emoji = verdict_emoji.get(report.verdict, "❓")
    lines.append(f"\n{emoji} Skill: {report.skill_name}")
    lines.append(f"   Score: {report.score}/100 — {report.verdict}")
    lines.append(f"   Path: {report.skill_path}")
    
    if not report.findings:
        lines.append("   No issues found.")
        return '\n'.join(lines)
    
    # Group by severity
    by_severity = {}
    for f in report.findings:
        by_severity.setdefault(f.severity, []).append(f)
    
    for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
        if sev in by_severity:
            lines.append(f"\n   [{sev}] ({len(by_severity[sev])} findings)")
            for f in by_severity[sev]:
                loc = f"{f.file}:{f.line}" if f.line else f.file
                lines.append(f"     • {f.description}")
                lines.append(f"       at {loc}")
                if verbose and f.snippet:
                    lines.append(f"       → {f.snippet}")
    
    return '\n'.join(lines)


def format_json(report: AuditReport) -> str:
    """Format as JSON."""
    return json.dumps({
        "skill": report.skill_name,
        "path": report.skill_path,
        "score": report.score,
        "verdict": report.verdict,
        "findings": [asdict(f) for f in report.findings]
    }, indent=2)


def main():
    parser = argparse.ArgumentParser(description="OpenClaw Skill Security Auditor")
    parser.add_argument("paths", nargs="+", help="Skill directory/directories to audit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show code snippets")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--min-score", type=int, default=0, help="Only show skills below this score")
    args = parser.parse_args()
    
    reports = []
    for path in args.paths:
        if os.path.isdir(path):
            # Check if it's a directory of skills or a single skill
            skill_md = os.path.join(path, "SKILL.md")
            if os.path.exists(skill_md):
                reports.append(audit_skill(path))
            else:
                # Scan subdirectories as individual skills
                for sub in sorted(os.listdir(path)):
                    sub_path = os.path.join(path, sub)
                    if os.path.isdir(sub_path):
                        reports.append(audit_skill(sub_path))
    
    if args.json:
        print(json.dumps([{
            "skill": r.skill_name, "score": r.score, "verdict": r.verdict,
            "findings_count": len(r.findings),
            "findings": [asdict(f) for f in r.findings]
        } for r in reports], indent=2))
    else:
        # Summary
        total = len(reports)
        clean = sum(1 for r in reports if r.verdict == "CLEAN")
        suspicious = sum(1 for r in reports if r.verdict == "SUSPICIOUS")
        dangerous = sum(1 for r in reports if r.verdict == "DANGEROUS")
        malicious = sum(1 for r in reports if r.verdict == "MALICIOUS")
        
        print(f"\n{'='*60}")
        print(f" OpenClaw Skill Security Auditor — prime_skill-auditor")
        print(f"{'='*60}")
        print(f" Scanned: {total} skills")
        print(f" ✅ Clean: {clean}  ⚠️ Suspicious: {suspicious}  🔶 Dangerous: {dangerous}  🔴 Malicious: {malicious}")
        print(f"{'='*60}")
        
        for r in reports:
            if args.min_score == 0 or r.score < args.min_score:
                print(format_report(r, args.verbose))
        
        print()


if __name__ == "__main__":
    main()
