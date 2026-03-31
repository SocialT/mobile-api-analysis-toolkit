#!/usr/bin/env python3
"""
Secret Scanner
Scans directories (decompiled APKs, source code, configs) for hardcoded secrets,
API keys, tokens, credentials, and sensitive data patterns.

Optimized for mobile app analysis — includes patterns for Firebase, AWS, Google,
Stripe, and many other common services.

Usage:
    python secret_scanner.py <directory> [--json] [--output <file>] [--severity <level>]
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# --- Secret Patterns ---
# Each pattern has: regex, severity (critical/high/medium/low), and description

SECRET_PATTERNS = [
    # --- Cloud Provider Keys ---
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'(AKIA[0-9A-Z]{16})'),
        "severity": "critical",
        "description": "AWS IAM access key — can provide access to AWS services",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.IGNORECASE),
        "severity": "critical",
        "description": "AWS secret key — full AWS account access when paired with access key",
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r'(AIza[0-9A-Za-z\-_]{35})'),
        "severity": "high",
        "description": "Google API key — may expose Maps, Firebase, or other Google services",
    },
    {
        "name": "Google OAuth Client Secret",
        "pattern": re.compile(r'(?:client_secret|google_secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{24})["\']?', re.IGNORECASE),
        "severity": "high",
        "description": "Google OAuth client secret — can impersonate the app's OAuth flow",
    },
    {
        "name": "Google Cloud Service Account",
        "pattern": re.compile(r'("type"\s*:\s*"service_account")'),
        "severity": "critical",
        "description": "Google Cloud service account JSON — full GCP access",
    },

    # --- Firebase ---
    {
        "name": "Firebase Database URL",
        "pattern": re.compile(r'(https://[a-z0-9-]+\.firebaseio\.com)'),
        "severity": "high",
        "description": "Firebase Realtime Database URL — may allow unauthorized read/write",
    },
    {
        "name": "Firebase Cloud Messaging Key",
        "pattern": re.compile(r'(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})'),
        "severity": "high",
        "description": "Firebase Cloud Messaging server key — can send push notifications",
    },
    {
        "name": "Firebase Config",
        "pattern": re.compile(r'(firebase[_-]?(?:api[_-]?key|project[_-]?id|app[_-]?id))\s*[=:]\s*["\']?([A-Za-z0-9_\-:.]+)["\']?', re.IGNORECASE),
        "severity": "medium",
        "description": "Firebase configuration value — part of app's Firebase setup",
    },

    # --- Payment / Financial ---
    {
        "name": "Stripe Secret Key",
        "pattern": re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'),
        "severity": "critical",
        "description": "Stripe live secret key — can process real payments and access account",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": re.compile(r'(pk_live_[0-9a-zA-Z]{24,})'),
        "severity": "medium",
        "description": "Stripe publishable key — client-side key, limited but still sensitive",
    },
    {
        "name": "PayPal Client ID/Secret",
        "pattern": re.compile(r'(?:paypal[_-]?(?:client|secret))[_-]?(?:id|key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE),
        "severity": "high",
        "description": "PayPal API credential — payment processing access",
    },

    # --- Communication / Social ---
    {
        "name": "Slack Webhook URL",
        "pattern": re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)'),
        "severity": "high",
        "description": "Slack webhook URL — can post messages to a Slack channel",
    },
    {
        "name": "Slack Bot/User Token",
        "pattern": re.compile(r'(xox[bpors]-[0-9]+-[0-9]+-[A-Za-z0-9]+)'),
        "severity": "critical",
        "description": "Slack API token — can read messages, channels, and user data",
    },
    {
        "name": "Twilio Account SID",
        "pattern": re.compile(r'(AC[a-f0-9]{32})'),
        "severity": "high",
        "description": "Twilio Account SID — SMS/voice service identifier",
    },
    {
        "name": "Twilio Auth Token",
        "pattern": re.compile(r'(?:twilio[_-]?(?:auth[_-]?token|secret))\s*[=:]\s*["\']?([a-f0-9]{32})["\']?', re.IGNORECASE),
        "severity": "critical",
        "description": "Twilio auth token — can send SMS, make calls, access account",
    },
    {
        "name": "SendGrid API Key",
        "pattern": re.compile(r'(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})'),
        "severity": "high",
        "description": "SendGrid API key — can send emails from the account",
    },

    # --- Version Control / CI ---
    {
        "name": "GitHub Token",
        "pattern": re.compile(r'(ghp_[A-Za-z0-9_]{36,})'),
        "severity": "critical",
        "description": "GitHub personal access token — repo access, possibly admin",
    },
    {
        "name": "GitHub OAuth App Secret",
        "pattern": re.compile(r'(gho_[A-Za-z0-9_]{36,})'),
        "severity": "high",
        "description": "GitHub OAuth app token",
    },
    {
        "name": "GitLab Token",
        "pattern": re.compile(r'(glpat-[A-Za-z0-9_\-]{20,})'),
        "severity": "critical",
        "description": "GitLab personal access token — repo and API access",
    },

    # --- Generic Patterns ---
    {
        "name": "Private Key (PEM)",
        "pattern": re.compile(r'(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)'),
        "severity": "critical",
        "description": "Private cryptographic key — TLS, signing, or encryption key exposure",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+)'),
        "severity": "high",
        "description": "JSON Web Token — may contain user identity, roles, and session data",
    },
    {
        "name": "Bearer Token (Hardcoded)",
        "pattern": re.compile(r'["\']Bearer\s+(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["\']'),
        "severity": "critical",
        "description": "Hardcoded Bearer authentication token",
    },
    {
        "name": "Generic API Key Assignment",
        "pattern": re.compile(r'(?:api[_-]?key|apikey|api_secret|app[_-]?key|app[_-]?secret|client[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.IGNORECASE),
        "severity": "high",
        "description": "Hardcoded API key or secret — service access credentials",
    },
    {
        "name": "Generic Password Assignment",
        "pattern": re.compile(r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{6,})["\']', re.IGNORECASE),
        "severity": "high",
        "description": "Hardcoded password — credential exposure",
    },
    {
        "name": "Generic Secret Assignment",
        "pattern": re.compile(r'(?:secret|secret_key|encryption_key|signing_key|auth_token)\s*[=:]\s*["\']([A-Za-z0-9_\-/+=]{8,})["\']', re.IGNORECASE),
        "severity": "high",
        "description": "Hardcoded secret or key — could be encryption, signing, or auth credential",
    },
    {
        "name": "Database Connection String",
        "pattern": re.compile(r'(?:jdbc:|mongodb(?:\+srv)?://|mysql://|postgres(?:ql)?://|redis://)[^\s"\'<>]+', re.IGNORECASE),
        "severity": "critical",
        "description": "Database connection string — may include credentials and host info",
    },
    {
        "name": "IP Address with Port",
        "pattern": re.compile(r'["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})["\']'),
        "severity": "medium",
        "description": "Hardcoded IP address with port — internal infrastructure exposure",
    },
    {
        "name": "Internal/Private URL",
        "pattern": re.compile(r'https?://(?:10\.\d+|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+[^\s"\'<>]*'),
        "severity": "medium",
        "description": "Internal network URL — reveals private infrastructure",
    },
    {
        "name": "Hardcoded Encryption IV/Nonce",
        "pattern": re.compile(r'(?:iv|nonce|initialization_vector)\s*[=:]\s*["\']([A-Fa-f0-9]{16,})["\']', re.IGNORECASE),
        "severity": "high",
        "description": "Hardcoded initialization vector — weakens encryption if reused",
    },
]

# Files to skip
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico',
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    '.mp3', '.mp4', '.avi', '.mov', '.wav', '.ogg',
    '.zip', '.tar', '.gz', '.bz2', '.rar', '.7z',
    '.apk', '.dex', '.so', '.dll', '.exe', '.class',
    '.pyc', '.pyo', '.o', '.obj',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
}

SKIP_DIRS = {
    '.git', '.svn', '.hg', 'node_modules', '__pycache__',
    '.gradle', 'build', '.idea', '.vscode',
    'original', 'META-INF',
}

# Common false positive values to ignore
FALSE_POSITIVE_VALUES = {
    "true", "false", "null", "none", "undefined",
    "changeme", "password", "secret", "example",
    "your_api_key", "your-api-key", "YOUR_API_KEY",
    "xxx", "yyy", "zzz", "test", "demo", "sample",
    "TODO", "FIXME", "PLACEHOLDER",
}


def should_scan_file(filepath: str) -> bool:
    """Check if a file should be scanned."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return False

    # Skip very large files (> 10MB)
    try:
        if os.path.getsize(filepath) > 10 * 1024 * 1024:
            return False
    except OSError:
        return False

    return True


def scan_file(filepath: str) -> list[dict]:
    """Scan a single file for secrets."""
    findings = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, PermissionError):
        return findings

    lines = content.split('\n')

    for pattern_info in SECRET_PATTERNS:
        for match in pattern_info["pattern"].finditer(content):
            value = match.group(1) if match.lastindex else match.group(0)

            # Skip false positives
            if value.lower().strip('"\'') in FALSE_POSITIVE_VALUES:
                continue
            if len(value) < 6:
                continue

            # Find line number
            start = match.start()
            line_num = content[:start].count('\n') + 1

            # Get the surrounding line for context
            if 0 < line_num <= len(lines):
                context_line = lines[line_num - 1].strip()
                if len(context_line) > 120:
                    context_line = context_line[:120] + "..."
            else:
                context_line = ""

            findings.append({
                "type": pattern_info["name"],
                "severity": pattern_info["severity"],
                "description": pattern_info["description"],
                "file": filepath,
                "line": line_num,
                "value": value[:80] + ("..." if len(value) > 80 else ""),
                "context": context_line,
            })

    return findings


def scan_directory(directory: str) -> dict:
    """Scan an entire directory tree for secrets."""
    all_findings = []
    files_scanned = 0
    files_skipped = 0

    for root, dirs, files in os.walk(directory):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)

            if not should_scan_file(filepath):
                files_skipped += 1
                continue

            files_scanned += 1
            findings = scan_file(filepath)
            all_findings.extend(findings)

    # Deduplicate by (type, value, file)
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f["type"], f["value"], f["file"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique_findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    # Categorize
    by_severity = defaultdict(list)
    for f in unique_findings:
        by_severity[f["severity"]].append(f)

    return {
        "metadata": {
            "directory": os.path.abspath(directory),
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "total_findings": len(unique_findings),
        },
        "findings": unique_findings,
        "by_severity": dict(by_severity),
        "summary": {
            "critical": len(by_severity.get("critical", [])),
            "high": len(by_severity.get("high", [])),
            "medium": len(by_severity.get("medium", [])),
            "low": len(by_severity.get("low", [])),
        }
    }


def print_results_rich(results: dict) -> None:
    """Print results using rich."""
    console = Console()
    meta = results["metadata"]
    summary = results["summary"]

    total_issues = meta["total_findings"]
    risk_text = "[red bold]SECRETS FOUND[/red bold]" if total_issues > 0 else "[green]CLEAN[/green]"

    console.print(Panel(
        f"[bold]Directory:[/bold] {meta['directory']}\n"
        f"[bold]Files Scanned:[/bold] {meta['files_scanned']} ({meta['files_skipped']} skipped)\n"
        f"[bold]Total Findings:[/bold] {total_issues}\n"
        f"[bold]Status:[/bold] {risk_text}\n\n"
        f"[red]Critical: {summary['critical']}[/red]  |  "
        f"[yellow]High: {summary['high']}[/yellow]  |  "
        f"[cyan]Medium: {summary['medium']}[/cyan]  |  "
        f"[dim]Low: {summary['low']}[/dim]",
        title="Secret Scanner",
        border_style="blue"
    ))

    severity_styles = {
        "critical": ("red bold", "CRITICAL"),
        "high": ("red", "HIGH"),
        "medium": ("yellow", "MEDIUM"),
        "low": ("cyan", "LOW"),
    }

    for severity in ["critical", "high", "medium", "low"]:
        findings = results["by_severity"].get(severity, [])
        if not findings:
            continue

        style, label = severity_styles[severity]
        table = Table(title=f"{label} Findings ({len(findings)})", show_lines=True)
        table.add_column("Type", style=style, min_width=20)
        table.add_column("Value", style="dim", min_width=25)
        table.add_column("File:Line", style="cyan", min_width=25)
        table.add_column("Description", min_width=30)

        for f in findings:
            rel_path = os.path.relpath(f["file"], results["metadata"]["directory"])
            table.add_row(
                f["type"],
                f["value"],
                f"{rel_path}:{f['line']}",
                f["description"],
            )
        console.print(table)

    if total_issues == 0:
        console.print("[green]No secrets or sensitive data patterns detected.[/green]")


def print_results_plain(results: dict) -> None:
    """Print results as plain text."""
    meta = results["metadata"]
    summary = results["summary"]

    print(f"\n{'='*60}")
    print(f"  Secret Scanner")
    print(f"{'='*60}")
    print(f"  Directory: {meta['directory']}")
    print(f"  Files Scanned: {meta['files_scanned']} ({meta['files_skipped']} skipped)")
    print(f"  Total Findings: {meta['total_findings']}")
    print(f"  Critical: {summary['critical']} | High: {summary['high']} | Medium: {summary['medium']} | Low: {summary['low']}")
    print(f"{'='*60}\n")

    for severity in ["critical", "high", "medium", "low"]:
        findings = results["by_severity"].get(severity, [])
        if not findings:
            continue

        print(f"--- {severity.upper()} ({len(findings)}) ---")
        for f in findings:
            rel_path = os.path.relpath(f["file"], results["metadata"]["directory"])
            print(f"  [{f['type']}]")
            print(f"    Value: {f['value']}")
            print(f"    File:  {rel_path}:{f['line']}")
            print(f"    Info:  {f['description']}")
            if f["context"]:
                print(f"    Line:  {f['context']}")
            print()

    if meta["total_findings"] == 0:
        print("  No secrets or sensitive data patterns detected.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Scan directories for hardcoded secrets, API keys, tokens, and credentials. "
                    "Optimized for mobile app analysis (decompiled APKs, source code).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python secret_scanner.py ./decompiled_apk/
  python secret_scanner.py ./src/ --severity high
  python secret_scanner.py ./project/ --json --output secrets_report.json

Typical workflow:
  1. Decompile APK:  jadx -d ./decompiled/ target.apk
  2. Scan for secrets: python secret_scanner.py ./decompiled/
        """
    )
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--output", "-o", help="Save results to file")
    parser.add_argument("--severity", "-s", choices=["critical", "high", "medium", "low"],
                        help="Minimum severity to report (default: all)")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found: {args.directory}", file=sys.stderr)
        sys.exit(1)

    results = scan_directory(args.directory)

    # Filter by severity if specified
    if args.severity:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_level = severity_order[args.severity]
        results["findings"] = [
            f for f in results["findings"]
            if severity_order.get(f["severity"], 99) <= min_level
        ]
        results["by_severity"] = {
            k: v for k, v in results["by_severity"].items()
            if severity_order.get(k, 99) <= min_level
        }
        results["metadata"]["total_findings"] = len(results["findings"])

    if args.json:
        output = json.dumps(results, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Results saved to {args.output}")
        else:
            print(output)
    else:
        if RICH_AVAILABLE:
            print_results_rich(results)
        else:
            print_results_plain(results)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults also saved to {args.output}")


if __name__ == "__main__":
    main()
