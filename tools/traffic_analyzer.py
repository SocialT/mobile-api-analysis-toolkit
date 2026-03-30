#!/usr/bin/env python3
"""
Traffic Analyzer
Parses HAR (HTTP Archive) files captured from mitmproxy, Burp Suite, or browser DevTools.
Categorizes API calls, extracts endpoints, detects sensitive data patterns.

Usage:
    python traffic_analyzer.py <har_file> [--json] [--output <file>] [--filter <domain>]
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import urlparse, parse_qs

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# --- Sensitive Data Patterns ---
SENSITIVE_PATTERNS = {
    "Email Address": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "Phone Number": re.compile(r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'),
    "Credit Card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    "JWT Token": re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    "API Key (header)": re.compile(r'(?:x-api-key|api[_-]?key|apikey)["\s:]+["\']?([A-Za-z0-9_\-]{16,})', re.IGNORECASE),
    "Bearer Token": re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'),
    "AWS Key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "Private IP": re.compile(r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'),
}


def parse_har(har_path: str) -> dict:
    """Parse a HAR file and return the data."""
    with open(har_path, 'r', encoding='utf-8', errors='ignore') as f:
        return json.load(f)


def analyze_entry(entry: dict) -> dict:
    """Analyze a single HAR entry."""
    request = entry.get("request", {})
    response = entry.get("response", {})

    url = request.get("url", "")
    parsed = urlparse(url)
    method = request.get("method", "UNKNOWN")
    status = response.get("status", 0)

    # Extract headers
    req_headers = {h["name"].lower(): h["value"] for h in request.get("headers", [])}
    resp_headers = {h["name"].lower(): h["value"] for h in response.get("headers", [])}

    # Extract query parameters
    query_params = parse_qs(parsed.query)

    # Request body
    post_data = request.get("postData", {})
    req_body = post_data.get("text", "") if post_data else ""
    req_mime = post_data.get("mimeType", "") if post_data else ""

    # Response body
    resp_content = response.get("content", {})
    resp_body = resp_content.get("text", "") if resp_content else ""
    resp_mime = resp_content.get("mimeType", "") if resp_content else ""
    resp_size = resp_content.get("size", 0) if resp_content else 0

    # Timing
    time_ms = entry.get("time", 0)

    return {
        "url": url,
        "method": method,
        "status": status,
        "host": parsed.hostname or "",
        "path": parsed.path or "/",
        "query_params": query_params,
        "req_headers": req_headers,
        "resp_headers": resp_headers,
        "req_body": req_body,
        "req_mime": req_mime,
        "resp_body": resp_body,
        "resp_mime": resp_mime,
        "resp_size": resp_size,
        "time_ms": round(time_ms, 2),
    }


def find_sensitive_data(entries: list[dict]) -> dict:
    """Scan all entries for sensitive data patterns."""
    findings = defaultdict(list)

    for entry in entries:
        searchable = " ".join([
            entry["url"],
            " ".join(f"{k}: {v}" for k, v in entry["req_headers"].items()),
            entry["req_body"],
            entry["resp_body"],
        ])

        for name, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(searchable)
            for match in matches:
                value = match if isinstance(match, str) else str(match)
                if len(value) > 4:
                    findings[name].append({
                        "value": value[:80],
                        "endpoint": f"{entry['method']} {entry['path']}",
                        "host": entry["host"],
                    })

    return dict(findings)


def analyze_har(har_path: str, domain_filter: str = None) -> dict:
    """Full analysis of a HAR file."""
    har_data = parse_har(har_path)
    raw_entries = har_data.get("log", {}).get("entries", [])

    entries = []
    for raw in raw_entries:
        analyzed = analyze_entry(raw)
        if domain_filter and domain_filter.lower() not in analyzed["host"].lower():
            continue
        entries.append(analyzed)

    # Aggregate stats
    hosts = Counter(e["host"] for e in entries)
    methods = Counter(e["method"] for e in entries)
    status_codes = Counter(e["status"] for e in entries)
    content_types = Counter(e["resp_mime"].split(";")[0].strip() for e in entries if e["resp_mime"])

    # Unique endpoints
    endpoints = defaultdict(set)
    for e in entries:
        endpoints[e["host"]].add(f"{e['method']} {e['path']}")

    # Auth headers
    auth_info = []
    for e in entries:
        for header_name in ("authorization", "x-api-key", "x-auth-token", "cookie"):
            if header_name in e["req_headers"]:
                auth_info.append({
                    "header": header_name,
                    "value": e["req_headers"][header_name][:80],
                    "endpoint": f"{e['method']} {e['host']}{e['path']}",
                })

    # Sensitive data scan
    sensitive = find_sensitive_data(entries)

    # Slowest requests
    sorted_by_time = sorted(entries, key=lambda x: x["time_ms"], reverse=True)[:10]

    return {
        "metadata": {
            "file": os.path.basename(har_path),
            "total_requests": len(entries),
            "filtered_domain": domain_filter,
        },
        "hosts": dict(hosts.most_common()),
        "methods": dict(methods),
        "status_codes": {str(k): v for k, v in status_codes.most_common()},
        "content_types": dict(content_types.most_common(10)),
        "endpoints": {host: sorted(paths) for host, paths in endpoints.items()},
        "auth_headers": auth_info[:20],
        "sensitive_data": sensitive,
        "slowest_requests": [
            {"endpoint": f"{e['method']} {e['host']}{e['path']}", "time_ms": e["time_ms"], "status": e["status"]}
            for e in sorted_by_time
        ],
    }


def print_results_rich(results: dict) -> None:
    """Print results using rich."""
    console = Console()

    # Metadata
    meta = results["metadata"]
    console.print(Panel(
        f"[bold]File:[/bold] {meta['file']}\n"
        f"[bold]Total Requests:[/bold] {meta['total_requests']}\n"
        f"[bold]Domain Filter:[/bold] {meta['filtered_domain'] or 'None'}",
        title="Traffic Analyzer",
        border_style="blue"
    ))

    # Hosts
    if results["hosts"]:
        table = Table(title="Hosts")
        table.add_column("Host", style="cyan")
        table.add_column("Requests", style="green", justify="right")
        for host, count in results["hosts"].items():
            table.add_row(host, str(count))
        console.print(table)

    # Methods & Status Codes side by side
    if results["methods"]:
        table = Table(title="HTTP Methods")
        table.add_column("Method", style="yellow")
        table.add_column("Count", justify="right")
        for method, count in results["methods"].items():
            table.add_row(method, str(count))
        console.print(table)

    if results["status_codes"]:
        table = Table(title="Status Codes")
        table.add_column("Code", style="magenta")
        table.add_column("Count", justify="right")
        for code, count in results["status_codes"].items():
            style = "green" if code.startswith("2") else "yellow" if code.startswith("3") else "red"
            table.add_row(f"[{style}]{code}[/{style}]", str(count))
        console.print(table)

    # Endpoints tree
    if results["endpoints"]:
        tree = Tree("[bold]API Endpoints[/bold]")
        for host, paths in results["endpoints"].items():
            host_branch = tree.add(f"[cyan]{host}[/cyan] ({len(paths)} endpoints)")
            for path in paths[:30]:
                host_branch.add(f"[dim]{path}[/dim]")
            if len(paths) > 30:
                host_branch.add(f"[dim]... and {len(paths) - 30} more[/dim]")
        console.print(tree)

    # Auth headers
    if results["auth_headers"]:
        table = Table(title="Authentication Headers Found", show_lines=True)
        table.add_column("Header", style="red bold")
        table.add_column("Value (truncated)", style="red")
        table.add_column("Endpoint", style="dim")
        seen = set()
        for auth in results["auth_headers"]:
            key = (auth["header"], auth["value"][:30])
            if key not in seen:
                seen.add(key)
                table.add_row(auth["header"], auth["value"], auth["endpoint"])
        console.print(table)

    # Sensitive data
    if results["sensitive_data"]:
        table = Table(title="Sensitive Data Detected", show_lines=True)
        table.add_column("Type", style="red bold")
        table.add_column("Value", style="red")
        table.add_column("Found In", style="dim")
        for data_type, items in results["sensitive_data"].items():
            seen_vals = set()
            for item in items[:5]:
                if item["value"] not in seen_vals:
                    seen_vals.add(item["value"])
                    table.add_row(data_type, item["value"], item["endpoint"])
        console.print(table)

    # Slowest requests
    if results["slowest_requests"]:
        table = Table(title="Slowest Requests (Top 10)")
        table.add_column("Endpoint", style="cyan")
        table.add_column("Time (ms)", style="yellow", justify="right")
        table.add_column("Status", justify="right")
        for req in results["slowest_requests"]:
            status_style = "green" if 200 <= req["status"] < 300 else "red"
            table.add_row(
                req["endpoint"],
                f"{req['time_ms']:.0f}",
                f"[{status_style}]{req['status']}[/{status_style}]"
            )
        console.print(table)


def print_results_plain(results: dict) -> None:
    """Print results as plain text."""
    meta = results["metadata"]
    print(f"\n{'='*60}")
    print(f"  Traffic Analyzer")
    print(f"{'='*60}")
    print(f"  File: {meta['file']}")
    print(f"  Total Requests: {meta['total_requests']}")
    print(f"  Domain Filter: {meta['filtered_domain'] or 'None'}")
    print(f"{'='*60}\n")

    if results["hosts"]:
        print("--- Hosts ---")
        for host, count in results["hosts"].items():
            print(f"  {host}: {count} requests")
        print()

    if results["methods"]:
        print("--- HTTP Methods ---")
        for method, count in results["methods"].items():
            print(f"  {method}: {count}")
        print()

    if results["status_codes"]:
        print("--- Status Codes ---")
        for code, count in results["status_codes"].items():
            print(f"  {code}: {count}")
        print()

    if results["endpoints"]:
        print("--- API Endpoints ---")
        for host, paths in results["endpoints"].items():
            print(f"\n  [{host}] ({len(paths)} endpoints)")
            for path in paths[:30]:
                print(f"    {path}")
            if len(paths) > 30:
                print(f"    ... and {len(paths) - 30} more")
        print()

    if results["auth_headers"]:
        print("--- Authentication Headers ---")
        seen = set()
        for auth in results["auth_headers"]:
            key = (auth["header"], auth["value"][:30])
            if key not in seen:
                seen.add(key)
                print(f"  [{auth['header']}] {auth['value']}")
                print(f"    -> {auth['endpoint']}")
        print()

    if results["sensitive_data"]:
        print("--- Sensitive Data Detected ---")
        for data_type, items in results["sensitive_data"].items():
            seen_vals = set()
            for item in items[:5]:
                if item["value"] not in seen_vals:
                    seen_vals.add(item["value"])
                    print(f"  [{data_type}] {item['value']}")
                    print(f"    -> {item['endpoint']}")
        print()

    if results["slowest_requests"]:
        print("--- Slowest Requests (Top 10) ---")
        for req in results["slowest_requests"]:
            print(f"  {req['time_ms']:>8.0f}ms  [{req['status']}] {req['endpoint']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze HTTP traffic from HAR files. Extracts endpoints, auth tokens, and sensitive data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python traffic_analyzer.py capture.har
  python traffic_analyzer.py capture.har --filter api.example.com
  python traffic_analyzer.py capture.har --json --output report.json

Generating HAR files:
  mitmproxy:   mitmdump -w dump.har --set hardump=./capture.har
  Browser:     DevTools > Network > Export HAR
  Burp Suite:  Save Items as HAR
        """
    )
    parser.add_argument("har", help="Path to the HAR file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--output", "-o", help="Save results to file")
    parser.add_argument("--filter", "-f", help="Filter by domain (e.g., api.example.com)")
    args = parser.parse_args()

    if not os.path.isfile(args.har):
        print(f"Error: File not found: {args.har}", file=sys.stderr)
        sys.exit(1)

    try:
        results = analyze_har(args.har, domain_filter=args.filter)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in HAR file: {args.har}", file=sys.stderr)
        sys.exit(1)

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
