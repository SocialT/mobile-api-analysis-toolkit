#!/usr/bin/env python3
"""
APK Endpoint Extractor
Extracts URLs, API endpoints, IP addresses, and potential secrets from APK files.

Usage:
    python apk_endpoint_extractor.py <apk_file> [--json] [--output <file>]
"""

import argparse
import json
import os
import re
import sys
import tempfile
import zipfile
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# --- Patterns ---

URL_PATTERN = re.compile(
    r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
)

IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b'
)

API_PATH_PATTERN = re.compile(
    r'["\'](/(?:api|v[0-9]+|rest|graphql|auth|oauth|login|register|user|admin|webhook)'
    r'[a-zA-Z0-9/_\-.*]*)["\']'
)

# Potential secrets / API keys
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS Secret Key": re.compile(r'(?:aws.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]'),
    "Google API Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "Firebase URL": re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),
    "Firebase API Key": re.compile(r'(?:firebase|FIREBASE).{0,30}[\'"][A-Za-z0-9_\-]{20,}[\'"]'),
    "Generic API Key": re.compile(r'(?:api[_-]?key|apikey|API_KEY)[\'"\s:=]+[\'"]?([A-Za-z0-9_\-]{16,})[\'"]?'),
    "Generic Secret": re.compile(r'(?:secret|SECRET|password|PASSWORD|token|TOKEN)[\'"\s:=]+[\'"]([A-Za-z0-9_\-]{8,})[\'"]'),
    "Bearer Token": re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'),
    "Base64 Encoded (long)": re.compile(r'[A-Za-z0-9+/]{64,}={0,2}'),
}

# Common uninteresting URLs to filter out
IGNORED_URL_PREFIXES = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "http://ns.adobe.com",
    "http://schemas.openxmlformats.org",
    "http://apache.org",
    "http://xml.org",
    "http://json-schema.org",
    "http://xmlns.com",
    "https://www.googleapis.com/auth/",
    "http://www.google.com/schemas",
)

IGNORED_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.ttf', '.otf', '.woff', '.woff2')


def extract_strings_from_binary(data: bytes, min_length: int = 8) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    return [match.decode('ascii', errors='ignore') for match in pattern.findall(data)]


def scan_content(content: str, results: dict) -> None:
    """Scan text content for URLs, IPs, API paths, and secrets."""
    # URLs
    for match in URL_PATTERN.findall(content):
        url = match.rstrip('.,;:\'\")}]>')
        if not url.lower().startswith(IGNORED_URL_PREFIXES) and not any(url.lower().endswith(ext) for ext in IGNORED_EXTENSIONS):
            results["urls"].add(url)

    # IP Addresses
    for match in IP_PATTERN.findall(content):
        octets = match.split(':')[0].split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            if not match.startswith(('0.', '127.', '255.')):
                results["ips"].add(match)

    # API Paths
    for match in API_PATH_PATTERN.findall(content):
        results["api_paths"].add(match)

    # Secrets
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.findall(content):
            value = match if isinstance(match, str) else match.group(0) if hasattr(match, 'group') else str(match)
            if len(value) > 6:
                results["secrets"][name].add(value)


def analyze_apk(apk_path: str) -> dict:
    """Analyze an APK file and extract all findings."""
    results = {
        "urls": set(),
        "ips": set(),
        "api_paths": set(),
        "secrets": defaultdict(set),
        "metadata": {
            "file": os.path.basename(apk_path),
            "size": os.path.getsize(apk_path),
            "files_scanned": 0,
        }
    }

    text_extensions = ('.xml', '.json', '.txt', '.properties', '.cfg', '.conf', '.yml', '.yaml', '.html', '.js', '.smali')
    binary_extensions = ('.dex', '.so')

    with zipfile.ZipFile(apk_path, 'r') as zf:
        for entry in zf.namelist():
            ext = os.path.splitext(entry)[1].lower()

            try:
                data = zf.read(entry)
            except Exception:
                continue

            results["metadata"]["files_scanned"] += 1

            if ext in text_extensions or entry == 'AndroidManifest.xml':
                try:
                    text = data.decode('utf-8', errors='ignore')
                    scan_content(text, results)
                except Exception:
                    pass

            elif ext in binary_extensions:
                strings = extract_strings_from_binary(data)
                for s in strings:
                    scan_content(s, results)

            elif ext == '.arsc':
                strings = extract_strings_from_binary(data, min_length=10)
                for s in strings:
                    scan_content(s, results)

    return results


def results_to_dict(results: dict) -> dict:
    """Convert results sets to serializable dict."""
    return {
        "metadata": results["metadata"],
        "urls": sorted(results["urls"]),
        "ip_addresses": sorted(results["ips"]),
        "api_paths": sorted(results["api_paths"]),
        "potential_secrets": {
            k: sorted(v) for k, v in results["secrets"].items() if v
        }
    }


def print_results_rich(results: dict) -> None:
    """Print results using rich tables."""
    console = Console()
    data = results_to_dict(results)

    console.print(Panel(
        f"[bold]File:[/bold] {data['metadata']['file']}\n"
        f"[bold]Size:[/bold] {data['metadata']['size']:,} bytes\n"
        f"[bold]Files Scanned:[/bold] {data['metadata']['files_scanned']}",
        title="APK Endpoint Extractor",
        border_style="blue"
    ))

    # URLs
    if data["urls"]:
        table = Table(title=f"URLs Found ({len(data['urls'])})", show_lines=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("URL", style="cyan")
        for i, url in enumerate(data["urls"], 1):
            table.add_row(str(i), url)
        console.print(table)

    # IPs
    if data["ip_addresses"]:
        table = Table(title=f"IP Addresses ({len(data['ip_addresses'])})")
        table.add_column("#", style="dim", width=4)
        table.add_column("IP Address", style="yellow")
        for i, ip in enumerate(data["ip_addresses"], 1):
            table.add_row(str(i), ip)
        console.print(table)

    # API Paths
    if data["api_paths"]:
        table = Table(title=f"API Paths ({len(data['api_paths'])})")
        table.add_column("#", style="dim", width=4)
        table.add_column("Path", style="green")
        for i, path in enumerate(data["api_paths"], 1):
            table.add_row(str(i), path)
        console.print(table)

    # Secrets
    if data["potential_secrets"]:
        table = Table(title="Potential Secrets / Keys", show_lines=True)
        table.add_column("Type", style="red bold")
        table.add_column("Value", style="red")
        for secret_type, values in data["potential_secrets"].items():
            for val in values:
                display = val[:60] + "..." if len(val) > 60 else val
                table.add_row(secret_type, display)
        console.print(table)

    if not any([data["urls"], data["ip_addresses"], data["api_paths"], data["potential_secrets"]]):
        console.print("[yellow]No endpoints or secrets found.[/yellow]")


def print_results_plain(results: dict) -> None:
    """Print results as plain text."""
    data = results_to_dict(results)

    print(f"\n{'='*60}")
    print(f"  APK Endpoint Extractor")
    print(f"{'='*60}")
    print(f"  File: {data['metadata']['file']}")
    print(f"  Size: {data['metadata']['size']:,} bytes")
    print(f"  Files Scanned: {data['metadata']['files_scanned']}")
    print(f"{'='*60}\n")

    if data["urls"]:
        print(f"--- URLs Found ({len(data['urls'])}) ---")
        for i, url in enumerate(data["urls"], 1):
            print(f"  {i:3}. {url}")
        print()

    if data["ip_addresses"]:
        print(f"--- IP Addresses ({len(data['ip_addresses'])}) ---")
        for i, ip in enumerate(data["ip_addresses"], 1):
            print(f"  {i:3}. {ip}")
        print()

    if data["api_paths"]:
        print(f"--- API Paths ({len(data['api_paths'])}) ---")
        for i, path in enumerate(data["api_paths"], 1):
            print(f"  {i:3}. {path}")
        print()

    if data["potential_secrets"]:
        print("--- Potential Secrets / Keys ---")
        for secret_type, values in data["potential_secrets"].items():
            for val in values:
                display = val[:60] + "..." if len(val) > 60 else val
                print(f"  [{secret_type}] {display}")
        print()

    if not any([data["urls"], data["ip_addresses"], data["api_paths"], data["potential_secrets"]]):
        print("  No endpoints or secrets found.")


def main():
    parser = argparse.ArgumentParser(
        description="Extract URLs, API endpoints, IP addresses, and secrets from APK files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python apk_endpoint_extractor.py app.apk
  python apk_endpoint_extractor.py app.apk --json
  python apk_endpoint_extractor.py app.apk --json --output report.json
        """
    )
    parser.add_argument("apk", help="Path to the APK file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--output", "-o", help="Save results to file")
    args = parser.parse_args()

    if not os.path.isfile(args.apk):
        print(f"Error: File not found: {args.apk}", file=sys.stderr)
        sys.exit(1)

    if not zipfile.is_zipfile(args.apk):
        print(f"Error: Not a valid APK/ZIP file: {args.apk}", file=sys.stderr)
        sys.exit(1)

    results = analyze_apk(args.apk)

    if args.json:
        output = json.dumps(results_to_dict(results), indent=2)
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
                json.dump(results_to_dict(results), f, indent=2)
            print(f"\nResults also saved to {args.output}")


if __name__ == "__main__":
    main()
