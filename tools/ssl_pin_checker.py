#!/usr/bin/env python3
"""
SSL Pinning Checker
Analyzes APK files to detect SSL/TLS certificate pinning implementations.
Identifies pinning methods, assesses bypass difficulty, and provides recommendations.

Usage:
    python ssl_pin_checker.py <apk_file> [--json] [--output <file>]
"""

import argparse
import json
import os
import re
import sys
import zipfile
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# --- Pinning Detection Patterns ---

PINNING_SIGNATURES = [
    # --- OkHttp CertificatePinner ---
    {
        "name": "OkHttp3 CertificatePinner",
        "category": "Network Library",
        "patterns": [
            re.compile(r'okhttp3[./]CertificatePinner'),
            re.compile(r'CertificatePinner\$Builder'),
            re.compile(r'CertificatePinner\.check'),
            re.compile(r'\.certificatePinner\('),
        ],
        "pin_value_pattern": re.compile(r'sha256/([A-Za-z0-9+/=]{43,44})'),
        "bypass_difficulty": "Easy",
        "bypass_method": "Frida hook on CertificatePinner.check() or Objection",
        "description": "OkHttp's built-in certificate pinner — checks SHA-256 hashes of certificates in the chain",
    },

    # --- Retrofit with OkHttp ---
    {
        "name": "Retrofit + OkHttp Pinning",
        "category": "Network Library",
        "patterns": [
            re.compile(r'retrofit2[./]'),
            re.compile(r'OkHttpClient\$Builder.*certificatePinner'),
        ],
        "pin_value_pattern": None,
        "bypass_difficulty": "Easy",
        "bypass_method": "Same as OkHttp — hook CertificatePinner.check()",
        "description": "Retrofit uses OkHttp under the hood — pinning is configured on the OkHttpClient",
    },

    # --- Android Network Security Config ---
    {
        "name": "Network Security Config (XML)",
        "category": "Android Framework",
        "patterns": [
            re.compile(r'network_security_config'),
            re.compile(r'networkSecurityConfig'),
            re.compile(r'<pin-set'),
            re.compile(r'<pin\s+digest="SHA-256"'),
        ],
        "pin_value_pattern": re.compile(r'<pin\s+digest="SHA-256">([A-Za-z0-9+/=]{43,44})</pin>'),
        "bypass_difficulty": "Easy",
        "bypass_method": "Patch network_security_config.xml and rebuild APK, or use Frida",
        "description": "Android's declarative pinning via res/xml/network_security_config.xml (Android 7+)",
    },

    # --- Custom TrustManager ---
    {
        "name": "Custom TrustManager",
        "category": "Java SSL/TLS",
        "patterns": [
            re.compile(r'X509TrustManager'),
            re.compile(r'checkServerTrusted'),
            re.compile(r'TrustManagerFactory'),
            re.compile(r'getAcceptedIssuers'),
        ],
        "pin_value_pattern": None,
        "bypass_difficulty": "Medium",
        "bypass_method": "Frida hook on checkServerTrusted() to make it accept all certs",
        "description": "Custom X509TrustManager implementation — validates server certificate manually",
    },

    # --- SSLPinning / Custom SSL Socket ---
    {
        "name": "Custom SSLSocketFactory",
        "category": "Java SSL/TLS",
        "patterns": [
            re.compile(r'SSLSocketFactory'),
            re.compile(r'SSLContext\.init'),
            re.compile(r'HttpsURLConnection\.setDefaultSSLSocketFactory'),
            re.compile(r'HostnameVerifier'),
            re.compile(r'setHostnameVerifier'),
        ],
        "pin_value_pattern": None,
        "bypass_difficulty": "Medium",
        "bypass_method": "Frida hook on SSLContext.init() with custom TrustManager",
        "description": "Custom SSL socket factory with hostname verification — manual TLS configuration",
    },

    # --- Certificate loaded from assets/raw ---
    {
        "name": "Embedded Certificate (Asset/Raw)",
        "category": "Certificate Bundle",
        "patterns": [
            re.compile(r'\.(?:cer|crt|pem|der|bks|p12|pfx)["\'>\s]', re.IGNORECASE),
            re.compile(r'KeyStore\.getInstance\(["\']BKS["\']'),
            re.compile(r'KeyStore\.getInstance\(["\']PKCS12["\']'),
            re.compile(r'CertificateFactory\.getInstance'),
            re.compile(r'loadTrustMaterial'),
        ],
        "pin_value_pattern": None,
        "bypass_difficulty": "Medium",
        "bypass_method": "Replace certificate in assets + rebuild, or Frida hook on KeyStore.load()",
        "description": "Certificate file embedded in app resources — loaded at runtime for pinning",
    },

    # --- Conscrypt / BoringSSL ---
    {
        "name": "Conscrypt TrustManager",
        "category": "Android Framework",
        "patterns": [
            re.compile(r'com\.android\.org\.conscrypt'),
            re.compile(r'TrustManagerImpl\.verifyChain'),
            re.compile(r'ConscryptFileDescriptorSocket'),
        ],
        "pin_value_pattern": None,
        "bypass_difficulty": "Easy-Medium",
        "bypass_method": "Frida hook on TrustManagerImpl.verifyChain()",
        "description": "Android's default TLS implementation (Conscrypt/BoringSSL) — system-level verification",
    },

    # --- TrustKit ---
    {
        "name": "TrustKit",
        "category": "Third-party Library",
        "patterns": [
            re.compile(r'com\.datatheorem\.android\.trustkit'),
            re.compile(r'TrustKit\.initializeWithNetworkSecurityConfiguration'),
            re.compile(r'TrustKit\.getInstance'),
        ],
        "pin_value_pattern": None,
        "bypass_difficulty": "Easy",
        "bypass_method": "Frida hook on TrustKit initialization or use Objection",
        "description": "TrustKit library — provides reporting and enforcement of certificate pinning",
    },

    # --- Native-level pinning ---
    {
        "name": "Native SSL Pinning (.so)",
        "category": "Native Code",
        "patterns": [
            re.compile(r'SSL_CTX_set_verify'),
            re.compile(r'SSL_set_verify'),
            re.compile(r'X509_verify_cert'),
            re.compile(r'SSL_CTX_load_verify_locations'),
            re.compile(r'mbedtls_ssl_conf_ca_chain'),
            re.compile(r'mbedtls_x509_crt_verify'),
        ],
        "pin_value_pattern": None,
        "bypass_difficulty": "Hard",
        "bypass_method": "Frida Interceptor.attach on native SSL verification functions, or binary patching",
        "description": "SSL pinning implemented in native C/C++ code — requires native-level hooking",
    },

    # --- Certificate hash comparison ---
    {
        "name": "Manual Certificate Hash Check",
        "category": "Custom Implementation",
        "patterns": [
            re.compile(r'MessageDigest\.getInstance\(["\']SHA-256["\']\)'),
            re.compile(r'getEncoded\(\)'),
            re.compile(r'\.getPublicKey\(\)'),
            re.compile(r'SubjectPublicKeyInfo'),
        ],
        "pin_value_pattern": re.compile(r'["\']([A-Fa-f0-9]{64})["\']'),
        "bypass_difficulty": "Medium",
        "bypass_method": "Frida hook on MessageDigest or the comparison method to always return true",
        "description": "Custom implementation that manually hashes and compares certificate public key",
    },

    # --- Flutter/Dart specific ---
    {
        "name": "Flutter SSL Pinning",
        "category": "Framework-specific",
        "patterns": [
            re.compile(r'SecurityContext'),
            re.compile(r'setTrustedCertificatesBytes'),
            re.compile(r'BadCertificateCallback'),
            re.compile(r'HandshakeException'),
        ],
        "pin_value_pattern": None,
        "bypass_difficulty": "Medium-Hard",
        "bypass_method": "Frida hook on Dart SSL functions or patch libflutter.so",
        "description": "Flutter/Dart SSL pinning — uses its own SSL stack independent of Android",
    },

    # --- React Native specific ---
    {
        "name": "React Native SSL Pinning",
        "category": "Framework-specific",
        "patterns": [
            re.compile(r'react-native-ssl-pinning'),
            re.compile(r'RNSslPinning'),
            re.compile(r'TrustKitReactNative'),
        ],
        "pin_value_pattern": None,
        "bypass_difficulty": "Easy-Medium",
        "bypass_method": "Frida hook on the native bridge module or underlying OkHttp pinner",
        "description": "React Native SSL pinning plugin — typically wraps OkHttp or TrustKit",
    },
]

# --- Anti-tampering / Integrity Checks (related to pinning defense) ---
INTEGRITY_SIGNATURES = [
    {
        "name": "APK Signature Verification",
        "patterns": [
            re.compile(r'PackageManager\.GET_SIGNATURES'),
            re.compile(r'GET_SIGNING_CERTIFICATES'),
            re.compile(r'PackageInfo.*signatures'),
            re.compile(r'signature.*hashCode'),
        ],
        "description": "App verifies its own APK signature — detects repackaging/patching",
    },
    {
        "name": "Root Detection",
        "patterns": [
            re.compile(r'isRooted|isDeviceRooted|checkRoot'),
            re.compile(r'com\.scottyab\.rootbeer'),
            re.compile(r'/system/bin/su|/system/xbin/su'),
            re.compile(r'com\.topjohnwu\.magisk'),
        ],
        "description": "Root detection — may block app on rooted devices where Frida runs",
    },
    {
        "name": "Frida Detection",
        "patterns": [
            re.compile(r'frida', re.IGNORECASE),
            re.compile(r'27042'),  # Default Frida port
            re.compile(r'gum-js-loop|gmain'),
            re.compile(r'LIBFRIDA'),
        ],
        "description": "Frida detection — app actively checks for Frida instrumentation",
    },
    {
        "name": "Xposed Detection",
        "patterns": [
            re.compile(r'de\.robv\.android\.xposed'),
            re.compile(r'XposedBridge'),
            re.compile(r'XposedHelpers'),
        ],
        "description": "Xposed framework detection — blocks hooking via Xposed",
    },
    {
        "name": "Debugger Detection",
        "patterns": [
            re.compile(r'android\.os\.Debug\.isDebuggerConnected'),
            re.compile(r'isDebuggerConnected'),
            re.compile(r'android:debuggable'),
            re.compile(r'ptrace'),
        ],
        "description": "Debugger detection — prevents dynamic analysis via debuggers",
    },
]


def extract_strings_from_binary(data: bytes, min_length: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    return [m.decode('ascii', errors='ignore') for m in pattern.findall(data)]


def analyze_apk(apk_path: str) -> dict:
    """Analyze APK for SSL pinning implementations."""
    results = {
        "pinning_detected": [],
        "integrity_checks": [],
        "pin_hashes": [],
        "certificate_files": [],
        "files_analyzed": 0,
        "metadata": {
            "file": os.path.basename(apk_path),
            "size": os.path.getsize(apk_path),
        }
    }

    text_extensions = {'.xml', '.json', '.txt', '.properties', '.smali', '.java', '.kt', '.js', '.html'}
    binary_extensions = {'.dex', '.so'}
    cert_extensions = {'.cer', '.crt', '.pem', '.der', '.bks', '.p12', '.pfx', '.jks'}

    pinning_matches = defaultdict(set)  # signature_name -> set of matched pattern strings
    integrity_matches = defaultdict(set)

    with zipfile.ZipFile(apk_path, 'r') as zf:
        for entry in zf.namelist():
            ext = os.path.splitext(entry)[1].lower()
            results["files_analyzed"] += 1

            # Check for embedded certificate files
            if ext in cert_extensions:
                results["certificate_files"].append(entry)

            # Read file content
            try:
                data = zf.read(entry)
            except Exception:
                continue

            # Get text content
            if ext in text_extensions:
                text = data.decode('utf-8', errors='ignore')
            elif ext in binary_extensions:
                strings = extract_strings_from_binary(data)
                text = '\n'.join(strings)
            elif entry.lower() == 'androidmanifest.xml' or ext == '.arsc':
                text = data.decode('utf-8', errors='ignore')
                strings = extract_strings_from_binary(data)
                text += '\n' + '\n'.join(strings)
            else:
                continue

            # Check pinning signatures
            for sig in PINNING_SIGNATURES:
                for pattern in sig["patterns"]:
                    matches = pattern.findall(text)
                    if matches:
                        for m in matches:
                            pinning_matches[sig["name"]].add(m if isinstance(m, str) else str(m))

                # Extract pin hash values
                if sig.get("pin_value_pattern"):
                    for match in sig["pin_value_pattern"].finditer(text):
                        value = match.group(1) if match.lastindex else match.group(0)
                        results["pin_hashes"].append({
                            "hash": value,
                            "source": sig["name"],
                            "file": entry,
                        })

            # Check integrity signatures
            for sig in INTEGRITY_SIGNATURES:
                for pattern in sig["patterns"]:
                    matches = pattern.findall(text)
                    if matches:
                        for m in matches:
                            integrity_matches[sig["name"]].add(m if isinstance(m, str) else str(m))

    # Build results
    for sig in PINNING_SIGNATURES:
        if sig["name"] in pinning_matches:
            results["pinning_detected"].append({
                "name": sig["name"],
                "category": sig["category"],
                "bypass_difficulty": sig["bypass_difficulty"],
                "bypass_method": sig["bypass_method"],
                "description": sig["description"],
                "evidence_count": len(pinning_matches[sig["name"]]),
                "evidence_samples": sorted(list(pinning_matches[sig["name"]]))[:5],
            })

    for sig in INTEGRITY_SIGNATURES:
        if sig["name"] in integrity_matches:
            results["integrity_checks"].append({
                "name": sig["name"],
                "description": sig["description"],
                "evidence_count": len(integrity_matches[sig["name"]]),
                "evidence_samples": sorted(list(integrity_matches[sig["name"]]))[:5],
            })

    # Deduplicate pin hashes
    seen_hashes = set()
    unique_hashes = []
    for h in results["pin_hashes"]:
        if h["hash"] not in seen_hashes:
            seen_hashes.add(h["hash"])
            unique_hashes.append(h)
    results["pin_hashes"] = unique_hashes

    # Overall assessment
    results["assessment"] = _assess_pinning(results)

    return results


def _assess_pinning(results: dict) -> dict:
    """Generate overall pinning assessment."""
    detections = results["pinning_detected"]
    integrity = results["integrity_checks"]

    if not detections:
        return {
            "pinning_level": "None",
            "overall_difficulty": "N/A",
            "summary": "No SSL pinning detected. Standard proxy setup with CA certificate should work.",
            "recommendation": "Set up mitmproxy with system CA certificate. No bypass needed.",
        }

    # Find hardest bypass
    difficulty_order = {"Easy": 1, "Easy-Medium": 2, "Medium": 3, "Medium-Hard": 4, "Hard": 5}
    max_difficulty = max(
        difficulty_order.get(d["bypass_difficulty"], 0) for d in detections
    )

    has_native = any(d["category"] == "Native Code" for d in detections)
    has_frida_detection = any(i["name"] == "Frida Detection" for i in integrity)
    has_root_detection = any(i["name"] == "Root Detection" for i in integrity)

    difficulty_labels = {1: "Easy", 2: "Easy-Medium", 3: "Medium", 4: "Medium-Hard", 5: "Hard"}
    overall = difficulty_labels.get(max_difficulty, "Unknown")

    if has_native and has_frida_detection:
        overall = "Hard"
        pinning_level = "Strong"
    elif has_native or has_frida_detection:
        overall = "Medium-Hard"
        pinning_level = "Moderate-Strong"
    elif len(detections) > 2:
        pinning_level = "Moderate (layered)"
    else:
        pinning_level = "Basic"

    methods = [d["name"] for d in detections]
    summary = f"Detected {len(detections)} pinning method(s): {', '.join(methods)}."

    if has_frida_detection:
        summary += " App also detects Frida — use renamed frida-server or gadget."
    if has_root_detection:
        summary += " Root detection present — combine with root bypass."

    recommendations = []
    if not has_native:
        recommendations.append("Try Objection first: `objection -g <package> explore` → `android sslpinning disable`")
    recommendations.append("Use the Frida SSL pinning bypass script from this toolkit")
    if has_frida_detection:
        recommendations.append("Rename frida-server binary and use a non-default port")
    if has_native:
        recommendations.append("Analyze native .so in Ghidra to find and patch SSL verification functions")

    return {
        "pinning_level": pinning_level,
        "overall_difficulty": overall,
        "summary": summary,
        "recommendations": recommendations,
    }


def print_results_rich(results: dict) -> None:
    """Print results using rich."""
    console = Console()
    assessment = results["assessment"]

    # Difficulty color
    diff = assessment["overall_difficulty"]
    diff_color = "green" if diff in ("N/A", "Easy") else "yellow" if "Medium" in diff else "red"

    # Level color
    level = assessment["pinning_level"]
    level_color = "green" if level == "None" else "yellow" if "Basic" in level else "red"

    console.print(Panel(
        f"[bold]File:[/bold] {results['metadata']['file']}\n"
        f"[bold]Files Analyzed:[/bold] {results['files_analyzed']}\n"
        f"[bold]Pinning Level:[/bold] [{level_color}]{level}[/{level_color}]\n"
        f"[bold]Bypass Difficulty:[/bold] [{diff_color}]{diff}[/{diff_color}]\n\n"
        f"[bold]Assessment:[/bold] {assessment['summary']}",
        title="SSL Pinning Checker",
        border_style="blue"
    ))

    # Pinning detections
    if results["pinning_detected"]:
        table = Table(title=f"Pinning Implementations Detected ({len(results['pinning_detected'])})", show_lines=True)
        table.add_column("Method", style="cyan", min_width=25)
        table.add_column("Category", style="yellow", width=18)
        table.add_column("Bypass Difficulty", width=16)
        table.add_column("Bypass Method", min_width=35)

        for det in results["pinning_detected"]:
            diff = det["bypass_difficulty"]
            diff_style = "green" if diff == "Easy" else "yellow" if "Medium" in diff else "red"
            table.add_row(
                det["name"],
                det["category"],
                f"[{diff_style}]{diff}[/{diff_style}]",
                det["bypass_method"],
            )
        console.print(table)

    # Pin hashes found
    if results["pin_hashes"]:
        table = Table(title=f"Certificate Pin Hashes Found ({len(results['pin_hashes'])})")
        table.add_column("Hash (SHA-256)", style="red", min_width=44)
        table.add_column("Source", style="cyan")
        table.add_column("File", style="dim")
        for h in results["pin_hashes"]:
            table.add_row(h["hash"], h["source"], h["file"])
        console.print(table)

    # Embedded certificates
    if results["certificate_files"]:
        table = Table(title=f"Embedded Certificate Files ({len(results['certificate_files'])})")
        table.add_column("File Path", style="yellow")
        for cert in results["certificate_files"]:
            table.add_row(cert)
        console.print(table)

    # Integrity checks
    if results["integrity_checks"]:
        table = Table(title=f"Anti-Tampering / Integrity Checks ({len(results['integrity_checks'])})", show_lines=True)
        table.add_column("Check", style="red", min_width=25)
        table.add_column("Description", min_width=40)
        table.add_column("Evidence", style="dim", width=8, justify="right")
        for check in results["integrity_checks"]:
            table.add_row(check["name"], check["description"], str(check["evidence_count"]))
        console.print(table)

    # Recommendations
    if "recommendations" in assessment:
        tree = Tree("[bold]Recommended Bypass Strategy[/bold]")
        for i, rec in enumerate(assessment["recommendations"], 1):
            tree.add(f"[green]{i}.[/green] {rec}")
        console.print(tree)
    elif assessment["pinning_level"] == "None":
        console.print("[green]No pinning bypass needed — standard proxy with CA cert should work.[/green]")


def print_results_plain(results: dict) -> None:
    """Print results as plain text."""
    assessment = results["assessment"]

    print(f"\n{'='*60}")
    print(f"  SSL Pinning Checker")
    print(f"{'='*60}")
    print(f"  File: {results['metadata']['file']}")
    print(f"  Files Analyzed: {results['files_analyzed']}")
    print(f"  Pinning Level: {assessment['pinning_level']}")
    print(f"  Bypass Difficulty: {assessment['overall_difficulty']}")
    print(f"  Assessment: {assessment['summary']}")
    print(f"{'='*60}\n")

    if results["pinning_detected"]:
        print(f"--- Pinning Implementations ({len(results['pinning_detected'])}) ---")
        for det in results["pinning_detected"]:
            print(f"  [{det['bypass_difficulty']}] {det['name']} ({det['category']})")
            print(f"    Bypass: {det['bypass_method']}")
            print(f"    Info:   {det['description']}")
        print()

    if results["pin_hashes"]:
        print(f"--- Pin Hashes ({len(results['pin_hashes'])}) ---")
        for h in results["pin_hashes"]:
            print(f"  {h['hash']} ({h['source']})")
        print()

    if results["certificate_files"]:
        print(f"--- Embedded Certificates ({len(results['certificate_files'])}) ---")
        for cert in results["certificate_files"]:
            print(f"  {cert}")
        print()

    if results["integrity_checks"]:
        print(f"--- Anti-Tampering Checks ({len(results['integrity_checks'])}) ---")
        for check in results["integrity_checks"]:
            print(f"  {check['name']}: {check['description']}")
        print()

    if "recommendations" in assessment:
        print("--- Recommended Bypass Strategy ---")
        for i, rec in enumerate(assessment["recommendations"], 1):
            print(f"  {i}. {rec}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Detect SSL/TLS certificate pinning implementations in Android APK files. "
                    "Assesses bypass difficulty and provides recommendations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssl_pin_checker.py app.apk
  python ssl_pin_checker.py app.apk --json
  python ssl_pin_checker.py app.apk --json --output pinning_report.json
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
