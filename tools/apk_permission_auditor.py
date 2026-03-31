#!/usr/bin/env python3
"""
APK Permission Auditor
Extracts and audits Android permissions from APK files.
Classifies each permission by protection level and highlights security risks.

Usage:
    python apk_permission_auditor.py <apk_file> [--json] [--output <file>]
"""

import argparse
import json
import os
import re
import sys
import zipfile
from xml.etree import ElementTree

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Android namespace used in manifest XML
ANDROID_NS = "http://schemas.android.com/apk/res/android"

# --- Permission Database ---
# Protection levels: dangerous, normal, signature, internal
# Risk: critical, high, medium, low, info

PERMISSION_DB = {
    # --- Dangerous Permissions (require runtime approval) ---
    "android.permission.READ_CALENDAR": {
        "level": "dangerous",
        "risk": "medium",
        "group": "Calendar",
        "description": "Read calendar events and details",
        "concern": "Can access user's schedule, meetings, and personal appointments",
    },
    "android.permission.WRITE_CALENDAR": {
        "level": "dangerous",
        "risk": "medium",
        "group": "Calendar",
        "description": "Add or modify calendar events",
        "concern": "Can inject events or modify existing appointments",
    },
    "android.permission.CAMERA": {
        "level": "dangerous",
        "risk": "high",
        "group": "Camera",
        "description": "Access the device camera",
        "concern": "Can capture photos/video without user awareness if misused",
    },
    "android.permission.READ_CONTACTS": {
        "level": "dangerous",
        "risk": "high",
        "group": "Contacts",
        "description": "Read the user's contacts",
        "concern": "Access to full contact list — names, numbers, emails, photos",
    },
    "android.permission.WRITE_CONTACTS": {
        "level": "dangerous",
        "risk": "high",
        "group": "Contacts",
        "description": "Modify or add contacts",
        "concern": "Can alter contact information or inject fake contacts",
    },
    "android.permission.GET_ACCOUNTS": {
        "level": "dangerous",
        "risk": "medium",
        "group": "Contacts",
        "description": "Access list of accounts on the device",
        "concern": "Reveals which services the user has accounts with",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "level": "dangerous",
        "risk": "critical",
        "group": "Location",
        "description": "Access precise GPS location",
        "concern": "Tracks user's exact location — serious privacy risk if exfiltrated",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "level": "dangerous",
        "risk": "high",
        "group": "Location",
        "description": "Access approximate location (network-based)",
        "concern": "Approximate location tracking via cell towers/WiFi",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "level": "dangerous",
        "risk": "critical",
        "group": "Location",
        "description": "Access location in the background",
        "concern": "Continuous location tracking even when app is not in use",
    },
    "android.permission.RECORD_AUDIO": {
        "level": "dangerous",
        "risk": "critical",
        "group": "Microphone",
        "description": "Record audio with the microphone",
        "concern": "Can eavesdrop on conversations — severe privacy risk",
    },
    "android.permission.READ_PHONE_STATE": {
        "level": "dangerous",
        "risk": "high",
        "group": "Phone",
        "description": "Read phone state (number, IMEI, call state)",
        "concern": "Access to device identifiers and call status — tracking risk",
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "level": "dangerous",
        "risk": "high",
        "group": "Phone",
        "description": "Read the device's phone number(s)",
        "concern": "Reveals user's phone number — PII exposure",
    },
    "android.permission.CALL_PHONE": {
        "level": "dangerous",
        "risk": "high",
        "group": "Phone",
        "description": "Initiate phone calls without user interaction",
        "concern": "Can make calls to premium numbers — financial risk",
    },
    "android.permission.READ_CALL_LOG": {
        "level": "dangerous",
        "risk": "critical",
        "group": "Phone",
        "description": "Read call history",
        "concern": "Full call history with contacts, times, and durations",
    },
    "android.permission.WRITE_CALL_LOG": {
        "level": "dangerous",
        "risk": "high",
        "group": "Phone",
        "description": "Write to call log",
        "concern": "Can modify or delete call history entries",
    },
    "android.permission.SEND_SMS": {
        "level": "dangerous",
        "risk": "critical",
        "group": "SMS",
        "description": "Send SMS messages",
        "concern": "Can send SMS to premium numbers — financial risk, or exfil data via SMS",
    },
    "android.permission.RECEIVE_SMS": {
        "level": "dangerous",
        "risk": "critical",
        "group": "SMS",
        "description": "Receive and process SMS messages",
        "concern": "Can intercept SMS — including 2FA codes and OTPs",
    },
    "android.permission.READ_SMS": {
        "level": "dangerous",
        "risk": "critical",
        "group": "SMS",
        "description": "Read SMS messages",
        "concern": "Access to all SMS messages — OTPs, personal conversations",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "level": "dangerous",
        "risk": "high",
        "group": "Storage",
        "description": "Read files from external storage",
        "concern": "Access to photos, downloads, documents on shared storage",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "level": "dangerous",
        "risk": "high",
        "group": "Storage",
        "description": "Write files to external storage",
        "concern": "Can modify or plant files on shared storage",
    },
    "android.permission.READ_MEDIA_IMAGES": {
        "level": "dangerous",
        "risk": "high",
        "group": "Storage",
        "description": "Read image files from shared storage",
        "concern": "Access to user's photos",
    },
    "android.permission.READ_MEDIA_VIDEO": {
        "level": "dangerous",
        "risk": "high",
        "group": "Storage",
        "description": "Read video files from shared storage",
        "concern": "Access to user's videos",
    },
    "android.permission.READ_MEDIA_AUDIO": {
        "level": "dangerous",
        "risk": "medium",
        "group": "Storage",
        "description": "Read audio files from shared storage",
        "concern": "Access to user's audio recordings and music",
    },
    "android.permission.BODY_SENSORS": {
        "level": "dangerous",
        "risk": "high",
        "group": "Sensors",
        "description": "Access body sensors (e.g., heart rate)",
        "concern": "Access to health/biometric data — sensitive PII",
    },
    "android.permission.ACTIVITY_RECOGNITION": {
        "level": "dangerous",
        "risk": "medium",
        "group": "Sensors",
        "description": "Recognize physical activity (walking, running, etc.)",
        "concern": "Behavioral tracking based on physical movement patterns",
    },
    "android.permission.POST_NOTIFICATIONS": {
        "level": "dangerous",
        "risk": "low",
        "group": "Notifications",
        "description": "Post notifications to the user",
        "concern": "Can be used for phishing or social engineering via fake notifications",
    },
    "android.permission.NEARBY_WIFI_DEVICES": {
        "level": "dangerous",
        "risk": "medium",
        "group": "WiFi",
        "description": "Discover and connect to nearby WiFi devices",
        "concern": "Can scan local network environment",
    },

    # --- Notable Normal Permissions ---
    "android.permission.INTERNET": {
        "level": "normal",
        "risk": "info",
        "group": "Network",
        "description": "Full internet access",
        "concern": "Required for data exfiltration — nearly all apps request this",
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "level": "normal",
        "risk": "info",
        "group": "Network",
        "description": "View network connectivity state",
        "concern": "Can detect WiFi vs cellular — minor fingerprinting",
    },
    "android.permission.ACCESS_WIFI_STATE": {
        "level": "normal",
        "risk": "low",
        "group": "Network",
        "description": "View WiFi connectivity state",
        "concern": "Can read WiFi SSID/BSSID — location inference",
    },
    "android.permission.CHANGE_NETWORK_STATE": {
        "level": "normal",
        "risk": "medium",
        "group": "Network",
        "description": "Change network connectivity state",
        "concern": "Can enable/disable network connections",
    },
    "android.permission.VIBRATE": {
        "level": "normal",
        "risk": "info",
        "group": "Hardware",
        "description": "Control device vibration",
        "concern": "Minimal risk",
    },
    "android.permission.WAKE_LOCK": {
        "level": "normal",
        "risk": "low",
        "group": "System",
        "description": "Prevent device from sleeping",
        "concern": "Battery drain — can keep device awake for background operations",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "level": "normal",
        "risk": "medium",
        "group": "System",
        "description": "Start at boot",
        "concern": "App runs automatically after reboot — persistence mechanism",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "level": "normal",
        "risk": "low",
        "group": "System",
        "description": "Run foreground services",
        "concern": "Long-running background operations with notification",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "level": "normal",
        "risk": "high",
        "group": "System",
        "description": "Request to install other APK packages",
        "concern": "Can prompt user to install additional (potentially malicious) apps",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "level": "normal",
        "risk": "high",
        "group": "System",
        "description": "Draw overlays on top of other apps",
        "concern": "Tapjacking / clickjacking attacks — overlay phishing screens",
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "level": "normal",
        "risk": "medium",
        "group": "System",
        "description": "Query all installed packages",
        "concern": "Fingerprinting — can enumerate all apps installed on the device",
    },
    "android.permission.USE_BIOMETRIC": {
        "level": "normal",
        "risk": "low",
        "group": "Auth",
        "description": "Use biometric hardware (fingerprint, face)",
        "concern": "Access to biometric auth — generally a security feature",
    },
    "android.permission.BLUETOOTH_CONNECT": {
        "level": "normal",
        "risk": "medium",
        "group": "Bluetooth",
        "description": "Connect to paired Bluetooth devices",
        "concern": "Can interact with Bluetooth devices — data transfer risk",
    },
}


def extract_manifest_from_apk(apk_path: str) -> str | None:
    """Extract AndroidManifest.xml from APK. Returns raw text or None."""
    with zipfile.ZipFile(apk_path, 'r') as zf:
        # Try to find a readable manifest (not binary XML)
        for name in zf.namelist():
            if name.lower() == "androidmanifest.xml":
                data = zf.read(name)
                # Check if it's binary XML (starts with specific bytes)
                if data[:4] == b'\x03\x00\x08\x00' or data[:2] == b'\x03\x00':
                    return None  # Binary XML — need aapt/apktool to decode
                try:
                    return data.decode('utf-8', errors='ignore')
                except Exception:
                    return None
    return None


def extract_permissions_from_text(content: str) -> list[str]:
    """Extract permission names from manifest text using regex (handles binary XML fallback)."""
    permissions = set()
    # Match uses-permission declarations
    pattern = re.compile(r'uses-permission[^>]*(?:android:name\s*=\s*"([^"]+)"|([a-zA-Z0-9_.]+permission[a-zA-Z0-9_.]+))', re.IGNORECASE)
    for match in pattern.finditer(content):
        perm = match.group(1) or match.group(2)
        if perm:
            permissions.add(perm)

    # Also try to find permission strings in binary data
    perm_pattern = re.compile(r'(android\.permission\.[A-Z_]+)')
    for match in perm_pattern.finditer(content):
        permissions.add(match.group(1))

    return sorted(permissions)


def extract_permissions_from_apk(apk_path: str) -> list[str]:
    """Extract all permissions from an APK file."""
    permissions = set()

    # Method 1: Try parsing XML manifest
    manifest_text = extract_manifest_from_apk(apk_path)
    if manifest_text:
        try:
            root = ElementTree.fromstring(manifest_text)
            for elem in root.iter():
                if elem.tag == "uses-permission" or elem.tag.endswith("}uses-permission"):
                    name = elem.get(f"{{{ANDROID_NS}}}name") or elem.get("name")
                    if name:
                        permissions.add(name)
        except ElementTree.ParseError:
            permissions.update(extract_permissions_from_text(manifest_text))

    # Method 2: String scan the entire APK for permission patterns (catches binary XML)
    with zipfile.ZipFile(apk_path, 'r') as zf:
        for entry in zf.namelist():
            if entry.lower() in ("androidmanifest.xml", "resources.arsc"):
                data = zf.read(entry)
                text = data.decode('utf-8', errors='ignore')
                perm_pattern = re.compile(r'android\.permission\.([A-Z][A-Z_]+)')
                for match in perm_pattern.finditer(text):
                    permissions.add(f"android.permission.{match.group(1)}")

                # Also catch custom permissions
                custom_pattern = re.compile(r'(com\.[a-zA-Z0-9_.]+\.permission\.[A-Z_]+)')
                for match in custom_pattern.finditer(text):
                    permissions.add(match.group(1))

    return sorted(permissions)


def extract_app_components(apk_path: str) -> dict:
    """Extract app components (activities, services, receivers, providers) from manifest."""
    components = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
    }

    manifest_text = extract_manifest_from_apk(apk_path)
    if not manifest_text:
        return components

    try:
        root = ElementTree.fromstring(manifest_text)
        app = root.find("application")
        if app is None:
            return components

        component_map = {
            "activity": "activities",
            "service": "services",
            "receiver": "receivers",
            "provider": "providers",
        }

        for tag, key in component_map.items():
            for elem in app.iter(tag):
                name = elem.get(f"{{{ANDROID_NS}}}name") or elem.get("name", "unknown")
                exported = elem.get(f"{{{ANDROID_NS}}}exported") or elem.get("exported")
                components[key].append(name)
                if exported == "true":
                    components["exported_components"].append(f"[{tag}] {name}")

    except ElementTree.ParseError:
        pass

    return components


def audit_permissions(permissions: list[str]) -> dict:
    """Audit the list of permissions and produce a categorized report."""
    categorized = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
        "unknown": [],
    }

    for perm in permissions:
        if perm in PERMISSION_DB:
            info = PERMISSION_DB[perm]
            entry = {
                "permission": perm,
                "short_name": perm.split(".")[-1],
                **info,
            }
            categorized[info["risk"]].append(entry)
        else:
            # Unknown or custom permission
            level = "unknown"
            if "dangerous" in perm.lower() or "admin" in perm.lower():
                level = "high"

            categorized["unknown"].append({
                "permission": perm,
                "short_name": perm.split(".")[-1],
                "level": "unknown",
                "risk": "unknown",
                "group": "Custom/Third-party",
                "description": "Custom or third-party permission (not in standard Android DB)",
                "concern": "Review manually — may have elevated privileges",
            })

    # Summary stats
    total = len(permissions)
    dangerous_count = sum(1 for p in permissions if PERMISSION_DB.get(p, {}).get("level") == "dangerous")

    summary = {
        "total_permissions": total,
        "dangerous_permissions": dangerous_count,
        "critical_findings": len(categorized["critical"]),
        "high_findings": len(categorized["high"]),
        "medium_findings": len(categorized["medium"]),
        "low_findings": len(categorized["low"]),
        "risk_score": _calculate_risk_score(categorized),
    }

    return {"summary": summary, "permissions": categorized}


def _calculate_risk_score(categorized: dict) -> str:
    """Calculate an overall risk score based on permission severity."""
    score = (
        len(categorized["critical"]) * 10
        + len(categorized["high"]) * 5
        + len(categorized["medium"]) * 2
        + len(categorized["low"]) * 1
    )

    if score >= 40:
        return f"CRITICAL ({score})"
    elif score >= 25:
        return f"HIGH ({score})"
    elif score >= 10:
        return f"MEDIUM ({score})"
    elif score > 0:
        return f"LOW ({score})"
    else:
        return f"MINIMAL ({score})"


def print_results_rich(audit: dict, apk_path: str, components: dict) -> None:
    """Print audit results using rich."""
    console = Console()
    summary = audit["summary"]

    # Header panel
    score = summary["risk_score"]
    score_color = "red" if "CRITICAL" in score else "yellow" if "HIGH" in score else "green"
    console.print(Panel(
        f"[bold]File:[/bold] {os.path.basename(apk_path)}\n"
        f"[bold]Total Permissions:[/bold] {summary['total_permissions']}\n"
        f"[bold]Dangerous Permissions:[/bold] [red]{summary['dangerous_permissions']}[/red]\n"
        f"[bold]Risk Score:[/bold] [{score_color}]{score}[/{score_color}]",
        title="APK Permission Auditor",
        border_style="blue"
    ))

    # Risk breakdown
    risk_levels = [
        ("critical", "red bold", "CRITICAL"),
        ("high", "red", "HIGH"),
        ("medium", "yellow", "MEDIUM"),
        ("low", "cyan", "LOW"),
        ("info", "dim", "INFO"),
        ("unknown", "magenta", "UNKNOWN"),
    ]

    for level, style, label in risk_levels:
        entries = audit["permissions"][level]
        if not entries:
            continue

        table = Table(title=f"{label} Risk Permissions ({len(entries)})", show_lines=True)
        table.add_column("Permission", style=style, min_width=30)
        table.add_column("Level", width=10)
        table.add_column("Group", width=12)
        table.add_column("Concern", min_width=40)

        for entry in entries:
            table.add_row(
                entry["short_name"],
                entry["level"],
                entry["group"],
                entry["concern"],
            )
        console.print(table)

    # Exported components
    if components["exported_components"]:
        table = Table(title=f"Exported Components ({len(components['exported_components'])})", show_lines=True)
        table.add_column("Type", style="yellow", width=12)
        table.add_column("Component Name", style="cyan")
        for comp in components["exported_components"]:
            parts = comp.split("] ", 1)
            comp_type = parts[0].strip("[")
            comp_name = parts[1] if len(parts) > 1 else comp
            table.add_row(comp_type, comp_name)
        console.print(table)

    # Component summary
    comp_counts = {k: len(v) for k, v in components.items() if k != "exported_components" and v}
    if comp_counts:
        table = Table(title="App Components Summary")
        table.add_column("Component Type", style="cyan")
        table.add_column("Count", justify="right")
        for comp_type, count in comp_counts.items():
            table.add_row(comp_type.title(), str(count))
        console.print(table)


def print_results_plain(audit: dict, apk_path: str, components: dict) -> None:
    """Print results as plain text."""
    summary = audit["summary"]

    print(f"\n{'='*60}")
    print(f"  APK Permission Auditor")
    print(f"{'='*60}")
    print(f"  File: {os.path.basename(apk_path)}")
    print(f"  Total Permissions: {summary['total_permissions']}")
    print(f"  Dangerous Permissions: {summary['dangerous_permissions']}")
    print(f"  Risk Score: {summary['risk_score']}")
    print(f"{'='*60}\n")

    risk_labels = ["critical", "high", "medium", "low", "info", "unknown"]

    for level in risk_labels:
        entries = audit["permissions"][level]
        if not entries:
            continue

        print(f"--- {level.upper()} Risk ({len(entries)}) ---")
        for entry in entries:
            print(f"  [{entry['level']}] {entry['short_name']}")
            print(f"    {entry['concern']}")
        print()

    if components["exported_components"]:
        print(f"--- Exported Components ({len(components['exported_components'])}) ---")
        for comp in components["exported_components"]:
            print(f"  {comp}")
        print()


def results_to_dict(audit: dict, apk_path: str, components: dict) -> dict:
    """Convert results to serializable dict."""
    return {
        "file": os.path.basename(apk_path),
        "summary": audit["summary"],
        "permissions": {
            level: entries
            for level, entries in audit["permissions"].items()
            if entries
        },
        "components": {k: v for k, v in components.items() if v},
    }


def main():
    parser = argparse.ArgumentParser(
        description="Audit Android app permissions from APK files. Classifies by risk level with security concerns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python apk_permission_auditor.py app.apk
  python apk_permission_auditor.py app.apk --json
  python apk_permission_auditor.py app.apk --json --output audit_report.json
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

    permissions = extract_permissions_from_apk(args.apk)
    components = extract_app_components(args.apk)
    audit = audit_permissions(permissions)

    if args.json:
        output = json.dumps(results_to_dict(audit, args.apk, components), indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Results saved to {args.output}")
        else:
            print(output)
    else:
        if RICH_AVAILABLE:
            print_results_rich(audit, args.apk, components)
        else:
            print_results_plain(audit, args.apk, components)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results_to_dict(audit, args.apk, components), f, indent=2)
            print(f"\nResults also saved to {args.output}")


if __name__ == "__main__":
    main()
