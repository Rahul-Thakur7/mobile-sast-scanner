#!/usr/bin/env python3
"""
MASTG-Scan — static mobile app security scanner (Android APK / iOS IPA)
Mapped to OWASP MASVS 2.x categories, methodology informed by OWASP MASTG.

Usage:
    python3 scan.py path/to/app.apk  -o report.html
    python3 scan.py path/to/app.ipa  -o report.html
"""
import sys
import argparse
import zipfile

try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.add(sys.stderr, level="ERROR")
except Exception:
    pass

from analyzer.android_analyzer import analyze_apk
from analyzer.ios_analyzer import analyze_ipa
from analyzer.report_generator import generate_html_report


def detect_platform(path: str) -> str:
    if path.lower().endswith(".apk"):
        return "android"
    if path.lower().endswith(".ipa"):
        return "ios"
    # fall back to sniffing zip contents
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if any(n == "AndroidManifest.xml" for n in names):
                return "android"
            if any(n.startswith("Payload/") for n in names):
                return "ios"
    except Exception:
        pass
    raise ValueError("Could not determine platform: expected a .apk or .ipa file")


def main():
    ap = argparse.ArgumentParser(description="Static mobile app security scanner (MASVS/MASTG-mapped)")
    ap.add_argument("app_file", help="Path to .apk or .ipa file")
    ap.add_argument("-o", "--output", default="mastg_report.html", help="Output HTML report path")
    args = ap.parse_args()

    platform = detect_platform(args.app_file)
    print(f"[*] Detected platform: {platform}")
    print(f"[*] Running static analysis against OWASP MASVS 2.x categories...")

    if platform == "android":
        report = analyze_apk(args.app_file)
    else:
        report = analyze_ipa(args.app_file)

    print(f"[*] {len(report.findings)} checks completed. Generating report...")
    html_doc = generate_html_report(report)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html_doc)

    counts = {}
    for f_ in report.findings:
        counts[f_.severity] = counts.get(f_.severity, 0) + 1
    print(f"[*] Severity breakdown: {counts}")
    print(f"[+] Report written to: {args.output}")


if __name__ == "__main__":
    main()
