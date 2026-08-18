<div align="center">

# 📱 MASTG-Scan

**Static security scanner for Android (`.apk`) and iOS (`.ipa`) apps.**
Findings mapped to both **OWASP MASVS 2.x** and the **OWASP Mobile Top 10 (2024)**, rendered as a single self-contained HTML report.

![platform](https://img.shields.io/badge/platform-Android%20%7C%20iOS-blue)
![python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/type-static%20analysis%20(SAST)-orange)

</div>

---

## What it is

Point it at an `.apk` or `.ipa`, and it:

1. Parses the manifest / `Info.plist`, signing cert, entitlements, and binary headers
2. Pattern-matches extracted strings for secrets, weak crypto, TLS bypasses, SQLi-prone queries, tracking SDKs, and more
3. Maps every finding to an **OWASP MASVS 2.x** category *and* an **OWASP Mobile Top 10 (2024)** ID
4. Renders one HTML report: risk grade, severity breakdown, two coverage matrices, and a finding-by-finding breakdown with evidence + remediation

No device, emulator, or network capture required — this is the static-analysis slice of a mobile pentest, not a replacement for one (see [Scope & limitations](#scope--limitations)).

## Quick start

```bash
git clone <this-repo>
cd mastg-scan
pip install -r requirements.txt

python3 scan.py path/to/app.apk -o report.html
python3 scan.py path/to/app.ipa -o report.html
```

Open `report.html` in a browser. That's it — no server, no config file.

## Check inventory

~31 Android checks / ~26 iOS checks, each of which can surface multiple findings depending on what's in the package:

| Mobile Top 10 (2024) | What's checked |
|---|---|
| **M1** Improper Credential Usage | 13 hardcoded-secret patterns (AWS, GCP, Stripe, Slack, JWT, private keys, basic-auth-in-URL, generic high-entropy tokens) |
| **M2** Inadequate Supply Chain Security | Third-party SDK / embedded-framework inventory (Firebase, AdMob, Facebook, AppsFlyer, Realm, OkHttp, SQLCipher, ...) |
| **M3** Insecure Authentication/Authorization | Exported components without permission checks, biometric-auth crypto-binding, debug-signed builds, `get-task-allow` |
| **M4** Insufficient Input/Output Validation | SQL injection (string-concatenated queries), XXE hardening, insecure deserialization, path traversal, WebView JS-bridge risk |
| **M5** Insecure Communication | Cleartext traffic flags, ATS config, Network Security Config, certificate pinning presence, **trust-all TrustManager / TLS-bypass detection**, weak TLS versions |
| **M6** Inadequate Privacy Controls | Dangerous permissions, ad/tracking ID usage, App Tracking Transparency compliance, Apple Privacy Manifest presence, clipboard access, screenshot exposure |
| **M7** Insufficient Binary Protections | Root/jailbreak detection presence, **anti-debug & anti-Frida detection**, PIE flag (Mach-O header parsing), FairPlay marker, native lib inventory |
| **M8** Security Misconfiguration | `debuggable`, `allowBackup`, outdated SDK targets, leftover staging/dev/localhost endpoints, world-readable/writable file modes |
| **M9** Insecure Data Storage | Backup config, external/shared storage usage, unencrypted local DB detection, Keychain accessibility, backup-exclusion attributes |
| **M10** Insufficient Cryptography | Weak algorithms (DES/RC4/ECB), weak hashes (MD5/SHA-1), insecure `Random`, hardcoded keys, weak Keychain accessibility constants |

Every finding also carries its underlying **MASVS** category (`STORAGE`, `CRYPTO`, `AUTH`, `NETWORK`, `PLATFORM`, `CODE`, `RESILIENCE`, `PRIVACY`) — see [`analyzer/masvs_catalog.py`](analyzer/masvs_catalog.py) for the full mapping.

## Sample report

Each finding shows severity, MASVS + Top-10 tags, evidence extracted from the package, and a remediation note:

```
[HIGH]  Exported components without permission protection          PLATFORM-02 · M3
The following components are exported with no android:permission
restricting access: activity:com.example.DebugActivity ...

  Recommendation: Set android:exported="false" for components not meant
  for external apps, or protect them with a signature-level permission.
```

Findings tagged `manual verification` are heuristic (symbol/string presence, not confirmed runtime behavior) and need a human to confirm before you file them as bugs.

## Project layout

```
scan.py                         CLI entry point
analyzer/
  android_analyzer.py           APK checks (manifest, permissions, exported components,
                                 signing, SQLi, TLS bypass, supply chain, ...)
  ios_analyzer.py                IPA checks (Info.plist, entitlements, Mach-O header,
                                 privacy manifest, Keychain, ...)
  common.py                     Shared heuristics: secret patterns, weak-crypto patterns,
                                 string extraction, symbol/regex scanning
  masvs_catalog.py               MASVS category labels + Mobile Top 10 mapping
  report_generator.py           Builds the HTML report
requirements.txt
```

## Extending it

Each check is a small function ending in `report.add(Finding(...))`. To add a new test case:

1. Add any new detection pattern/symbol list to `common.py`.
2. Write a `_check_xxx(...)` function in `android_analyzer.py` and/or `ios_analyzer.py`.
3. Call it from `analyze_apk()` / `analyze_ipa()`.
4. Give it a `check_id` prefix that's already mapped in `CHECK_ID_TOP10_DEFAULTS` (in `masvs_catalog.py`), or add a new mapping entry.

The report generator needs no changes — it renders whatever findings exist and groups them automatically.

## Scope & limitations

This is a **static-analysis triage tool**, not a full automated pentest. It cannot replace manual + dynamic testing on a real device or emulator — intercepting live traffic, exercising auth/business-logic flows, or attempting runtime bypass (e.g. with Frida) all require an actual running app, which no file-upload tool can do.

Concretely:
- String/symbol matches indicate an API is *linked or referenced*, not that it's *exploited* in practice — expect some false positives.
- Obfuscated, encrypted, or dynamically-loaded code is invisible to this tool.
- Server-side vulnerabilities (auth bypass on the backend, IDOR, business-logic flaws) are out of scope entirely — this only looks at the client binary.

Treat every finding as a lead for a human reviewer, not a proven vulnerability.

## Roadmap ideas

- Web upload UI (Flask/FastAPI wrapper around the existing engine)
- Decompiled smali/Objective-C method-body inspection (current string-scan approach can't see actual arguments/control flow)
- SBOM / CVE lookup for detected third-party SDK versions
- PDF export of the report

## License

MIT — use it, fork it, break it.

## Disclaimer

For use on applications you own or are authorized to test. This tool performs static analysis only and makes no guarantee of completeness; absence of findings does not mean an app is secure.
