import os
import re
import zipfile
import tempfile

from .common import (
    Finding, Report, extract_printable_strings, scan_secrets_in_text,
    scan_weak_crypto, scan_symbols, scan_cleartext_urls, scan_regex_list, detect_third_party_sdks,
    WEBVIEW_RISK_SYMBOLS, ROOT_JAILBREAK_DETECTION_SYMBOLS, CERT_PINNING_SYMBOLS,
    TLS_BYPASS_SYMBOLS, TRUST_ALL_HEURISTIC_RE, SQLI_PATTERNS, XXE_SYMBOLS, XXE_SAFE_SYMBOLS,
    DESERIALIZATION_SYMBOLS, PATH_TRAVERSAL_RE, TRACKING_SYMBOLS, CLIPBOARD_SYMBOLS,
    SCREEN_PROTECTION_SYMBOLS, ANTI_DEBUG_SYMBOLS, ANTI_FRIDA_SYMBOLS, TEST_ENDPOINT_PATTERNS,
    WORLD_PERM_SYMBOLS, EXTERNAL_STORAGE_SYMBOLS, UNENCRYPTED_DB_HINT_SYMBOLS,
    BIOMETRIC_SYMBOLS, BIOMETRIC_CRYPTO_BINDING_SYMBOLS,
)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE", "android.permission.GET_ACCOUNTS",
    "android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION",
}


def analyze_apk(path: str) -> Report:
    from androguard.core.apk import APK

    report = Report(platform="Android", file_name=os.path.basename(path), file_size=os.path.getsize(path))
    from .common import sha256_of_file
    report.sha256 = sha256_of_file(path)

    apk = APK(path)
    report.app_name = apk.get_app_name() or apk.get_package()
    report.package_id = apk.get_package()
    report.version = f"{apk.get_androidversion_name()} ({apk.get_androidversion_code()})"
    report.min_os = f"minSdk {apk.get_min_sdk_version()}"
    report.target_os = f"targetSdk {apk.get_target_sdk_version()}"
    report.permissions = apk.get_permissions()

    # ---- Gather all text (manifest + resources + dex string pools) for pattern scanning ----
    all_text_parts = []
    try:
        all_text_parts.append(apk.get_android_manifest_axml().get_xml() .decode("utf-8", "ignore")
                               if hasattr(apk.get_android_manifest_axml(), "get_xml") else "")
    except Exception:
        pass
    try:
        all_text_parts.append(apk.get_android_manifest_xml().__str__())
    except Exception:
        pass

    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if name.endswith((".dex", ".xml", ".json", ".properties", ".txt", ".cfg")) or name.startswith("assets/"):
                try:
                    data = z.read(name)
                    if len(data) > 15_000_000:
                        continue
                    strs = extract_printable_strings(data, min_len=6)
                    all_text_parts.append("\n".join(strs))
                except Exception:
                    continue
    all_text = "\n".join(all_text_parts)

    _check_manifest_flags(apk, report)
    _check_permissions(report)
    _check_exported_components(apk, report)
    _check_network_security(apk, path, report)
    _check_signing(apk, report)
    _check_secrets_and_crypto(all_text, report)
    _check_webview(all_text, report)
    _check_root_detection(all_text, report)
    _check_cert_pinning(all_text, report)
    _check_backup_debug_logging(all_text, apk, report)
    _check_native_libs(path, report)
    _check_tls_bypass(all_text, report)
    _check_sqli_and_injection(all_text, report)
    _check_supply_chain(all_text, report)
    _check_tracking_privacy(all_text, report)
    _check_anti_debug_frida(all_text, report)
    _check_test_endpoints_and_misconfig(all_text, report)
    _check_insecure_storage_indicators(all_text, report)
    _check_biometric_auth(all_text, report)

    return report


def _add(report, check_id, category, mastg_ref, title, severity, description, evidence=None, recommendation=None, manual=False, top10=None):
    from .masvs_catalog import CHECK_ID_TOP10_DEFAULTS
    if top10 is None:
        top10 = CHECK_ID_TOP10_DEFAULTS.get(check_id)
    report.add(Finding(check_id, category, mastg_ref, title, severity, description, evidence, recommendation, manual, top10))


def _get_manifest_app_attr(apk, attr):
    try:
        xml = apk.get_android_manifest_xml()
        app_el = xml.find("application")
        if app_el is not None:
            return app_el.get(f"{{http://schemas.android.com/apk/res/android}}{attr}")
    except Exception:
        pass
    return None


def _check_manifest_flags(apk, report):
    debuggable = _get_manifest_app_attr(apk, "debuggable") == "true"
    _add(report, "CODE-01", "CODE", "MASTG-TEST: debuggable flag",
         "Application debuggable flag",
         "CRITICAL" if debuggable else "PASS",
         "The application is built with android:debuggable=\"true\", allowing anyone to attach a debugger and "
         "inspect/modify runtime behavior on any device." if debuggable else
         "The application is not marked debuggable in the manifest.",
         recommendation="Ensure android:debuggable is false (or unset) in release builds." if debuggable else None)

    allow_backup = None
    try:
        xml = apk.get_android_manifest_xml()
        app_el = xml.find("application")
        if app_el is not None:
            ab_attr = "{http://schemas.android.com/apk/res/android}allowBackup"
            allow_backup = app_el.get(ab_attr)
    except Exception:
        pass

    if allow_backup is None or allow_backup == "true":
        _add(report, "STORAGE-01", "STORAGE", "MASTG-TEST: android:allowBackup / backup rules",
             "android:allowBackup not disabled",
             "MEDIUM",
             "android:allowBackup is true or unset (defaults to true), which allows app data to be extracted "
             "via `adb backup` on devices where USB debugging is enabled, or via cloud backup.",
             evidence=f"android:allowBackup={allow_backup!r}",
             recommendation="Set android:allowBackup=\"false\", or configure android:fullBackupContent to "
                            "explicitly exclude sensitive files.")
    else:
        _add(report, "STORAGE-01", "STORAGE", "MASTG-TEST: android:allowBackup / backup rules",
             "Backup disabled", "PASS", "android:allowBackup is explicitly set to false.")

    try:
        xml = apk.get_android_manifest_xml()
        app_el = xml.find("application")
        ct_attr = "{http://schemas.android.com/apk/res/android}usesCleartextTraffic"
        uses_cleartext = app_el.get(ct_attr) if app_el is not None else None
    except Exception:
        uses_cleartext = None

    target_sdk = apk.get_target_sdk_version()
    try:
        target_sdk_int = int(target_sdk)
    except Exception:
        target_sdk_int = 0

    if uses_cleartext == "true":
        _add(report, "NETWORK-01", "NETWORK", "MASTG-TEST: cleartext traffic",
             "Cleartext traffic explicitly allowed",
             "HIGH",
             "android:usesCleartextTraffic=\"true\" is set, permitting unencrypted HTTP traffic app-wide, "
             "unless overridden per-domain by a Network Security Config.",
             evidence="android:usesCleartextTraffic=true",
             recommendation="Remove the flag (default is false on API 28+) and only allow cleartext for "
                            "specific, justified debug endpoints via networkSecurityConfig.")
    elif uses_cleartext == "false":
        _add(report, "NETWORK-01", "NETWORK", "MASTG-TEST: cleartext traffic", "Cleartext traffic disabled",
             "PASS", "android:usesCleartextTraffic is explicitly false.")
    elif target_sdk_int and target_sdk_int < 28:
        _add(report, "NETWORK-01", "NETWORK", "MASTG-TEST: cleartext traffic",
             "Cleartext traffic allowed by default (legacy targetSdk)",
             "MEDIUM",
             f"targetSdkVersion is {target_sdk_int} (<28), so cleartext HTTP is allowed by default since the "
             "flag was not explicitly set and the safer Android 9 default doesn't apply.",
             recommendation="Raise targetSdkVersion and/or explicitly set usesCleartextTraffic=false.")
    else:
        _add(report, "NETWORK-01", "NETWORK", "MASTG-TEST: cleartext traffic", "Cleartext traffic not explicitly allowed",
             "PASS", "No explicit usesCleartextTraffic=true, and targetSdk >= 28 defaults to false.")

    if target_sdk_int and target_sdk_int < 30:
        _add(report, "CODE-02", "CODE", "MASTG-TEST: target SDK currency",
             "Outdated targetSdkVersion",
             "MEDIUM" if target_sdk_int < 28 else "LOW",
             f"App targets SDK {target_sdk_int}. Low target SDK versions opt out of many modern platform "
             "security defaults and are increasingly rejected by app stores.",
             recommendation="Raise targetSdkVersion to a current, store-compliant level.")


def _check_permissions(report):
    dangerous = [p for p in report.permissions if p in DANGEROUS_PERMISSIONS]
    if dangerous:
        _add(report, "PLATFORM-01", "PLATFORM", "MASTG-TEST: permission usage analysis",
             "Sensitive/dangerous permissions requested",
             "INFO",
             f"The app requests {len(dangerous)} dangerous-protection-level permission(s). This is not a "
             "vulnerability by itself, but each should be justified by an in-app feature and reviewed for "
             "least-privilege.",
             evidence=", ".join(sorted(dangerous)),
             manual=True,
             recommendation="Confirm each permission maps to a real feature and is requested contextually "
                            "(runtime prompt) rather than all at launch.")


def _check_exported_components(apk, report):
    try:
        xml = apk.get_android_manifest_xml()
    except Exception:
        return
    ns = "{http://schemas.android.com/apk/res/android}"
    risky = []
    for comp_type in ("activity", "activity-alias", "service", "receiver", "provider"):
        app_el = xml.find("application")
        if app_el is None:
            continue
        for el in app_el.findall(comp_type):
            name = el.get(f"{ns}name", "?")
            exported = el.get(f"{ns}exported")
            has_intent_filter = el.find("intent-filter") is not None
            permission = el.get(f"{ns}permission")
            is_exported = (exported == "true") or (exported is None and has_intent_filter)
            if is_exported and not permission:
                risky.append((comp_type, name))

    if risky:
        sample = "; ".join(f"{t}:{n}" for t, n in risky[:12])
        more = f" (+{len(risky)-12} more)" if len(risky) > 12 else ""
        _add(report, "PLATFORM-02", "PLATFORM", "MASTG-TEST: exported component analysis",
             "Exported components without permission protection",
             "HIGH",
             f"{len(risky)} component(s) are exported (explicitly, or implicitly via an intent-filter) with no "
             "android:permission restricting access, making them callable by any other app on the device.",
             evidence=sample + more,
             recommendation="Set android:exported=\"false\" for components not meant for external apps, or "
                            "protect them with a signature-level custom permission. Validate all inputs to any "
                            "component that must remain exported.")
    else:
        _add(report, "PLATFORM-02", "PLATFORM", "MASTG-TEST: exported component analysis",
             "No unprotected exported components found", "PASS",
             "All discoverable exported components declare a permission, or none are exported.")


def _check_network_security(apk, path, report):
    nsc_found = False
    trusts_user_ca = False
    disables_pinning = False
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if "network_security_config" in name.lower() and name.endswith(".xml"):
                nsc_found = True
                try:
                    content = z.read(name).decode("utf-8", "ignore")
                    if "<certificates src=\"user\"" in content or 'src="user"' in content:
                        trusts_user_ca = True
                    if "<trust-anchors>" in content and "system" not in content:
                        pass
                except Exception:
                    pass

    if trusts_user_ca:
        _add(report, "NETWORK-02", "NETWORK", "MASTG-TEST: network security config / cert trust",
             "Network Security Config trusts user-added CAs",
             "MEDIUM",
             "The Network Security Config includes the 'user' certificate store as a trust-anchor, meaning "
             "traffic can be intercepted by any CA the device user (or an attacker with device access / a "
             "malicious profile) has installed -- this is normal for debug builds but risky in production.",
             recommendation="Restrict trust-anchors to 'system' only in release builds, and add certificate "
                            "pinning for high-value endpoints.")
    elif nsc_found:
        _add(report, "NETWORK-02", "NETWORK", "MASTG-TEST: network security config / cert trust",
             "Network Security Config present", "PASS",
             "A Network Security Config is present and does not appear to trust user-added CAs by default "
             "(verify pinning manually for critical endpoints).", manual=True)
    else:
        _add(report, "NETWORK-02", "NETWORK", "MASTG-TEST: network security config / cert trust",
             "No Network Security Config found",
             "LOW",
             "No res/xml network_security_config.xml was found. The app relies entirely on Android's platform "
             "TLS defaults with no custom pinning or cleartext restrictions layer.",
             recommendation="Add a Network Security Config to explicitly control cleartext policy and, ideally, "
                            "pin certificates/public keys for sensitive backend connections.")


def _check_signing(apk, report):
    try:
        certs = apk.get_certificates()
    except Exception:
        certs = []
    if not certs:
        _add(report, "CODE-03", "CODE", "MASTG-TEST: app signature", "Could not verify signing certificate",
             "INFO", "No parsable v1/v2/v3 signing certificate was found by static parsing.", manual=True)
        return
    for cert in certs:
        subject = str(cert.subject)
        if "Android Debug" in subject or "CN=Android Debug" in subject:
            _add(report, "CODE-03", "CODE", "MASTG-TEST: app signature",
                 "Signed with the Android Debug certificate",
                 "CRITICAL",
                 "The APK is signed with the default debug keystore (CN=Android Debug). This build should "
                 "never be distributed -- it also usually implies debuggable builds and disabled ProGuard/R8.",
                 evidence=subject)
        else:
            _add(report, "CODE-03", "CODE", "MASTG-TEST: app signature", "Release signing certificate present",
                 "PASS", f"Signed with a non-debug certificate.", evidence=subject)


def _check_secrets_and_crypto(all_text, report):
    secrets = scan_secrets_in_text(all_text)
    if secrets:
        lines = []
        for name, count, samples in secrets:
            lines.append(f"{name} x{count}: " + ", ".join(samples))
        _add(report, "STORAGE-02", "STORAGE", "MASTG-TEST: hardcoded secrets in app package",
             "Hardcoded secrets / API keys found in package contents",
             "HIGH",
             f"Pattern-matching across manifest, resources, assets and dex string pools found {len(secrets)} "
             "class(es) of likely hardcoded secret. These may be false positives (e.g. sample/test keys, "
             "third-party SDK identifiers that are meant to be public) -- each must be manually confirmed.",
             evidence="\n".join(lines),
             manual=True,
             recommendation="Move genuine secrets server-side or behind a runtime config/secrets manager; "
                            "never ship long-lived credentials inside the client binary.")
    else:
        _add(report, "STORAGE-02", "STORAGE", "MASTG-TEST: hardcoded secrets in app package",
             "No obvious hardcoded secrets found by pattern matching", "PASS",
             "No matches for common secret/key formats were found. This does not rule out obfuscated or "
             "encoded secrets.", manual=True)

    weak = scan_weak_crypto(all_text)
    if weak:
        lines = [f"{name} (matched {n}x)" for name, n in weak]
        _add(report, "CRYPTO-01", "CRYPTO", "MASTG-TEST: cryptographic algorithm usage",
             "References to weak/deprecated cryptographic primitives",
             "HIGH",
             "The compiled code/string pool references weak algorithms or modes (e.g. DES/RC4/ECB, MD5/SHA-1 "
             "used as a security hash, java.util.Random for security-sensitive values). String presence "
             "indicates the API is linked/reachable; confirm actual usage in context.",
             evidence="\n".join(lines),
             manual=True,
             recommendation="Use AES-GCM (authenticated) for encryption, SHA-256+ for integrity/hashing, and "
                            "SecureRandom for anything security-relevant.")
    else:
        _add(report, "CRYPTO-01", "CRYPTO", "MASTG-TEST: cryptographic algorithm usage",
             "No obviously weak crypto primitives detected", "PASS",
             "No matches for common weak-crypto signatures were found in extracted strings.")

    cleartext_urls, total = scan_cleartext_urls(all_text)
    if total:
        _add(report, "NETWORK-03", "NETWORK", "MASTG-TEST: cleartext endpoint discovery",
             "Hardcoded http:// (non-TLS) endpoints found in strings",
             "MEDIUM",
             f"{total} distinct http:// URL(s) were found embedded in the app. These may be traffic endpoints, "
             "third-party SDK defaults, or dead code -- confirm which are actually reachable at runtime.",
             evidence="\n".join(cleartext_urls),
             manual=True,
             recommendation="Migrate all live endpoints to HTTPS and remove unused legacy URLs.")


def _check_webview(all_text, report):
    present = scan_symbols(all_text, WEBVIEW_RISK_SYMBOLS)
    if "addJavascriptInterface" in present:
        _add(report, "PLATFORM-03", "PLATFORM", "MASTG-TEST: WebView JS bridge",
             "WebView JavaScript bridge (addJavascriptInterface) referenced",
             "HIGH",
             "The app references addJavascriptInterface, which -- if used with a WebView that loads any "
             "attacker-influenceable content and targets API<17, or exposes overly powerful methods -- can "
             "allow arbitrary code execution via JS-to-Java bridging.",
             evidence=", ".join(present),
             manual=True,
             recommendation="Avoid exposing bridge objects to WebViews that load remote/untrusted content; "
                            "annotate only the minimum required methods with @JavascriptInterface.")
    elif present:
        _add(report, "PLATFORM-03", "PLATFORM", "MASTG-TEST: WebView configuration",
             "WebView configuration APIs referenced -- manual review recommended",
             "LOW",
             "WebView-related configuration calls were found in the code. Static analysis cannot determine the "
             "actual argument values (e.g. whether JS or universal file access is enabled).",
             evidence=", ".join(present),
             manual=True,
             recommendation="Manually inspect WebView setup: JavaScript should be off unless required, file/"
                            "universal access from file URLs should be disabled, and loaded content should be "
                            "restricted to trusted origins.")
    else:
        _add(report, "PLATFORM-03", "PLATFORM", "MASTG-TEST: WebView configuration",
             "No WebView usage detected", "PASS", "No WebView configuration symbols were found in the package.")


def _check_root_detection(all_text, report):
    present = scan_symbols(all_text, ROOT_JAILBREAK_DETECTION_SYMBOLS)
    if present:
        _add(report, "RESILIENCE-01", "RESILIENCE", "MASTG-TEST: root detection",
             "Root-detection related strings/symbols present", "PASS",
             "Symbols associated with root-detection logic were found, suggesting some anti-tampering controls "
             "exist. Effectiveness must be verified dynamically (root detection is trivially bypassable with "
             "tools like Frida/Magisk Hide/Zygisk without a layered defense).",
             evidence=", ".join(present), manual=True)
    else:
        _add(report, "RESILIENCE-01", "RESILIENCE", "MASTG-TEST: root detection",
             "No root-detection logic detected",
             "MEDIUM" if "financ" in all_text.lower() or "bank" in all_text.lower() else "LOW",
             "No common root-detection library or symbol was found. For apps handling sensitive data/payments, "
             "the absence of any root/tamper checks lowers the bar for on-device attacks.",
             recommendation="For high-risk apps, add root/jailbreak and debugger detection as a defense-in-"
                            "depth layer (not a primary control), ideally combined with runtime app "
                            "self-protection (RASP) and server-side risk signals.")


def _check_cert_pinning(all_text, report):
    present = scan_symbols(all_text, CERT_PINNING_SYMBOLS)
    if present:
        _add(report, "NETWORK-04", "NETWORK", "MASTG-TEST: certificate/public-key pinning",
             "Certificate pinning related symbols found", "PASS",
             "Symbols associated with certificate/public-key pinning (e.g. OkHttp CertificatePinner, custom "
             "TrustManager) were found. Confirm pinning is actually enforced and covers all sensitive hosts.",
             evidence=", ".join(present), manual=True)
    else:
        _add(report, "NETWORK-04", "NETWORK", "MASTG-TEST: certificate/public-key pinning",
             "No certificate pinning detected",
             "MEDIUM",
             "No pinning-related symbols were found. The app likely relies solely on the platform trust store, "
             "making MITM easier if a malicious/enterprise CA is trusted on the device.",
             recommendation="Add certificate or public-key pinning (e.g. via Network Security Config "
                            "pin-set, or OkHttp CertificatePinner) for endpoints carrying sensitive data.")


def _check_backup_debug_logging(all_text, apk, report):
    log_calls = len(re.findall(r"\bLog\.[dv]\(", all_text))
    if log_calls > 0:
        _add(report, "PRIVACY-01", "PRIVACY", "MASTG-TEST: sensitive data in logs",
             "Verbose/debug log calls present",
             "LOW",
             f"~{log_calls} Log.d()/Log.v() call site references were found. These can leak sensitive data to "
             "logcat on non-production builds and are sometimes accidentally shipped enabled.",
             manual=True,
             recommendation="Strip debug logging in release builds (ProGuard/R8 rule or build-variant guard) "
                            "and ensure no PII/secrets are ever logged at any level.")


def _check_native_libs(path, report):
    archs = set()
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            m = re.match(r"lib/([^/]+)/.*\.so$", name)
            if m:
                archs.add(m.group(1))
    if archs:
        _add(report, "CODE-04", "CODE", "MASTG-TEST: native library inventory", "Native libraries present",
             "INFO",
             f"App ships native (.so) libraries for architecture(s): {', '.join(sorted(archs))}. Native code "
             "is not covered by JVM-level static analysis and should be reviewed separately (e.g. with "
             "Ghidra/IDA) for memory-safety and hardening flags (PIE, stack canaries, RELRO).",
             manual=True)


# ---------------------------------------------------------------------------
# Additional OWASP Mobile Top 10 (2024) coverage
# ---------------------------------------------------------------------------

def _check_tls_bypass(all_text, report):
    present = scan_symbols(all_text, TLS_BYPASS_SYMBOLS)
    empty_trust = TRUST_ALL_HEURISTIC_RE.search(all_text) is not None
    if empty_trust:
        _add(report, "NETWORK-05", "NETWORK", "MASTG-TEST: TLS trust validation bypass",
             "Trust-all TrustManager pattern detected (empty checkServerTrusted body)",
             "CRITICAL",
             "An empty-bodied checkServerTrusted() override was found, a classic pattern for disabling "
             "certificate chain validation entirely and accepting any server certificate -- this defeats TLS "
             "and enables trivial MITM.",
             recommendation="Never ship a TrustManager that unconditionally trusts all certificates, even for "
                            "debug builds; gate it behind a build flavor that cannot reach production.")
    elif present:
        _add(report, "NETWORK-05", "NETWORK", "MASTG-TEST: TLS trust validation bypass",
             "Symbols associated with TLS/hostname validation overrides found",
             "MEDIUM",
             "Code references APIs that are commonly (but not always) used to weaken or bypass certificate/"
             "hostname validation. Manually confirm whether validation is actually being disabled.",
             evidence=", ".join(present), manual=True,
             recommendation="Ensure any custom TrustManager/HostnameVerifier still performs full chain and "
                            "hostname validation; restrict permissive overrides to non-production builds.")
    else:
        _add(report, "NETWORK-05", "NETWORK", "MASTG-TEST: TLS trust validation bypass",
             "No TLS/certificate-validation bypass patterns found", "PASS",
             "No trust-all TrustManager or hostname-verifier-bypass patterns were detected in extracted strings.")


def _check_sqli_and_injection(all_text, report):
    sqli_hits = scan_regex_list(all_text, SQLI_PATTERNS)
    if sqli_hits:
        lines = [f"{name} (matched {n}x)" for name, n in sqli_hits]
        _add(report, "CODE-05", "CODE", "MASTG-TEST: local SQL injection",
             "Possible SQL injection via string-concatenated queries",
             "HIGH",
             "Database query APIs (rawQuery/execSQL) appear to be built with string concatenation rather than "
             "parameterized placeholders (?), which is vulnerable to local SQL injection if any part of the "
             "query includes external or user-controlled input (content providers, deep links, IPC extras).",
             evidence="\n".join(lines), manual=True,
             recommendation="Use parameterized queries (SQLiteDatabase#rawQuery with a selectionArgs array) "
                            "and never concatenate untrusted input directly into SQL.")
    else:
        _add(report, "CODE-05", "CODE", "MASTG-TEST: local SQL injection",
             "No obvious string-concatenated SQL query patterns found", "PASS",
             "No rawQuery/execSQL string-concatenation patterns were found in extracted strings.")

    xxe_present = scan_symbols(all_text, XXE_SYMBOLS)
    xxe_hardened = scan_symbols(all_text, XXE_SAFE_SYMBOLS)
    if xxe_present and not xxe_hardened:
        _add(report, "CODE-06", "CODE", "MASTG-TEST: XML external entity (XXE) handling",
             "XML parser in use with no visible hardening against XXE",
             "MEDIUM",
             f"The app uses {', '.join(xxe_present)} to parse XML, but no hardening flags (disabling DOCTYPE/"
             "external entities, enabling FEATURE_SECURE_PROCESSING) were found in the string pool. If any "
             "parsed XML can come from an untrusted source (e.g. a server response, imported file), this may "
             "allow XXE (local file read/SSRF).",
             evidence=", ".join(xxe_present), manual=True,
             recommendation="Disable DOCTYPE declarations and external entity resolution on every "
                            "XML parser/factory instance that processes untrusted input.")

    deser_present = scan_symbols(all_text, DESERIALIZATION_SYMBOLS)
    if deser_present:
        _add(report, "CODE-07", "CODE", "MASTG-TEST: insecure deserialization",
             "Native (de)serialization APIs referenced",
             "MEDIUM",
             "ObjectInputStream/readObject-style native deserialization was found. If any deserialized data "
             "can originate from an untrusted source (IPC, file, network), this is a classic gadget-chain / "
             "arbitrary-object-instantiation risk.",
             evidence=", ".join(deser_present), manual=True,
             recommendation="Avoid native Java serialization for untrusted data; prefer a safe format "
                            "(JSON/Protobuf) with strict schema validation.")

    if PATH_TRAVERSAL_RE.search(all_text):
        _add(report, "CODE-07b", "CODE", "MASTG-TEST: path traversal",
             "Path-traversal-like string patterns found",
             "LOW",
             "Repeated '../' sequences or dynamically concatenated external-storage paths were found in "
             "strings, which can indicate file path construction vulnerable to path traversal if any segment "
             "is attacker-influenced (e.g. a filename from an Intent or a downloaded archive entry).",
             manual=True,
             recommendation="Canonicalize and validate any file path built from external input; reject paths "
                            "containing '..' segments before use.", top10="M4")


def _check_supply_chain(all_text, report):
    sdks = detect_third_party_sdks(all_text)
    if sdks:
        _add(report, "SUPPLY-01", "CODE", "MASTG-TEST: third-party SDK / dependency inventory",
             f"{len(sdks)} third-party SDK(s)/libraries identified",
             "INFO",
             "Static string signatures for common third-party SDKs were found. Each is a supply-chain trust "
             "dependency -- confirm versions are current/patched and that each SDK's data collection is "
             "disclosed in your privacy policy and (for iOS) its privacy manifest.",
             evidence=", ".join(sorted(sdks)), manual=True,
             recommendation="Maintain an SBOM for embedded SDKs, track CVEs for each, and remove any SDK that "
                            "is unused or whose maintenance/trust level cannot be verified.")


def _check_tracking_privacy(all_text, report):
    tracking = scan_symbols(all_text, TRACKING_SYMBOLS)
    clipboard = scan_symbols(all_text, CLIPBOARD_SYMBOLS)
    screen_protect = scan_symbols(all_text, SCREEN_PROTECTION_SYMBOLS)

    if tracking:
        _add(report, "PRIVACY-02", "PRIVACY", "MASTG-TEST: advertising/tracking identifier usage",
             "Advertising/tracking identifier APIs referenced",
             "INFO",
             "The app references advertising-ID or tracking APIs. Confirm this use is disclosed in the app's "
             "privacy policy/data-safety form and that any required consent flow is actually implemented.",
             evidence=", ".join(tracking), manual=True)

    if clipboard:
        _add(report, "PRIVACY-02b", "PRIVACY", "MASTG-TEST: clipboard access",
             "Clipboard access APIs referenced",
             "LOW",
             "The app reads or writes the system clipboard. Clipboard contents can be sensitive (passwords, "
             "OTPs copied from elsewhere) and are readable by other apps on many OS versions -- avoid copying "
             "secrets to it, and avoid reading it unless necessary for the feature at hand.",
             evidence=", ".join(clipboard), manual=True)

    if not screen_protect:
        _add(report, "PRIVACY-02c", "PRIVACY", "MASTG-TEST: screenshot/app-switcher exposure",
             "No FLAG_SECURE / snapshot-protection usage detected",
             "LOW",
             "No reference to FLAG_SECURE (Android) was found. Screens showing sensitive data (payment forms, "
             "auth codes, personal records) will be visible in the OS app-switcher thumbnail and can be "
             "captured by screen-recording malware unless explicitly protected.",
             manual=True,
             recommendation="Set FLAG_SECURE on any Activity/Window that displays sensitive data.")


def _check_anti_debug_frida(all_text, report):
    anti_debug = scan_symbols(all_text, ANTI_DEBUG_SYMBOLS)
    anti_frida = scan_symbols(all_text, ANTI_FRIDA_SYMBOLS)
    if anti_debug or anti_frida:
        _add(report, "RESILIENCE-02", "RESILIENCE", "MASTG-TEST: anti-debugging / anti-instrumentation",
             "Anti-debugging or anti-instrumentation checks present", "PASS",
             "Symbols associated with debugger-detection or Frida/instrumentation-detection were found. "
             "Effectiveness must be verified dynamically -- these checks are commonly bypassed unless "
             "layered and combined with server-side attestation.",
             evidence=", ".join(anti_debug + anti_frida), manual=True)
    else:
        _add(report, "RESILIENCE-02", "RESILIENCE", "MASTG-TEST: anti-debugging / anti-instrumentation",
             "No anti-debugging/anti-instrumentation logic detected",
             "LOW",
             "No common debugger-detection or Frida-detection symbols were found. For high-risk apps this "
             "means a debugger or Frida can attach without any resistance.",
             recommendation="Add debugger/instrumentation detection as a defense-in-depth layer for "
                            "high-value apps, combined with server-side integrity attestation "
                            "(Play Integrity API) rather than relying on client checks alone.")


def _check_test_endpoints_and_misconfig(all_text, report):
    hits = []
    for pattern in TEST_ENDPOINT_PATTERNS:
        found = set(re.findall(pattern, all_text, re.IGNORECASE))
        hits += list(found)[:5]
    if hits:
        _add(report, "CODE-08", "CODE", "MASTG-TEST: leftover debug/staging endpoints",
             "Development/staging/local endpoints found in release package",
             "MEDIUM",
             "The package contains references to staging/dev/test/localhost/emulator-loopback endpoints. "
             "If shipped in a production build, these can point to less-secured backends or leak internal "
             "infrastructure details.",
             evidence=", ".join(sorted(set(hits))[:15]), manual=True,
             recommendation="Strip all non-production endpoint references from release builds via build "
                            "flavors/config, not just app-side environment switches.")

    world_perms = scan_symbols(all_text, WORLD_PERM_SYMBOLS)
    if world_perms:
        _add(report, "CODE-08b", "CODE", "MASTG-TEST: world-readable/writable file modes",
             "MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE referenced",
             "HIGH",
             "The deprecated world-readable/writable file modes were found referenced. Files opened with "
             "these modes are accessible to any other app on the device (pre-Android 7) or indicate legacy, "
             "unsafe file-permission code.",
             evidence=", ".join(world_perms), top10="M9",
             recommendation="Use MODE_PRIVATE (the default) for all app files; share data via a properly "
                            "permissioned ContentProvider or scoped storage instead.")


def _check_insecure_storage_indicators(all_text, report):
    ext_storage = scan_symbols(all_text, EXTERNAL_STORAGE_SYMBOLS)
    db_hint = scan_symbols(all_text, UNENCRYPTED_DB_HINT_SYMBOLS)
    has_sqlcipher = "sqlcipher" in all_text.lower() or "SQLCipher" in all_text

    if ext_storage:
        _add(report, "STORAGE-03", "STORAGE", "MASTG-TEST: external/shared storage usage",
             "App reads/writes external (shared) storage",
             "MEDIUM",
             "The app references external storage APIs. Any sensitive data written there is world-readable "
             "on many Android versions/configurations and survives app uninstall.",
             evidence=", ".join(ext_storage), manual=True,
             recommendation="Keep sensitive data in app-private internal storage (or EncryptedFile/"
                            "EncryptedSharedPreferences from Jetpack Security); never place secrets on "
                            "external/shared storage.")

    if db_hint and not has_sqlcipher:
        _add(report, "STORAGE-03b", "STORAGE", "MASTG-TEST: local database encryption",
             "SQLite database usage found with no encryption library detected",
             "MEDIUM",
             "The app creates/opens a local SQLite database, but no encryption layer (e.g. SQLCipher) was "
             "detected in the package. If the database stores sensitive data, it is stored in plaintext on "
             "disk and readable with root/backup access.",
             evidence=", ".join(db_hint), manual=True,
             recommendation="Encrypt local databases containing sensitive data (e.g. via SQLCipher or the "
                            "Jetpack Security library) or avoid storing sensitive data locally at all.")


def _check_biometric_auth(all_text, report):
    biometric = scan_symbols(all_text, BIOMETRIC_SYMBOLS)
    crypto_binding = scan_symbols(all_text, BIOMETRIC_CRYPTO_BINDING_SYMBOLS)
    if biometric and not crypto_binding:
        _add(report, "AUTH-01", "AUTH", "MASTG-TEST: biometric authentication implementation",
             "Biometric prompt used without visible cryptographic binding",
             "MEDIUM",
             "Biometric APIs are referenced, but no CryptoObject/setUserAuthenticationRequired binding was "
             "found. A biometric prompt used purely as a boolean gate (rather than to unlock a hardware-"
             "backed key) can potentially be bypassed by hooking the callback, since it doesn't cryptographically "
             "prove the biometric check occurred.",
             evidence=", ".join(biometric), manual=True,
             recommendation="Bind biometric authentication to a CryptoObject backed by an Android Keystore "
                            "key with setUserAuthenticationRequired(true), so a bypassed UI check alone "
                            "cannot unlock protected data.")
    elif biometric:
        _add(report, "AUTH-01", "AUTH", "MASTG-TEST: biometric authentication implementation",
             "Biometric authentication with cryptographic binding indicators found", "PASS",
             "Biometric APIs are used alongside key-binding APIs, suggesting (not confirming) proper "
             "hardware-backed binding. Verify manually.",
             evidence=", ".join(biometric + crypto_binding), manual=True)
