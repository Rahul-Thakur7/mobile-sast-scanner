import os
import re
import glob
import struct
import plistlib
import zipfile
import tempfile
import shutil

from .common import (
    Finding, Report, extract_printable_strings, scan_secrets_in_text,
    scan_weak_crypto, scan_symbols, sha256_of_file, scan_regex_list, detect_third_party_sdks,
    ROOT_JAILBREAK_DETECTION_SYMBOLS, CERT_PINNING_SYMBOLS,
    TLS_BYPASS_SYMBOLS, TRUST_ALL_HEURISTIC_RE, TRACKING_SYMBOLS, CLIPBOARD_SYMBOLS,
    SCREEN_PROTECTION_SYMBOLS, ANTI_DEBUG_SYMBOLS, ANTI_FRIDA_SYMBOLS, TEST_ENDPOINT_PATTERNS,
    EXTERNAL_STORAGE_SYMBOLS, KEYCHAIN_GOOD_ACCESSIBILITY, BACKUP_EXCLUSION_SYMBOLS,
    BIOMETRIC_SYMBOLS, BIOMETRIC_CRYPTO_BINDING_SYMBOLS, DESERIALIZATION_SYMBOLS,
)

MACHO_MAGICS = {0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe}
FAT_MAGICS = {0xcafebabe, 0xbebafeca}


def analyze_ipa(path: str) -> Report:
    report = Report(platform="iOS", file_name=os.path.basename(path), file_size=os.path.getsize(path))
    report.sha256 = sha256_of_file(path)

    tmpdir = tempfile.mkdtemp(prefix="ipa_")
    try:
        with zipfile.ZipFile(path) as z:
            z.extractall(tmpdir)

        app_dirs = glob.glob(os.path.join(tmpdir, "Payload", "*.app"))
        if not app_dirs:
            _add(report, "CODE-00", "CODE", "MASTG package structure", "Not a valid IPA",
                 "INFO", "No Payload/*.app directory found -- this may not be a valid IPA.")
            return report
        app_dir = app_dirs[0]

        info_plist_path = os.path.join(app_dir, "Info.plist")
        plist = {}
        if os.path.exists(info_plist_path):
            with open(info_plist_path, "rb") as f:
                try:
                    plist = plistlib.load(f)
                except Exception:
                    plist = {}

        report.app_name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or app_dir
        report.package_id = plist.get("CFBundleIdentifier", "unknown")
        report.version = f"{plist.get('CFBundleShortVersionString','?')} ({plist.get('CFBundleVersion','?')})"
        report.min_os = f"MinimumOSVersion {plist.get('MinimumOSVersion', 'unknown')}"
        report.target_os = report.min_os

        # gather text for pattern scanning: Info.plist raw + entitlements + strings from binary & frameworks
        all_text_parts = []
        try:
            with open(info_plist_path, "rb") as f:
                all_text_parts.append(f.read().decode("utf-8", "ignore"))
        except Exception:
            pass

        binary_path = os.path.join(app_dir, plist.get("CFBundleExecutable", "")) if plist.get("CFBundleExecutable") else None
        macho_findings = _analyze_macho(binary_path, report) if binary_path and os.path.exists(binary_path) else {}

        # strings from the main binary and any embedded frameworks/dylibs
        candidates = []
        if binary_path and os.path.exists(binary_path):
            candidates.append(binary_path)
        candidates += glob.glob(os.path.join(app_dir, "Frameworks", "*"))
        for c in candidates:
            if os.path.isfile(c) and os.path.getsize(c) < 60_000_000:
                try:
                    with open(c, "rb") as f:
                        data = f.read()
                    all_text_parts.append("\n".join(extract_printable_strings(data, min_len=6)))
                except Exception:
                    pass

        all_text = "\n".join(all_text_parts)

        _check_ats(plist, report)
        _check_url_schemes(plist, report)
        _check_file_sharing(plist, report)
        _check_entitlements(app_dir, report)
        _check_binary_protections(macho_findings, report)
        _check_secrets_and_crypto(all_text, report)
        _check_keychain_accessibility(all_text, report)
        _check_jailbreak_detection(all_text, report)
        _check_cert_pinning(all_text, report)
        _check_privacy_usage_strings(plist, report)
        _check_tls_bypass(all_text, report)
        _check_supply_chain(all_text, app_dir, report)
        _check_privacy_manifest(app_dir, plist, all_text, report)
        _check_tracking_and_clipboard(all_text, report)
        _check_anti_debug_frida(all_text, report)
        _check_test_endpoints(all_text, report)
        _check_storage_indicators(app_dir, all_text, report)
        _check_biometric_auth(all_text, report)
        _check_deserialization(all_text, report)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return report


def _add(report, check_id, category, mastg_ref, title, severity, description, evidence=None, recommendation=None, manual=False, top10=None):
    from .masvs_catalog import CHECK_ID_TOP10_DEFAULTS
    if top10 is None:
        top10 = CHECK_ID_TOP10_DEFAULTS.get(check_id)
    report.add(Finding(check_id, category, mastg_ref, title, severity, description, evidence, recommendation, manual, top10))


def _check_ats(plist, report):
    ats = plist.get("NSAppTransportSecurity", {})
    if not ats:
        _add(report, "NETWORK-01", "NETWORK", "MASTG-TEST: App Transport Security config",
             "App Transport Security enabled (default)", "PASS",
             "No NSAppTransportSecurity overrides found -- ATS defaults (TLS 1.2+, no arbitrary loads) apply.")
        return

    if ats.get("NSAllowsArbitraryLoads") is True and not ats.get("NSExceptionDomains"):
        _add(report, "NETWORK-01", "NETWORK", "MASTG-TEST: App Transport Security config",
             "ATS disabled globally (NSAllowsArbitraryLoads=true)",
             "HIGH",
             "NSAllowsArbitraryLoads is true with no domain restrictions, allowing plaintext HTTP and "
             "weak-TLS connections to any host.",
             recommendation="Remove the global override; scope any necessary exceptions to specific domains "
                            "under NSExceptionDomains with the narrowest possible flags.")
    exceptions = ats.get("NSExceptionDomains", {})
    risky_domains = []
    for domain, cfg in exceptions.items():
        if cfg.get("NSExceptionAllowsInsecureHTTPLoads") or cfg.get("NSIncludesSubdomains") and cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
            risky_domains.append(domain)
        if cfg.get("NSExceptionMinimumTLSVersion") in ("TLSv1.0", "TLSv1.1"):
            risky_domains.append(f"{domain} (weak min TLS)")
    if risky_domains:
        _add(report, "NETWORK-01b", "NETWORK", "MASTG-TEST: App Transport Security exceptions",
             "ATS exceptions weaken transport security for specific domains",
             "MEDIUM",
             "One or more NSExceptionDomains entries allow insecure HTTP or a weak minimum TLS version.",
             evidence=", ".join(risky_domains),
             recommendation="Remove insecure-load exceptions and require TLS 1.2+ for every domain.")
    elif not (ats.get("NSAllowsArbitraryLoads") is True and not exceptions):
        _add(report, "NETWORK-01", "NETWORK", "MASTG-TEST: App Transport Security config",
             "ATS configured with scoped exceptions only", "PASS",
             "ATS overrides exist but do not appear to globally disable transport security.",
             evidence=str(list(exceptions.keys())) if exceptions else None, manual=True)


def _check_url_schemes(plist, report):
    schemes = []
    for entry in plist.get("CFBundleURLTypes", []) or []:
        schemes += entry.get("CFBundleURLSchemes", [])
    if schemes:
        _add(report, "PLATFORM-01", "PLATFORM", "MASTG-TEST: custom URL scheme handling",
             "Custom URL scheme(s) registered",
             "MEDIUM",
             f"The app registers {len(schemes)} custom URL scheme(s). Any app can register the same scheme "
             "and hijack it, and unvalidated scheme input is a common source of logic-abuse or injection bugs.",
             evidence=", ".join(schemes),
             manual=True,
             recommendation="Prefer Universal Links over custom schemes where possible. If a scheme is kept, "
                            "strictly validate/allow-list all incoming parameters and never trigger sensitive "
                            "actions (auth, payments) directly from a URL without user confirmation.")


def _check_file_sharing(plist, report):
    file_sharing = plist.get("UIFileSharingEnabled", False)
    docs_in_place = plist.get("LSSupportsOpeningDocumentsInPlace", False)
    if file_sharing:
        _add(report, "STORAGE-01", "STORAGE", "MASTG-TEST: iTunes/Files file sharing",
             "UIFileSharingEnabled is true",
             "MEDIUM",
             "The app's Documents directory is exposed via the Files app / iTunes file sharing. Any sensitive "
             "file placed there is directly accessible to the device user without jailbreak.",
             recommendation="Disable UIFileSharingEnabled unless the exposed files are meant to be user-"
                            "accessible, and never store sensitive data in the exposed Documents directory.")
    if docs_in_place:
        _add(report, "STORAGE-01b", "STORAGE", "MASTG-TEST: document provider exposure",
             "LSSupportsOpeningDocumentsInPlace is true", "LOW",
             "The app exposes its documents to other apps/the Files app for in-place editing.", manual=True)


def _check_entitlements(app_dir, report):
    ent_files = glob.glob(os.path.join(app_dir, "*.entitlements"))
    embedded_provision = os.path.join(app_dir, "embedded.mobileprovision")
    found_debug = False
    keychain_groups = []

    text_blob = ""
    for f in ent_files:
        try:
            with open(f, "rb") as fh:
                text_blob += fh.read().decode("utf-8", "ignore")
        except Exception:
            pass
    if os.path.exists(embedded_provision):
        try:
            with open(embedded_provision, "rb") as fh:
                text_blob += fh.read().decode("utf-8", "ignore")
        except Exception:
            pass

    if "get-task-allow" in text_blob and re.search(r"<key>get-task-allow</key>\s*<true/>", text_blob):
        found_debug = True

    kc = re.findall(r"<string>([^<]*keychain-access-groups[^<]*)</string>", text_blob)
    keychain_groups = re.findall(r"keychain-access-groups.*?(?:<array>(.*?)</array>)", text_blob, re.S)

    if found_debug:
        _add(report, "CODE-01", "CODE", "MASTG-TEST: get-task-allow entitlement",
             "get-task-allow entitlement is true",
             "CRITICAL",
             "The embedded provisioning/entitlements grant get-task-allow=true, meaning the binary is "
             "debuggable by any attached debugger even outside Xcode. This should never be present in an "
             "App Store / production build.",
             recommendation="Rebuild with a distribution provisioning profile (get-task-allow=false).")
    else:
        _add(report, "CODE-01", "CODE", "MASTG-TEST: get-task-allow entitlement",
             "No debug entitlement detected", "PASS",
             "get-task-allow was not found set to true in available entitlement/provisioning data.",
             manual=not ent_files and not os.path.exists(embedded_provision))

    if keychain_groups:
        _add(report, "STORAGE-02", "STORAGE", "MASTG-TEST: keychain access groups",
             "Keychain access groups declared", "INFO",
             "The app declares keychain-access-groups, used to share Keychain items across an app family or "
             "with extensions. Confirm the group is scoped to only the apps that need it.",
             manual=True)


def _analyze_macho(binary_path, report):
    """Read Mach-O header to detect PIE and encryption info. Returns a dict of flags."""
    info = {"pie": None, "encrypted": None, "arch_count": 0, "error": None}
    try:
        with open(binary_path, "rb") as f:
            data = f.read(4)
            magic = struct.unpack(">I", data)[0]
            if magic in FAT_MAGICS:
                # fat binary -- just note arch count, PIE/encryption checked on first slice
                f.seek(0)
                header = f.read(8)
                _, nfat = struct.unpack(">II", header)
                info["arch_count"] = nfat
                # jump to first arch's offset
                arch_hdr = f.read(20)
                cputype, cpusubtype, offset, size, align = struct.unpack(">IIIII", arch_hdr)
                f.seek(offset)
                magic_bytes = f.read(4)
                magic2 = struct.unpack(">I", magic_bytes)[0]
                _parse_macho_slice(f, magic2, info)
            elif magic in MACHO_MAGICS:
                info["arch_count"] = 1
                f.seek(0)
                _parse_macho_slice(f, magic, info)
            else:
                info["error"] = "unrecognized binary format"
    except Exception as e:
        info["error"] = str(e)
    return info


def _parse_macho_slice(f, magic, info):
    little = magic in (0xcefaedfe, 0xcffaedfe)
    is64 = magic in (0xfeedfacf, 0xcffaedfe)
    endian = "<" if little else ">"
    f.seek(f.tell() - 4)
    if is64:
        fmt = endian + "IiiIIIII"
        size = struct.calcsize(fmt)
        magic_, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(fmt, f.read(size))
    else:
        fmt = endian + "IiiIIII"
        size = struct.calcsize(fmt)
        magic_, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(fmt, f.read(size))

    MH_PIE = 0x200000
    info["pie"] = bool(flags & MH_PIE)

    # walk load commands looking for LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64
    LC_ENCRYPTION_INFO = 0x21
    LC_ENCRYPTION_INFO_64 = 0x2C
    for _ in range(ncmds):
        cmd_hdr = f.read(8)
        if len(cmd_hdr) < 8:
            break
        cmd, cmdsize = struct.unpack(endian + "II", cmd_hdr)
        body = f.read(cmdsize - 8)
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            try:
                cryptoff, cryptsize, cryptid = struct.unpack(endian + "III", body[:12])
                info["encrypted"] = bool(cryptid)
            except Exception:
                pass


def _check_binary_protections(macho_findings, report):
    if macho_findings.get("error"):
        _add(report, "CODE-02", "CODE", "MASTG-TEST: binary hardening (PIE)",
             "Could not parse Mach-O binary", "INFO", macho_findings["error"], manual=True)
        return

    if macho_findings.get("pie") is False:
        _add(report, "CODE-02", "CODE", "MASTG-TEST: binary hardening (PIE)",
             "Binary compiled without PIE (Position Independent Executable)",
             "HIGH",
             "The main executable does not set the PIE flag, disabling ASLR for the binary's own image and "
             "making memory-corruption exploits significantly easier to build reliably.",
             recommendation="Rebuild with PIE enabled (default in modern Xcode; check custom linker flags "
                            "like -no_pie).")
    elif macho_findings.get("pie") is True:
        _add(report, "CODE-02", "CODE", "MASTG-TEST: binary hardening (PIE)",
             "PIE enabled", "PASS", "The main executable is position-independent (ASLR-compatible).")

    encrypted = macho_findings.get("encrypted")
    if encrypted is False:
        _add(report, "RESILIENCE-02", "RESILIENCE", "MASTG-TEST: FairPlay binary encryption",
             "Binary is not FairPlay-encrypted (cryptid=0)",
             "INFO",
             "The LC_ENCRYPTION_INFO load command has cryptid=0. This is normal for locally-built/ad-hoc/"
             "enterprise IPAs and for IPAs already decrypted for analysis; a real App Store download is "
             "encrypted until launched on-device. Not itself exploitable, but confirm this matches the "
             "expected distribution channel.",
             manual=True)


def _check_secrets_and_crypto(all_text, report):
    secrets = scan_secrets_in_text(all_text)
    if secrets:
        lines = [f"{name} x{count}: " + ", ".join(samples) for name, count, samples in secrets]
        _add(report, "STORAGE-03", "STORAGE", "MASTG-TEST: hardcoded secrets in app package",
             "Hardcoded secrets / API keys found in binary or bundle",
             "HIGH",
             f"Pattern-matching across Info.plist, the main binary and embedded frameworks found "
             f"{len(secrets)} class(es) of likely hardcoded secret. Confirm each manually -- some may be "
             "intentionally-public SDK identifiers.",
             evidence="\n".join(lines), manual=True,
             recommendation="Move genuine secrets server-side; never ship long-lived credentials in the "
                            "client binary or bundle resources.")
    else:
        _add(report, "STORAGE-03", "STORAGE", "MASTG-TEST: hardcoded secrets in app package",
             "No obvious hardcoded secrets found by pattern matching", "PASS",
             "No matches for common secret/key formats were found.", manual=True)

    weak = scan_weak_crypto(all_text)
    if weak:
        lines = [f"{name} (matched {n}x)" for name, n in weak]
        _add(report, "CRYPTO-01", "CRYPTO", "MASTG-TEST: cryptographic algorithm usage",
             "References to weak/deprecated cryptographic primitives or Keychain settings",
             "MEDIUM",
             "String scanning of the binary found references associated with weak cryptography or a weak "
             "Keychain accessibility constant. Presence indicates linkage, not confirmed usage.",
             evidence="\n".join(lines), manual=True,
             recommendation="Use CryptoKit/CommonCrypto with AES-GCM and SHA-256+; avoid always-accessible "
                            "Keychain items.")


def _check_keychain_accessibility(all_text, report):
    if "kSecAttrAccessibleAlways" in all_text and "kSecAttrAccessibleAlwaysThisDeviceOnly" not in all_text.replace("kSecAttrAccessibleAlways", "", 1):
        pass  # already covered by weak-crypto pattern; avoid duplicate noisy finding


def _check_jailbreak_detection(all_text, report):
    present = scan_symbols(all_text, ROOT_JAILBREAK_DETECTION_SYMBOLS)
    if present:
        _add(report, "RESILIENCE-01", "RESILIENCE", "MASTG-TEST: jailbreak detection",
             "Jailbreak-detection related strings/symbols present", "PASS",
             "Symbols/strings associated with jailbreak detection were found. Effectiveness must be verified "
             "dynamically -- static jailbreak checks are commonly bypassed with tools like Frida or "
             "Liberty/Shadow.",
             evidence=", ".join(present), manual=True)
    else:
        _add(report, "RESILIENCE-01", "RESILIENCE", "MASTG-TEST: jailbreak detection",
             "No jailbreak-detection logic detected", "LOW",
             "No common jailbreak-detection paths/symbols were found. Consider adding checks as a "
             "defense-in-depth layer for high-risk apps (payments, banking, health).",
             recommendation="Add jailbreak-detection heuristics (suspicious file paths, sandbox write test, "
                            "dyld injected libraries) combined with server-side risk signals, not as the sole "
                            "control.")


def _check_cert_pinning(all_text, report):
    present = scan_symbols(all_text, CERT_PINNING_SYMBOLS)
    if present:
        _add(report, "NETWORK-04", "NETWORK", "MASTG-TEST: certificate/public-key pinning",
             "Certificate pinning related symbols found", "PASS",
             "Symbols associated with certificate/public-key pinning were found in the binary. Confirm pinning "
             "is enforced for all endpoints handling sensitive data.",
             evidence=", ".join(present), manual=True)
    else:
        _add(report, "NETWORK-04", "NETWORK", "MASTG-TEST: certificate/public-key pinning",
             "No certificate pinning detected", "MEDIUM",
             "No pinning-related symbols were found in the binary. The app likely relies solely on the "
             "system trust store.",
             recommendation="Add certificate or public-key pinning (URLSession delegate + SecTrust evaluation, "
                            "or a library such as TrustKit) for sensitive endpoints.")


def _check_privacy_usage_strings(plist, report):
    usage_keys = [k for k in plist.keys() if k.startswith("NS") and k.endswith("UsageDescription")]
    missing_generic = [k for k in usage_keys if len(str(plist.get(k, "")).strip()) < 10]
    if missing_generic:
        _add(report, "PRIVACY-01", "PRIVACY", "MASTG-TEST: purpose strings for sensitive APIs",
             "Weak or placeholder privacy usage-description strings",
             "LOW",
             "One or more Info.plist *UsageDescription keys are empty or unusually short, which App Store "
             "review may reject and which gives the user little context for a permission prompt.",
             evidence=", ".join(missing_generic),
             recommendation="Write a clear, specific purpose string for every requested sensitive API.")
    if not usage_keys:
        _add(report, "PRIVACY-01", "PRIVACY", "MASTG-TEST: purpose strings for sensitive APIs",
             "No sensitive-API usage-description keys present", "INFO",
             "No NS*UsageDescription keys were found -- the app likely does not request camera/location/"
             "contacts/etc. Confirm this matches expected functionality.", manual=True)


# ---------------------------------------------------------------------------
# Additional OWASP Mobile Top 10 (2024) coverage
# ---------------------------------------------------------------------------

def _check_tls_bypass(all_text, report):
    present = scan_symbols(all_text, TLS_BYPASS_SYMBOLS)
    empty_trust = TRUST_ALL_HEURISTIC_RE.search(all_text) is not None
    if empty_trust or "kCFStreamSSLAllowsExpiredCertificates" in all_text or "kCFStreamSSLAllowsAnyRoot" in all_text:
        _add(report, "NETWORK-05", "NETWORK", "MASTG-TEST: TLS trust validation bypass",
             "Certificate validation bypass indicators found",
             "CRITICAL" if empty_trust else "HIGH",
             "Strings associated with disabling certificate validation (accepting expired/any-root "
             "certificates, or an empty-bodied trust callback) were found. If active, this defeats TLS and "
             "enables trivial MITM.",
             evidence=", ".join(present) or "kCFStreamSSLAllowsExpiredCertificates/kCFStreamSSLAllowsAnyRoot",
             recommendation="Remove any certificate-validation bypass from production builds; use "
                            "URLSession's default validation plus pinning for sensitive endpoints.")
    elif present:
        _add(report, "NETWORK-05", "NETWORK", "MASTG-TEST: TLS trust validation bypass",
             "Symbols associated with TLS challenge handling found",
             "LOW",
             "Code references URLSession challenge-handling APIs. These are also used for legitimate pinning "
             "-- manually confirm the challenge handler doesn't call completionHandler(.useCredential, ...) "
             "unconditionally.",
             evidence=", ".join(present), manual=True)
    else:
        _add(report, "NETWORK-05", "NETWORK", "MASTG-TEST: TLS trust validation bypass",
             "No TLS/certificate-validation bypass patterns found", "PASS",
             "No trust-all or certificate-bypass patterns were detected in extracted strings.")


def _check_supply_chain(all_text, app_dir, report):
    sdks = detect_third_party_sdks(all_text)
    frameworks = []
    fw_dir = os.path.join(app_dir, "Frameworks")
    if os.path.isdir(fw_dir):
        frameworks = [f for f in os.listdir(fw_dir) if f.endswith((".framework", ".dylib"))]

    if sdks or frameworks:
        evidence_parts = []
        if sdks:
            evidence_parts.append("SDK signatures: " + ", ".join(sorted(sdks)))
        if frameworks:
            evidence_parts.append("Embedded frameworks: " + ", ".join(sorted(frameworks)[:25]))
        _add(report, "SUPPLY-01", "CODE", "MASTG-TEST: third-party SDK / dependency inventory",
             f"{len(sdks)} SDK signature(s), {len(frameworks)} embedded framework(s) identified",
             "INFO",
             "Static inventory of embedded frameworks and known SDK string signatures. Each is a supply-"
             "chain trust dependency -- confirm versions are current/patched and disclosed in the app's "
             "privacy manifest and App Store privacy labels.",
             evidence="\n".join(evidence_parts), manual=True,
             recommendation="Maintain an SBOM for embedded SDKs/frameworks, track CVEs, and remove unused "
                            "dependencies.")


def _check_privacy_manifest(app_dir, plist, all_text, report):
    has_privacy_manifest = os.path.exists(os.path.join(app_dir, "PrivacyInfo.xcprivacy"))
    tracking_symbols = scan_symbols(all_text, TRACKING_SYMBOLS)
    has_att_usage_string = bool(plist.get("NSUserTrackingUsageDescription"))

    if tracking_symbols and not has_att_usage_string:
        _add(report, "PRIVACY-02", "PRIVACY", "MASTG-TEST: App Tracking Transparency compliance",
             "Tracking-related APIs referenced without an ATT usage string",
             "MEDIUM",
             "The app references advertising/tracking identifier APIs (IDFA/ASIdentifierManager) but "
             "Info.plist has no NSUserTrackingUsageDescription. Apple requires the App Tracking Transparency "
             "prompt (with this string) before accessing IDFA or otherwise tracking across apps.",
             evidence=", ".join(tracking_symbols), manual=True,
             recommendation="Add NSUserTrackingUsageDescription and call ATTrackingManager."
                            "requestTrackingAuthorization before any cross-app tracking, or remove the "
                            "tracking code if unused.")
    elif tracking_symbols:
        _add(report, "PRIVACY-02", "PRIVACY", "MASTG-TEST: App Tracking Transparency compliance",
             "Tracking APIs referenced alongside an ATT usage string", "PASS",
             "NSUserTrackingUsageDescription is present alongside tracking-related symbols.",
             evidence=", ".join(tracking_symbols), manual=True)

    if not has_privacy_manifest:
        _add(report, "PRIVACY-03", "PRIVACY", "MASTG-TEST: Apple Privacy Manifest presence",
             "No PrivacyInfo.xcprivacy privacy manifest found",
             "LOW",
             "Apple now requires a privacy manifest declaring data collection and 'required reason' API usage "
             "for apps and, since 2024, for many common third-party SDKs. Its absence may cause App Store "
             "submission warnings/rejections and signals incomplete privacy documentation.",
             recommendation="Add PrivacyInfo.xcprivacy declaring collected data types and required-reason "
                            "API usage; verify each embedded third-party SDK ships its own manifest too.")
    else:
        _add(report, "PRIVACY-03", "PRIVACY", "MASTG-TEST: Apple Privacy Manifest presence",
             "Privacy manifest present", "PASS", "PrivacyInfo.xcprivacy was found in the app bundle.")


def _check_tracking_and_clipboard(all_text, report):
    clipboard = scan_symbols(all_text, CLIPBOARD_SYMBOLS)
    screen_protect = scan_symbols(all_text, SCREEN_PROTECTION_SYMBOLS)

    if clipboard:
        _add(report, "PRIVACY-02b", "PRIVACY", "MASTG-TEST: clipboard (UIPasteboard) access",
             "UIPasteboard access referenced",
             "LOW",
             "The app reads or writes the system pasteboard. Avoid copying secrets (passwords, OTPs) to it, "
             "and avoid reading it unless the feature genuinely requires it -- iOS surfaces a paste "
             "notification banner, but contents can still be sensitive.",
             evidence=", ".join(clipboard), manual=True)

    if "ignoreSnapshotOnNextApplicationLaunch" not in all_text:
        _add(report, "PRIVACY-02c", "PRIVACY", "MASTG-TEST: app-switcher snapshot exposure",
             "No app-switcher snapshot redaction detected",
             "LOW",
             "No call to ignoreSnapshotOnNextApplicationLaunch (or an equivalent blur-on-background pattern) "
             "was found. Screens with sensitive data will appear in the iOS app-switcher snapshot / "
             "background thumbnail unless explicitly obscured.",
             manual=True,
             recommendation="Blur or replace sensitive screens with a placeholder view when the app enters "
                            "the background (applicationDidEnterBackground / scene willResignActive).")


def _check_anti_debug_frida(all_text, report):
    anti_debug = scan_symbols(all_text, ANTI_DEBUG_SYMBOLS)
    anti_frida = scan_symbols(all_text, ANTI_FRIDA_SYMBOLS)
    if anti_debug or anti_frida:
        _add(report, "RESILIENCE-02", "RESILIENCE", "MASTG-TEST: anti-debugging / anti-instrumentation",
             "Anti-debugging or anti-instrumentation checks present", "PASS",
             "Symbols associated with ptrace-based debugger detection or Frida/instrumentation detection "
             "were found. Effectiveness must be verified dynamically -- these are commonly bypassed unless "
             "layered and combined with server-side attestation (e.g. DeviceCheck/App Attest).",
             evidence=", ".join(anti_debug + anti_frida), manual=True)
    else:
        _add(report, "RESILIENCE-02", "RESILIENCE", "MASTG-TEST: anti-debugging / anti-instrumentation",
             "No anti-debugging/anti-instrumentation logic detected",
             "LOW",
             "No common ptrace-based debugger-detection or Frida-detection symbols were found.",
             recommendation="Add debugger/instrumentation resistance for high-value apps, combined with "
                            "server-side attestation (App Attest/DeviceCheck) rather than client checks alone.")


def _check_test_endpoints(all_text, report):
    hits = []
    for pattern in TEST_ENDPOINT_PATTERNS:
        found = set(re.findall(pattern, all_text, re.IGNORECASE))
        hits += list(found)[:5]
    if hits:
        _add(report, "CODE-08", "CODE", "MASTG-TEST: leftover debug/staging endpoints",
             "Development/staging/local endpoints found in release package",
             "MEDIUM",
             "The binary/bundle contains references to staging/dev/test/localhost endpoints. If shipped in a "
             "production build, these can point to less-secured backends or leak internal infrastructure "
             "details.",
             evidence=", ".join(sorted(set(hits))[:15]), manual=True,
             recommendation="Strip all non-production endpoint references from release builds via build "
                            "configurations, not just runtime environment switches.")


def _check_storage_indicators(app_dir, all_text, report):
    ext_hint = scan_symbols(all_text, EXTERNAL_STORAGE_SYMBOLS)  # mostly Android-flavored but harmless to check
    good_accessibility = scan_symbols(all_text, KEYCHAIN_GOOD_ACCESSIBILITY)
    backup_excl = scan_symbols(all_text, BACKUP_EXCLUSION_SYMBOLS)
    has_realm = "io.realm" in all_text.lower() or "realm" in all_text.lower()
    has_realm_encryption = "encryptionKey" in all_text or "RLMRealmConfiguration" in all_text and "encryptionKey" in all_text

    if "kSecClass" in all_text and not good_accessibility:
        _add(report, "STORAGE-04", "STORAGE", "MASTG-TEST: Keychain accessibility level",
             "Keychain usage found without a restrictive accessibility constant",
             "LOW",
             "The app uses the Keychain (kSecClass) but no restrictive accessibility constant "
             "(*ThisDeviceOnly) was found in strings, so items may be using a broader default and could be "
             "included in iCloud Keychain sync or accessible before first unlock, depending on configuration.",
             manual=True,
             recommendation="Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or stricter) for sensitive "
                            "Keychain items so they never leave the device via backup/sync.")

    if not backup_excl:
        _add(report, "STORAGE-04b", "STORAGE", "MASTG-TEST: iTunes/iCloud backup exclusion",
             "No explicit backup-exclusion attribute usage detected",
             "LOW",
             "No reference to NSURLIsExcludedFromBackupKey was found. Any sensitive file written to the "
             "Documents/Library directory without this attribute will be included in iTunes/iCloud device "
             "backups.",
             manual=True,
             recommendation="Set the 'do not back up' resource attribute on any file containing sensitive/"
                            "cached data, or store it in a Keychain item instead.")

    if has_realm and not has_realm_encryption:
        _add(report, "STORAGE-04c", "STORAGE", "MASTG-TEST: local database encryption (Realm)",
             "Realm database usage found with no encryption key configuration detected",
             "MEDIUM",
             "The app appears to use Realm for local storage, but no encryptionKey configuration was found "
             "in extracted strings. Unencrypted Realm files are readable in plaintext given filesystem "
             "access.",
             manual=True,
             recommendation="Configure Realm with an encryption key stored in the Keychain for any database "
                            "holding sensitive data.")


def _check_biometric_auth(all_text, report):
    biometric = scan_symbols(all_text, BIOMETRIC_SYMBOLS)
    crypto_binding = scan_symbols(all_text, BIOMETRIC_CRYPTO_BINDING_SYMBOLS)
    if biometric and not crypto_binding:
        _add(report, "AUTH-01", "AUTH", "MASTG-TEST: biometric authentication implementation",
             "Biometric prompt (LAContext) used without visible Keychain/SecAccessControl binding",
             "MEDIUM",
             "LAContext/evaluatePolicy is referenced, but no SecAccessControl biometry binding "
             "(kSecAccessControlBiometryAny or similar) was found. A biometric check used only as a boolean "
             "gate -- rather than to unlock a Keychain item protected by SecAccessControl -- can potentially "
             "be bypassed by manipulating the evaluatePolicy completion handler at runtime.",
             evidence=", ".join(biometric), manual=True,
             recommendation="Protect sensitive Keychain items with SecAccessControl + kSecAccessControlBiometryAny "
                            "(or .biometryCurrentSet) so the OS -- not app logic -- enforces the biometric gate.")
    elif biometric:
        _add(report, "AUTH-01", "AUTH", "MASTG-TEST: biometric authentication implementation",
             "Biometric authentication with SecAccessControl binding indicators found", "PASS",
             "LAContext usage is accompanied by SecAccessControl/biometry-binding symbols, suggesting "
             "(not confirming) proper Keychain-backed binding. Verify manually.",
             evidence=", ".join(biometric + crypto_binding), manual=True)


def _check_deserialization(all_text, report):
    present = scan_symbols(all_text, DESERIALIZATION_SYMBOLS)
    if present:
        _add(report, "CODE-07", "CODE", "MASTG-TEST: insecure deserialization",
             "NSKeyedUnarchiver / native deserialization APIs referenced",
             "MEDIUM",
             "NSKeyedUnarchiver or similar deserialization APIs were found. If used on data from an untrusted "
             "source (network, pasteboard, inter-app file) without secure coding "
             "(requiresSecureCoding/decodeObjectOfClass), this can allow arbitrary object instantiation.",
             evidence=", ".join(present), manual=True,
             recommendation="Use NSSecureCoding with an explicit allowed-class list, or a safe format (JSON) "
                            "with strict schema validation, for any untrusted serialized data.")
