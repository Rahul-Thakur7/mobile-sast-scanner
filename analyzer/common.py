import re
import math
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    check_id: str            # e.g. "STORAGE-01"
    category: str            # MASVS category key, e.g. "STORAGE"
    mastg_ref: str           # short human label, e.g. "MASTG local-storage tests"
    title: str
    severity: str             # CRITICAL / HIGH / MEDIUM / LOW / INFO / PASS
    description: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    manual: bool = False      # True => static tool cannot conclusively verify, needs manual/dynamic test
    top10: Optional[str] = None   # OWASP Mobile Top 10 (2024) ID, e.g. "M9"


@dataclass
class Report:
    app_name: str = ""
    package_id: str = ""
    version: str = ""
    platform: str = ""
    file_name: str = ""
    file_size: int = 0
    sha256: str = ""
    min_os: str = ""
    target_os: str = ""
    permissions: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def add(self, f: Finding):
        self.findings.append(f)


# ---------------------------------------------------------------------------
# Shared heuristics used by both the Android and iOS analyzers
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("AWS Access Key",        r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key (heuristic)", r"(?i)aws(.{0,20})?(secret|access)[_-]?key(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API Key",        r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth Token",    r"ya29\.[0-9A-Za-z\-_]+"),
    ("Firebase DB URL",       r"[a-z0-9-]+\.firebaseio\.com"),
    ("Slack Token",           r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    ("Stripe Live Key",       r"sk_live_[0-9a-zA-Z]{24,}"),
    ("PayPal/Braintree Token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("Generic Bearer/JWT",    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("Private Key Block",     r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----"),
    ("Hardcoded Password Var", r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{4,}['\"]"),
    ("Hardcoded Secret Var",  r"(?i)(secret|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
    ("Basic Auth in URL",     r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("Generic High-Entropy Token", r"(?i)(token|apikey|api_key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{24,}['\"]"),
]

WEAK_CRYPTO_PATTERNS = [
    ("DES",  r"\bDES/[A-Za-z0-9]+/[A-Za-z0-9]+\b|\bDESede\b"),
    ("RC4",  r"\bRC4\b"),
    ("MD5 as security hash", r"MessageDigest\.getInstance\(\s*[\"']MD5[\"']"),
    ("SHA-1 as security hash", r"MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']"),
    ("AES-ECB", r"AES/ECB"),
    ("Static IV (heuristic)", r"IvParameterSpec\(\s*new byte"),
    ("Insecure Random", r"\bjava\.util\.Random\b"),
    ("kSecAttrAccessibleAlways", r"kSecAttrAccessibleAlways\b(?!This)"),
    ("Hardcoded SecretKeySpec", r"SecretKeySpec\(\s*[\"'][0-9A-Za-z+/=]{8,}[\"']"),
    ("Weak SSL/TLS protocol", r"SSLContext\.getInstance\(\s*[\"'](SSL|TLSv1)[\"']\s*\)|SSLContext\.getInstance\(\s*[\"']TLSv1\.1?[\"']\s*\)"),
    ("Custom (weak) hash rounds", r"for\s*\(\s*int\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*1\s*;"),
]

CLEARTEXT_URL_RE = re.compile(r"http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^\s'\"<>]*")

WEBVIEW_RISK_SYMBOLS = [
    "addJavascriptInterface",
    "setJavaScriptEnabled",
    "setAllowFileAccess",
    "setAllowFileAccessFromFileURLs",
    "setAllowUniversalAccessFromFileURLs",
    "setMixedContentMode",
    "evaluateJavascript",
    "onReceivedSslError",
    "shouldOverrideUrlLoading",
]

ROOT_JAILBREAK_DETECTION_SYMBOLS = [
    "RootBeer", "isDeviceRooted", "checkRootMethod", "magisk", "com.noshufou.android.su",
    "Superuser.apk", "test-keys", "/system/app/Superuser.apk",
    "Cydia.app", "MobileSubstrate", "/private/var/lib/apt", "jailbreak", "isJailbroken",
]

CERT_PINNING_SYMBOLS = [
    "CertificatePinner", "X509TrustManager", "TrustManagerFactory",
    "NSURLSessionPinningDelegate", "SecTrustEvaluate", "kSSLSessionOptionBreakOnServerAuth",
    "certificatePinner", "PinningTrustManager",
]

# --- M5: Insecure Communication -- TLS/cert-validation bypass indicators ---
TLS_BYPASS_SYMBOLS = [
    "ALLOW_ALL_HOSTNAME_VERIFIER",
    "SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER",
    "NullHostnameVerifier",
    "checkClientTrusted",       # presence alone isn't proof, paired with empty-body heuristic below
    "checkServerTrusted",
    "setHostnameVerifier",
    "X509TrustManager() {",     # inline anonymous TrustManager -- common trust-all pattern
    "return true; // always trust",
    "kCFStreamSSLAllowsExpiredCertificates",
    "kCFStreamSSLAllowsAnyRoot",
    "NSURLSession:didReceiveChallenge",
    "continueWithoutCredential",
]
TRUST_ALL_HEURISTIC_RE = re.compile(
    r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}", re.S)  # empty-body TrustManager override

# --- M4: Insufficient Input/Output Validation ---
SQLI_PATTERNS = [
    ("rawQuery/execSQL with string concatenation", r"(rawQuery|execSQL)\s*\(\s*[\"'][^\"']*\"\s*\+"),
    ("String.format used to build SQL", r"String\.format\([^)]*(SELECT|INSERT|UPDATE|DELETE)[^)]*%s"),
]
XXE_SYMBOLS = ["DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory"]
XXE_SAFE_SYMBOLS = ["FEATURE_SECURE_PROCESSING", "disallow-doctype-decl", "setExpandEntityReferences"]
DESERIALIZATION_SYMBOLS = ["ObjectInputStream", "readObject", "NSKeyedUnarchiver", "unarchiveObjectWithData"]
PATH_TRAVERSAL_RE = re.compile(r"(\.\./){2,}|getExternalFilesDir\([^)]*\)\s*\+\s*\w*\+")

# --- M2: Inadequate Supply Chain Security -- common 3rd-party SDK package fragments ---
THIRD_PARTY_SDK_SIGNATURES = {
    "Firebase / Google Analytics":     ["com.google.firebase", "com.google.android.gms.analytics"],
    "Google AdMob / Ads":              ["com.google.android.gms.ads"],
    "Facebook SDK":                    ["com.facebook.appevents", "com.facebook.FacebookSdk"],
    "AppsFlyer":                       ["com.appsflyer"],
    "Adjust":                          ["com.adjust.sdk"],
    "Branch.io":                       ["io.branch.referral"],
    "Crashlytics / Firebase Crash":    ["com.crashlytics", "com.google.firebase.crashlytics"],
    "OkHttp":                          ["com.squareup.okhttp", "okhttp3"],
    "Retrofit":                        ["retrofit2"],
    "Realm DB":                        ["io.realm"],
    "SQLCipher (encrypted DB)":        ["net.sqlcipher", "SQLCipher"],
    "Braintree/PayPal SDK":            ["com.braintreepayments", "com.paypal"],
    "Segment":                         ["com.segment.analytics"],
    "Mixpanel":                        ["com.mixpanel.android"],
    "Amplitude":                       ["com.amplitude.api"],
    "Unity Ads / Unity Engine":        ["com.unity3d"],
    "AppLovin":                        ["com.applovin"],
}

# --- M6: Inadequate Privacy Controls -- tracking / advertising indicators ---
TRACKING_SYMBOLS = [
    "AdvertisingIdClient", "getAdvertisingIdInfo", "ASIdentifierManager", "advertisingIdentifier",
    "IDFA", "GAID", "AppTrackingTransparency", "requestTrackingAuthorization",
]
CLIPBOARD_SYMBOLS = ["ClipboardManager", "UIPasteboard"]
SCREEN_PROTECTION_SYMBOLS = ["FLAG_SECURE", "ignoreSnapshotOnNextApplicationLaunch"]

# --- M7: Insufficient Binary Protections -- anti-debug / anti-instrumentation ---
ANTI_DEBUG_SYMBOLS = [
    "Debug.isDebuggerConnected", "isDebuggerConnected", "ptrace", "P_TRACED", "sysctl",
    "android.os.Debug", "TracerPid",
]
ANTI_FRIDA_SYMBOLS = ["frida-server", "gum-js-loop", "gmain", "FridaGadget", "frida-agent", "re.frida.server"]

# --- M8: Security Misconfiguration -- leftover debug/test endpoints ---
TEST_ENDPOINT_PATTERNS = [
    r"https?://(staging|stage|dev|test|qa|uat)[.-][a-zA-Z0-9\-\.]+",
    r"https?://10\.0\.2\.2(:\d+)?",           # Android emulator loopback to host
    r"https?://[a-zA-Z0-9\-]+\.ngrok\.io",
    r"https?://localhost(:\d+)?",
]
WORLD_PERM_SYMBOLS = ["MODE_WORLD_READABLE", "MODE_WORLD_WRITEABLE"]

# --- M9: Insecure Data Storage ---
EXTERNAL_STORAGE_SYMBOLS = ["getExternalStorageDirectory", "Environment.getExternalStorageDirectory", "WRITE_EXTERNAL_STORAGE"]
UNENCRYPTED_DB_HINT_SYMBOLS = ["CREATE TABLE", "openOrCreateDatabase", "SQLiteOpenHelper"]
KEYCHAIN_GOOD_ACCESSIBILITY = ["kSecAttrAccessibleWhenUnlockedThisDeviceOnly", "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"]
BACKUP_EXCLUSION_SYMBOLS = ["NSURLIsExcludedFromBackupKey", "addSkipBackupAttribute"]

# --- M3: Insecure Authentication/Authorization ---
BIOMETRIC_SYMBOLS = ["BiometricPrompt", "FingerprintManager", "LAContext", "evaluatePolicy"]
BIOMETRIC_CRYPTO_BINDING_SYMBOLS = ["setUserAuthenticationRequired", "CryptoObject", "kSecAccessControlBiometryAny"]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    occur = {}
    for b in data:
        occur[b] = occur.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in occur.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_printable_strings(data: bytes, min_len: int = 5) -> List[str]:
    """Very fast ASCII string extraction (like `strings` binary)."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [m.decode("ascii", errors="ignore") for m in pattern.findall(data)]


def scan_secrets_in_text(all_text: str, max_hits_per_pattern: int = 5):
    hits = []
    for name, pattern in SECRET_PATTERNS:
        found = set(re.findall(pattern, all_text))
        if found:
            sample = list(found)[:max_hits_per_pattern]
            redacted = [s if len(s) < 12 else s[:6] + "…redacted…" + s[-4:] for s in sample]
            hits.append((name, len(found), redacted))
    return hits


def scan_weak_crypto(all_text: str):
    hits = []
    for name, pattern in WEAK_CRYPTO_PATTERNS:
        n = len(re.findall(pattern, all_text))
        if n:
            hits.append((name, n))
    return hits


def scan_symbols(all_text: str, symbol_list: List[str]):
    present = []
    for sym in symbol_list:
        if sym in all_text:
            present.append(sym)
    return present


def detect_third_party_sdks(all_text: str):
    found = []
    for sdk_name, sigs in THIRD_PARTY_SDK_SIGNATURES.items():
        if any(sig in all_text for sig in sigs):
            found.append(sdk_name)
    return found


def scan_regex_list(all_text: str, pattern_list):
    """pattern_list: list of (name, regex) tuples. Returns [(name, match_count)]."""
    hits = []
    for name, pattern in pattern_list:
        n = len(re.findall(pattern, all_text))
        if n:
            hits.append((name, n))
    return hits


def scan_cleartext_urls(all_text: str, limit: int = 15):
    urls = sorted(set(CLEARTEXT_URL_RE.findall(all_text)))
    # filter obvious noise like schema URLs / xml namespaces
    urls = [u for u in urls if "w3.org" not in u and "schemas.android.com" not in u
            and "xmlpull.org" not in u and "apple.com/DTDs" not in u]
    return urls[:limit], len(urls)
