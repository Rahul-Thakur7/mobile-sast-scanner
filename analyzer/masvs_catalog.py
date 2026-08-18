"""
Catalog of check IDs mapped to the OWASP MASVS 2.x categories and the
corresponding OWASP MASTG test areas. This is used purely to LABEL findings
produced by this tool's own static analysis -- it does not claim to
reproduce OWASP's text, and it does not claim to be a complete or official
MASTG run. Full MASTG coverage requires manual + dynamic testing on a real
device; this tool automates the static-analysis slice of that work and
flags everything else as "manual verification needed".

Reference: OWASP MASVS 2.x categories (owasp.org/www-project-mobile-app-security)
  MASVS-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK,
  MASVS-PLATFORM, MASVS-CODE, MASVS-RESILIENCE, MASVS-PRIVACY
"""

MASVS_CATEGORIES = {
    "STORAGE": "Secure storage of sensitive data at rest",
    "CRYPTO": "Use of cryptography",
    "AUTH": "Authentication & session management",
    "NETWORK": "Network communication security (data-in-transit)",
    "PLATFORM": "Platform interaction (IPC, permissions, WebViews)",
    "CODE": "Code quality & build configuration",
    "RESILIENCE": "Anti-tampering / anti-reverse-engineering",
    "PRIVACY": "Data collection & privacy controls",
}

# OWASP Mobile Top 10 (2024 release) -- github.com/OWASP/www-project-mobile-top-10
MOBILE_TOP10 = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]

SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0, "PASS": 0}

# Default OWASP Mobile Top 10 (2024) mapping applied automatically by check_id prefix,
# used whenever a check doesn't pass an explicit top10= value.
CHECK_ID_TOP10_DEFAULTS = {
    "CODE-00": "M8", "CODE-01": "M8", "CODE-02": "M8", "CODE-03": "M8", "CODE-04": "M7",
    "CODE-05": "M4", "CODE-06": "M4", "CODE-07": "M4", "CODE-08": "M8",
    "STORAGE-01": "M9", "STORAGE-01b": "M9", "STORAGE-02": "M1", "STORAGE-03": "M9",
    "NETWORK-01": "M5", "NETWORK-01b": "M5", "NETWORK-02": "M5", "NETWORK-03": "M5",
    "NETWORK-04": "M5", "NETWORK-05": "M5",
    "PLATFORM-01": "M6", "PLATFORM-02": "M3", "PLATFORM-03": "M4",
    "CRYPTO-01": "M10", "CRYPTO-02": "M10",
    "RESILIENCE-01": "M7", "RESILIENCE-02": "M7",
    "PRIVACY-01": "M6", "PRIVACY-02": "M6",
    "SUPPLY-01": "M2",
    "AUTH-01": "M3",
}

