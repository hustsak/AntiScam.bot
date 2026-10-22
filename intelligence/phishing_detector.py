"""
KhmerShield-AI - Explainable Phishing & Scam Detection Engine.

Analyzes URL structure, path, and query parameters for:
- Credential harvesting & login deception patterns
- Payment and banking lure keywords
- Urgency and social engineering triggers
- Unusual non-standard ports
- Excessive URL length and obfuscated encoding
- Deceptive file extensions (.apk, .exe, .scr, double extensions)
- Credentials embedded in URL / @ symbol abuse
- Open redirect parameter patterns
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote


# Login and account harvesting keywords
CREDENTIAL_HARVEST_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "auth", "authenticate",
    "password", "passwd", "credential", "account-verify", "verify-account",
    "security-center", "update-profile", "restore-access", "unlock-account",
    "kyc-verify", "wallet-connect", "import-wallet", "private-key", "seed-phrase"
}

# Payment & scam lure keywords
PAYMENT_LURE_KEYWORDS = {
    "payment", "invoice", "receipt", "transfer", "refund", "remittance",
    "win-prize", "lucky-draw", "airdrop", "free-gift", "claim-reward",
    "bonus-claim", "gift-card", "lottery", "giveaway"
}

# Urgency / psychological coercion patterns
URGENCY_KEYWORDS = {
    "urgent", "action-required", "suspended", "immediate", "emergency",
    "terminated", "warning-alert", "security-alert", "restricted-notice"
}

# Dangerous or suspicious executable/payload extensions in URLs
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".apk",
    ".msi", ".jar", ".dll", ".hta", ".iso", ".wsf", ".vbe"
}

# Standard web ports
STANDARD_PORTS = {80, 443}


def analyze_phishing_indicators(normalized_data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Evaluate URL path, query, port, and structure against explainable phishing rules.
    Returns a list of structured findings.
    """
    findings: list[dict[str, Any]] = []

    raw_url = normalized_data.get("raw_url", "")
    normalized_url = normalized_data.get("normalized_url", "")
    scheme = normalized_data.get("scheme", "")
    domain = normalized_data.get("domain", "")
    port = normalized_data.get("port")
    path = normalized_data.get("path", "")
    query = normalized_data.get("query", "")
    has_credentials = normalized_data.get("has_credentials", False)
    is_ip = normalized_data.get("is_ip", False)
    ssrf_risk = normalized_data.get("ssrf_risk", False)

    # 1. SSRF and Private Network Protection
    if ssrf_risk:
        findings.append({
            "finding": "SSRF / Internal Infrastructure Risk",
            "severity": "critical",
            "explanation": (
                "The URL targets a private IP, loopback, or cloud internal metadata address. "
                "These destinations cannot be queried and represent an attempted Server-Side Request Forgery."
            ),
            "evidence": f"Target address is restricted: {domain}",
            "score_contribution": 60,
        })

    # 2. Embedded Credentials / Userinfo or '@' symbol in URL
    if has_credentials or "@" in raw_url:
        findings.append({
            "finding": "Embedded Credentials / '@' Symbol Deception",
            "severity": "high",
            "explanation": (
                "The URL contains an '@' character or embedded credentials. Browsers historically treat text "
                "before '@' as authentication userinfo, allowing attackers to make 'fake-bank.com@malicious.com' "
                "look like a trusted domain to unsuspecting victims."
            ),
            "evidence": f"Credential pattern detected in URL authority component",
            "score_contribution": 35,
        })

    # 3. Non-Standard Port Usage
    if port and port not in STANDARD_PORTS:
        severity = "high" if port in {2082, 2083, 8080, 8888, 8443, 9000, 10000} else "medium"
        findings.append({
            "finding": f"Non-Standard Port Usage (Port {port})",
            "severity": severity,
            "explanation": (
                f"The URL specifies custom port {port} instead of standard HTTP (80) or HTTPS (443). "
                "Phishing kits and rogue administrative consoles frequently host on non-standard ports to evade security proxies."
            ),
            "evidence": f"Port: {port}",
            "score_contribution": 20,
        })

    # 4. Excessive URL Length
    url_len = len(normalized_url)
    if url_len > 180:
        findings.append({
            "finding": "Excessive URL Length",
            "severity": "medium",
            "explanation": (
                f"The URL is unusually long ({url_len} characters). Attackers use long URLs to hide malicious "
                "paths or parameters beyond mobile browser address bar visibility."
            ),
            "evidence": f"Total character length: {url_len}",
            "score_contribution": 15,
        })

    # 5. Excessive URL Percent-Encoding
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", raw_url)
    if len(encoded_matches) > 6:
        findings.append({
            "finding": "Heavy Percent-Encoding / Obfuscation",
            "severity": "medium",
            "explanation": (
                f"The URL contains {len(encoded_matches)} hex percent-encoded sequences. "
                "Excessive encoding is often utilized to conceal suspicious keywords from automated web filters."
            ),
            "evidence": f"Found {len(encoded_matches)} encoded characters in URL",
            "score_contribution": 15,
        })

    # Decoded path and query for semantic analysis
    combined_path_query = (unquote(path) + " " + unquote(query)).lower()

    # 6. Credential & Login Harvesting Indicators
    matched_creds = [k for k in CREDENTIAL_HARVEST_KEYWORDS if k in combined_path_query]
    if matched_creds:
        # If hosted on an IP address or suspicious TLD, elevate severity
        severity = "critical" if is_ip else "high"
        findings.append({
            "finding": "Credential Harvesting / Account Lure Patterns",
            "severity": severity,
            "explanation": (
                f"The URL path or query contains keywords associated with login, account recovery, or credential input "
                f"({', '.join(matched_creds[:3])}). If this site does not belong to a verified institution, entering data is dangerous."
            ),
            "evidence": f"Matched patterns: {', '.join(matched_creds)}",
            "score_contribution": 35,
        })

    # 7. Payment, Lucky Draw, and Scam Lures
    matched_lures = [k for k in PAYMENT_LURE_KEYWORDS if k in combined_path_query]
    if matched_lures:
        findings.append({
            "finding": "Financial / Incentive Scam Lure Keywords",
            "severity": "high",
            "explanation": (
                f"The URL advertises prizes, payments, or rewards ({', '.join(matched_lures[:3])}). "
                "Fake lottery, airdrop, and free gift campaigns are among the most common scam vectors on Telegram."
            ),
            "evidence": f"Lure keywords detected: {', '.join(matched_lures)}",
            "score_contribution": 25,
        })

    # 8. Urgency / Social Engineering Triggers
    matched_urgency = [k for k in URGENCY_KEYWORDS if k in combined_path_query]
    if matched_urgency:
        findings.append({
            "finding": "Psychological Urgency Trigger",
            "severity": "medium",
            "explanation": (
                f"The URL incorporates urgency triggers ({', '.join(matched_urgency[:2])}) designed to pressure "
                "victims into hasty compliance before verifying legitimacy."
            ),
            "evidence": f"Urgency keywords: {', '.join(matched_urgency)}",
            "score_contribution": 15,
        })

    # 9. Direct Executable / Dangerous Download in URL Path
    lowered_path = path.lower()
    for ext in EXECUTABLE_EXTENSIONS:
        if lowered_path.endswith(ext) or f"{ext}?" in lowered_path:
            findings.append({
                "finding": f"Direct Payload Download Detected ({ext})",
                "severity": "critical",
                "explanation": (
                    f"The URL points directly to an executable, script, or mobile package file ({ext}). "
                    "Visiting this link may trigger automatic malicious downloads or malware delivery."
                ),
                "evidence": f"Direct file extension: {ext} in path {path}",
                "score_contribution": 45,
            })
            break

    # 10. Open Redirect Parameter Vulnerability
    redirect_params = {"redirect", "redirect_url", "redir", "url", "next", "return", "dest", "destination", "target"}
    param_names = [p.split("=")[0].lower() for p in query.split("&") if "=" in p]
    matched_redirect_params = [p for p in param_names if p in redirect_params]
    if matched_redirect_params:
        findings.append({
            "finding": "Potential Open Redirect Parameter",
            "severity": "low",
            "explanation": (
                f"The URL contains parameters commonly associated with external redirects ({', '.join(matched_redirect_params)}). "
                "Attackers leverage open redirects on trusted websites to bounce victims to malicious destinations."
            ),
            "evidence": f"Parameters: {', '.join(matched_redirect_params)}",
            "score_contribution": 10,
        })

    return findings
