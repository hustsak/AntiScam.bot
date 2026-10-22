"""
KhmerShield-AI - Domain and Brand Impersonation Analyzer.

Analyzes domain characteristics including:
- Excessive subdomains
- Suspicious and high-abuse TLDs
- Known URL shorteners
- Brand impersonation (Cambodian banking, payment apps, Telegram, global brands)
- Punycode and homograph lookalike indicators
- Domain entropy (DGA detection)
"""

from __future__ import annotations

import math
import re
from typing import Any


# High abuse / disposable TLDs frequently observed in phishing and scams
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "fit", "icu",
    "work", "click", "rest", "country", "live", "club", "surf", "monster",
    "beauty", "hair", "skin", "quest", "sbs", "cfd", "cyou"
}

# Known URL shorteners (often used to obscure true scam destinations)
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "rebrand.ly", "lnkd.in", "t.me"
}

# High-profile brands frequently targeted by scams in Cambodia and on Telegram
TARGETED_BRANDS: dict[str, list[str]] = {
    # Cambodian Banks & Payment Platforms
    "ABA Bank": ["aba", "ababank", "aba-bank", "aba-mobile", "abapayment"],
    "Wing Bank": ["wing", "wingmoney", "wingbank", "wing-pay"],
    "ACLEDA Bank": ["acleda", "acledabank", "acleda-mobile", "toan-chit"],
    "TrueMoney": ["truemoney", "true-money"],
    "Bakong": ["bakong", "nbc-bakong", "bakong-kh"],
    "Canadia Bank": ["canadia", "canadiabank"],
    "Prince Bank": ["princebank", "prince-bank"],
    "Sathapana Bank": ["sathapana", "sathapanabank"],
    "Chip Mong Bank": ["chipmong", "chipmongbank"],

    # Social & Messaging Platforms
    "Telegram": ["telegram", "telegrarn", "telegam", "telegrram", "tgram"],
    "Facebook / Meta": ["facebook", "meta-verify", "fb-support", "fb-security"],
    "WhatsApp": ["whatsapp", "whatsap", "whats-app"],
    "TikTok": ["tiktok", "tik-tok"],

    # Tech & Cloud Ecosystem
    "Google": ["google", "gmail", "googledrive"],
    "Microsoft": ["microsoft", "office365", "outlook", "onedrive"],
    "Apple": ["apple", "icloud", "appleid"],
    "Netflix": ["netflix", "net-flix"],
    "PayPal": ["paypal", "pay-pal"],

    # Crypto Exchanges & Wallets
    "Binance": ["binance", "binance-us"],
    "Bybit": ["bybit"],
    "MetaMask": ["metamask", "meta-mask"],
    "Trust Wallet": ["trustwallet", "trust-wallet"],
}

# Legitimate authoritative domains for whitelisting brand mentions
LEGITIMATE_BRAND_DOMAINS: dict[str, set[str]] = {
    "ABA Bank": {"ababank.com"},
    "Wing Bank": {"wingmoney.com", "wingbank.com.kh"},
    "ACLEDA Bank": {"acledabank.com.kh"},
    "TrueMoney": {"truemoney.com.kh", "truemoney.com"},
    "Bakong": {"bakong.nbc.gov.kh", "bakong.nbc.org.kh", "nbc.gov.kh"},
    "Canadia Bank": {"canadiabank.com.kh"},
    "Prince Bank": {"princebank.com.kh"},
    "Sathapana Bank": {"sathapana.com.kh"},
    "Chip Mong Bank": {"chipmongbank.com"},
    "Telegram": {"telegram.org", "t.me", "telegram.me"},
    "Facebook / Meta": {"facebook.com", "fb.com", "meta.com"},
    "WhatsApp": {"whatsapp.com"},
    "TikTok": {"tiktok.com"},
    "Google": {"google.com", "google.com.kh", "accounts.google.com"},
    "Microsoft": {"microsoft.com", "live.com", "office.com"},
    "Apple": {"apple.com", "icloud.com"},
    "Netflix": {"netflix.com"},
    "PayPal": {"paypal.com"},
    "Binance": {"binance.com"},
    "Bybit": {"bybit.com"},
    "MetaMask": {"metamask.io"},
    "Trust Wallet": {"trustwallet.com"},
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for domain randomness/DGA detection."""
    if not text:
        return 0.0
    prob_dict: dict[str, int] = {}
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in prob_dict.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def analyze_domain(domain: str, is_ip: bool = False, unicode_domain: str | None = None) -> list[dict[str, Any]]:
    """
    Analyze domain attributes and return explainable findings.
    Each finding conforms to the required specification:
      - finding: str
      - severity: 'low' | 'medium' | 'high' | 'critical'
      - explanation: str
      - evidence: str
      - score_contribution: int
    """
    findings: list[dict[str, Any]] = []

    if is_ip:
        findings.append({
            "finding": "Raw IP Address as Hostname",
            "severity": "high",
            "explanation": (
                "The URL uses a raw numeric IP address instead of a standard domain name. "
                "Legitimate services almost exclusively use registered domain names."
            ),
            "evidence": f"Host is direct IP: {domain}",
            "score_contribution": 35,
        })
        return findings

    clean_domain = domain.lower().strip()
    labels = clean_domain.split(".")

    # 1. Excessive Subdomains Check
    if len(labels) > 4:
        findings.append({
            "finding": "Excessive Subdomains",
            "severity": "medium",
            "explanation": (
                "The URL domain contains an unusually deep subdomain structure (>4 levels). "
                "Attackers use deep subdomains to mimic legitimate brand names or bypass basic domain filters."
            ),
            "evidence": f"Domain has {len(labels)} labels: {domain}",
            "score_contribution": 20,
        })

    # 2. Suspicious / Disposable TLD
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append({
            "finding": "High-Abuse Top-Level Domain",
            "severity": "medium",
            "explanation": (
                f"The domain uses '.{tld}', a top-level domain frequently associated with automated "
                "malicious campaigns, disposable spam sites, and low-cost phishing infrastructure."
            ),
            "evidence": f"TLD: .{tld}",
            "score_contribution": 18,
        })

    # 3. Known URL Shortener
    if clean_domain in KNOWN_SHORTENERS or any(clean_domain.endswith("." + s) for s in KNOWN_SHORTENERS):
        findings.append({
            "finding": "URL Shortener Service Detected",
            "severity": "medium",
            "explanation": (
                "The URL uses a link shortening service. Shortened links obscure the final destination, "
                "preventing users from inspecting where the link actually leads before clicking."
            ),
            "evidence": f"Shortener domain: {clean_domain}",
            "score_contribution": 15,
        })

    # 4. Brand Impersonation / Deceptive Lookalikes
    # Extract registered domain / base without standard TLDs for matching
    base_parts = labels[:-1] if len(labels) > 1 else labels
    base_domain_str = "-".join(base_parts)

    for brand_name, keywords in TARGETED_BRANDS.items():
        legit_domains = LEGITIMATE_BRAND_DOMAINS.get(brand_name, set())

        # Check if the domain itself is an official verified domain of that brand
        is_legit = False
        for legit in legit_domains:
            if clean_domain == legit or clean_domain.endswith("." + legit):
                is_legit = True
                break

        if is_legit:
            continue

        # Look for keywords in non-legit domains
        matched_keyword = None
        for kw in keywords:
            # Match keyword if present with hyphens, subdomains, or exact word boundary
            pattern = re.compile(rf"(^|[-_.0-9]){re.escape(kw)}([-_.0-9]|$)", re.IGNORECASE)
            if pattern.search(clean_domain) or kw in base_domain_str:
                matched_keyword = kw
                break

        if matched_keyword:
            findings.append({
                "finding": f"Deceptive Brand Impersonation: {brand_name}",
                "severity": "critical",
                "explanation": (
                    f"The domain incorporates references to '{brand_name}' ({matched_keyword}) but is not "
                    f"hosted on the official {brand_name} infrastructure. This is a primary indicator of phishing."
                ),
                "evidence": f"Found brand indicator '{matched_keyword}' in unregistered domain '{clean_domain}'",
                "score_contribution": 55,
            })
            break  # Avoid double-flagging multiple brands on one domain

    # 5. Punycode / Internationalized Domain Name (IDN) Homograph Indicator
    if "xn--" in clean_domain or (unicode_domain and unicode_domain != clean_domain):
        findings.append({
            "finding": "Punycode / IDN Homograph Candidate",
            "severity": "high",
            "explanation": (
                "The domain utilizes Punycode / non-ASCII characters. Cybercriminals exploit internationalized "
                "characters that look visually identical to Latin letters to trick users into trusting a spoofed domain."
            ),
            "evidence": f"ASCII: {clean_domain} | Unicode Representation: {unicode_domain or clean_domain}",
            "score_contribution": 30,
        })

    # 6. Domain Name Shannon Entropy (DGA or Random Generation)
    # Exclude common TLDs from entropy calculation
    core_label = labels[0] if labels else clean_domain
    entropy = calculate_entropy(core_label)
    if entropy > 3.8 and len(core_label) >= 10:
        findings.append({
            "finding": "High Domain Entropy (Potential DGA)",
            "severity": "medium",
            "explanation": (
                f"The domain label '{core_label}' has high character randomness (entropy {entropy:.2f}), "
                "characteristic of Domain Generation Algorithms (DGA) used by malware command-and-control servers."
            ),
            "evidence": f"Entropy: {entropy} on label '{core_label}'",
            "score_contribution": 20,
        })

    return findings
