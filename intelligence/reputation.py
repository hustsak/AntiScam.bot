"""
KhmerShield-AI - Threat Intelligence & Reputation Provider Integrations.

Supports:
- Google Safe Browsing API v4
- VirusTotal API v3 (URL Analysis)
- DNS Host Resolution & IP Verification

Security & Reliability Principles:
- Environment variable API key retrieval (never hardcoded, never logged).
- Works gracefully without external API keys (flags as 'not_configured').
- Non-blocking network timeouts (max 4.0s) and exception resilience.
- Local in-memory TTL caching to respect rate limits.
- Clear distinction between 'clean', 'threat_found', 'unavailable', and 'not_configured'.
"""

from __future__ import annotations

import base64
import os
import socket
import time
from typing import Any
import urllib.parse

import requests
from dotenv import load_dotenv

load_dotenv()

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

# In-memory reputation cache: key -> (timestamp, data)
REPUTATION_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
CACHE_TTL_SECONDS = 300  # 5 minutes cache


def check_dns(domain: str) -> dict[str, Any]:
    """Perform safe local DNS resolution to verify domain existence and retrieve IPs."""
    clean_domain = domain.strip().lower()
    try:
        addr_info = socket.getaddrinfo(clean_domain, None)
        ips = sorted(list({item[4][0] for item in addr_info if item and len(item) > 4}))
        return {
            "status": "resolved",
            "has_dns": bool(ips),
            "resolved_ips": ips,
            "error": None,
        }
    except socket.gaierror as e:
        return {
            "status": "unresolvable",
            "has_dns": False,
            "resolved_ips": [],
            "error": f"Domain does not resolve: {e.strerror}",
        }
    except Exception as e:
        return {
            "status": "error",
            "has_dns": False,
            "resolved_ips": [],
            "error": str(e),
        }


def check_google_safe_browsing(url: str) -> dict[str, Any]:
    """
    Query Google Safe Browsing Lookup API (v4).
    Returns threat matches or clean status.
    """
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {
            "provider": "google_safe_browsing",
            "status": "not_configured",
            "threat_detected": False,
            "threats": [],
            "message": "Google Safe Browsing API key not configured.",
        }

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {
            "clientId": "khmershield-ai",
            "clientVersion": "0.1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=4.0)
        if resp.status_code == 429:
            return {
                "provider": "google_safe_browsing",
                "status": "rate_limited",
                "threat_detected": False,
                "threats": [],
                "message": "Provider rate limit reached.",
            }
        resp.raise_for_status()
        data = resp.json()

        matches = data.get("matches", [])
        if matches:
            threat_types = list({m.get("threatType", "THREAT") for m in matches})
            return {
                "provider": "google_safe_browsing",
                "status": "threat_found",
                "threat_detected": True,
                "threats": threat_types,
                "message": f"Identified as {', '.join(threat_types)} by Google Safe Browsing.",
            }

        return {
            "provider": "google_safe_browsing",
            "status": "clean",
            "threat_detected": False,
            "threats": [],
            "message": "No match found in Google Safe Browsing database.",
        }
    except requests.Timeout:
        return {
            "provider": "google_safe_browsing",
            "status": "timeout",
            "threat_detected": False,
            "threats": [],
            "message": "Google Safe Browsing request timed out.",
        }
    except Exception as e:
        return {
            "provider": "google_safe_browsing",
            "status": "error",
            "threat_detected": False,
            "threats": [],
            "message": f"Provider error: {e}",
        }


def check_virustotal(url: str) -> dict[str, Any]:
    """
    Query VirusTotal API v3 URL report using base64 URL identifier.
    Does not submit new scans, only queries existing reputation.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "provider": "virustotal",
            "status": "not_configured",
            "threat_detected": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_engines": 0,
            "message": "VirusTotal API key not configured.",
        }

    # VirusTotal v3 URL ID is base64 encoded URL without padding
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:
        resp = requests.get(endpoint, headers=headers, timeout=4.0)
        if resp.status_code == 404:
            return {
                "provider": "virustotal",
                "status": "not_found",
                "threat_detected": False,
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "total_engines": 0,
                "message": "URL has not been previously submitted to VirusTotal.",
            }
        if resp.status_code == 429:
            return {
                "provider": "virustotal",
                "status": "rate_limited",
                "threat_detected": False,
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "total_engines": 0,
                "message": "VirusTotal rate limit exceeded.",
            }
        resp.raise_for_status()
        data = resp.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = sum(stats.values()) if stats else 0

        threat_detected = (malicious + suspicious) > 0

        return {
            "provider": "virustotal",
            "status": "threat_found" if threat_detected else "clean",
            "threat_detected": threat_detected,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "total_engines": total,
            "message": (
                f"{malicious} engine(s) flagged this URL as malicious"
                if threat_detected
                else f"Clean across {total} security vendors."
            ),
        }
    except requests.Timeout:
        return {
            "provider": "virustotal",
            "status": "timeout",
            "threat_detected": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_engines": 0,
            "message": "VirusTotal request timed out.",
        }
    except Exception as e:
        return {
            "provider": "virustotal",
            "status": "error",
            "threat_detected": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_engines": 0,
            "message": f"VirusTotal query error: {e}",
        }


def get_combined_reputation(url: str, domain: str, skip_cache: bool = False) -> dict[str, Any]:
    """
    Fetch reputation data across all threat intelligence sources with caching.
    """
    now = time.time()
    cache_key = f"{url}|{domain}"

    if not skip_cache and cache_key in REPUTATION_CACHE:
        cached_time, cached_data = REPUTATION_CACHE[cache_key]
        if now - cached_time < CACHE_TTL_SECONDS:
            return cached_data

    # Check local DNS
    dns_result = check_dns(domain)

    # Check external reputation providers
    gsb_result = check_google_safe_browsing(url)
    vt_result = check_virustotal(url)

    combined = {
        "dns": dns_result,
        "google_safe_browsing": gsb_result,
        "virustotal": vt_result,
        "threat_confirmed": bool(gsb_result.get("threat_detected") or vt_result.get("threat_detected")),
    }

    REPUTATION_CACHE[cache_key] = (now, combined)
    return combined
