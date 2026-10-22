"""
KhmerShield-AI - Explainable URL Risk Scoring Engine.

Combines domain findings, phishing heuristics, and threat intelligence
reputation into a transparent, bounded 0-100 risk score.

Severity Thresholds (Configurable):
  0 - 19  : LOW
 20 - 49  : MEDIUM
 50 - 79  : HIGH
 80 - 100 : CRITICAL

Verdicts:
  - MALICIOUS
  - SUSPICIOUS
  - NO_KNOWN_THREAT
  - UNKNOWN
  - SCAN_ERROR

Guarantees:
  - UNKNOWN or SCAN_ERROR are never treated as LOW.
  - Correlated findings are capped to avoid runaway double counting.
"""

from __future__ import annotations

from typing import Any


DEFAULT_THRESHOLDS = {
    "low_max": 19,
    "medium_max": 49,
    "high_max": 79,
    "critical_min": 80,
}


def calculate_url_risk(
    findings: list[dict[str, Any]],
    reputation: dict[str, Any],
    is_valid: bool = True,
    error_message: str | None = None,
    thresholds: dict[str, int] | None = None,
) -> dict[str, Any]:
    """
    Compute explainable risk score, level, verdict, recommendations, and scan limitations.
    """
    cfg = thresholds or DEFAULT_THRESHOLDS

    if not is_valid or error_message:
        return {
            "score": 0,
            "level": "UNKNOWN",
            "verdict": "SCAN_ERROR",
            "recommendation": "The submitted URL could not be processed due to invalid syntax or security restrictions.",
            "limitations": [error_message or "Invalid URL input."],
        }

    raw_score = 0
    score_breakdown: list[dict[str, Any]] = []

    # 1. Tally rule-based findings
    # Track categories to prevent runaway double-counting of correlated heuristics
    flagged_categories: set[str] = set()

    for item in findings:
        contrib = item.get("score_contribution", 0)
        finding_name = item.get("finding", "Unknown")

        # Cap multiple keyword heuristics if one is already counted
        if "Lure" in finding_name or "Harvesting" in finding_name:
            if "credentials_or_lures" in flagged_categories:
                contrib = min(contrib, 15)  # reduced weight for subsequent correlated findings
            flagged_categories.add("credentials_or_lures")

        raw_score += contrib
        score_breakdown.append({
            "finding": finding_name,
            "severity": item.get("severity", "low"),
            "contribution": contrib,
        })

    # 2. Factor in Threat Intelligence Reputation
    gsb = reputation.get("google_safe_browsing", {})
    if gsb.get("threat_detected"):
        raw_score += 65
        score_breakdown.append({
            "finding": "Google Safe Browsing Flag",
            "severity": "critical",
            "contribution": 65,
        })

    vt = reputation.get("virustotal", {})
    if vt.get("threat_detected"):
        malicious_count = vt.get("malicious_count", 0)
        vt_contrib = min(75, 40 + (malicious_count * 5))
        raw_score += vt_contrib
        score_breakdown.append({
            "finding": f"VirusTotal Security Vendor Detections ({malicious_count} engines)",
            "severity": "critical",
            "contribution": vt_contrib,
        })

    # 3. DNS resolution context
    dns = reputation.get("dns", {})
    is_unresolvable = dns.get("status") == "unresolvable"

    # Clamp score to 0..100
    final_score = max(0, min(100, raw_score))

    # 4. Determine Risk Level
    if final_score >= cfg["critical_min"]:
        level = "CRITICAL"
    elif final_score >= 50:
        level = "HIGH"
    elif final_score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    # 5. Determine Explainable Verdict
    if final_score >= 80 or reputation.get("threat_confirmed"):
        verdict = "MALICIOUS"
    elif final_score >= 20:
        verdict = "SUSPICIOUS"
    elif is_unresolvable and final_score < 20:
        # Unresolvable domain without other indicators cannot be proven safe
        verdict = "UNKNOWN"
        level = "MEDIUM"
    else:
        verdict = "NO_KNOWN_THREAT"

    # 6. Actionable Recommendations
    if verdict == "MALICIOUS":
        recommendation = (
            "🚨 CRITICAL WARNING: Do NOT open this link or enter passwords, phone numbers, "
            "or banking credentials. This domain matches active phishing or malware distribution patterns."
        )
    elif verdict == "SUSPICIOUS":
        recommendation = (
            "⚠️ CAUTION: Suspicious indicators detected. Independently verify the sender's identity "
            "before clicking or entering any personal or financial information."
        )
    elif verdict == "UNKNOWN":
        recommendation = (
            "ℹ️ UNVERIFIED: The domain does not resolve to an active server or has no threat history. "
            "Exercise normal caution as newly created scam domains may not yet be cataloged."
        )
    else:
        recommendation = (
            "✅ No known threat detected in our current heuristic rules and threat intelligence feeds. "
            "Always remain vigilant when interacting with unexpected links."
        )

    # 7. Note Scan Limitations
    limitations: list[str] = []
    if gsb.get("status") == "not_configured":
        limitations.append("Google Safe Browsing reputation check is not configured.")
    elif gsb.get("status") in {"timeout", "error", "rate_limited"}:
        limitations.append(f"Google Safe Browsing check unavailable: {gsb.get('message')}")

    if vt.get("status") == "not_configured":
        limitations.append("VirusTotal reputation check is not configured.")
    elif vt.get("status") in {"timeout", "error", "rate_limited"}:
        limitations.append(f"VirusTotal check unavailable: {vt.get('message')}")

    if is_unresolvable:
        limitations.append("Domain could not be resolved via standard DNS.")

    return {
        "score": final_score,
        "level": level,
        "verdict": verdict,
        "recommendation": recommendation,
        "score_breakdown": score_breakdown,
        "limitations": limitations,
    }
