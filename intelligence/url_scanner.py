"""
KhmerShield-AI - URL & Phishing Intelligence Pipeline Orchestrator.

Orchestrates:
1. Normalization & SSRF validation (url_normalizer)
2. Domain & brand impersonation analysis (domain_analyzer)
3. Structural phishing & scam heuristic checks (phishing_detector)
4. Threat intelligence & DNS reputation checks (reputation)
5. Explainable multi-factor risk scoring (risk_scorer)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from intelligence.url_normalizer import validate_and_normalize_url
from intelligence.domain_analyzer import analyze_domain
from intelligence.phishing_detector import analyze_phishing_indicators
from intelligence.reputation import get_combined_reputation
from intelligence.risk_scorer import calculate_url_risk


def scan_url(raw_url: str, skip_cache: bool = False, source: str = "web") -> dict[str, Any]:
    """
    Execute end-to-end security analysis for a candidate URL.
    Returns fully structured, serializable scan results.
    """
    scan_id = f"KS-URL-{uuid.uuid4().hex[:8].upper()}"
    scanned_at = datetime.now(timezone.utc).isoformat()

    # Step 1: Normalization & Validation
    norm = validate_and_normalize_url(raw_url)

    if not norm["is_valid"]:
        risk_eval = calculate_url_risk(
            findings=[],
            reputation={},
            is_valid=False,
            error_message=norm["error"],
        )
        return {
            "scan_id": scan_id,
            "url": raw_url,
            "normalized_url": raw_url,
            "domain": "",
            "risk_score": risk_eval["score"],
            "risk_level": risk_eval["level"],
            "verdict": risk_eval["verdict"],
            "recommendation": risk_eval["recommendation"],
            "findings": [{
                "finding": "Invalid or Forbidden URL",
                "severity": "critical" if norm.get("ssrf_risk") else "medium",
                "explanation": norm["error"] or "Malformed URL",
                "evidence": raw_url,
                "score_contribution": 0,
            }],
            "reputation": {},
            "score_breakdown": [],
            "limitations": risk_eval["limitations"],
            "scanned_at": scanned_at,
            "source": source,
        }

    domain = norm["domain"]
    normalized_url = norm["normalized_url"]

    # Step 2: Domain & Brand Impersonation Analysis
    domain_findings = analyze_domain(
        domain=domain,
        is_ip=norm["is_ip"],
        unicode_domain=norm.get("unicode_domain"),
    )

    # Step 3: Phishing & Scam Heuristics Analysis
    phishing_findings = analyze_phishing_indicators(norm)

    # Combine static findings
    all_findings = domain_findings + phishing_findings

    # Step 4: Reputation & DNS Check (skip external queries if SSRF/internal IP)
    if norm["ssrf_risk"]:
        reputation: dict[str, Any] = {
            "dns": {"status": "restricted", "has_dns": False, "resolved_ips": []},
            "google_safe_browsing": {"status": "skipped_ssrf", "threat_detected": False},
            "virustotal": {"status": "skipped_ssrf", "threat_detected": False},
            "threat_confirmed": False,
        }
    else:
        reputation = get_combined_reputation(
            url=normalized_url,
            domain=domain,
            skip_cache=skip_cache,
        )

    # Step 5: Risk Scoring Engine
    risk_eval = calculate_url_risk(
        findings=all_findings,
        reputation=reputation,
        is_valid=True,
    )

    return {
        "scan_id": scan_id,
        "url": raw_url,
        "normalized_url": normalized_url,
        "sanitized_url": norm.get("sanitized_url", normalized_url),
        "domain": domain,
        "unicode_domain": norm.get("unicode_domain", domain),
        "risk_score": risk_eval["score"],
        "risk_level": risk_eval["level"],
        "verdict": risk_eval["verdict"],
        "recommendation": risk_eval["recommendation"],
        "findings": all_findings,
        "score_breakdown": risk_eval["score_breakdown"],
        "reputation": reputation,
        "limitations": risk_eval["limitations"],
        "scanned_at": scanned_at,
        "source": source,
    }
