"""
KhmerShield-AI - URL Intelligence & Phishing Scanner API Router.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Query, status

from api.schemas import URLScanRequest, URLScanResponse
from intelligence.url_scanner import scan_url
from database.connection import save_url_record, get_url_records

router = APIRouter(prefix="/api", tags=["URL & Phishing Intelligence"])


@router.post(
    "/scan-url",
    response_model=URLScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan suspicious URL for phishing, impersonation, and scam threats",
)
async def api_scan_url(payload: URLScanRequest) -> dict[str, Any]:
    """
    Submits a URL to KhmerShield-AI's multi-layered detection pipeline:
    - URL parsing, punycode normalization, and SSRF filtering
    - Domain reputation & brand impersonation checks (Cambodian banks, Telegram, global brands)
    - Phishing heuristics (credential harvesting, lures, urgency triggers)
    - Threat intelligence feeds (Google Safe Browsing, VirusTotal, DNS)
    - 0-100 explainable risk scoring
    """
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL parameter cannot be empty."
        )

    # Execute security analysis
    result = scan_url(
        raw_url=raw_url,
        skip_cache=payload.skip_cache,
        source=payload.source,
    )

    # Persist scan history safely
    try:
        save_url_record(result)
    except Exception as exc:
        print(f"[KhmerShield DB Warning] Record save failed: {exc}")

    return result


@router.get(
    "/url-cases",
    summary="List historical URL security scans",
)
async def api_get_url_cases(
    risk: str | None = Query(None, description="Filter by risk level: low, medium, high, critical"),
    search: str | None = Query(None, description="Search term for URL, domain, or scan ID"),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """Retrieve indexed URL scan records with optional risk and keyword filters."""
    cases = get_url_records(risk=risk, search=search, limit=limit)
    return {
        "total": len(cases),
        "cases": cases,
    }


@router.get(
    "/url-cases/stats",
    summary="Get aggregate URL threat statistics",
)
async def api_get_url_case_stats() -> dict[str, Any]:
    """Calculate threat distribution statistics across all URL scans."""
    cases = get_url_records(limit=1000)
    stats = {
        "total": len(cases),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "malicious": 0,
    }

    for c in cases:
        level = str(c.get("risk_level", "")).lower()
        if level in stats:
            stats[level] += 1
        if str(c.get("verdict", "")).upper() == "MALICIOUS":
            stats["malicious"] += 1

    return stats
