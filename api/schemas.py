"""
KhmerShield-AI - Pydantic Schemas for API Requests and Responses.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str = Field(
        ...,
        description="The candidate HTTP/HTTPS URL to scan for phishing and scam indicators.",
        min_length=3,
        max_length=4096,
        examples=["https://example.com", "https://aba-bank-security-verify.xyz"],
    )
    skip_cache: bool = Field(
        default=False,
        description="Bypass cached reputation results if fresh threat intelligence is required."
    )
    source: str = Field(
        default="web",
        description="The origin of the scan request (web, telegram, api)."
    )


class FindingItem(BaseModel):
    finding: str
    severity: str
    explanation: str
    evidence: str
    score_contribution: int = 0


class URLScanResponse(BaseModel):
    scan_id: str
    url: str
    normalized_url: str
    sanitized_url: str | None = None
    domain: str
    unicode_domain: str | None = None
    risk_score: int
    risk_level: str
    verdict: str
    recommendation: str
    findings: list[dict[str, Any]] = []
    reputation: dict[str, Any] = {}
    limitations: list[str] = []
    scanned_at: str
    source: str = "web"
