"""
KhmerShield-AI - Database Models (SQLAlchemy).

Defines schema for URL scan history and security cases:
- scan_id (indexed, unique)
- submitted_url (sanitized if sensitive)
- normalized_url
- domain (indexed)
- risk_score (integer 0-100)
- risk_level (LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN)
- verdict (MALICIOUS, SUSPICIOUS, NO_KNOWN_THREAT, UNKNOWN, SCAN_ERROR)
- findings (JSON)
- reputation (JSON)
- scanned_at (timestamp)
- source (web, telegram, api)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class URLScanRecord(Base):
    __tablename__ = "url_scan_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), unique=True, index=True, nullable=False)
    submitted_url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(32), index=True, nullable=False, default="UNKNOWN")
    verdict = Column(String(64), nullable=False, default="UNKNOWN")
    findings = Column(JSON, nullable=False, default=list)
    reputation = Column(JSON, nullable=False, default=dict)
    scanned_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    source = Column(String(32), nullable=False, default="web")

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "url": self.submitted_url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "verdict": self.verdict,
            "findings": self.findings,
            "reputation": self.reputation,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
            "source": self.source,
        }
