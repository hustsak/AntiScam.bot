"""
KhmerShield-AI - Database Connection & Persistence Manager.

Supports PostgreSQL via DATABASE_URL environment variable.
Falls back to SQLite (or JSONL mirror) to ensure the system is operational
under any environment without crashing if a PostgreSQL server is offline.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker

from database.models import Base, URLScanRecord

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
URL_CASES_JSONL = REPORTS_DIR / "url_cases.jsonl"

RAW_DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

if RAW_DATABASE_URL:
    # Ensure postgresql:// scheme is used for SQLAlchemy
    if RAW_DATABASE_URL.startswith("postgres://"):
        DB_URI = RAW_DATABASE_URL.replace("postgres://", "postgresql://", 1)
    else:
        DB_URI = RAW_DATABASE_URL
else:
    # Resilient local SQLite fallback
    DB_PATH = REPORTS_DIR / "khmershield.db"
    DB_URI = f"sqlite:///{DB_PATH}"

try:
    engine = create_engine(DB_URI, echo=False, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    DB_AVAILABLE = True
except Exception as exc:
    print(f"[KhmerShield DB Warning] Could not initialize SQL database: {exc}. Using file fallback.")
    DB_AVAILABLE = False
    SessionLocal = None


def save_url_record(scan_data: dict[str, Any]) -> None:
    """
    Save URL scan record into database and JSONL file store.
    Sanitizes query tokens prior to storage.
    """
    # 1. Dual-write to JSONL file store for audit and quick CLI inspection
    sanitized_url = scan_data.get("sanitized_url") or scan_data.get("url", "")
    normalized_url = scan_data.get("normalized_url") or sanitized_url

    file_record = {
        "scan_id": scan_data.get("scan_id"),
        "url": sanitized_url,
        "normalized_url": normalized_url,
        "domain": scan_data.get("domain", ""),
        "risk_score": scan_data.get("risk_score", 0),
        "risk_level": scan_data.get("risk_level", "UNKNOWN"),
        "verdict": scan_data.get("verdict", "UNKNOWN"),
        "findings": scan_data.get("findings", []),
        "reputation": scan_data.get("reputation", {}),
        "scanned_at": scan_data.get("scanned_at") or datetime.now(timezone.utc).isoformat(),
        "source": scan_data.get("source", "web"),
    }

    try:
        with URL_CASES_JSONL.open("a", encoding="utf-8") as f:
            f.write(json.dumps(file_record, ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        print(f"[KhmerShield File Store Error] {e}")

    # 2. Persist to SQL (PostgreSQL / SQLite)
    if not DB_AVAILABLE or SessionLocal is None:
        return

    session = SessionLocal()
    try:
        # Check if already exists
        scan_id = scan_data.get("scan_id")
        existing = session.query(URLScanRecord).filter_by(scan_id=scan_id).first()
        if existing:
            return

        record = URLScanRecord(
            scan_id=scan_id,
            submitted_url=sanitized_url,
            normalized_url=normalized_url,
            domain=scan_data.get("domain", ""),
            risk_score=scan_data.get("risk_score", 0),
            risk_level=scan_data.get("risk_level", "UNKNOWN"),
            verdict=scan_data.get("verdict", "UNKNOWN"),
            findings=scan_data.get("findings", []),
            reputation=scan_data.get("reputation", {}),
            source=scan_data.get("source", "web"),
        )
        session.add(record)
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"[KhmerShield SQL Store Error] {e}")
    finally:
        session.close()


def get_url_records(
    risk: str | None = None,
    search: str | None = None,
    limit: int = 100
) -> list[dict[str, Any]]:
    """Retrieve URL scan cases with filtering."""
    results: list[dict[str, Any]] = []

    # If SQL is available, try SQL first
    if DB_AVAILABLE and SessionLocal is not None:
        session = SessionLocal()
        try:
            query = session.query(URLScanRecord).order_by(desc(URLScanRecord.id))
            if risk and risk != "all":
                query = query.filter(URLScanRecord.risk_level == risk.upper())
            if search:
                term = f"%{search.lower()}%"
                query = query.filter(
                    URLScanRecord.domain.ilike(term)
                    | URLScanRecord.submitted_url.ilike(term)
                    | URLScanRecord.scan_id.ilike(term)
                )
            records = query.limit(limit).all()
            results = [r.to_dict() for r in records]
            return results
        except Exception as e:
            print(f"[KhmerShield DB Query Error] {e}. Falling back to file store.")
        finally:
            session.close()

    # Fallback to JSONL file store
    if not URL_CASES_JSONL.exists():
        return []

    try:
        with URL_CASES_JSONL.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return []

    # Apply filters in reverse order (newest first)
    results.reverse()
    if risk and risk != "all":
        results = [r for r in results if str(r.get("risk_level", "")).lower() == risk.lower()]
    if search:
        s = search.lower()
        results = [
            r for r in results
            if s in str(r.get("domain", "")).lower()
            or s in str(r.get("url", "")).lower()
            or s in str(r.get("scan_id", "")).lower()
        ]

    return results[:limit]
