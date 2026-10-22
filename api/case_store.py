from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CASES_FILE = Path(__file__).resolve().parent.parent / "reports" / "telegram_cases.jsonl"


def create_case(scan_result: dict[str, Any], source: str = "web") -> dict[str, Any]:
    CASES_FILE.parent.mkdir(parents=True, exist_ok=True)

    case_id = f"KS-{uuid.uuid4().hex[:12].upper()}"

    case = {
        "case_id": case_id,
        "source": source,
        "created_at": datetime.now(timezone.utc).isoformat(),
        **scan_result,
    }

    with CASES_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(case, ensure_ascii=False, default=str) + "\n")

    return case


def get_cases() -> list[dict[str, Any]]:
    if not CASES_FILE.exists():
        return []

    cases: list[dict[str, Any]] = []

    with CASES_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                cases.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return cases


def get_case(case_id: str) -> dict[str, Any] | None:
    for case in reversed(get_cases()):
        if case.get("case_id") == case_id:
            return case

    return None
