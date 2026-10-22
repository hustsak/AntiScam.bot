from pathlib import Path

import yara


RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def load_rules():
    rule_files = list(RULES_DIR.glob("*.yar"))

    if not rule_files:
        return None

    filepaths = {
        f"rule_{index}": str(path)
        for index, path in enumerate(rule_files)
    }

    return yara.compile(filepaths=filepaths)


def scan_with_yara(file_path: str) -> list[dict]:
    rules = load_rules()

    if rules is None:
        return []

    try:
        matches = rules.match(file_path)

    except Exception as error:
        return [
            {
                "type": "yara_error",
                "severity": "medium",
                "message": f"YARA scan failed: {error}",
            }
        ]

    findings = []

    for match in matches:
        severity = "medium"

        try:
            severity = match.meta.get("severity", "medium")
        except Exception:
            pass

        findings.append(
            {
                "type": "yara_match",
                "severity": severity,
                "rule": match.rule,
                "message": (
                    f"YARA rule matched: {match.rule}"
                ),
            }
        )

    return findings