SEVERITY_POINTS = {
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 50,
}


def calculate_risk(findings) -> dict:
    flat_findings = []

    if isinstance(findings, dict):
        for key, val in findings.items():
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        flat_findings.append(item)
            elif isinstance(val, dict):
                flat_findings.append(val)
    elif isinstance(findings, list):
        for item in findings:
            if isinstance(item, dict):
                flat_findings.append(item)

    score = 0
    valid_findings = []

    for finding in flat_findings:
        ftype = finding.get("type", "")
        if ftype in ("clamav_error", "yara_error", "clamav_timeout"):
            continue
        valid_findings.append(finding)
        sev = str(finding.get("severity", "low")).lower()
        score += SEVERITY_POINTS.get(sev, 10)

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "findings_count": len(valid_findings),
    }
